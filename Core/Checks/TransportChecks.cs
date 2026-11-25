using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using SsddMailAnalyser.Core;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core.Checks;

// ===================================================================== MX

public sealed class MxHost
{
    public string Host { get; init; } = "";
    public ushort Preference { get; init; }
    public List<IPAddress> Addresses { get; } = new();
    public string? Problem { get; set; }
}

public sealed class MxCheck
{
    public string Domain { get; init; } = "";
    public DnsStatus Status { get; set; }
    public bool NullMx { get; set; }
    public bool ImplicitMx { get; set; }
    public List<MxHost> Hosts { get; } = new();
    public string Detail { get; set; } = "";
    public bool DomainExists => Status != DnsStatus.NxDomain;
    public bool Usable => !NullMx && Hosts.Any(h => h.Addresses.Count > 0);
}

public static class MxChecker
{
    public static MxCheck Check(DnsClient dns, string domain, CancellationToken cancel)
    {
        var check = new MxCheck { Domain = DomainUtil.Normalize(domain) };
        var r = dns.Query(check.Domain, DnsType.MX, cancel);
        check.Status = r.Status;

        if (r.IsTransient)
        {
            check.Detail = $"MX lookup failed: {r.Describe()}";
            return check;
        }
        if (r.Status == DnsStatus.NxDomain)
        {
            check.Detail = "the domain does not exist (NXDOMAIN)";
            return check;
        }

        var mx = r.Mx();
        if (mx.Count == 1 && string.IsNullOrEmpty(mx[0].Target) && mx[0].Preference == 0)
        {
            check.NullMx = true;
            check.Detail = "null MX (\"0 .\"): the domain declares that it accepts no mail";
            return check;
        }

        if (mx.Count == 0)
        {
            // RFC 5321 5.1: no MX means the domain's own A/AAAA is the mail server.
            check.ImplicitMx = true;
            var host = new MxHost { Host = check.Domain };
            host.Addresses.AddRange(dns.Addresses(check.Domain, cancel));
            if (host.Addresses.Count == 0) host.Problem = "no MX and no A/AAAA record";
            check.Hosts.Add(host);
            check.Detail = host.Addresses.Count > 0
                ? "no MX record; senders fall back to the domain's A record"
                : "no MX and no address record: nobody can deliver to this domain";
            return check;
        }

        foreach (var rec in mx)
        {
            var host = new MxHost { Host = rec.Target ?? "", Preference = rec.Preference };
            if (NetUtil.TryParseIp(host.Host, out _))
            {
                host.Problem = "MX points to an IP address, not a host name (invalid)";
            }
            else
            {
                host.Addresses.AddRange(dns.Addresses(host.Host, cancel));
                var cname = dns.Query(host.Host, DnsType.A, cancel).OfType(DnsType.CNAME).Any();
                if (host.Addresses.Count == 0) host.Problem = "the MX host name does not resolve";
                else if (cname) host.Problem = "the MX host is a CNAME (tolerated by most, not RFC-conformant)";
            }
            check.Hosts.Add(host);
        }
        check.Detail = string.Join(", ", check.Hosts.Select(h => $"{h.Preference} {h.Host}"));
        return check;
    }
}

// ===================================================================== MTA-STS / TLS-RPT / DANE

public sealed class MtaStsCheck
{
    public string Domain { get; init; } = "";
    public string? TxtRecord { get; set; }
    public string? TlsRpt { get; set; }
    public bool PolicyFetched { get; set; }
    public string? Mode { get; set; }
    public List<string> MxPatterns { get; } = new();
    public string? Problem { get; set; }
    public List<string> UncoveredMx { get; } = new();
    public Dictionary<string, string> Tlsa { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public static class MtaStsChecker
{
    public static MtaStsCheck Check(DnsClient dns, string domain, MxCheck mx, bool fetchPolicy, CancellationToken cancel, TraceLog? trace = null)
    {
        var check = new MtaStsCheck { Domain = DomainUtil.Normalize(domain) };

        check.TxtRecord = dns.Query("_mta-sts." + check.Domain, DnsType.TXT, cancel).Texts()
            .FirstOrDefault(t => t.StartsWith("v=STSv1", StringComparison.OrdinalIgnoreCase));
        check.TlsRpt = dns.Query("_smtp._tls." + check.Domain, DnsType.TXT, cancel).Texts()
            .FirstOrDefault(t => t.StartsWith("v=TLSRPTv1", StringComparison.OrdinalIgnoreCase));

        foreach (var host in mx.Hosts.Take(4))
        {
            var t = dns.Query($"_25._tcp.{host.Host}", DnsType.TLSA, cancel);
            if (t.IsOk) check.Tlsa[host.Host] = string.Join(" | ", t.OfType(DnsType.TLSA).Select(x => x.Tlsa));
        }

        if (check.TxtRecord is null || !fetchPolicy) return check;

        const int MaxPolicyBytes = 64 * 1024;   // the size RFC 8461 suggests as an upper bound
        var url = $"https://mta-sts.{check.Domain}/.well-known/mta-sts.txt";
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            // RFC 8461 3.3: redirects must not be followed, and a policy is small. A sending
            // server that meets a redirect has no policy, so neither has this check.
            using var handler = new HttpClientHandler { AllowAutoRedirect = false };
            using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8), MaxResponseContentBufferSize = MaxPolicyBytes };
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = http.Send(request, cancel);
            if (!response.IsSuccessStatusCode)
            {
                int status = (int)response.StatusCode;
                check.Problem = status is >= 300 and < 400
                    ? $"policy URL answered HTTP {status}, a redirect" + (response.Headers.Location is { } to ? $" to {to}" : "") + "; sending servers do not follow redirects for MTA-STS (RFC 8461)"
                    : $"policy URL answered HTTP {status}";
                trace?.Add("HTTP", "GET " + url, TraceOutcome.Fail, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}",
                           string.Join("\n", response.Headers.Select(h => $"{h.Key}: {string.Join(", ", h.Value)}")), sw.Elapsed.TotalMilliseconds);
                return check;
            }
            using var stream = response.Content.ReadAsStream(cancel);
            using var reader = new StreamReader(stream);
            var body = reader.ReadToEnd();
            check.PolicyFetched = true;
            trace?.Add("HTTP", "GET " + url, TraceOutcome.Ok, $"HTTP {(int)response.StatusCode}, {body.Length} bytes", body, sw.Elapsed.TotalMilliseconds);
            foreach (var line in body.Split('\n'))
            {
                var kv = line.Split(':', 2);
                if (kv.Length != 2) continue;
                var key = kv[0].Trim().ToLowerInvariant();
                var value = kv[1].Trim();
                if (key == "mode") check.Mode = value.ToLowerInvariant();
                else if (key == "mx") check.MxPatterns.Add(value.ToLowerInvariant());
            }

            foreach (var host in mx.Hosts)
            {
                if (!check.MxPatterns.Any(p => Matches(p, host.Host))) check.UncoveredMx.Add(host.Host);
            }
        }
        catch (Exception ex) when (ex is UriFormatException or InvalidOperationException)
        {
            check.Problem = "policy URL cannot be formed for this domain name";
            trace?.Add("HTTP", "GET " + url, TraceOutcome.Fail, check.Problem, ex.Message, sw.Elapsed.TotalMilliseconds);
        }
        catch (HttpRequestException ex)
        {
            check.Problem = "policy could not be fetched: " + (ex.InnerException?.Message ?? ex.Message);
            trace?.Add("HTTP", "GET " + url, TraceOutcome.Fail, check.Problem, ex.ToString(), sw.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
        {
            check.Problem = "policy fetch timed out";
            trace?.Add("HTTP", "GET " + url, TraceOutcome.Fail, check.Problem, "", sw.Elapsed.TotalMilliseconds);
        }
        return check;
    }

    private static bool Matches(string pattern, string host)
    {
        if (pattern.StartsWith("*."))
        {
            var suffix = pattern[1..];
            return host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                   && host.Count(c => c == '.') == pattern.Count(c => c == '.');
        }
        return host.Equals(pattern, StringComparison.OrdinalIgnoreCase);
    }
}

// ===================================================================== SMTP probe

public sealed class SmtpProbeResult
{
    public string Host { get; init; } = "";
    public IPAddress? Address { get; set; }
    public TcpOutcome Connect { get; set; }
    public double ConnectMs { get; set; }
    public bool Connected => Connect == TcpOutcome.Connected;
    public string? Banner { get; set; }
    public int BannerCode { get; set; }
    public List<string> Capabilities { get; } = new();
    public bool StartTlsOffered { get; set; }
    public bool TlsEstablished { get; set; }
    public string? TlsProtocol { get; set; }
    public string? TlsCipher { get; set; }
    public string? CertSubject { get; set; }
    public string? CertIssuer { get; set; }
    public List<string> CertNames { get; } = new();
    public DateTime? CertNotBefore { get; set; }
    public DateTime? CertNotAfter { get; set; }
    public string? CertThumbprint { get; set; }
    public bool CertNameMatches { get; set; }
    public string? CertChainProblem { get; set; }
    public long? MaxSize { get; set; }
    public string? Error { get; set; }
    public bool PortBlockedLocally { get; set; }
    public List<string> Transcript { get; } = new();
}

/// <summary>
/// Connects to an MX on port 25, reads the banner, says EHLO, upgrades with STARTTLS and
/// looks at the certificate. Sends no MAIL FROM: nothing is ever delivered or queued.
/// Every step goes into the trace with its timing and the server's full reply.
/// </summary>
public static class SmtpProbe
{
    /// <summary>The whole session may take this long, however slowly the server answers.</summary>
    public const int SessionSeconds = 45;

    /// <param name="publicIp">This machine's public address, when known: it is what EHLO announces.</param>
    public static SmtpProbeResult Probe(string host, IPAddress address, CancellationToken cancel, TraceLog? trace = null, int timeoutSeconds = 10,
                                        IPAddress? publicIp = null, int sessionSeconds = SessionSeconds)
    {
        var result = new SmtpProbeResult { Host = host, Address = address };
        var timeout = TimeSpan.FromSeconds(timeoutSeconds);

        var tcp = TcpProbe.Connect(address, 25, timeout, cancel, keepOpen: true);
        result.Connect = tcp.Outcome;
        result.ConnectMs = tcp.Ms;
        trace?.Add("TCP", $"connect {host} [{address}]:25", tcp.Outcome == TcpOutcome.Connected ? TraceOutcome.Ok : TraceOutcome.Fail,
                   tcp.Describe(), tcp.Error ?? "", tcp.Ms);
        if (tcp.Outcome != TcpOutcome.Connected || tcp.Socket is null)
        {
            result.Error = tcp.Describe();
            result.PortBlockedLocally = tcp.Outcome is TcpOutcome.Timeout or TcpOutcome.Unreachable;
            tcp.Socket?.Dispose();
            return result;
        }

        using var socket = tcp.Socket;

        // The read timeout starts again with every byte, so a server that drips its reply can
        // hold a blocking read for hours, and Cancel cannot reach into one. One ceiling for the
        // session, and Cancel, both end it the only way a blocked read can be ended: by closing
        // the socket under it.
        using var ceiling = new CancellationTokenSource(TimeSpan.FromSeconds(sessionSeconds));
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(cancel, ceiling.Token);
        using var closer = stop.Token.Register(() =>
        {
            try { socket.Close(); }
            catch (ObjectDisposedException) { }
        });

        try
        {
            Stream stream = new NetworkStream(socket, ownsSocket: false);
            stream.ReadTimeout = (int)timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)timeout.TotalMilliseconds;

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var banner = ReadResponse(stream, result);
            result.Banner = banner.Text;
            result.BannerCode = banner.Code;
            trace?.Add("SMTP", "(wait for greeting)", banner.Code == 220 ? TraceOutcome.Ok : TraceOutcome.Fail,
                       $"{banner.Code} {First(banner)}", banner.Raw, sw.Elapsed.TotalMilliseconds);
            if (banner.Code != 220)
            {
                result.Error = $"server greeted with {banner.Code}: {banner.Text}";
                return result;
            }

            var helo = HeloName(publicIp);
            var ehlo = Command(stream, $"EHLO {helo}", result, trace);
            if (ehlo.Code != 250)
            {
                result.Error = $"EHLO answered {ehlo.Code}: {ehlo.Text}";
                return result;
            }
            foreach (var line in ehlo.Lines.Skip(1)) result.Capabilities.Add(line);
            result.StartTlsOffered = result.Capabilities.Any(c => c.StartsWith("STARTTLS", StringComparison.OrdinalIgnoreCase));
            var size = result.Capabilities.FirstOrDefault(c => c.StartsWith("SIZE", StringComparison.OrdinalIgnoreCase));
            if (size is not null && long.TryParse(size[4..].Trim(), out var max) && max > 0) result.MaxSize = max;

            if (!result.StartTlsOffered)
            {
                Command(stream, "QUIT", result, trace);
                return result;
            }

            var starttls = Command(stream, "STARTTLS", result, trace);
            if (starttls.Code != 220)
            {
                result.Error = $"STARTTLS answered {starttls.Code}: {starttls.Text}";
                return result;
            }

            X509Certificate2? cert = null;
            SslPolicyErrors errors = SslPolicyErrors.None;
            var chainLines = new List<string>();
            X509ChainStatus[] chainStatus = Array.Empty<X509ChainStatus>();

            using var ssl = new SslStream(stream, false, (_, c, chain, e) =>
            {
                if (c is not null) cert = new X509Certificate2(c);
                errors = e;
                if (chain is not null)
                {
                    chainStatus = chain.ChainStatus;
                    foreach (var el in chain.ChainElements)
                        chainLines.Add($"  {el.Certificate.Subject}  (issuer {el.Certificate.Issuer}, valid {el.Certificate.NotBefore:yyyy-MM-dd} to {el.Certificate.NotAfter:yyyy-MM-dd})");
                }
                return true;   // certificate problems are reported, not a reason to abort the probe
            });
            ssl.ReadTimeout = (int)timeout.TotalMilliseconds;
            ssl.WriteTimeout = (int)timeout.TotalMilliseconds;

            sw.Restart();
            // Async reads ignore ReadTimeout, so the handshake gets its own deadline.
            using var handshake = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            handshake.CancelAfter(timeout);
            try
            {
                // On the overlay's worker thread there is no synchronisation context to deadlock on.
                ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = SslProtocols.None,   // let the OS choose
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, handshake.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException) when (!cancel.IsCancellationRequested)
            {
                result.Error = $"TLS handshake timed out after {timeout.TotalSeconds:0} s";
                trace?.Add("TLS", $"TLS handshake with {host} (SNI {host})", TraceOutcome.Fail, result.Error, "", sw.Elapsed.TotalMilliseconds);
                return result;
            }
            catch (IOException ex)
            {
                trace?.Add("TLS", $"TLS handshake with {host} (SNI {host})", TraceOutcome.Fail,
                           "connection closed during the handshake: " + (ex.InnerException?.Message ?? ex.Message), ex.ToString(), sw.Elapsed.TotalMilliseconds);
                throw;
            }
            catch (AuthenticationException ex)
            {
                trace?.Add("TLS", $"TLS handshake with {host} (SNI {host})", TraceOutcome.Fail,
                           ex.InnerException?.Message ?? ex.Message, ex.ToString(), sw.Elapsed.TotalMilliseconds);
                throw;
            }

            result.TlsEstablished = true;
            result.TlsProtocol = ssl.SslProtocol.ToString();
            try { result.TlsCipher = ssl.NegotiatedCipherSuite.ToString(); }
            catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException) { result.TlsCipher = null; }

            if (cert is not null)
            {
                result.CertSubject = cert.GetNameInfo(X509NameType.SimpleName, false);
                result.CertIssuer = cert.Issuer;
                result.CertNotBefore = cert.NotBefore;
                result.CertNotAfter = cert.NotAfter;
                result.CertThumbprint = cert.Thumbprint;
                foreach (var ext in cert.Extensions)
                {
                    if (ext is X509SubjectAlternativeNameExtension san)
                        result.CertNames.AddRange(san.EnumerateDnsNames());
                }
                if (result.CertNames.Count == 0 && result.CertSubject is not null) result.CertNames.Add(result.CertSubject);
                result.CertNameMatches = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
            }
            if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0)
            {
                result.CertChainProblem = chainStatus.Length > 0
                    ? string.Join("; ", chainStatus.Select(st => st.StatusInformation.Trim()).Where(st => st.Length > 0).Distinct())
                    : "certificate chain is not trusted";
            }

            if (trace is not null)
            {
                var details = new StringBuilder();
                details.AppendLine($"Protocol:     {result.TlsProtocol}");
                details.AppendLine($"Cipher suite: {result.TlsCipher ?? "-"}");
                details.AppendLine($"SNI sent:     {host}");
                details.AppendLine($"Subject:      {cert?.Subject}");
                details.AppendLine($"Issuer:       {result.CertIssuer}");
                details.AppendLine($"Valid:        {result.CertNotBefore:yyyy-MM-dd HH:mm} to {result.CertNotAfter:yyyy-MM-dd HH:mm}");
                details.AppendLine($"Names (SAN):  {string.Join(", ", result.CertNames)}");
                details.AppendLine($"Thumbprint:   {result.CertThumbprint}");
                details.AppendLine($"Policy errors: {errors}");
                if (result.CertChainProblem is not null) details.AppendLine($"Chain:        {result.CertChainProblem}");
                if (chainLines.Count > 0) { details.AppendLine("Chain as built here:"); foreach (var l in chainLines) details.AppendLine(l); }
                bool clean = errors == SslPolicyErrors.None && result.CertNotAfter > DateTime.Now;
                trace.Add("TLS", $"TLS handshake with {host} (SNI {host})", clean ? TraceOutcome.Ok : TraceOutcome.Warn,
                          $"{result.TlsProtocol}, {result.TlsCipher ?? "cipher n/a"}, cert {result.CertSubject} until {result.CertNotAfter:yyyy-MM-dd}" + (clean ? "" : $", {errors}"),
                          details.ToString(), sw.Elapsed.TotalMilliseconds);
            }

            try
            {
                Command(ssl, $"EHLO {helo}", result, trace);
                Command(ssl, "QUIT", result, trace);
            }
            catch (IOException)
            {
                // some servers close right after QUIT; nothing to learn from that
            }
        }
        catch (Exception ex) when (stop.IsCancellationRequested &&
                                   ex is IOException or SocketException or InvalidOperationException or AuthenticationException or OperationCanceledException)
        {
            // The socket was closed under the session: by Cancel, or by the ceiling.
            cancel.ThrowIfCancellationRequested();
            result.Error = $"probe stopped after {sessionSeconds} s: the server answers too slowly to finish a session";
            trace?.Add("SMTP", $"session with {host}", TraceOutcome.Fail, result.Error,
                       "The server kept the connection open but sent its replies too slowly. Nothing is concluded from the part that did arrive.");
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            throw;
        }
        catch (AuthenticationException ex)
        {
            result.Error = "TLS handshake failed: " + (ex.InnerException?.Message ?? ex.Message);
        }
        catch (IOException ex)
        {
            result.Error = "connection dropped: " + (ex.InnerException?.Message ?? ex.Message);
            trace?.Add("SMTP", $"session with {host}", TraceOutcome.Fail, result.Error, ex.ToString());
        }
        catch (Exception ex) when (ex is SocketException or InvalidOperationException or TimeoutException)
        {
            result.Error = ex.GetBaseException().Message;
            trace?.Add("SMTP", $"session with {host}", TraceOutcome.Fail, result.Error, ex.ToString());
        }
        return result;
    }

    /// <summary>
    /// What EHLO announces. Never this computer's name: that would hand an internal host and
    /// domain name to a server outside (and to everyone the trace is shared with). The public
    /// address as a literal (RFC 5321 4.1.3) tells the server nothing it does not see already,
    /// and unlike a made-up name it is nothing a strict server can fail to resolve.
    /// </summary>
    internal static string HeloName(IPAddress? publicIp)
    {
        if (publicIp is not null && NetUtil.IsPublic(publicIp))
        {
            if (publicIp.IsIPv4MappedToIPv6) publicIp = publicIp.MapToIPv4();
            return publicIp.AddressFamily == AddressFamily.InterNetworkV6 ? $"[IPv6:{publicIp}]" : $"[{publicIp}]";
        }
        return "ssdd-probe.invalid";
    }

    private sealed record Reply(int Code, string Text, List<string> Lines, string Raw);

    private static string First(Reply r) => r.Lines.FirstOrDefault() ?? "";

    private static Reply Command(Stream stream, string command, SmtpProbeResult result, TraceLog? trace)
    {
        result.Transcript.Add("C: " + command);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var bytes = Encoding.ASCII.GetBytes(command + "\r\n");
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush();
        var reply = ReadResponse(stream, result);
        var outcome = reply.Code is >= 200 and < 400 ? TraceOutcome.Ok : reply.Code is >= 400 and < 500 ? TraceOutcome.Warn : TraceOutcome.Fail;
        trace?.Add("SMTP", "C: " + command, outcome, $"{reply.Code} {First(reply)}", reply.Raw, sw.Elapsed.TotalMilliseconds);
        return reply;
    }

    private static Reply ReadResponse(Stream stream, SmtpProbeResult result)
    {
        var lines = new List<string>();
        var raw = new StringBuilder();
        int code = 0;
        while (true)
        {
            var line = ReadLine(stream);
            if (line is null) throw new IOException("connection closed by the server");
            result.Transcript.Add("S: " + line);
            raw.Append("S: ").Append(line).Append('\n');
            if (line.Length >= 3 && int.TryParse(line[..3], out var c)) code = c;
            lines.Add(line.Length > 4 ? line[4..] : "");
            if (line.Length < 4 || line[3] != '-') break;
            if (lines.Count > 100) break;
        }
        return new Reply(code, string.Join(" ", lines), lines, raw.ToString());
    }

    // Byte-wise on purpose: a buffered reader would swallow the start of the TLS handshake.
    private static string? ReadLine(Stream stream)
    {
        var buffer = new List<byte>();
        while (true)
        {
            int b = stream.ReadByte();
            if (b < 0) return buffer.Count == 0 ? null : Encoding.ASCII.GetString(buffer.ToArray());
            if (b == '\n') break;
            if (b != '\r') buffer.Add((byte)b);
            if (buffer.Count > 4096) break;
        }
        return Encoding.ASCII.GetString(buffer.ToArray());
    }
}
