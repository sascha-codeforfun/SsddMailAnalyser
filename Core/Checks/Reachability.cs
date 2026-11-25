using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using SsddMailAnalyser.Core;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core.Checks;

public enum TcpOutcome { Connected, Refused, Timeout, Unreachable, Error }

public sealed class TcpResult
{
    public IPAddress Ip { get; init; } = IPAddress.None;
    public int Port { get; init; }
    public TcpOutcome Outcome { get; init; }
    public double Ms { get; init; }
    public double TimeoutMs { get; init; }
    public string? Error { get; init; }

    /// <summary>The open socket, only when asked to keep it.</summary>
    public Socket? Socket { get; init; }

    public string Describe() => Outcome switch
    {
        TcpOutcome.Connected => $"connected in {Ms:0} ms",
        TcpOutcome.Refused => $"refused (TCP reset) after {Ms:0.0} ms",
        TcpOutcome.Timeout => $"no answer within {TimeoutMs / 1000:0} s (silently dropped)",
        TcpOutcome.Unreachable => $"unreachable after {Ms:0} ms (ICMP reject): {Error}",
        _ => $"error after {Ms:0} ms: {Error}",
    };
}

/// <summary>A bare TCP connect with timing and the exact way it failed.</summary>
public static class TcpProbe
{
    public static TcpResult Connect(IPAddress ip, int port, TimeSpan timeout, CancellationToken cancel, bool keepOpen = false)
    {
        Socket? socket = null;
        var sw = Stopwatch.StartNew();
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        limit.CancelAfter(timeout);
        try
        {
            socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.ConnectAsync(new IPEndPoint(ip, port), limit.Token).AsTask().GetAwaiter().GetResult();
            var ms = sw.Elapsed.TotalMilliseconds;
            if (!keepOpen) socket.Dispose();
            return new TcpResult { Ip = ip, Port = port, Outcome = TcpOutcome.Connected, Ms = ms, TimeoutMs = timeout.TotalMilliseconds, Socket = keepOpen ? socket : null };
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            socket?.Dispose();
            throw;
        }
        catch (OperationCanceledException)
        {
            socket?.Dispose();
            return new TcpResult { Ip = ip, Port = port, Outcome = TcpOutcome.Timeout, Ms = sw.Elapsed.TotalMilliseconds, TimeoutMs = timeout.TotalMilliseconds };
        }
        catch (SocketException ex)
        {
            socket?.Dispose();
            var outcome = ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => TcpOutcome.Refused,
                SocketError.TimedOut => TcpOutcome.Timeout,
                SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.AccessDenied or SocketError.NetworkDown => TcpOutcome.Unreachable,
                _ => TcpOutcome.Error,
            };
            return new TcpResult
            {
                Ip = ip, Port = port, Outcome = outcome, Ms = sw.Elapsed.TotalMilliseconds, TimeoutMs = timeout.TotalMilliseconds,
                Error = $"{ex.SocketErrorCode}: {ex.Message}",
            };
        }
    }
}

// ===================================================================== can this machine do SMTP at all?

public enum ReachVerdict
{
    /// <summary>Port 25 to the big providers connects: the path from here is open.</summary>
    Open,
    /// <summary>Port 25 fails everywhere, other ports pass: a firewall or the ISP blocks 25.</summary>
    Port25Blocked,
    /// <summary>Port 25 is reset faster than any round trip: a device on this side rejects it.</summary>
    RejectedHere,
    /// <summary>Neither 25 nor 587 gets out.</summary>
    NoOutbound,
    Unknown,
}

public sealed class ReachProbe
{
    public string Purpose { get; init; } = "";
    public string Host { get; init; } = "";
    public TcpResult Result { get; init; } = new();
}

public sealed class ReachabilityResult
{
    public List<ReachProbe> Controls25 { get; } = new();
    public List<ReachProbe> Controls587 { get; } = new();

    /// <summary>Port 443 on the target MX's IP: a round-trip baseline for judging a reset on 25.</summary>
    public ReachProbe? TargetBaseline { get; set; }

    public string? PublicIp { get; set; }
    public string PublicIpSource { get; set; } = "";
    public List<BlocklistResult> PublicIpListings { get; } = new();

    public ReachVerdict Verdict { get; set; } = ReachVerdict.Unknown;
    public string Summary { get; set; } = "";

    public IEnumerable<ReachProbe> All =>
        Controls25.Concat(Controls587).Concat(TargetBaseline is null ? Array.Empty<ReachProbe>() : new[] { TargetBaseline });
}

/// <summary>
/// Before blaming a recipient for a failed port-25 probe: does port 25 work from here at all?
/// Control connections to Google's and Microsoft's MX hosts (which accept everyone), the same
/// providers' submission port 587 for comparison, a timing baseline to the target, and this
/// machine's public IP as the world sees it, with its blocklist status.
/// </summary>
public static class Reachability
{
    private static readonly TimeSpan ControlTimeout = TimeSpan.FromSeconds(6);

    public static ReachabilityResult Run(DnsClient dns, TraceLog trace, MxCheck? targetMx, CancellationToken cancel, bool publicOnly = false)
    {
        var r = new ReachabilityResult();

        foreach (var (domain, fallback) in new[] { ("gmail.com", "gmail-smtp-in.l.google.com"), ("outlook.com", "outlook-com.olc.protection.outlook.com") })
        {
            var host = dns.Query(domain, DnsType.MX, cancel).Mx().FirstOrDefault()?.Target;
            if (string.IsNullOrEmpty(host)) host = fallback;
            var probe = ProbeHost(dns, trace, host, 25, $"control: {domain} MX", cancel);
            if (probe is not null) r.Controls25.Add(probe);
        }
        foreach (var host in new[] { "smtp.gmail.com", "smtp.office365.com" })
        {
            var probe = ProbeHost(dns, trace, host, 587, "control: submission port", cancel);
            if (probe is not null) r.Controls587.Add(probe);
        }

        // Outside the site, a target that resolves only to private addresses is not connected to.
        var target = targetMx?.Hosts.FirstOrDefault(h => h.Addresses.Any(a => !publicOnly || NetUtil.IsPublic(a)));
        if (target is not null)
        {
            var reachable = target.Addresses.Where(a => !publicOnly || NetUtil.IsPublic(a)).ToList();
            var ip = reachable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? reachable[0];
            var res = TcpProbe.Connect(ip, 443, TimeSpan.FromSeconds(4), cancel);
            r.TargetBaseline = new ReachProbe { Purpose = "baseline: target MX on 443", Host = target.Host, Result = res };
            trace.Add("TCP", $"connect {target.Host} [{ip}]:443 (round-trip baseline)",
                      res.Outcome is TcpOutcome.Connected or TcpOutcome.Refused ? TraceOutcome.Info : TraceOutcome.Warn,
                      res.Describe() + (res.Outcome is TcpOutcome.Connected or TcpOutcome.Refused ? " - usable as round-trip time" : " - no baseline"),
                      res.Error ?? "", res.Ms);
        }

        FindPublicIp(dns, trace, r, cancel);
        if (r.PublicIp is not null && NetUtil.TryParseIp(r.PublicIp, out var publicIp))
        {
            r.PublicIpListings.AddRange(BlocklistChecker.CheckIp(dns, publicIp, "analysis system's public IP", null, cancel));
            var listed = r.PublicIpListings.Where(l => l.Status == ListingStatus.Listed).ToList();
            trace.Add("Note", $"blocklists for this machine's public IP {r.PublicIp}", listed.Count > 0 ? TraceOutcome.Warn : TraceOutcome.Ok,
                      listed.Count > 0 ? "listed on " + string.Join(", ", listed.Select(l => l.Name)) : "not listed",
                      string.Join("\n", r.PublicIpListings.Select(l => $"{l.Name}: {l.Status} {l.Detail}")));
        }

        Judge(r);
        trace.Add("Note", "SMTP reachability from this machine", r.Verdict == ReachVerdict.Open ? TraceOutcome.Ok : TraceOutcome.Warn,
                  r.Verdict.ToString(), r.Summary);
        return r;
    }

    private static ReachProbe? ProbeHost(DnsClient dns, TraceLog trace, string host, int port, string purpose, CancellationToken cancel)
    {
        var ip = dns.Addresses(host, cancel).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
        if (ip is null)
        {
            trace.Add("TCP", $"connect {host}:{port} ({purpose})", TraceOutcome.Warn, "host name did not resolve; skipped");
            return null;
        }
        var res = TcpProbe.Connect(ip, port, ControlTimeout, cancel);
        trace.Add("TCP", $"connect {host} [{ip}]:{port} ({purpose})",
                  res.Outcome == TcpOutcome.Connected ? TraceOutcome.Ok : TraceOutcome.Fail, res.Describe(), res.Error ?? "", res.Ms);
        return new ReachProbe { Purpose = purpose, Host = host, Result = res };
    }

    /// <summary>
    /// The public IP as authoritative servers see it: Google's ns1 answers o-o.myaddr.l.google.com
    /// with the querying address, Akamai's whoami.akamai.net likewise. Asked directly (not
    /// through a resolver, which would report its own address). Needs port 53.
    /// </summary>
    private static void FindPublicIp(DnsClient dns, TraceLog trace, ReachabilityResult r, CancellationToken cancel)
    {
        var attempts = new[]
        {
            ("ns1.google.com", "216.239.32.10", "o-o.myaddr.l.google.com", DnsType.TXT),
            ("ns1-1.akamaitech.net", "193.108.88.1", "whoami.akamai.net", DnsType.A),
        };
        foreach (var (server, fallbackIp, name, type) in attempts)
        {
            cancel.ThrowIfCancellationRequested();
            var serverIp = dns.Addresses(server, cancel).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                           ?? IPAddress.Parse(fallbackIp);
            ushort id = (ushort)Random.Shared.Next(0, 65536);
            var sw = Stopwatch.StartNew();
            try
            {
                var raw = DnsTransport.Exchange(serverIp, DnsWire.BuildQuery(id, name, type, recursionDesired: false), id, TimeSpan.FromSeconds(3));
                if (raw is null)
                {
                    DnsTransport.Log(trace, "DNS", name, type, $"{server} [{serverIp}]", false, sw.Elapsed.TotalMilliseconds, null, "no answer (port 53 blocked?)");
                    continue;
                }
                var msg = DnsWire.Parse(raw);
                DnsTransport.Log(trace, "DNS", name, type, $"{server} [{serverIp}]", false, sw.Elapsed.TotalMilliseconds, msg, null, "public IP lookup");
                string? ip = type == DnsType.TXT
                    ? msg.Answers.Where(a => a.Type == DnsType.TXT).Select(a => a.Text ?? "").FirstOrDefault(t => NetUtil.TryParseIp(t, out _))
                    : msg.Answers.Where(a => a.Type == DnsType.A).Select(a => a.Address?.ToString()).FirstOrDefault();
                if (ip is not null)
                {
                    r.PublicIp = ip;
                    r.PublicIpSource = $"{name} via {server}";
                    return;
                }
            }
            catch (Exception ex) when (ex is SocketException or System.IO.IOException or FormatException or IndexOutOfRangeException)
            {
                DnsTransport.Log(trace, "DNS", name, type, $"{server} [{serverIp}]", false, sw.Elapsed.TotalMilliseconds, null, ex.Message);
            }
        }
    }

    private static void Judge(ReachabilityResult r)
    {
        var c25 = r.Controls25.Select(p => p.Result).ToList();
        var c587 = r.Controls587.Select(p => p.Result).ToList();
        double? rtt = c587.Where(x => x.Outcome == TcpOutcome.Connected).Select(x => (double?)x.Ms).Min();

        if (c25.Count == 0)
        {
            r.Verdict = ReachVerdict.Unknown;
            r.Summary = "The control hosts could not be resolved, so port 25 could not be tested.";
            return;
        }
        if (c25.Any(x => x.Outcome == TcpOutcome.Connected))
        {
            r.Verdict = ReachVerdict.Open;
            r.Summary = $"Port 25 to the control hosts connects ({string.Join(", ", c25.Select(x => x.Describe()))}). Outbound SMTP works from here, so a failed probe to the target is about the target.";
            return;
        }

        bool allRefused = c25.All(x => x.Outcome == TcpOutcome.Refused);
        double fastest = c25.Min(x => x.Ms);
        bool tooFast = fastest < 3 || (rtt is { } t && fastest < t * 0.4);
        if (allRefused && tooFast)
        {
            r.Verdict = ReachVerdict.RejectedHere;
            r.Summary = $"Port 25 is reset after {fastest:0.0} ms" + (rtt is { } t2 ? $", while a real round trip to the same providers takes {t2:0} ms" : "") +
                        ". A reset that fast comes from a device near the analysis system (local firewall, router or the ISP's first hop), not from the destination.";
            return;
        }

        if (c587.Any(x => x.Outcome == TcpOutcome.Connected))
        {
            r.Verdict = ReachVerdict.Port25Blocked;
            r.Summary = $"Port 25 fails to every control host ({string.Join(", ", c25.Select(x => x.Describe()))}) while port 587 to the same providers connects. Port 25 is blocked on this path: a firewall here or the ISP.";

            // Equal reset delays to unrelated networks, far above the real round trip, point to
            // one local device intercepting port 25 and giving up on its own timer.
            var resets = c25.Where(x => x.Outcome == TcpOutcome.Refused).Select(x => x.Ms).ToList();
            if (resets.Count >= 2 && rtt is { } real)
            {
                double min = resets.Min(), max = resets.Max();
                if (min > real * 5 && min > 200 && (max - min) <= Math.Max(50, min * 0.05))
                    r.Summary += $" The resets all arrive after the same {min:0} ms, while a real round trip takes {real:0} ms: " +
                                 "a single device near this machine intercepts port 25 and gives up on its own timer " +
                                 "(router, security appliance, antivirus mail proxy or the ISP's filter), not the destinations.";
            }
            return;
        }

        r.Verdict = ReachVerdict.NoOutbound;
        r.Summary = "Neither port 25 nor port 587 gets out from here. Only DNS (or HTTPS) seems to be allowed.";
    }
}
