using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Threading;
using SsddMailAnalyser.Core;

namespace SsddMailAnalyser.Core.Dns;

/// <summary>One way of getting DNS answers.</summary>
public interface IDnsResolver
{
    /// <summary>For the report: "DNS server 192.0.2.53", "DNS over HTTPS (Cloudflare)", ...</summary>
    string Label { get; }

    /// <summary>True once any answer came back, so later timeouts are about the name, not the path.</summary>
    bool HasAnswered { get; }

    /// <summary>Where every exchange is recorded, when set.</summary>
    TraceLog? Trace { get; set; }

    DnsResponse Resolve(string name, DnsType type, CancellationToken cancel);
}

/// <summary>UDP with TCP fallback on truncation, to one server.</summary>
public static class DnsTransport
{
    /// <summary>Returns the raw answer, or null on timeout. Socket errors are thrown.</summary>
    public static byte[]? Exchange(IPAddress server, byte[] query, ushort id, TimeSpan timeout) =>
        Exchange(server, query, id, timeout, out _);

    public static byte[]? Exchange(IPAddress server, byte[] query, ushort id, TimeSpan timeout, out bool usedTcp)
    {
        usedTcp = false;
        var raw = SendUdp(server, query, id, timeout);
        if (raw is null) return null;
        if ((raw[2] & 0x02) != 0)   // TC: truncated, ask again over TCP
        {
            var tcp = SendTcp(server, query, timeout);
            if (tcp is not null)
            {
                raw = tcp;
                usedTcp = true;
            }
        }
        return raw;
    }

    /// <summary>Records one DNS exchange in the trace, dig-style.</summary>
    public static void Log(TraceLog? trace, string kind, string name, DnsType type, string target, bool recursive,
                           double ms, DnsMessage? msg, string? error, string? note = null)
    {
        if (trace is null) return;
        var action = $"{type} {name}  ->  {target}{(recursive ? "  (recursive)" : "  (non-recursive)")}";
        if (msg is null)
        {
            trace.Add(kind, action, TraceOutcome.Fail, error ?? "no answer", "", ms);
            return;
        }
        var outcome = msg.Rcode switch
        {
            0 => msg.Answers.Any(a => a.Type == type) ? TraceOutcome.Ok : TraceOutcome.Info,
            3 => TraceOutcome.Info,
            _ => TraceOutcome.Fail,
        };
        var result = (note is null ? "" : note + "; ") + msg.Summary();
        trace.Add(kind, action, outcome, result, msg.Format(name, type), ms);
    }

    private static byte[]? SendUdp(IPAddress server, byte[] query, ushort id, TimeSpan timeout)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        socket.ReceiveTimeout = (int)timeout.TotalMilliseconds;
        socket.SendTimeout = (int)timeout.TotalMilliseconds;
        socket.Connect(new IPEndPoint(server, 53));
        socket.Send(query);

        var buffer = new byte[4096];
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            int n;
            try
            {
                n = socket.Receive(buffer);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
            {
                return null;
            }
            if (n < 12) continue;
            if (((buffer[0] << 8) | buffer[1]) != id) continue;   // a stray answer
            var result = new byte[n];
            Array.Copy(buffer, result, n);
            return result;
        }
        return null;
    }

    private static byte[]? SendTcp(IPAddress server, byte[] query, TimeSpan timeout)
    {
        using var client = new TcpClient(server.AddressFamily);
        var connect = client.ConnectAsync(server, 53);
        try
        {
            if (!connect.Wait(timeout)) return null;
        }
        catch (AggregateException)
        {
            return null;
        }

        using var stream = client.GetStream();
        stream.ReadTimeout = (int)timeout.TotalMilliseconds;
        stream.WriteTimeout = (int)timeout.TotalMilliseconds;

        var framed = new byte[query.Length + 2];
        framed[0] = (byte)(query.Length >> 8);
        framed[1] = (byte)(query.Length & 0xFF);
        Array.Copy(query, 0, framed, 2, query.Length);
        stream.Write(framed, 0, framed.Length);

        var lengthBytes = ReadExactly(stream, 2);
        int length = (lengthBytes[0] << 8) | lengthBytes[1];
        return ReadExactly(stream, length);
    }

    private static byte[] ReadExactly(Stream stream, int count)
    {
        var buffer = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = stream.Read(buffer, read, count - read);
            if (n <= 0) throw new IOException("connection closed by the DNS server");
            read += n;
        }
        return buffer;
    }

    public static bool IsPathError(SocketException ex) => ex.SocketErrorCode is
        SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.AccessDenied or
        SocketError.ConnectionReset or SocketError.ConnectionRefused or SocketError.NetworkDown or
        SocketError.AddressFamilyNotSupported or SocketError.TimedOut;
}

// ===================================================================== a recursive server

/// <summary>A recursive DNS server: this computer's, the company's, or a public one.</summary>
public sealed class RecursiveResolver : IDnsResolver
{
    private readonly IPAddress _server;
    private readonly TimeSpan _timeout;

    public RecursiveResolver(IPAddress server, string? label = null, TimeSpan? timeout = null)
    {
        _server = server;
        _timeout = timeout ?? TimeSpan.FromSeconds(4);
        Label = label ?? $"DNS server {server}";
    }

    public string Label { get; }
    public bool HasAnswered { get; private set; }
    public TraceLog? Trace { get; set; }

    public DnsResponse Resolve(string name, DnsType type, CancellationToken cancel)
    {
        string? lastError = null;
        bool pathError = false;

        for (int attempt = 0; attempt < 2; attempt++)
        {
            cancel.ThrowIfCancellationRequested();
            ushort id = (ushort)Random.Shared.Next(0, 65536);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var raw = DnsTransport.Exchange(_server, DnsWire.BuildQuery(id, name, type, recursionDesired: true), id, _timeout, out var tcp);
                if (raw is null)
                {
                    lastError = "timeout";
                    DnsTransport.Log(Trace, "DNS", name, type, $"{_server} UDP", true, sw.Elapsed.TotalMilliseconds, null, $"no answer within {_timeout.TotalSeconds:0} s (attempt {attempt + 1})");
                    continue;
                }
                HasAnswered = true;
                var msg = DnsWire.Parse(raw);
                DnsTransport.Log(Trace, "DNS", name, type, $"{_server} {(tcp ? "TCP" : "UDP")}", true, sw.Elapsed.TotalMilliseconds, msg, null);
                return msg.ToResponse(name, type, Label);
            }
            catch (SocketException ex)
            {
                lastError = ex.Message;
                pathError = DnsTransport.IsPathError(ex);
                DnsTransport.Log(Trace, "DNS", name, type, $"{_server} UDP", true, sw.Elapsed.TotalMilliseconds, null, $"socket error {ex.SocketErrorCode}: {ex.Message}");
            }
            catch (Exception ex) when (ex is IOException or FormatException or IndexOutOfRangeException or ArgumentException)
            {
                lastError = ex.Message;
                DnsTransport.Log(Trace, "DNS", name, type, $"{_server}", true, sw.Elapsed.TotalMilliseconds, null, ex.Message);
            }
        }

        return new DnsResponse
        {
            Name = name,
            Type = type,
            Status = lastError == "timeout" ? DnsStatus.Timeout : DnsStatus.Error,
            Error = lastError,
            TransportFailure = !HasAnswered && (lastError == "timeout" || pathError),
            Via = Label,
        };
    }
}

// ===================================================================== DNS over HTTPS

/// <summary>
/// RFC 8484 DNS over HTTPS. Goes through the system proxy like a browser, so it works where
/// only HTTPS is let out. Same wire format as UDP, so the same parser.
/// </summary>
public sealed class DohResolver : IDnsResolver
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(8) };
    private readonly Uri _endpoint;

    public DohResolver(string endpoint, string provider)
    {
        _endpoint = new Uri(endpoint);
        Label = $"DNS over HTTPS ({provider})";
    }

    public string Label { get; }
    public bool HasAnswered { get; private set; }
    public TraceLog? Trace { get; set; }

    public static DohResolver Cloudflare() => new("https://cloudflare-dns.com/dns-query", "Cloudflare");
    public static DohResolver Google() => new("https://dns.google/dns-query", "Google");
    public static DohResolver Quad9() => new("https://dns.quad9.net/dns-query", "Quad9");

    public DnsResponse Resolve(string name, DnsType type, CancellationToken cancel)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var target = $"POST {_endpoint}";
        try
        {
            var query = DnsWire.BuildQuery(0, name, type, recursionDesired: true);   // id 0 per RFC 8484
            using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
            {
                Content = new ByteArrayContent(query),
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

            using var response = Http.Send(request, cancel);
            if (!response.IsSuccessStatusCode)
            {
                DnsTransport.Log(Trace, "DoH", name, type, target, true, sw.Elapsed.TotalMilliseconds, null, $"HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
                return Failed(name, type, $"HTTP {(int)response.StatusCode} from {_endpoint.Host}", transport: !HasAnswered);
            }

            using var stream = response.Content.ReadAsStream(cancel);
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            var parsed = DnsWire.Parse(ms.ToArray());
            HasAnswered = true;
            DnsTransport.Log(Trace, "DoH", name, type, target, true, sw.Elapsed.TotalMilliseconds, parsed, null, $"HTTP {(int)response.StatusCode}");
            return parsed.ToResponse(name, type, Label);
        }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            DnsTransport.Log(Trace, "DoH", name, type, target, true, sw.Elapsed.TotalMilliseconds, null, "timeout");
            return Failed(name, type, "timeout", transport: !HasAnswered, timeout: true);
        }
        catch (HttpRequestException ex)
        {
            var error = ex.InnerException?.Message ?? ex.Message;
            DnsTransport.Log(Trace, "DoH", name, type, target, true, sw.Elapsed.TotalMilliseconds, null, error);
            return Failed(name, type, error, transport: !HasAnswered);
        }
        catch (Exception ex) when (ex is IOException or FormatException or IndexOutOfRangeException or ArgumentException)
        {
            DnsTransport.Log(Trace, "DoH", name, type, target, true, sw.Elapsed.TotalMilliseconds, null, ex.Message);
            return Failed(name, type, ex.Message, transport: false);
        }
    }

    private DnsResponse Failed(string name, DnsType type, string error, bool transport, bool timeout = false) => new()
    {
        Name = name,
        Type = type,
        Status = timeout ? DnsStatus.Timeout : DnsStatus.Error,
        Error = error,
        TransportFailure = transport,
        Via = Label,
    };
}

// ===================================================================== iterative from the root

public sealed class NsHost
{
    public string Name { get; init; } = "";
    public List<IPAddress> Ips { get; } = new();
}

public sealed class ZoneServers
{
    public string Zone { get; init; } = "";
    public List<NsHost> Hosts { get; } = new();
    public string Display => Zone.Length == 0 ? "the root" : Zone;
}

public sealed class AuthorityAnswer
{
    public string Server { get; init; } = "";
    public IPAddress? Ip { get; init; }
    public DnsResponse Response { get; init; } = new();
}

/// <summary>
/// Resolves the way a mail server's own resolver would on a cold cache: from the root, down
/// the referrals, to the domain's own name servers. No cache in between, so a record fixed a
/// minute ago shows as fixed, and public-resolver restrictions (Spamhaus) do not apply.
/// Needs UDP/TCP port 53 to the internet.
/// </summary>
public sealed class IterativeResolver : IDnsResolver
{
    private static readonly (string Name, string Ip)[] RootHints =
    {
        ("a.root-servers.net", "198.41.0.4"),
        ("b.root-servers.net", "170.247.170.2"),
        ("c.root-servers.net", "192.33.4.12"),
        ("d.root-servers.net", "199.7.91.13"),
        ("e.root-servers.net", "192.203.230.10"),
        ("f.root-servers.net", "192.5.5.241"),
        ("g.root-servers.net", "192.112.36.4"),
        ("h.root-servers.net", "198.97.190.53"),
        ("i.root-servers.net", "192.36.148.17"),
        ("j.root-servers.net", "192.58.128.30"),
        ("k.root-servers.net", "193.0.14.129"),
        ("l.root-servers.net", "199.7.83.42"),
        ("m.root-servers.net", "202.12.27.33"),
    };

    private readonly Dictionary<string, ZoneServers> _cuts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<(string, DnsType), string> _answerZone = new();
    private readonly TimeSpan _timeout = TimeSpan.FromSeconds(3);
    private readonly object _gate = new();
    private int _rootStart = Random.Shared.Next(RootHints.Length);

    public IterativeResolver()
    {
        var root = new ZoneServers { Zone = "" };
        foreach (var (name, ip) in RootHints)
        {
            var host = new NsHost { Name = name };
            host.Ips.Add(IPAddress.Parse(ip));
            root.Hosts.Add(host);
        }
        _cuts[""] = root;
    }

    public string Label => "authoritative name servers (resolved from the root)";
    public bool HasAnswered { get; private set; }
    public TraceLog? Trace { get; set; }

    /// <summary>
    /// Set once a root or top-level server "answered" the way only a recursive resolver does:
    /// something on the network answers port 53 in place of the servers asked. From then on
    /// nothing this resolver hears is the authoritative view, so every query fails as a
    /// transport failure and the next resolver in the chain takes over.
    /// </summary>
    public string? Interception { get; private set; }

    public DnsResponse Resolve(string name, DnsType type, CancellationToken cancel)
    {
        lock (_gate)
        {
            if (Interception is not null) return Intercepted(DnsWire.Normalize(name), type);
            return ResolveInternal(name, type, cancel, 0);
        }
    }

    private DnsResponse Intercepted(string name, DnsType type) =>
        Fail(name, type, DnsStatus.Error, "port 53 is intercepted on this network: " + Interception, transport: true);

    /// <summary>
    /// Root servers never offer recursion, and neither they nor the top-level servers give a
    /// non-authoritative NXDOMAIN or a non-authoritative answer: below their own data they only
    /// refer. Anything else did not come from them.
    /// </summary>
    private static bool LooksIntercepted(ZoneServers zone, DnsMessage msg, string qname, DnsType type)
    {
        bool root = zone.Zone.Length == 0;
        bool topLevel = !root && !zone.Zone.Contains('.');
        if (!root && !topLevel) return false;
        if (root && (msg.Flags & 0x0080) != 0) return true;   // RA from a root server
        if (msg.Authoritative) return false;
        return msg.Rcode == 3 || msg.Answers.Any(a => a.Name == qname && (a.Type == type || a.Type == DnsType.CNAME));
    }

    /// <summary>The zone whose servers gave the final answer for this name, after a Resolve.</summary>
    public ZoneServers? AnsweringZone(string name, DnsType type)
    {
        lock (_gate)
        {
            return _answerZone.TryGetValue((DnsWire.Normalize(name), type), out var z) && _cuts.TryGetValue(z, out var servers) ? servers : null;
        }
    }

    /// <summary>
    /// Asks every authoritative server of the zone that holds <paramref name="name"/> the same
    /// question. Disagreement between them is the classic cause of "it works sometimes".
    /// </summary>
    public (ZoneServers? Zone, List<AuthorityAnswer> Answers) AskAll(string name, DnsType type, CancellationToken cancel)
    {
        lock (_gate)
        {
            name = DnsWire.Normalize(name);
            if (Interception is not null) return (null, new List<AuthorityAnswer>());
            ResolveInternal(name, type, cancel, 0);
            if (Interception is not null) return (null, new List<AuthorityAnswer>());
            if (!_answerZone.TryGetValue((name, type), out var zoneName) || !_cuts.TryGetValue(zoneName, out var zone) || zoneName.Length == 0)
                return (null, new List<AuthorityAnswer>());

            var answers = new List<AuthorityAnswer>();
            foreach (var host in zone.Hosts.Take(8))
            {
                cancel.ThrowIfCancellationRequested();
                EnsureAddresses(host, cancel, 1);
                var ip = host.Ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? host.Ips.FirstOrDefault();
                if (ip is null)
                {
                    answers.Add(new AuthorityAnswer
                    {
                        Server = host.Name,
                        Response = new DnsResponse { Name = name, Type = type, Status = DnsStatus.Error, Error = "the name server's own name does not resolve" },
                    });
                    continue;
                }
                answers.Add(new AuthorityAnswer { Server = host.Name, Ip = ip, Response = AskOne(ip, host.Name, name, type) });
            }
            return (zone, answers);
        }
    }

    private DnsResponse AskOne(IPAddress ip, string server, string name, DnsType type)
    {
        ushort id = (ushort)Random.Shared.Next(0, 65536);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var target = $"{server} [{ip}]";
        try
        {
            var raw = DnsTransport.Exchange(ip, DnsWire.BuildQuery(id, name, type, recursionDesired: false), id, _timeout, out var tcp);
            if (raw is null)
            {
                DnsTransport.Log(Trace, "DNS", name, type, target + " UDP", false, sw.Elapsed.TotalMilliseconds, null, $"no answer within {_timeout.TotalSeconds:0} s");
                return new DnsResponse { Name = name, Type = type, Status = DnsStatus.Timeout, Error = "no answer" };
            }
            var msg = DnsWire.Parse(raw);
            DnsTransport.Log(Trace, "DNS", name, type, target + (tcp ? " TCP" : " UDP"), false, sw.Elapsed.TotalMilliseconds, msg, null,
                             msg.Authoritative ? "authoritative answer" : "NOT authoritative");
            // A non-authoritative NOERROR without answers (a referral) from a server listed
            // for the zone means a lame delegation.
            if (msg.Rcode == 0 && !msg.Authoritative && !msg.Answers.Any())
                return new DnsResponse { Name = name, Type = type, Status = DnsStatus.ServFail, Error = "not authoritative for the zone (lame delegation)" };
            return msg.ToResponse(name, type, ip.ToString());
        }
        catch (Exception ex) when (ex is SocketException or IOException or FormatException or IndexOutOfRangeException or ArgumentException)
        {
            DnsTransport.Log(Trace, "DNS", name, type, target, false, sw.Elapsed.TotalMilliseconds, null, ex.Message);
            return new DnsResponse { Name = name, Type = type, Status = DnsStatus.Error, Error = ex.Message };
        }
    }

    private DnsResponse ResolveInternal(string name, DnsType type, CancellationToken cancel, int depth)
    {
        name = DnsWire.Normalize(name);
        if (depth > 6) return Fail(name, type, DnsStatus.ServFail, "name server names nest too deeply");

        var chain = new List<DnsRecord>();
        string qname = name;
        var zone = ClosestCut(qname);

        for (int step = 0; step < 40; step++)
        {
            cancel.ThrowIfCancellationRequested();
            var (msg, error) = AskZone(zone, qname, type, cancel, depth);
            if (Interception is not null) return Intercepted(name, type);
            if (msg is null)
            {
                if (zone.Zone.Length == 0 && !HasAnswered)
                    return Fail(name, type, DnsStatus.Timeout, "no root server reachable (UDP/TCP port 53 blocked?)", transport: true);
                return Fail(name, type, DnsStatus.ServFail, $"no name server of {zone.Display} answered ({error})", chain);
            }

            if (msg.Rcode == 3)
            {
                _answerZone[(qname, type)] = zone.Zone;
                _answerZone[(name, type)] = zone.Zone;
                return Result(name, type, DnsStatus.NxDomain, chain);
            }

            var direct = msg.Answers.Where(a => a.Name == qname && a.Type == type).ToList();
            if (direct.Count > 0)
            {
                _answerZone[(qname, type)] = zone.Zone;
                if (chain.Count == 0) _answerZone[(name, type)] = zone.Zone;
                chain.AddRange(msg.Answers.Where(a => a.Type == type || a.Type == DnsType.CNAME));
                return Result(name, type, DnsStatus.Ok, chain);
            }

            var cname = msg.Answers.FirstOrDefault(a => a.Name == qname && a.Type == DnsType.CNAME);
            if (cname is not null && type != DnsType.CNAME)
            {
                if (chain.Count == 0) _answerZone[(name, type)] = zone.Zone;
                chain.Add(cname);
                var target = cname.Target ?? "";
                var inline = msg.Answers.Where(a => a.Name == target && a.Type == type).ToList();
                if (inline.Count > 0)
                {
                    chain.AddRange(inline);
                    return Result(name, type, DnsStatus.Ok, chain);
                }
                if (chain.Count > 8) return Fail(name, type, DnsStatus.ServFail, "CNAME chain too long (loop?)", chain);
                qname = target;
                zone = ClosestCut(qname);
                continue;
            }

            var referral = msg.Authority
                .Where(r => r.Type == DnsType.NS && IsWithin(qname, r.Name) && IsStrictlyBelow(r.Name, zone.Zone))
                .ToList();

            if (msg.Authoritative || referral.Count == 0 && msg.Authority.Any(r => r.Type == DnsType.SOA))
            {
                _answerZone[(qname, type)] = zone.Zone;
                if (chain.Count == 0) _answerZone[(name, type)] = zone.Zone;
                return Result(name, type, DnsStatus.NoData, chain);
            }

            if (referral.Count == 0)
                return Fail(name, type, DnsStatus.ServFail, $"name servers of {zone.Display} gave neither an answer nor a referral (lame delegation)", chain);

            var cut = new ZoneServers { Zone = referral[0].Name };
            foreach (var ns in referral.Where(r => r.Name == referral[0].Name))
            {
                var host = new NsHost { Name = ns.Target ?? "" };
                host.Ips.AddRange(msg.Additional
                    .Where(a => a.Name == host.Name && a.Type is DnsType.A or DnsType.AAAA && a.Address is not null)
                    .Select(a => a.Address!));
                cut.Hosts.Add(host);
            }
            _cuts[cut.Zone] = cut;
            zone = cut;
        }
        return Fail(name, type, DnsStatus.ServFail, "too many referrals", chain);
    }

    private (DnsMessage? Message, string? Error) AskZone(ZoneServers zone, string qname, DnsType type, CancellationToken cancel, int depth)
    {
        string? lastError = null;
        var hosts = zone.Hosts;
        int start = zone.Zone.Length == 0 ? _rootStart++ % hosts.Count : 0;
        int tried = 0;

        // Servers that already timed out in this run are asked last, not first: a dead server
        // would otherwise cost a full timeout on every query to its zone.
        var order = Enumerable.Range(0, hosts.Count).Select(i => hosts[(start + i) % hosts.Count])
            .OrderBy(h => h.Ips.Count > 0 && h.Ips.All(a => _dead.Contains(a)) ? 1 : 0)
            .ToList();

        for (int i = 0; i < order.Count && tried < 4; i++)
        {
            cancel.ThrowIfCancellationRequested();
            var host = order[i];
            EnsureAddresses(host, cancel, depth + 1);
            var ip = host.Ips.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !_dead.Contains(a))
                     ?? host.Ips.FirstOrDefault(a => !_dead.Contains(a))
                     ?? host.Ips.FirstOrDefault();
            if (ip is null) { lastError = $"{host.Name} does not resolve"; continue; }
            if (_dead.Contains(ip) && order.Skip(i + 1).Any(h => h.Ips.Any(a => !_dead.Contains(a)) || h.Ips.Count == 0)) continue;
            tried++;

            ushort id = (ushort)Random.Shared.Next(0, 65536);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var target = $"{host.Name} [{ip}] ({zone.Display})";
            try
            {
                var raw = DnsTransport.Exchange(ip, DnsWire.BuildQuery(id, qname, type, recursionDesired: false), id, _timeout, out var tcp);
                if (raw is null)
                {
                    lastError = $"{host.Name} timed out";
                    _dead.Add(ip);
                    DnsTransport.Log(Trace, "DNS", qname, type, target + " UDP", false, sw.Elapsed.TotalMilliseconds, null, $"no answer within {_timeout.TotalSeconds:0} s");
                    continue;
                }
                var msg = DnsWire.Parse(raw);
                HasAnswered = true;
                DnsTransport.Log(Trace, "DNS", qname, type, target + (tcp ? " TCP" : " UDP"), false, sw.Elapsed.TotalMilliseconds, msg, null, Describe(msg, qname, type));
                if (LooksIntercepted(zone, msg, qname, type))
                {
                    Interception = $"the query to {host.Name} [{ip}] came back as a recursive resolver's answer ({msg.Summary()})";
                    Trace?.Add("DNS", "port 53 check", TraceOutcome.Fail, "port 53 is intercepted on this network",
                               $"Asked {target} for {qname} {type} without recursion.\nGot: {msg.Summary()}\n\n" +
                               "A root or top-level name server refers downwards or answers with authority (aa). This answer has the shape a " +
                               "recursive resolver gives, so it came from something on the path (firewall DNS proxy, captive portal, provider), " +
                               "not from the server asked. Nothing heard on port 53 here is the authoritative view; it is not used.");
                    return (null, "port 53 is intercepted");
                }
                if (msg.Rcode is 2 or 5 or 4 or 1) { lastError = $"{host.Name} answered {DnsMessage.RcodeName(msg.Rcode)}"; continue; }
                return (msg, null);
            }
            catch (SocketException ex)
            {
                lastError = $"{host.Name}: {ex.SocketErrorCode}";
                DnsTransport.Log(Trace, "DNS", qname, type, target, false, sw.Elapsed.TotalMilliseconds, null, $"socket error {ex.SocketErrorCode}");
            }
            catch (Exception ex) when (ex is IOException or FormatException or IndexOutOfRangeException or ArgumentException)
            {
                lastError = $"{host.Name}: {ex.Message}";
                DnsTransport.Log(Trace, "DNS", qname, type, target, false, sw.Elapsed.TotalMilliseconds, null, ex.Message);
            }
        }
        return (null, lastError ?? "no usable name server");
    }

    /// <summary>What a step of the walk produced: answer, referral, CNAME or nothing.</summary>
    private static string Describe(DnsMessage msg, string qname, DnsType type)
    {
        if (msg.Rcode == 3) return "name does not exist";
        if (msg.Answers.Any(a => a.Name == qname && a.Type == type)) return "answer";
        var cname = msg.Answers.FirstOrDefault(a => a.Name == qname && a.Type == DnsType.CNAME);
        if (cname is not null) return $"CNAME to {cname.Target}";
        var ns = msg.Authority.Where(r => r.Type == DnsType.NS).ToList();
        if (ns.Count > 0 && !msg.Authoritative)
            return $"referral to {(ns[0].Name.Length == 0 ? "the root" : ns[0].Name)} ({ns.Count} name servers, {msg.Additional.Count(a => a.Type is DnsType.A or DnsType.AAAA)} glue)";
        if (msg.Authoritative) return "authoritative: no record of this type";
        return "neither answer nor referral";
    }

    // Name-server addresses that timed out once in this run.
    private readonly HashSet<IPAddress> _dead = new();

    // Name-server host name -> usable addresses, shared by every referral that names it.
    private readonly Dictionary<string, List<IPAddress>> _nsAddresses = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _nsResolving = new(StringComparer.OrdinalIgnoreCase);

    private void EnsureAddresses(NsHost host, CancellationToken cancel, int depth)
    {
        if (host.Name.Length == 0) return;
        // Glue can point anywhere; non-public addresses (private, documentation ranges) are
        // unreachable and would only cost a timeout.
        host.Ips.RemoveAll(ip => !NetUtil.IsPublic(ip));
        if (host.Ips.Count > 0) return;

        if (_nsAddresses.TryGetValue(host.Name, out var known))
        {
            host.Ips.AddRange(known);
            return;
        }
        // Two zones whose name servers live in each other: stop the loop, use the other servers.
        if (!_nsResolving.Add(host.Name)) return;
        try
        {
            var found = ResolveInternal(host.Name, DnsType.A, cancel, depth).Addresses();
            if (found.Count == 0)
                found = ResolveInternal(host.Name, DnsType.AAAA, cancel, depth).Addresses();
            var usable = found.Where(NetUtil.IsPublic).ToList();
            if (found.Count > 0 && usable.Count == 0)
                Trace?.Add("DNS", $"name server {host.Name}", TraceOutcome.Warn,
                           $"resolves only to non-public addresses ({string.Join(", ", found)}): skipped",
                           "The operator publishes addresses that cannot be reached; queries to this server would only time out.");
            // A failed lookup (timeout) is not cached: the next referral may try again.
            if (found.Count > 0) _nsAddresses[host.Name] = usable;
            host.Ips.AddRange(usable);
        }
        finally
        {
            _nsResolving.Remove(host.Name);
        }
    }

    private ZoneServers ClosestCut(string name)
    {
        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < labels.Length; i++)
        {
            var candidate = string.Join(".", labels.Skip(i));
            if (_cuts.TryGetValue(candidate, out var cut)) return cut;
        }
        return _cuts[""];
    }

    private static bool IsWithin(string name, string zone) =>
        zone.Length == 0 || name.Equals(zone, StringComparison.OrdinalIgnoreCase) || name.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase);

    private static bool IsStrictlyBelow(string child, string parent) =>
        !child.Equals(parent, StringComparison.OrdinalIgnoreCase) && IsWithin(child, parent);

    private DnsResponse Result(string name, DnsType type, DnsStatus status, List<DnsRecord> answers) => new()
    {
        Name = name,
        Type = type,
        Status = status == DnsStatus.Ok && !answers.Any(a => a.Type == type) ? DnsStatus.NoData : status,
        Answers = answers.ToList(),
        Via = Label,
    };

    private DnsResponse Fail(string name, DnsType type, DnsStatus status, string error, List<DnsRecord>? answers = null, bool transport = false) => new()
    {
        Name = name,
        Type = type,
        Status = status,
        Error = error,
        TransportFailure = transport,
        Answers = answers?.ToList() ?? new List<DnsRecord>(),
        Via = Label,
    };
}
