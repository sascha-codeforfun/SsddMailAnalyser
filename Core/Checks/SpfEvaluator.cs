using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core.Checks;

public enum SpfVerdict { Pass, Fail, SoftFail, Neutral, None, PermError, TempError }

public sealed class SpfEvaluation
{
    public string Domain { get; init; } = "";
    public IPAddress? Ip { get; init; }
    public SpfVerdict Verdict { get; set; }
    public string Reason { get; set; } = "";
    public string? Matched { get; set; }
    public int Lookups { get; set; }
    public int VoidLookups { get; set; }
    public List<string> Trace { get; } = new();
}

public sealed class SpfHealth
{
    public string Domain { get; init; } = "";
    public SpfVerdict Status { get; set; } = SpfVerdict.None;   // None, Pass (= healthy), PermError, TempError
    public string? Record { get; set; }
    public int TotalLookups { get; set; }
    public string? AllTerm { get; set; }
    public List<string> Tree { get; } = new();
    public List<string> Problems { get; } = new();
    public List<string> Notes { get; } = new();
    public bool HasMacros { get; set; }
}

/// <summary>
/// SPF (RFC 7208) evaluated from scratch against the live DNS: what the receiving server
/// would conclude today for a given IP, and how the record holds up as a whole (the
/// 10-lookup limit is per evaluation, so a record can pass for one IP and break for another).
/// </summary>
public sealed class SpfEvaluator
{
    private sealed class SpfAbort : Exception
    {
        public SpfAbort(SpfVerdict verdict, string message) : base(message) => Verdict = verdict;
        public SpfVerdict Verdict { get; }
    }

    private readonly DnsClient _dns;
    private readonly CancellationToken _cancel;

    private int _lookups;
    private int _voids;
    private List<string> _trace = new();
    private IPAddress _ip = IPAddress.None;
    private string _sender = "";
    private string _helo = "";

    public SpfEvaluator(DnsClient dns, CancellationToken cancel)
    {
        _dns = dns;
        _cancel = cancel;
    }

    public static bool IsSpfRecord(string txt)
    {
        var t = txt.Trim();
        return t.Equals("v=spf1", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("v=spf1 ", StringComparison.OrdinalIgnoreCase);
    }

    // ================================================================== evaluation

    public SpfEvaluation Evaluate(IPAddress ip, string domain, string? sender = null, string? helo = null)
    {
        _lookups = 0;
        _voids = 0;
        _trace = new List<string>();
        _ip = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
        domain = DomainUtil.Normalize(domain);
        _sender = string.IsNullOrWhiteSpace(sender) ? "postmaster@" + domain : sender.Trim();
        _helo = string.IsNullOrWhiteSpace(helo) ? domain : helo.Trim();

        var result = new SpfEvaluation { Domain = domain, Ip = _ip };
        try
        {
            var (verdict, matched) = CheckHost(domain, 0);
            result.Verdict = verdict;
            result.Matched = matched;
            result.Reason = verdict switch
            {
                SpfVerdict.None => $"{domain} publishes no SPF record",
                SpfVerdict.Neutral when matched is null => "no mechanism matched; the record ends without an 'all' (neutral)",
                _ when matched is not null => "matched " + matched,
                _ => verdict.ToString(),
            };
        }
        catch (SpfAbort abort)
        {
            result.Verdict = abort.Verdict;
            result.Reason = abort.Message;
        }
        result.Lookups = _lookups;
        result.VoidLookups = _voids;
        result.Trace.AddRange(_trace);
        return result;
    }

    private (SpfVerdict Verdict, string? Matched) CheckHost(string domain, int depth)
    {
        _cancel.ThrowIfCancellationRequested();
        if (depth > 15) throw new SpfAbort(SpfVerdict.PermError, "include/redirect nesting too deep (loop?)");
        var indent = new string(' ', depth * 2);

        var response = _dns.Query(domain, DnsType.TXT, _cancel);
        if (response.IsTransient)
            throw new SpfAbort(SpfVerdict.TempError, $"TXT lookup for {domain} failed: {response.Describe()}");
        if (response.Status == DnsStatus.NxDomain)
        {
            _trace.Add($"{indent}{domain}: domain does not exist");
            return (SpfVerdict.None, null);
        }

        var records = response.Texts().Where(IsSpfRecord).ToList();
        if (records.Count == 0)
        {
            _trace.Add($"{indent}{domain}: no SPF record");
            return (SpfVerdict.None, null);
        }
        if (records.Count > 1)
            throw new SpfAbort(SpfVerdict.PermError, $"{domain} publishes {records.Count} SPF records; exactly one is allowed");

        var record = records[0];
        _trace.Add($"{indent}{domain}: {record}");

        string? redirect = null;
        foreach (var term in record.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            if (IsModifier(term, out var modName, out var modValue))
            {
                if (modName == "redirect")
                {
                    if (redirect is not null) throw new SpfAbort(SpfVerdict.PermError, $"{domain}: more than one redirect=");
                    redirect = modValue;
                }
                continue;
            }

            var (qualifier, name, arg, cidr4, cidr6) = ParseMechanism(term, domain);
            bool match = name switch
            {
                "all" => true,
                "ip4" => MatchIp(arg, AddressFamily.InterNetwork, term, domain),
                "ip6" => MatchIp(arg, AddressFamily.InterNetworkV6, term, domain),
                "a" => MatchA(Expand(arg ?? domain, domain), cidr4, cidr6),
                "mx" => MatchMx(Expand(arg ?? domain, domain), cidr4, cidr6),
                "ptr" => MatchPtr(Expand(arg ?? domain, domain)),
                "exists" => MatchExists(Expand(arg ?? throw new SpfAbort(SpfVerdict.PermError, $"{domain}: exists without a domain"), domain)),
                "include" => MatchInclude(Expand(arg ?? throw new SpfAbort(SpfVerdict.PermError, $"{domain}: include without a domain"), domain), depth, out _),
                _ => throw new SpfAbort(SpfVerdict.PermError, $"{domain}: unknown mechanism '{term}'"),
            };

            if (match)
            {
                var where = depth == 0 ? term : $"{term} (in {domain})";
                if (name == "include" && _lastIncludeMatch is not null) where = $"{term} -> {_lastIncludeMatch}";
                _trace.Add($"{indent}  => {term} matches");
                return (qualifier, where);
            }
        }

        if (redirect is not null)
        {
            CountLookup();
            var target = Expand(redirect, domain);
            var (verdict, matched) = CheckHost(target, depth + 1);
            if (verdict == SpfVerdict.None)
                throw new SpfAbort(SpfVerdict.PermError, $"redirect={target} has no SPF record");
            return (verdict, matched is null ? $"redirect={target}" : $"redirect={target} -> {matched}");
        }

        return (SpfVerdict.Neutral, null);
    }

    private string? _lastIncludeMatch;

    private bool MatchInclude(string target, int depth, out string? matched)
    {
        CountLookup();
        var (verdict, inner) = CheckHost(target, depth + 1);
        matched = inner;
        _lastIncludeMatch = inner;
        switch (verdict)
        {
            case SpfVerdict.Pass: return true;
            case SpfVerdict.Fail:
            case SpfVerdict.SoftFail:
            case SpfVerdict.Neutral: return false;
            case SpfVerdict.TempError: throw new SpfAbort(SpfVerdict.TempError, $"include:{target} could not be resolved");
            default: throw new SpfAbort(SpfVerdict.PermError, $"include:{target} has no SPF record");
        }
    }

    private bool MatchIp(string? arg, AddressFamily family, string term, string domain)
    {
        if (string.IsNullOrEmpty(arg)) throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' has no address");
        var parts = arg.Split('/');
        if (!IPAddress.TryParse(parts[0], out var net) || net.AddressFamily != family)
            throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' is not a valid address");
        int max = family == AddressFamily.InterNetwork ? 32 : 128;
        int prefix = max;
        if (parts.Length > 1 && (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out prefix) || prefix < 0 || prefix > max))
            throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' has an invalid prefix length");
        if (_ip.AddressFamily != family) return false;
        return NetUtil.InCidr(_ip, net, prefix);
    }

    private bool MatchA(string target, int cidr4, int cidr6)
    {
        CountLookup();
        var type = _ip.AddressFamily == AddressFamily.InterNetwork ? DnsType.A : DnsType.AAAA;
        var r = _dns.Query(target, type, _cancel);
        if (r.IsTransient) throw new SpfAbort(SpfVerdict.TempError, $"lookup of {target} failed: {r.Describe()}");
        if (r.IsEmpty) { CountVoid(target); return false; }
        int prefix = type == DnsType.A ? cidr4 : cidr6;
        return r.Addresses().Any(a => NetUtil.InCidr(_ip, a, prefix));
    }

    private bool MatchMx(string target, int cidr4, int cidr6)
    {
        CountLookup();
        var r = _dns.Query(target, DnsType.MX, _cancel);
        if (r.IsTransient) throw new SpfAbort(SpfVerdict.TempError, $"MX lookup of {target} failed: {r.Describe()}");
        if (r.IsEmpty) { CountVoid(target); return false; }
        var mx = r.Mx();
        if (mx.Count > 10) throw new SpfAbort(SpfVerdict.PermError, $"mx:{target} has more than 10 MX records");
        var type = _ip.AddressFamily == AddressFamily.InterNetwork ? DnsType.A : DnsType.AAAA;
        int prefix = type == DnsType.A ? cidr4 : cidr6;
        foreach (var exchange in mx)
        {
            if (string.IsNullOrEmpty(exchange.Target)) continue;
            var addrs = _dns.Query(exchange.Target, type, _cancel);
            if (addrs.Addresses().Any(a => NetUtil.InCidr(_ip, a, prefix))) return true;
        }
        return false;
    }

    private bool MatchPtr(string target)
    {
        CountLookup();
        var r = _dns.Query(NetUtil.ReverseName(_ip), DnsType.PTR, _cancel);
        if (r.IsEmpty) { CountVoid(NetUtil.ReverseName(_ip)); return false; }
        foreach (var name in r.Targets(DnsType.PTR).Take(10))
        {
            if (!(name.Equals(target, StringComparison.OrdinalIgnoreCase) || name.EndsWith("." + target, StringComparison.OrdinalIgnoreCase))) continue;
            if (_dns.Addresses(name, _cancel).Any(a => a.Equals(_ip))) return true;
        }
        return false;
    }

    private bool MatchExists(string target)
    {
        CountLookup();
        var r = _dns.Query(target, DnsType.A, _cancel);
        if (r.IsTransient) throw new SpfAbort(SpfVerdict.TempError, $"lookup of {target} failed: {r.Describe()}");
        if (r.IsEmpty) { CountVoid(target); return false; }
        return true;
    }

    private void CountLookup()
    {
        _lookups++;
        if (_lookups > 10)
            throw new SpfAbort(SpfVerdict.PermError, "more than 10 DNS-querying mechanisms (RFC 7208 limit) before a match");
    }

    private void CountVoid(string name)
    {
        _voids++;
        if (_voids > 2)
            throw new SpfAbort(SpfVerdict.PermError, $"more than 2 lookups returned nothing (last: {name})");
    }

    // ================================================================== parsing

    private static bool IsModifier(string term, out string name, out string value)
    {
        name = value = "";
        int eq = term.IndexOf('=');
        int colon = term.IndexOf(':');
        int slash = term.IndexOf('/');
        if (eq <= 0) return false;
        if (colon >= 0 && colon < eq) return false;
        if (slash >= 0 && slash < eq) return false;
        var n = term[..eq];
        if (!char.IsLetter(n[0]) || !n.All(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.')) return false;
        name = n.ToLowerInvariant();
        value = term[(eq + 1)..];
        return true;
    }

    private static (SpfVerdict Qualifier, string Name, string? Arg, int Cidr4, int Cidr6) ParseMechanism(string term, string domain)
    {
        var q = SpfVerdict.Pass;
        var t = term;
        switch (t[0])
        {
            case '+': q = SpfVerdict.Pass; t = t[1..]; break;
            case '-': q = SpfVerdict.Fail; t = t[1..]; break;
            case '~': q = SpfVerdict.SoftFail; t = t[1..]; break;
            case '?': q = SpfVerdict.Neutral; t = t[1..]; break;
        }
        if (t.Length == 0) throw new SpfAbort(SpfVerdict.PermError, $"{domain}: empty term '{term}'");

        int colon = t.IndexOf(':');
        int slash = t.IndexOf('/');
        int nameEnd = colon >= 0 ? colon : (slash >= 0 ? slash : t.Length);
        if (slash >= 0 && slash < nameEnd) nameEnd = slash;
        var name = t[..nameEnd].ToLowerInvariant();
        string? arg = null;
        string rest = t[nameEnd..];

        int cidr4 = 32, cidr6 = 128;
        if (name is "ip4" or "ip6")
        {
            if (!rest.StartsWith(':')) throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' has no address");
            return (q, name, rest[1..], cidr4, cidr6);
        }

        if (rest.StartsWith(':'))
        {
            rest = rest[1..];
            // domain-spec, then optional /cidr4 and //cidr6 (macros never contain '/')
            int s = rest.IndexOf('/');
            arg = s >= 0 ? rest[..s] : rest;
            rest = s >= 0 ? rest[s..] : "";
        }

        if (rest.Length > 0)
        {
            // "/24", "//64", "/24//64"
            var dual = rest.Split("//");
            if (dual[0].StartsWith('/') && dual[0].Length > 1
                && !int.TryParse(dual[0][1..], NumberStyles.Integer, CultureInfo.InvariantCulture, out cidr4))
                throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' has an invalid prefix length");
            if (dual.Length > 1 && dual[1].Length > 0
                && !int.TryParse(dual[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out cidr6))
                throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' has an invalid prefix length");
        }

        if (name is "a" or "mx" && (cidr4 is < 0 or > 32 || cidr6 is < 0 or > 128))
            throw new SpfAbort(SpfVerdict.PermError, $"{domain}: '{term}' has an invalid prefix length");
        return (q, name, string.IsNullOrEmpty(arg) ? null : arg, cidr4, cidr6);
    }

    // ================================================================== macros (RFC 7208 section 7)

    private string Expand(string spec, string domain)
    {
        if (!spec.Contains('%')) return spec;
        var sb = new StringBuilder();
        for (int i = 0; i < spec.Length; i++)
        {
            char c = spec[i];
            if (c != '%') { sb.Append(c); continue; }
            if (i + 1 >= spec.Length) throw new SpfAbort(SpfVerdict.PermError, $"bad macro in '{spec}'");
            char n = spec[++i];
            if (n == '%') { sb.Append('%'); continue; }
            if (n == '_') { sb.Append(' '); continue; }
            if (n == '-') { sb.Append("%20"); continue; }
            if (n != '{') throw new SpfAbort(SpfVerdict.PermError, $"bad macro in '{spec}'");
            int close = spec.IndexOf('}', i);
            if (close < 0) throw new SpfAbort(SpfVerdict.PermError, $"unterminated macro in '{spec}'");
            var body = spec[(i + 1)..close];
            i = close;
            sb.Append(ExpandOne(body, domain, spec));
        }
        return sb.ToString();
    }

    private string ExpandOne(string body, string domain, string spec)
    {
        if (body.Length == 0) throw new SpfAbort(SpfVerdict.PermError, $"empty macro in '{spec}'");
        char letter = char.ToLowerInvariant(body[0]);
        int at = _sender.LastIndexOf('@');
        string local = at > 0 ? _sender[..at] : "postmaster";
        string senderDomain = at >= 0 ? _sender[(at + 1)..] : _sender;

        string value = letter switch
        {
            's' => _sender,
            'l' => local,
            'o' => senderDomain,
            'd' => domain,
            'i' => _ip.AddressFamily == AddressFamily.InterNetwork
                    ? _ip.ToString()
                    : string.Join(".", Enumerable.Reverse(NetUtil.ReversedLabels(_ip).Split('.'))),
            'p' => "unknown",
            'v' => _ip.AddressFamily == AddressFamily.InterNetwork ? "in-addr" : "ip6",
            'h' => _helo,
            'c' or 'r' or 't' => "",
            _ => throw new SpfAbort(SpfVerdict.PermError, $"unknown macro letter '{body[0]}' in '{spec}'"),
        };

        // transformers: digits, 'r', then delimiters
        int pos = 1;
        int keep = 0;
        while (pos < body.Length && char.IsDigit(body[pos])) keep = keep * 10 + (body[pos++] - '0');
        bool reverse = false;
        if (pos < body.Length && char.ToLowerInvariant(body[pos]) == 'r') { reverse = true; pos++; }
        var delimiters = body[pos..];
        if (delimiters.Length == 0) delimiters = ".";
        if (delimiters.Any(d => !".-+,/_=".Contains(d)))
            throw new SpfAbort(SpfVerdict.PermError, $"bad macro delimiters in '{spec}'");

        if (keep == 0 && !reverse && delimiters == ".") return value;
        var parts = value.Split(delimiters.ToCharArray()).ToList();
        if (reverse) parts.Reverse();
        if (keep > 0 && keep < parts.Count) parts = parts.Skip(parts.Count - keep).ToList();
        return string.Join(".", parts);
    }

    // ================================================================== record health

    /// <summary>
    /// Walks the whole record, counting its DNS-querying terms for a worst-case evaluation
    /// (a target reached twice is expanded only once), and lists the structural problems.
    /// </summary>
    public SpfHealth Health(string domain)
    {
        domain = DomainUtil.Normalize(domain);
        var health = new SpfHealth { Domain = domain };

        var r = _dns.Query(domain, DnsType.TXT, _cancel);
        if (r.IsTransient)
        {
            health.Status = SpfVerdict.TempError;
            health.Problems.Add($"TXT lookup failed: {r.Describe()}");
            return health;
        }
        var records = r.Texts().Where(IsSpfRecord).ToList();
        if (records.Count == 0)
        {
            health.Status = SpfVerdict.None;
            return health;
        }
        health.Record = records[0];
        if (records.Count > 1)
        {
            health.Status = SpfVerdict.PermError;
            health.Problems.Add($"{records.Count} SPF records published; receivers treat this as a permanent error");
            foreach (var rec in records) health.Tree.Add(rec);
            return health;
        }

        int total = 0;
        Walk(domain, records[0], 0, health, ref total, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { domain });
        health.TotalLookups = total;

        var terms = records[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);
        health.AllTerm = terms.FirstOrDefault(t => t.TrimStart('+', '-', '~', '?').Equals("all", StringComparison.OrdinalIgnoreCase));
        bool hasRedirect = terms.Any(t => t.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase));

        if (total > 10)
            health.Problems.Add($"needs {total} DNS lookups when fully expanded; the limit is 10. Senders whose IP is only matched after the 10th lookup get a permanent error");
        else if (total >= 9)
            health.Notes.Add($"{total} of 10 DNS lookups used; one more include and it breaks");

        if (health.AllTerm is "+all" or "all")
            health.Problems.Add("'+all' authorises every IP on the internet; receivers treat such records as worthless");
        else if (health.AllTerm is null && !hasRedirect)
            health.Notes.Add("no 'all' at the end: unmatched IPs get 'neutral', which DMARC does not count as a pass");
        else if (health.AllTerm == "?all")
            health.Notes.Add("'?all' (neutral): SPF never fails for unauthorised IPs");

        if (records[0].Length > 450)
            health.Notes.Add($"record is {records[0].Length} characters; close to what fits in one DNS answer");

        health.Status = health.Problems.Any(p => p.Contains("permanent error") || p.Contains("limit is 10") || p.Contains("no SPF record") || p.Contains("does not exist"))
            ? SpfVerdict.PermError
            : SpfVerdict.Pass;
        return health;
    }

    private void Walk(string domain, string record, int depth, SpfHealth health, ref int total, HashSet<string> visited)
    {
        _cancel.ThrowIfCancellationRequested();
        var indent = new string(' ', depth * 2);
        health.Tree.Add($"{indent}{domain}: {record}");
        if (depth > 12) { health.Problems.Add("include nesting too deep (loop?)"); return; }

        foreach (var term in record.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            string? target = null;
            bool counts = false;

            if (IsModifier(term, out var mod, out var val))
            {
                if (mod != "redirect") continue;
                counts = true;
                target = val;
            }
            else
            {
                var t = term.TrimStart('+', '-', '~', '?');
                var lower = t.ToLowerInvariant();
                if (lower.StartsWith("include:")) { counts = true; target = t[8..]; }
                else if (lower == "a" || lower.StartsWith("a:") || lower.StartsWith("a/")) counts = true;
                else if (lower == "mx" || lower.StartsWith("mx:") || lower.StartsWith("mx/")) counts = true;
                else if (lower.StartsWith("ptr"))
                {
                    counts = true;
                    if (!health.Problems.Any(p => p.Contains("ptr")) && !health.Notes.Any(n => n.Contains("ptr")))
                        health.Notes.Add("uses the deprecated 'ptr' mechanism (slow; some receivers skip it)");
                }
                else if (lower.StartsWith("exists:")) counts = true;
                else if (lower.StartsWith("ip4:") || lower.StartsWith("ip6:"))
                {
                    var addr = t[4..].Split('/')[0];
                    if (!IPAddress.TryParse(addr, out _))
                        health.Problems.Add($"'{term}' in {domain} is not a valid address: permanent error when reached");
                }
            }

            if (counts) total++;
            if (target is null) continue;

            if (target.Contains('%'))
            {
                health.HasMacros = true;
                health.Tree.Add($"{indent}  {term}  (macro, expanded per message)");
                continue;
            }
            if (!visited.Add(target))
            {
                health.Tree.Add($"{indent}  {term}  (already counted)");
                continue;
            }

            var r = _dns.Query(target, DnsType.TXT, _cancel);
            if (r.IsTransient)
            {
                health.Problems.Add($"{term} in {domain}: lookup failed ({r.Describe()}) - temporary error for receivers");
                continue;
            }
            var sub = r.Texts().Where(IsSpfRecord).ToList();
            if (sub.Count == 0)
            {
                health.Problems.Add(r.Status == DnsStatus.NxDomain
                    ? $"{term} in {domain}: '{target}' does not exist - permanent error when reached"
                    : $"{term} in {domain}: '{target}' has no SPF record - permanent error when reached");
                health.Tree.Add($"{indent}  {target}: (no SPF record)");
                continue;
            }
            if (sub.Count > 1)
            {
                health.Problems.Add($"{target} publishes {sub.Count} SPF records - permanent error when reached");
                continue;
            }
            Walk(target, sub[0], depth + 1, health, ref total, visited);
        }
    }
}
