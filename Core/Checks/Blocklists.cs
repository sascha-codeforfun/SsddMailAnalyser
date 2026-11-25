using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core.Checks;

public enum ListingStatus { NotListed, Listed, Unusable, Failed }

/// <summary>How much a listing matters to real receivers.</summary>
public enum ListTier
{
    /// <summary>Used by many receivers, including large ones: a listing costs delivery.</summary>
    Major,

    /// <summary>Used by some filters and appliances: a listing can cost delivery there.</summary>
    Minor,

    /// <summary>Lists whole ranges or provider networks because of other addresses in them.</summary>
    Neighbourhood,
}

public sealed class BlocklistResult
{
    public string Zone { get; init; } = "";
    public string Name { get; init; } = "";
    public string Subject { get; init; } = "";

    /// <summary>What the subject is in this case: "sending IP", "sender's MX host", "DKIM domain", ...</summary>
    public string Role { get; init; } = "";

    public ListTier Tier { get; init; }
    public bool IsDomainList { get; init; }
    public string DelistUrl { get; init; } = "";
    public string About { get; init; } = "";
    public ListingStatus Status { get; set; }
    public string Detail { get; set; } = "";

    /// <summary>The list answered its RFC 5782 test entry correctly.</summary>
    public bool Verified { get; set; }
    public string SelfTest { get; set; } = "";

    public bool Severe => Tier == ListTier.Major;

    /// <summary>The list drops entries within days of the last abuse: a listing is by nature recent.</summary>
    public bool Expiring { get; init; }
}

/// <summary>
/// DNS blocklists, curated rather than exhaustive: lists that receivers actually use, in three
/// tiers, plus the domain lists that matter for mail. Every list is self-tested once per
/// analysis (RFC 5782: 127.0.0.2 must be listed, 127.0.0.1 must not), so a dead list or one
/// that answers "listed" to everything is reported as unusable instead of raising an alarm.
/// </summary>
public static class BlocklistChecker
{
    private sealed record ListDef(
        string Zone, string Name, ListTier Tier, bool V6, string DelistUrl, string About,
        string? PositiveTest = null, string? NegativeTest = null,
        string[]? RefusedPrefixes = null, bool Expiring = false);

    // Answers some lists give to refuse a querier rather than to list something. Only applied to
    // the lists known to use them: elsewhere the same code can be a real answer.
    private static readonly string[] SpamhausRefused = { "127.255.255." };
    private static readonly string[] BlockedQuerier = { "127.0.0.1" };

    private static readonly ListDef[] IpLists =
    {
        // ---- major
        new("zen.spamhaus.org", "Spamhaus ZEN", ListTier.Major, true, "https://check.spamhaus.org/",
            "The most widely used list; combines SBL, CSS, XBL and PBL.", RefusedPrefixes: SpamhausRefused),
        new("b.barracudacentral.org", "Barracuda", ListTier.Major, false, "https://www.barracudacentral.org/rbl/removal-request",
            "Used by Barracuda appliances and many other filters."),
        new("bl.spamcop.net", "SpamCop", ListTier.Major, false, "https://www.spamcop.net/bl.shtml",
            "Listings from user spam reports; expire automatically within 24 hours of the last report.", Expiring: true),
        new("bl.mailspike.net", "Mailspike", ListTier.Major, false, "https://mailspike.org/",
            "Reputation-based list used by several filter vendors."),

        // ---- minor
        new("psbl.surriel.com", "PSBL", ListTier.Minor, false, "https://psbl.org/",
            "Passive spam trap list; self-service removal."),
        new("dnsbl-1.uceprotect.net", "UCEPROTECT Level 1", ListTier.Minor, false, "https://www.uceprotect.net/en/rblcheck.php",
            "Single IPs seen at UCEPROTECT's traps; expires 7 days after the last hit.", Expiring: true),
        new("dnsbl.dronebl.org", "DroneBL", ListTier.Minor, false, "https://dronebl.org/lookup",
            "Botnet drones and open proxies."),
        new("bl.blocklist.de", "blocklist.de", ListTier.Minor, false, "https://www.blocklist.de/en/delist.html",
            "IPs reported for attacks (brute force, abuse) by participating servers."),
        new("truncate.gbudb.net", "GBUdb Truncate", ListTier.Minor, false, "https://www.gbudb.com/truncate/",
            "Statistical reputation list used by Message Sniffer filters."),

        // ---- neighbourhood
        new("dnsbl-2.uceprotect.net", "UCEPROTECT Level 2", ListTier.Neighbourhood, false, "https://www.uceprotect.net/en/rblcheck.php",
            "Lists a provider's allocation when IPs in it were caught spamming in the last 7 days. The IP itself need not have done anything.", Expiring: true),
        new("dnsbl-3.uceprotect.net", "UCEPROTECT Level 3", ListTier.Neighbourhood, false, "https://www.uceprotect.net/en/rblcheck.php",
            "Lists a provider's entire network (ASN) when too many of its IPs were caught spamming.", Expiring: true),
    };

    private static readonly ListDef[] DomainLists =
    {
        new("dbl.spamhaus.org", "Spamhaus DBL", ListTier.Major, false, "https://check.spamhaus.org/",
            "Domains seen in spam, phishing and malware.", PositiveTest: "dbltest.com", NegativeTest: "example.com", RefusedPrefixes: SpamhausRefused),
        new("multi.surbl.org", "SURBL", ListTier.Major, false, "https://www.surbl.org/surbl-analysis",
            "Domains seen in message bodies of spam, phishing and malware.", PositiveTest: "test.surbl.org", NegativeTest: "example.com", RefusedPrefixes: BlockedQuerier),
        new("multi.uribl.com", "URIBL", ListTier.Minor, false, "https://admin.uribl.com/",
            "Domains seen in spam; black is a listing, grey and red are weaker signals.", PositiveTest: "test.uribl.com", NegativeTest: "example.com", RefusedPrefixes: BlockedQuerier),
    };

    public static IEnumerable<string> IpListNames => IpLists.Select(l => l.Name);

    // ------------------------------------------------------------------ self-test, once per DNS client

    private sealed class SelfTestResult
    {
        public bool Usable;
        public bool Verified;
        public string Note = "";
    }

    private static readonly ConditionalWeakTable<DnsClient, Dictionary<string, SelfTestResult>> Tests = new();

    private static SelfTestResult SelfTest(DnsClient dns, ListDef list, bool domainList, CancellationToken cancel)
    {
        var cache = Tests.GetOrCreateValue(dns);
        lock (cache)
        {
            if (cache.TryGetValue(list.Zone, out var known)) return known;
        }

        var positive = domainList ? $"{list.PositiveTest}.{list.Zone}" : $"2.0.0.127.{list.Zone}";
        var negative = domainList ? $"{list.NegativeTest}.{list.Zone}" : $"1.0.0.127.{list.Zone}";
        var result = new SelfTestResult();

        var neg = dns.Query(negative, DnsType.A, cancel);
        var pos = dns.Query(positive, DnsType.A, cancel);
        var posCodes = pos.Addresses().Select(a => a.ToString()).ToList();
        var negCodes = neg.Addresses().Select(a => a.ToString()).ToList();

        if (neg.IsOk && negCodes.Any(c => !Refused(list, c)))
        {
            result.Usable = false;
            result.Note = $"self-test failed: the test entry that must not be listed answers {string.Join(", ", negCodes)} - the list (or the resolver) answers 'listed' to everything";
        }
        else if (pos.IsOk && posCodes.Count > 0 && posCodes.All(c => Refused(list, c)))
        {
            result.Usable = false;
            result.Note = $"self-test: the list refuses queries from here ({string.Join(", ", posCodes)}) - public or shared resolver, or the list requires registration";
        }
        else if (pos.IsTransient && neg.IsTransient)
        {
            result.Usable = false;
            result.Note = $"self-test: the list does not answer ({pos.Describe()})";
        }
        else if (pos.IsOk && posCodes.All(c => c.StartsWith("127.", StringComparison.Ordinal)))
        {
            result.Usable = true;
            result.Verified = true;
            result.Note = "self-test passed";
        }
        else
        {
            // The list answers, but not to its test entry: results are kept and marked as unverified.
            result.Usable = true;
            result.Verified = false;
            result.Note = $"self-test inconclusive: the test entry answered {pos.Describe()}; results are unverified";
        }

        lock (cache) cache[list.Zone] = result;
        return result;
    }

    private static bool Refused(ListDef list, string code) =>
        list.RefusedPrefixes is { } prefixes && prefixes.Any(p => p.EndsWith('.') ? code.StartsWith(p, StringComparison.Ordinal) : code == p);

    // ------------------------------------------------------------------ queries

    public static List<BlocklistResult> CheckIp(DnsClient dns, IPAddress ip, string role, Action<string>? progress, CancellationToken cancel)
    {
        var results = new List<BlocklistResult>();
        var reversed = NetUtil.ReversedLabels(ip);
        bool v6 = ip.AddressFamily == AddressFamily.InterNetworkV6;

        foreach (var list in IpLists)
        {
            if (v6 && !list.V6) continue;
            cancel.ThrowIfCancellationRequested();
            progress?.Invoke(list.Name);
            results.Add(Check(dns, list, false, $"{reversed}.{list.Zone}", ip.ToString(), role, cancel));
        }
        return results;
    }

    public static List<BlocklistResult> CheckDomain(DnsClient dns, string domain, string role, CancellationToken cancel)
    {
        var results = new List<BlocklistResult>();
        var d = DomainUtil.Normalize(domain);
        foreach (var list in DomainLists)
        {
            cancel.ThrowIfCancellationRequested();
            results.Add(Check(dns, list, true, $"{d}.{list.Zone}", d, role, cancel));
        }
        return results;
    }

    private static BlocklistResult Check(DnsClient dns, ListDef list, bool domainList, string queryName, string subject, string role, CancellationToken cancel)
    {
        var result = new BlocklistResult
        {
            Zone = list.Zone,
            Name = list.Name,
            Subject = subject,
            Role = role,
            Tier = list.Tier,
            IsDomainList = domainList,
            DelistUrl = list.DelistUrl,
            About = list.About,
            Expiring = list.Expiring,
        };

        var test = SelfTest(dns, list, domainList, cancel);
        result.Verified = test.Verified;
        result.SelfTest = test.Note;
        if (!test.Usable)
        {
            result.Status = ListingStatus.Unusable;
            result.Detail = test.Note;
            return result;
        }

        var r = dns.Query(queryName, DnsType.A, cancel);
        if (r.IsTransient)
        {
            result.Status = ListingStatus.Failed;
            result.Detail = r.Describe();
            return result;
        }
        if (r.IsEmpty)
        {
            result.Status = ListingStatus.NotListed;
            result.Detail = "not listed" + (test.Verified ? "" : " (list unverified)");
            return result;
        }

        var codes = r.Addresses().Select(a => a.ToString()).ToList();
        if (codes.All(c => Refused(list, c)))
        {
            result.Status = ListingStatus.Unusable;
            result.Detail = $"query refused by the list ({string.Join(", ", codes)}) - public or shared resolver, or rate limit";
            return result;
        }
        if (codes.All(c => !c.StartsWith("127.", StringComparison.Ordinal)))
        {
            result.Status = ListingStatus.Unusable;
            result.Detail = $"answer {string.Join(", ", codes)} is not a list code - the resolver rewrites answers";
            return result;
        }

        // URIBL grey/red without black: a weak signal, not a listing.
        var meanings = codes.Where(c => !Refused(list, c)).Select(c => DescribeCode(list.Zone, c)).ToList();
        if (list.Zone == "multi.uribl.com" && codes.All(c => UriblBits(c) is var b && (b & 2) == 0 && b != 0))
        {
            result.Status = ListingStatus.NotListed;
            result.Detail = "not on the black list; weaker signal: " + string.Join(", ", meanings);
            return result;
        }

        result.Status = ListingStatus.Listed;
        result.Detail = string.Join(", ", meanings) + (test.Verified ? "" : " (list unverified)");

        var txt = dns.Query(queryName, DnsType.TXT, cancel).Texts().FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(txt)) result.Detail += " - " + txt;
        return result;
    }

    private static int UriblBits(string code) =>
        code.StartsWith("127.0.0.", StringComparison.Ordinal) && int.TryParse(code[8..], out var v) ? v : 0;

    private static string DescribeCode(string zone, string code)
    {
        switch (zone)
        {
            case "zen.spamhaus.org":
                return code switch
                {
                    "127.0.0.2" => "SBL (spam source)",
                    "127.0.0.3" => "SBL CSS (snowshoe spam)",
                    "127.0.0.4" or "127.0.0.5" or "127.0.0.6" or "127.0.0.7" => "XBL (infected or exploited host)",
                    "127.0.0.9" => "DROP (hijacked network)",
                    "127.0.0.10" => "PBL (ISP says: end-user range, should not send direct-to-MX)",
                    "127.0.0.11" => "PBL (Spamhaus says: end-user range)",
                    _ => code,
                };
            case "dbl.spamhaus.org":
                return code switch
                {
                    "127.0.1.2" => "spam domain",
                    "127.0.1.4" => "phishing domain",
                    "127.0.1.5" => "malware domain",
                    "127.0.1.6" => "botnet C&C domain",
                    "127.0.1.102" => "abused legit spam domain",
                    "127.0.1.103" => "abused redirector",
                    "127.0.1.104" => "abused legit phishing",
                    "127.0.1.105" => "abused legit malware",
                    _ => code,
                };
            case "multi.surbl.org":
            {
                int bits = UriblBits(code);
                var parts = new List<string>();
                if ((bits & 8) != 0) parts.Add("phishing");
                if ((bits & 16) != 0) parts.Add("malware");
                if ((bits & 64) != 0) parts.Add("spam/abuse");
                if ((bits & 128) != 0) parts.Add("cracked site");
                return parts.Count > 0 ? string.Join(" + ", parts) + $" ({code})" : code;
            }
            case "multi.uribl.com":
            {
                int bits = UriblBits(code);
                var parts = new List<string>();
                if ((bits & 2) != 0) parts.Add("black");
                if ((bits & 4) != 0) parts.Add("grey");
                if ((bits & 8) != 0) parts.Add("red");
                return parts.Count > 0 ? string.Join(" + ", parts) + $" ({code})" : code;
            }
            case "dnsbl-2.uceprotect.net":
                return $"the IP's allocation is listed ({code})";
            case "dnsbl-3.uceprotect.net":
                return $"the provider's network (ASN) is listed ({code})";
            default:
                return code;
        }
    }
}
