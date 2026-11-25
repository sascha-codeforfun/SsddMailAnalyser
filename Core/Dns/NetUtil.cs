using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace SsddMailAnalyser.Core.Dns;

public static class NetUtil
{
    public static bool TryParseIp(string? text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (string.IsNullOrWhiteSpace(text)) return false;
        text = text.Trim().Trim('[', ']');
        if (text.StartsWith("IPv6:", StringComparison.OrdinalIgnoreCase)) text = text[5..];
        if (!IPAddress.TryParse(text, out var parsed) || parsed is null) return false;
        // IPAddress.TryParse accepts "1" or "123" as IPv4; mail evidence never means that.
        if (parsed.AddressFamily == AddressFamily.InterNetwork && text.Count(c => c == '.') != 3) return false;
        ip = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    /// <summary>True for addresses that can appear on the public internet.</summary>
    public static bool IsPublic(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;   // CGNAT
            if (b[0] == 0 || b[0] >= 224) return false;
            // Documentation and benchmarking ranges (RFC 5737, RFC 2544): never on the internet.
            if (b[0] == 192 && b[1] == 0 && b[2] == 2) return false;
            if (b[0] == 198 && b[1] == 51 && b[2] == 100) return false;
            if (b[0] == 203 && b[1] == 0 && b[2] == 113) return false;
            if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return false;
            if (b[0] == 127) return false;
            return true;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast) return false;
            var b = ip.GetAddressBytes();
            if ((b[0] & 0xFE) == 0xFC) return false;   // fc00::/7 unique local
            if (ip.Equals(IPAddress.IPv6None) || ip.Equals(IPAddress.IPv6Any)) return false;
            return true;
        }
        return false;
    }

    public static bool InCidr(IPAddress ip, IPAddress network, int prefix)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (network.IsIPv4MappedToIPv6) network = network.MapToIPv4();
        if (ip.AddressFamily != network.AddressFamily) return false;

        var a = ip.GetAddressBytes();
        var n = network.GetAddressBytes();
        int bits = a.Length * 8;
        if (prefix < 0 || prefix > bits) return false;

        int full = prefix / 8;
        for (int i = 0; i < full; i++)
            if (a[i] != n[i]) return false;

        int rest = prefix % 8;
        if (rest == 0) return true;
        int mask = 0xFF << (8 - rest) & 0xFF;
        return (a[full] & mask) == (n[full] & mask);
    }

    /// <summary>The PTR query name: 4.3.2.1.in-addr.arpa or the ip6.arpa nibble form.</summary>
    public static string ReverseName(IPAddress ip) => ReversedLabels(ip) + (ip.AddressFamily == AddressFamily.InterNetwork ? ".in-addr.arpa" : ".ip6.arpa");

    /// <summary>The address in reverse label order, as used by DNS blocklists.</summary>
    public static string ReversedLabels(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        var b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork)
            return $"{b[3]}.{b[2]}.{b[1]}.{b[0]}";

        var sb = new StringBuilder();
        for (int i = b.Length - 1; i >= 0; i--)
        {
            sb.Append("0123456789abcdef"[b[i] & 0x0F]).Append('.');
            sb.Append("0123456789abcdef"[b[i] >> 4]).Append('.');
        }
        return sb.ToString(0, sb.Length - 1);
    }

    /// <summary>The DNS servers this machine is configured with, IPv4 first.</summary>
    public static List<(IPAddress Address, string Adapter)> SystemResolvers()
    {
        var list = new List<(IPAddress, string)>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (dns.IsIPv6SiteLocal && dns.ToString().StartsWith("fec0", StringComparison.OrdinalIgnoreCase)) continue;
                    if (list.Any(x => x.Item1.Equals(dns))) continue;
                    list.Add((dns, nic.Name));
                }
            }
        }
        catch (NetworkInformationException)
        {
            // fall through: the caller offers public resolvers
        }
        return list.OrderBy(x => x.Item1.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToList();
    }
}

public static class DomainUtil
{
    // Public suffixes with two labels that occur in business mail. Not the full Public Suffix
    // List (which would be a large external file); the report says the organisational domain
    // is approximated.
    private static readonly HashSet<string> TwoLabelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "nhs.uk",
        "co.at", "or.at", "ac.at", "gv.at",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "net.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr",
        "com.br", "net.br", "org.br", "gov.br",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.hk", "com.sg", "com.my", "com.tw", "com.tr", "com.mx", "com.ar", "com.co", "com.pe",
        "com.pl", "net.pl", "org.pl",
        "co.za", "co.in", "net.in", "org.in", "co.il", "org.il", "ac.il",
        "com.ua", "co.th", "co.id", "or.id", "com.vn", "com.ph", "com.pk", "com.sa", "com.eg",
        "com.es", "com.pt", "com.gr", "com.cy", "com.mt",
    };

    public static string Normalize(string? domain) => (domain ?? "").Trim().Trim('.', '<', '>').ToLowerInvariant();

    /// <summary>The organisational domain (RFC 7489 3.2), approximated.</summary>
    public static string OrgDomain(string? domain)
    {
        var d = Normalize(domain);
        var labels = d.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length <= 2) return d;
        var lastTwo = labels[^2] + "." + labels[^1];
        int keep = TwoLabelSuffixes.Contains(lastTwo) ? 3 : 2;
        return string.Join(".", labels.Skip(labels.Length - keep));
    }

    /// <summary>Relaxed alignment: same organisational domain.</summary>
    public static bool AlignedRelaxed(string? a, string? b) =>
        !string.IsNullOrEmpty(a) && !string.IsNullOrEmpty(b) &&
        string.Equals(OrgDomain(a), OrgDomain(b), StringComparison.OrdinalIgnoreCase);

    public static bool AlignedStrict(string? a, string? b) =>
        !string.IsNullOrEmpty(a) && string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase);

    /// <summary>The domain part of an address, or the text itself if it already is a domain.</summary>
    public static string DomainOf(string? addressOrDomain)
    {
        var s = (addressOrDomain ?? "").Trim().Trim('<', '>', '"', ' ');
        int at = s.LastIndexOf('@');
        return Normalize(at >= 0 ? s[(at + 1)..] : s);
    }

    /// <summary>
    /// Only the characters a DNS name is made of: letters, digits, hyphen, underscore, dots
    /// between non-empty labels (international names included). No dot is required: a
    /// single-label internal domain is a name too. What this keeps out is everything that
    /// means something else once the name is put into a URL: / : ? # @ and blanks.
    /// </summary>
    public static bool IsNameSafe(string? s)
    {
        s = Normalize(s);
        if (s.Length == 0 || s.StartsWith('.') || s.Contains("..")) return false;
        foreach (var c in s)
            if (!(char.IsLetterOrDigit(c) || c == '-' || c == '.' || c == '_')) return false;
        return true;
    }

    public static bool LooksLikeDomain(string? s)
    {
        s = Normalize(s);
        if (s.Length < 3 || !s.Contains('.')) return false;
        foreach (var c in s)
            if (!(char.IsLetterOrDigit(c) || c == '-' || c == '.' || c == '_' || c > 127)) return false;
        return true;
    }
}
