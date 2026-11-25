using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Checks;

// ===================================================================== DKIM

public enum DkimKeyStatus { Found, Missing, Revoked, Invalid, NotDkim, LookupFailed }

public sealed class DkimKeyCheck
{
    public string Selector { get; init; } = "";
    public string Domain { get; init; } = "";
    public string QueryName => $"{Selector}._domainkey.{Domain}";
    public DkimKeyStatus Status { get; set; }
    public string? Record { get; set; }
    public string? CnameTarget { get; set; }
    public string KeyType { get; set; } = "rsa";
    public int KeyBits { get; set; }
    public bool Testing { get; set; }
    public string Detail { get; set; } = "";
}

public static class DkimChecker
{
    /// <summary>Selectors worth probing when no signature is at hand.</summary>
    public static readonly string[] CommonSelectors =
    {
        "selector1", "selector2",                 // Microsoft 365
        "google",                                  // Google Workspace
        "default", "dkim", "mail", "k1", "k2", "k3", "s1", "s2", "smtp", "key1", "key2",
        "mandrill", "mxvault", "everlytickey1", "zoho", "hs1", "hs2", "sig1", "fm1", "fm2", "fm3", "protonmail",
    };

    public static DkimKeyCheck Check(DnsClient dns, string selector, string domain, CancellationToken cancel)
    {
        var check = new DkimKeyCheck { Selector = selector.Trim(), Domain = DomainUtil.Normalize(domain) };
        var r = dns.Query(check.QueryName, DnsType.TXT, cancel);
        check.CnameTarget = r.OfType(DnsType.CNAME).Select(c => c.Target).LastOrDefault();

        if (r.IsTransient)
        {
            check.Status = DkimKeyStatus.LookupFailed;
            check.Detail = r.Describe();
            return check;
        }
        if (r.IsEmpty)
        {
            check.Status = DkimKeyStatus.Missing;
            check.Detail = check.CnameTarget is not null
                ? $"CNAME points to {check.CnameTarget}, which has no key"
                : r.Status == DnsStatus.NxDomain ? "no such record (NXDOMAIN)" : "the name exists but has no TXT record";
            return check;
        }

        var txt = r.Texts().FirstOrDefault(t => t.Contains("p=", StringComparison.OrdinalIgnoreCase)) ?? r.Texts().First();
        check.Record = txt;
        var tags = HeaderBlock.ParseTags(txt);

        if (tags.TryGetValue("v", out var v) && !v.Equals("DKIM1", StringComparison.OrdinalIgnoreCase))
        {
            check.Status = DkimKeyStatus.NotDkim;
            check.Detail = $"TXT record found but v={v}";
            return check;
        }
        if (!tags.TryGetValue("p", out var p))
        {
            check.Status = DkimKeyStatus.NotDkim;
            check.Detail = "TXT record found but it has no p= key";
            return check;
        }
        if (tags.TryGetValue("k", out var k)) check.KeyType = k.ToLowerInvariant();
        if (tags.TryGetValue("t", out var t)) check.Testing = t.Split(':').Any(f => f.Trim().Equals("y", StringComparison.OrdinalIgnoreCase));

        p = new string(p.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (p.Length == 0)
        {
            check.Status = DkimKeyStatus.Revoked;
            check.Detail = "the key is empty (p=): the selector has been revoked";
            return check;
        }

        byte[] der;
        try
        {
            der = Convert.FromBase64String(p);
        }
        catch (FormatException)
        {
            check.Status = DkimKeyStatus.Invalid;
            check.Detail = "the p= value is not valid base64 (often a record split or pasted wrongly)";
            return check;
        }

        if (check.KeyType == "ed25519")
        {
            check.KeyBits = der.Length * 8;
            check.Status = der.Length == 32 ? DkimKeyStatus.Found : DkimKeyStatus.Invalid;
            check.Detail = der.Length == 32 ? "Ed25519 key" : $"Ed25519 key has {der.Length} bytes, expected 32";
            return check;
        }

        try
        {
            using var rsa = RSA.Create();
            try
            {
                rsa.ImportSubjectPublicKeyInfo(der, out _);
            }
            catch (CryptographicException)
            {
                rsa.ImportRSAPublicKey(der, out _);
            }
            check.KeyBits = rsa.KeySize;
            check.Status = DkimKeyStatus.Found;
            check.Detail = $"RSA {rsa.KeySize}-bit key" + (check.Testing ? ", test mode (t=y)" : "");
        }
        catch (CryptographicException)
        {
            check.Status = DkimKeyStatus.Invalid;
            check.Detail = "the key does not decode as an RSA public key (truncated or damaged record)";
        }
        return check;
    }
}

// ===================================================================== DMARC

public sealed class DmarcCheck
{
    public string FromDomain { get; init; } = "";
    public string QueriedDomain { get; set; } = "";
    public bool Found { get; set; }
    public bool FromOrgDomain { get; set; }
    public bool LookupFailed { get; set; }
    public string? Record { get; set; }
    public string? Problem { get; set; }
    public string Policy { get; set; } = "none";       // effective for the From domain
    public string? P { get; set; }
    public string? Sp { get; set; }
    public int Pct { get; set; } = 100;
    public string Adkim { get; set; } = "r";
    public string Aspf { get; set; } = "r";
    public string? Rua { get; set; }

    public bool Enforcing => Found && Problem is null && Policy is "reject" or "quarantine" && Pct > 0;
}

public static class DmarcChecker
{
    public static DmarcCheck Check(DnsClient dns, string fromDomain, CancellationToken cancel)
    {
        var d = DomainUtil.Normalize(fromDomain);
        var check = new DmarcCheck { FromDomain = d, QueriedDomain = d };

        if (!Lookup(dns, d, check, cancel) && !check.LookupFailed)
        {
            var org = DomainUtil.OrgDomain(d);
            if (!org.Equals(d, StringComparison.OrdinalIgnoreCase))
            {
                check.QueriedDomain = org;
                check.FromOrgDomain = Lookup(dns, org, check, cancel);
            }
        }

        if (check.Found && check.Problem is null)
        {
            check.Policy = (check.FromOrgDomain ? check.Sp ?? check.P : check.P) ?? "none";
        }
        return check;
    }

    private static bool Lookup(DnsClient dns, string domain, DmarcCheck check, CancellationToken cancel)
    {
        var r = dns.Query("_dmarc." + domain, DnsType.TXT, cancel);
        if (r.IsTransient)
        {
            check.LookupFailed = true;
            check.Problem = $"lookup of _dmarc.{domain} failed: {r.Describe()}";
            return false;
        }
        var records = r.Texts().Where(t => t.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)).ToList();
        if (records.Count == 0) return false;

        check.Found = true;
        check.Record = records[0];
        if (records.Count > 1)
        {
            check.Problem = $"{records.Count} DMARC records at _dmarc.{domain}; receivers ignore all of them";
            return true;
        }

        var tags = HeaderBlock.ParseTags(records[0]);
        check.P = tags.GetValueOrDefault("p")?.ToLowerInvariant();
        check.Sp = tags.GetValueOrDefault("sp")?.ToLowerInvariant();
        if (int.TryParse(tags.GetValueOrDefault("pct"), out var pct)) check.Pct = Math.Clamp(pct, 0, 100);
        check.Adkim = (tags.GetValueOrDefault("adkim") ?? "r").ToLowerInvariant();
        check.Aspf = (tags.GetValueOrDefault("aspf") ?? "r").ToLowerInvariant();
        check.Rua = tags.GetValueOrDefault("rua");

        if (check.P is null)
            check.Problem = "the record has no p= tag; receivers treat it as invalid";
        else if (check.P is not ("none" or "quarantine" or "reject"))
            check.Problem = $"p={check.P} is not a valid policy";
        return true;
    }
}

// ===================================================================== reverse DNS

public sealed class ReverseDnsCheck
{
    public IPAddress Ip { get; init; } = IPAddress.None;
    public List<string> Names { get; } = new();
    public bool LookupFailed { get; set; }
    public string? ConfirmedName { get; set; }
    public bool LooksGeneric { get; set; }
    public string Detail { get; set; } = "";
    public bool Ok => ConfirmedName is not null;
}

public static class ReverseDnsChecker
{
    private static readonly string[] GenericMarkers = { "dynamic", "dyn.", "dsl", "dial", "pool", "dhcp", "cable", "client", "customer", "broadband", "ppp", "static.", "unassigned", "host-" };

    public static ReverseDnsCheck Check(DnsClient dns, IPAddress ip, CancellationToken cancel)
    {
        var check = new ReverseDnsCheck { Ip = ip };
        var r = dns.Query(NetUtil.ReverseName(ip), DnsType.PTR, cancel);
        if (r.IsTransient)
        {
            check.LookupFailed = true;
            check.Detail = r.Describe();
            return check;
        }
        check.Names.AddRange(r.Targets(DnsType.PTR));
        if (check.Names.Count == 0)
        {
            check.Detail = "no PTR record";
            return check;
        }

        foreach (var name in check.Names)
        {
            if (dns.Addresses(name, cancel).Any(a => a.Equals(ip)))
            {
                check.ConfirmedName = name;
                break;
            }
        }

        var shown = check.ConfirmedName ?? check.Names[0];
        var b = ip.GetAddressBytes();
        var dashed = string.Join("-", b.Select(x => x.ToString()));
        var reversedDashed = string.Join("-", Enumerable.Reverse(b).Select(x => x.ToString()));
        check.LooksGeneric = GenericMarkers.Any(m => shown.Contains(m, StringComparison.OrdinalIgnoreCase))
                             || shown.Contains(dashed) || shown.Contains(reversedDashed);

        check.Detail = check.ConfirmedName is not null
            ? $"{check.ConfirmedName} (resolves back to {ip})"
            : $"PTR {string.Join(", ", check.Names)} does not resolve back to {ip}";
        if (check.LooksGeneric) check.Detail += "; the name looks like a generic access-network name";
        return check;
    }
}
