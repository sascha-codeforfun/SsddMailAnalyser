using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core.Mail;

public sealed class NdrStatus
{
    public string Code { get; init; } = "";            // 5.7.26
    public string? ReplyCode { get; init; }            // 550
    public string Context { get; init; } = "";         // the line it was found on
    public NdrMeaning? Meaning { get; init; }
    public bool IsPermanent => Code.StartsWith('5');
}

public sealed class NdrInfo
{
    public string Text { get; init; } = "";
    public List<NdrStatus> Statuses { get; } = new();
    public List<string> Recipients { get; } = new();
    public List<string> RemoteHosts { get; } = new();
    public List<IPAddress> Ips { get; } = new();
    public string? ReportingMta { get; set; }
    public string? DiagnosticText { get; set; }
    public List<(NdrCategory Category, string Hint)> Hints { get; } = new();
    public MailEvidence? Embedded { get; set; }        // headers of the returned message
    public bool LooksLikeDelay { get; set; }

    public NdrStatus? Primary =>
        Statuses.Where(s => s.Code.StartsWith('5')).OrderByDescending(s => s.Meaning is not null).ThenByDescending(Specificity).FirstOrDefault()
        ?? Statuses.Where(s => s.Code.StartsWith('4')).OrderByDescending(s => s.Meaning is not null).ThenByDescending(Specificity).FirstOrDefault();

    // 5.7.26 says more than 5.7.1, which says more than 5.0.0.
    private static int Specificity(NdrStatus s)
    {
        var p = s.Code.Split('.');
        return p.Length == 3 && int.TryParse(p[2], out var n) ? (n > 1 ? 2 : n) + (p[1] != "0" ? 1 : 0) : 0;
    }

    public bool HasAnything => !string.IsNullOrWhiteSpace(Text);

    public NdrCategory Category
    {
        get
        {
            var p = Primary?.Meaning?.Category ?? NdrCategory.Unknown;
            // A generic 5.7.1 / 5.7.0 is better described by its text.
            if ((p is NdrCategory.Policy or NdrCategory.Unknown) && Hints.Count > 0) return Hints[0].Category;
            return p;
        }
    }
}

public static class NdrParser
{
    private static readonly Regex RxEnhanced = new(@"(?<![\d.])(?:(?<reply>[45]\d\d)[\s\-#]+)?#?(?<code>[245]\.\d{1,3}\.\d{1,3})(?![\d.]*\d)", RegexOptions.Compiled);
    private static readonly Regex RxField = new(@"^(?<name>[A-Za-z][A-Za-z0-9\-]*)\s*:\s*(?<value>.*)$", RegexOptions.Compiled | RegexOptions.Multiline);
    private static readonly Regex RxHostIp = new(@"([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})\s*[\[(]\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)\s*[\])]", RegexOptions.Compiled);

    // Header fields whose content must not count as bounce text: they quote spam scores and
    // authentication results of the bounce itself or of the returned message.
    private static readonly Regex RxNoise = new(@"^(X-[A-Za-z0-9\-]+|Received|Received-SPF|Authentication-Results|ARC-[A-Za-z\-]+|DKIM-Signature|Content-[A-Za-z\-]+|MIME-Version|Message-ID|References|In-Reply-To|Thread-[A-Za-z]+|Accept-Language|Content-Language)\s*:", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static NdrInfo Parse(string? input)
    {
        var flat = MimeText.Flatten(input);
        var text = flat.Text;
        var info = new NdrInfo { Text = text };
        if (string.IsNullOrWhiteSpace(text)) return info;

        var scan = RemoveNoise(text);

        // ---------------------------------------------------------------- status codes
        foreach (var line in scan.Split('\n'))
        {
            foreach (Match m in RxEnhanced.Matches(line))
            {
                var code = m.Groups["code"].Value;
                if (code.StartsWith('2')) continue;    // 2.x.x is success, e.g. other recipients
                if (info.Statuses.Any(s => s.Code == code)) continue;
                info.Statuses.Add(new NdrStatus
                {
                    Code = code,
                    ReplyCode = m.Groups["reply"].Success ? m.Groups["reply"].Value : null,
                    Context = Trim(line.Trim(), 300),
                    Meaning = NdrKnowledge.Lookup(code),
                });
            }
        }

        // ---------------------------------------------------------------- DSN fields
        foreach (Match m in RxField.Matches(scan))
        {
            var name = m.Groups["name"].Value.ToLowerInvariant();
            var value = m.Groups["value"].Value.Trim();
            switch (name)
            {
                case "final-recipient":
                case "original-recipient":
                    AddAddress(info, value);
                    break;
                case "remote-mta":
                    AddHost(info, value.Contains(';') ? value[(value.IndexOf(';') + 1)..] : value);
                    break;
                case "reporting-mta":
                    info.ReportingMta ??= (value.Contains(';') ? value[(value.IndexOf(';') + 1)..] : value).Trim();
                    break;
                case "diagnostic-code":
                    info.DiagnosticText ??= Trim(value, 400);
                    break;
                case "action":
                    if (value.Equals("delayed", StringComparison.OrdinalIgnoreCase)) info.LooksLikeDelay = true;
                    break;
            }
        }

        // ---------------------------------------------------------------- Exchange / Postfix prose
        foreach (var pattern in new[]
                 {
                     @"(?:Generating server|Generierender Server|Remote server|Remoteserver|Receiving server|Empfangender Server)\s*:\s*(\S+)",
                     @"host\s+(\S+)\s*\[[^\]]+\]\s+said",
                     @"Remote Server returned\s+'?([^']+)'?",
                 })
        {
            foreach (Match m in Regex.Matches(scan, pattern, RegexOptions.IgnoreCase))
            {
                var v = m.Groups[1].Value.Trim().TrimEnd('.', ',', ';');
                if (pattern.Contains("returned"))
                    info.DiagnosticText ??= Trim(v, 400);
                else
                    AddHost(info, v);
            }
        }

        // "host [ip]" pairs: only the address is kept; the host names in Exchange bounces are
        // mostly Microsoft's own internal servers.
        foreach (Match m in RxHostIp.Matches(scan))
        {
            if (NetUtil.TryParseIp(m.Groups[2].Value, out var ip) && NetUtil.IsPublic(ip) && !info.Ips.Contains(ip))
                info.Ips.Add(ip);
        }

        if (info.Recipients.Count == 0)
        {
            // Exchange prose: "Your message to x@y couldn't be delivered." / "Delivery has failed to these recipients"
            var m = Regex.Match(scan, @"(?:message to|Nachricht an|recipients? or groups?:|Empfänger(?:n| oder Gruppen)?:)\s*<?([^\s<>@]+@[^\s<>,;]+?)>?(?=[.,;]?(?:\s|$))", RegexOptions.IgnoreCase);
            if (m.Success) AddAddress(info, m.Groups[1].Value);
        }

        if (info.DiagnosticText is null && info.Primary is { } primary)
            info.DiagnosticText = primary.Context;

        // ---------------------------------------------------------------- keyword hints
        var lower = scan.ToLowerInvariant();
        foreach (var (keys, category, hint) in NdrKnowledge.Keywords)
        {
            if (keys.Any(k => lower.Contains(k)) && !info.Hints.Any(h => h.Hint == hint))
                info.Hints.Add((category, hint));
        }
        if (info.Statuses.Count > 0 && info.Statuses.All(s => s.Code.StartsWith('4'))) info.LooksLikeDelay = true;
        if (Regex.IsMatch(lower, @"delivery (has been )?delayed|not yet been delivered|verzögert|still trying"))
            info.LooksLikeDelay = true;

        // ---------------------------------------------------------------- returned message headers
        var embedded = flat.EmbeddedHeaders;
        if (embedded is null)
        {
            // Exchange prints "Original message headers:" in the bounce body.
            var start = Regex.Match(text, @"^(Received|Return-Path|DKIM-Signature|ARC-Seal|From)\s*:", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            int marker = text.IndexOf("Original message headers", StringComparison.OrdinalIgnoreCase);
            if (marker < 0) marker = text.IndexOf("Ursprüngliche Nachrichtenkopfzeilen", StringComparison.OrdinalIgnoreCase);
            if (marker >= 0)
            {
                var after = Regex.Match(text[marker..], @"^[A-Za-z][A-Za-z0-9\-]*\s*:", RegexOptions.Multiline);
                if (after.Success) embedded = text[(marker + after.Index)..];
            }
            else if (start.Success && start.Index > 0)
            {
                embedded = text[start.Index..];
            }
        }
        if (embedded is not null)
        {
            var ev = HeaderAnalyzer.Analyze(embedded);
            if (ev.HasAnything) info.Embedded = ev;
        }

        return info;
    }

    private const int MaxLine = 1000;

    private static string RemoveNoise(string text)
    {
        var sb = new StringBuilder();
        bool skipping = false;
        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (skipping && raw.Length > 0 && (raw[0] == ' ' || raw[0] == '\t')) continue;
            skipping = RxNoise.IsMatch(raw);
            if (skipping) continue;
            // No line of a bounce is longer than a mail line may be (998). Anything beyond is a
            // pasted blob, and unbroken runs of that size make the patterns below crawl.
            if (raw.Length > MaxLine) sb.Append(raw, 0, MaxLine).Append('\n');
            else sb.Append(raw).Append('\n');
        }
        return sb.ToString();
    }

    private static void AddAddress(NdrInfo info, string value)
    {
        var v = value.Contains(';') ? value[(value.IndexOf(';') + 1)..] : value;
        var a = HeaderBlock.ExtractAddress(v) ?? v.Trim().Trim('<', '>');
        if (a.Contains('@') && !info.Recipients.Contains(a, StringComparer.OrdinalIgnoreCase)) info.Recipients.Add(a);
    }

    private static void AddHost(NdrInfo info, string value)
    {
        var v = value.Trim().Trim('[', ']', '(', ')', '\'', '"').TrimEnd('.');
        if (NetUtil.TryParseIp(v, out var ip))
        {
            if (NetUtil.IsPublic(ip) && !info.Ips.Contains(ip)) info.Ips.Add(ip);
            return;
        }
        if (!DomainUtil.LooksLikeDomain(v)) return;
        v = v.ToLowerInvariant();
        if (!info.RemoteHosts.Contains(v)) info.RemoteHosts.Add(v);
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}
