using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Dns;

namespace SsddMailAnalyser.Core.Diagnosis;

/// <summary>
/// How well the sender declares itself: the gaps that do not break SPF or DKIM outright but
/// make receiving filters distrust the mail. Plus which side each finding belongs to, and
/// what the technician's statement "the other side works normally" changes in the ranking.
/// </summary>
public static partial class Diagnoser
{
    private const int BonusAttested = 45;

    // ================================================================== sender setup

    private static void SenderSetup(AnalysisResult r, List<Finding> f)
    {
        var sender = r.Targets.SenderDomain;
        if (string.IsNullOrEmpty(sender)) return;
        var b = r.Baseline;
        string who = "Sender's domain admin";

        // ---- DKIM: the working mail carried no signature at all
        if (b.HasAnything && b.DkimSignatures.Count == 0)
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Sender setup",
                Title = $"Mail from {sender} is not DKIM-signed",
                Detail = "The working mail carried no DKIM signature. SPF alone breaks as soon as mail is forwarded, and many filters rate unsigned mail lower. " +
                         "With DMARC, a valid aligned DKIM signature is the leg that survives forwarding.",
                WhoFixes = who,
                NextStep = $"Enable DKIM signing for {sender} on the sending mail server or hosting panel and publish the key it generates.",
                Fix = $"<selector>._domainkey.{sender}.  TXT  \"v=DKIM1; k=rsa; p=<public key from the mail server>\"",
                Score = 10,
            });
        }

        // ---- SPF: how it ends, and how many addresses it authorises
        var health = r.EnvelopeSpf;
        if (health?.Record is { } record && health.Status == SpfVerdict.Pass)
        {
            var terms = record.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            double v4 = 0;
            foreach (var t in terms)
            {
                var term = t.TrimStart('+');
                if (!term.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) continue;
                var parts = term[4..].Split('/');
                int prefix = parts.Length > 1 && int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) ? p : 32;
                if (prefix is >= 0 and <= 32) v4 += Math.Pow(2, 32 - prefix);
            }
            if (v4 > 4096)
            {
                f.Add(new Finding
                {
                    Severity = Severity.Info,
                    Area = "Sender setup",
                    Title = $"The SPF record of {health.Domain} authorises {v4:N0} IPv4 addresses",
                    Detail = "Whole provider ranges are listed directly. Every customer of that provider can then send mail that passes SPF for this domain, " +
                             "so SPF alone proves little, and some filters weigh broad records down. Combined with a missing DMARC record this makes the domain easy to impersonate.",
                    WhoFixes = who,
                    NextStep = "Replace the broad ranges with the provider's include: (or the actual sending hosts) and add DMARC with DKIM.",
                });
            }
            if (health.AllTerm is "~all" && r.Dmarc is { Found: false })
            {
                f.Add(new Finding
                {
                    Severity = Severity.Info,
                    Area = "Sender setup",
                    Title = $"The SPF record of {health.Domain} ends in ~all and there is no DMARC",
                    Detail = "~all (softfail) asks receivers to accept unauthorised senders anyway. Without DMARC nothing tells them otherwise, " +
                             "so forged mail in the domain's name is accepted too - and receivers protect themselves by rating the whole domain down.",
                    WhoFixes = who,
                    NextStep = "Publish DMARC first; once the reports show all real mail passing, consider -all.",
                });
            }
        }

        // ---- the sending server: shared host, HELO, reverse DNS
        if (r.Ptr is { Ok: true, ConfirmedName: { } ptrName } && !DomainUtil.AlignedRelaxed(ptrName, sender))
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Sender setup",
                Title = $"Mail for {sender} leaves a shared server ({ptrName})",
                Detail = $"The sending IP {r.Ptr.Ip} belongs to {DomainUtil.OrgDomain(ptrName)}, not to {sender}. Its reputation is shared with every other customer on it; " +
                         "a neighbour sending spam lowers the rating of this sender's mail too. Not an error, but a reason why strict filters may treat it with suspicion.",
                WhoFixes = who,
                NextStep = "Make sure SPF, DKIM and DMARC are complete so the domain's own reputation counts; for business-critical mail consider a dedicated mail service.",
            });
        }
        var helo = b.SendingHelo;
        if (!string.IsNullOrEmpty(helo) && r.Ptr is { ConfirmedName: { } confirmed } && b.SendingIp is not null
            && r.Ptr.Ip.Equals(b.SendingIp) && !helo.Equals(confirmed, StringComparison.OrdinalIgnoreCase)
            && !NetUtil.TryParseIp(helo, out _))
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Sender setup",
                Title = $"The sending server greets as {helo}, but its reverse DNS says {confirmed}",
                Detail = "Many filters score a mismatch between the HELO name and the PTR record.",
                WhoFixes = "Sender's mail server admin (or hosting provider)",
                NextStep = $"Configure the server to greet with {confirmed}, or set the PTR to the HELO name.",
            });
        }
        else if (!string.IsNullOrEmpty(helo) && NetUtil.TryParseIp(helo.Trim('[', ']'), out _))
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Sender setup",
                Title = $"The sending server greets with a bare IP address ({helo})",
                Detail = "A HELO without a host name is a classic spam-bot signal; many filters reject or heavily penalise it.",
                WhoFixes = "Sender's mail server admin (or hosting provider)",
                NextStep = "Configure the server to greet with its fully qualified host name.",
            });
        }
    }

    // ================================================================== whose side

    private static FindingSide SideOf(AnalysisResult r, Finding x)
    {
        if (x.Area is "SMTP path" or "DNS path") return FindingSide.Analysis;
        var who = x.WhoFixes ?? "";
        if (who.StartsWith("Sender", StringComparison.OrdinalIgnoreCase) || who.StartsWith("The sender", StringComparison.OrdinalIgnoreCase)
            || who.StartsWith("Owner of the sending", StringComparison.OrdinalIgnoreCase))
            return FindingSide.Sender;
        if (who.StartsWith("Recipient", StringComparison.OrdinalIgnoreCase) || who.StartsWith("Owner of the receiving", StringComparison.OrdinalIgnoreCase))
            return FindingSide.Recipient;
        if (who.StartsWith("DNS admin at the recipient", StringComparison.OrdinalIgnoreCase)) return FindingSide.Recipient;
        if (who.StartsWith("DNS admin at the sender", StringComparison.OrdinalIgnoreCase)) return FindingSide.Sender;
        if (who.StartsWith("Firewall admin of the analysis", StringComparison.OrdinalIgnoreCase)) return FindingSide.Analysis;

        switch (x.Area)
        {
            case "SPF" or "DKIM" or "DMARC" or "Reverse DNS" or "Reputation" or "Sender setup" or "Failing mail" or "History" or "DNS timing":
                return FindingSide.Sender;
            case "Routing" or "TLS" or "SMTP":
                return FindingSide.Recipient;
            case "DNS" or "Name servers":
                var s = r.Targets.SenderDomain;
                var rc = r.Targets.ReceiverDomain;
                bool mentionsSender = s.Length > 0 && x.Title.Contains(s, StringComparison.OrdinalIgnoreCase);
                bool mentionsReceiver = rc.Length > 0 && x.Title.Contains(rc, StringComparison.OrdinalIgnoreCase);
                return mentionsSender && !mentionsReceiver ? FindingSide.Sender
                     : mentionsReceiver && !mentionsSender ? FindingSide.Recipient
                     : FindingSide.General;
            default:
                return FindingSide.General;
        }
    }

    // ================================================================== "the other side works"

    /// <summary>
    /// The technician states that the supported site's side handles other mail normally.
    /// Gaps on the external party's side then become the likely explanation, and rank above
    /// generic advice.
    /// </summary>
    private static void Attestation(AnalysisResult r, List<Finding> f)
    {
        if (!r.Input.OtherMailWorks) return;
        bool inbound = r.Input.Direction == Direction.Inbound;
        var external = inbound ? FindingSide.Sender : FindingSide.Recipient;
        string because = inbound
            ? "the recipient's side receives other mail normally"
            : "the sender's other mail reaches other recipients normally";

        foreach (var x in f.Where(x => x.Side == external && x.Severity is Severity.Critical or Severity.Warning))
        {
            x.Score += BonusAttested;
            x.Because.Add(because);
        }

        // Findings that would blame the supported side lose weight; they stay visible.
        var supported = inbound ? FindingSide.Recipient : FindingSide.Sender;
        foreach (var x in f.Where(x => x.Side == supported && x.Severity == Severity.Warning))
            x.Score -= 20;
    }
}
