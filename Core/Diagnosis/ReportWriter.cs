using System;
using System.Linq;
using System.Text;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

/// <summary>A plain-text report: readable in a ticket, a mail to the other side's admin, or a log.</summary>
public static class ReportWriter
{
    public static string Write(AnalysisResult r, string appName)
    {
        var sb = new StringBuilder();
        var t = r.Targets;
        bool inbound = r.Input.Direction == Direction.Inbound;

        sb.AppendLine($"{appName} - mail delivery diagnosis");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine($"Date:       {r.When:yyyy-MM-dd HH:mm}");
        if (r.Input.ReverseCheck)
            sb.AppendLine($"Case:       reverse-direction check, without evidence: mail from {Or(t.SenderDomain)} to {Or(t.ReceiverDomain)}");
        else
            sb.AppendLine($"Case:       mail from {Or(t.SenderDomain)} does not reach {Or(t.ReceiverDomain)} (analysed at the {(inbound ? "recipient" : "sender")}'s side)");
        sb.AppendLine($"Sender:     {Or(t.SenderDomain)} (envelope {Or(t.EnvelopeDomain)}, IP {Or(t.SendingIp)})");
        sb.AppendLine($"Receiver:   {Or(t.ReceiverDomain)}");
        sb.AppendLine($"Ran on:     {(r.Input.Location == AnalysisLocation.Isolated ? "an isolated analysis system (public DNS and the evidence only)" : $"inside the {(inbound ? "recipient" : "sender")}'s network (internal DNS, compared with the public view)")}");
        if (r.Input.OtherMailWorks)
            sb.AppendLine($"Stated:     {(inbound ? "the recipient's side receives other mail normally" : "the sender's other mail reaches other recipients normally")}");
        sb.AppendLine($"DNS:        {r.ResolverUsed}");
        foreach (var fb in r.Fallbacks) sb.AppendLine($"            {fb}");
        sb.AppendLine();

        if (r.Likely is { } likely)
        {
            sb.AppendLine("LIKELY CAUSE");
            sb.AppendLine(new string('-', 60));
            sb.AppendLine($"[{Word(likely.Severity)}] {likely.Title}");
            Wrap(sb, likely.Detail, "  ");
            if (likely.Because.Count > 0) sb.AppendLine("  Ranked first because: " + string.Join("; ", likely.Because));
            sb.AppendLine("  Who fixes it: " + likely.WhoFixes);
            Wrap(sb, "Next step: " + likely.NextStep, "  ");
            foreach (var e in likely.Evidence) sb.AppendLine("    " + e);
            sb.AppendLine();
        }

        // Requests per party: what to ask whom, since from an isolated system nobody can be fixed directly.
        var requests = r.Findings
            .Where(x => x.Severity is Severity.Critical or Severity.Warning or Severity.Inconclusive)
            .Where(x => x.WhoFixes is { Length: > 1 } && x.NextStep is { Length: > 1 })
            .GroupBy(x => x.WhoFixes)
            .ToList();
        if (requests.Count > 0)
        {
            sb.AppendLine("REQUESTS PER PARTY");
            sb.AppendLine(new string('-', 60));
            foreach (var g in requests)
            {
                sb.AppendLine(g.Key + ":");
                foreach (var x in g) Wrap(sb, $"- {x.NextStep}  ({x.Title})", "  ");
                sb.AppendLine();
            }
        }

        if (r.Compare.Count > 0)
        {
            bool withFailing = r.Compare.Any(c => c.Failing.Length > 0);
            sb.AppendLine(withFailing ? "WORKING MAIL / FAILING MAIL / NOW (live DNS)" : "THEN (working mail) VS NOW (live DNS)");
            sb.AppendLine(new string('-', 60));
            int w1 = Math.Min(34, r.Compare.Max(c => c.Check.Length));
            int w2 = Math.Min(36, r.Compare.Max(c => c.Then.Length));
            int w3 = Math.Min(36, r.Compare.Max(c => c.Failing.Length));
            foreach (var c in r.Compare)
            {
                var failingCell = (c.FailingChanged ? "*" : "") + c.Failing;
                var nowCell = (c.NowChanged ? "*" : "") + c.Now;
                sb.AppendLine(withFailing
                    ? $"{Pad(c.Check, w1)}  {Pad(c.Then, w2)}  {Pad(failingCell, w3)}  {nowCell}  [{Word(c.Verdict)}]"
                    : $"{Pad(c.Check, w1)}  {Pad(c.Then, w2)}  {nowCell}  [{Word(c.Verdict)}]");
                if (c.NowChanged) sb.AppendLine($"{new string(' ', w1 + 2)}  * {(c.ChangeHelps ? "changed, in favour of delivery" : "changed")}: {c.ChangeNote}");
            }
            if (r.Compare.Any(c => c.NowChanged || c.FailingChanged))
                sb.AppendLine("* = differs from the working mail");
            sb.AppendLine();
        }

        sb.AppendLine("ALL FINDINGS");
        sb.AppendLine(new string('-', 60));
        foreach (var f in r.Findings)
        {
            sb.AppendLine($"[{Word(f.Severity)}] {f.Area}: {f.Title}");
            Wrap(sb, f.Detail, "  ");
            if (f.WhoFixes is { Length: > 1 }) sb.AppendLine("  Who fixes it: " + f.WhoFixes);
            if (f.NextStep is { Length: > 1 }) Wrap(sb, "Next step: " + f.NextStep, "  ");
            if (f.Fix.Length > 0) sb.AppendLine("  Record: " + f.Fix);
            foreach (var e in f.Evidence) sb.AppendLine("    " + e);
            sb.AppendLine();
        }

        var records = new StringBuilder();
        if (r.EnvelopeSpf?.Record is { } spf) records.AppendLine($"SPF   {r.EnvelopeSpf.Domain}: {spf}");
        if (r.FromSpf?.Record is { } spf2) records.AppendLine($"SPF   {r.FromSpf.Domain}: {spf2}");
        foreach (var k in r.Dkim) records.AppendLine($"DKIM  {k.QueryName}: {k.Status} {k.Detail}");
        if (r.Dmarc is { } d) records.AppendLine($"DMARC _dmarc.{d.QueriedDomain}: {d.Record ?? "(none)"}");
        if (r.EnvelopeSpf is { Tree.Count: > 0 } health)
        {
            records.AppendLine("SPF tree:");
            foreach (var line in health.Tree) records.AppendLine("  " + line);
        }
        if (records.Length > 0)
        {
            sb.AppendLine("DNS RECORDS");
            sb.AppendLine(new string('-', 60));
            sb.Append(records);
            sb.AppendLine();
        }

        var atTime = Diagnoser.AtTheTimeLines(r);
        if (atTime.Count > 0)
        {
            sb.AppendLine("RECORDS AT THE TIME OF THE WORKING MAIL, CHANGES AND TTLS");
            sb.AppendLine(new string('-', 60));
            foreach (var (label, value) in atTime) sb.AppendLine($"{label}: {value}");
            sb.AppendLine();
        }

        MailSection(sb, "WORKING MAIL (from the headers)", r.Baseline);
        if (r.FailingEvidence is { } failing)
            MailSection(sb, r.FailingFromBounce ? "FAILING MAIL (returned in the bounce)" : "FAILING MAIL (from the headers)", failing);

        if (r.NameServers.Count > 0)
        {
            sb.AppendLine("AUTHORITATIVE NAME SERVERS");
            sb.AppendLine(new string('-', 60));
            foreach (var c in r.NameServers)
            {
                sb.AppendLine($"{c.Purpose}  {c.Name} {c.Type}  (zone {c.Zone})");
                foreach (var a in c.Answers) sb.AppendLine($"  {a.Server} ({a.Ip}): {a.Response.Fingerprint()}");
            }
            sb.AppendLine();
        }

        if (r.Split.Count > 0)
        {
            sb.AppendLine("INTERNAL DNS VS PUBLIC DNS");
            sb.AppendLine(new string('-', 60));
            foreach (var v in r.Split)
            {
                sb.AppendLine($"{v.Purpose}  {v.Name} {v.Type}{(v.Differs ? "   <- differs" : "")}");
                sb.AppendLine($"  internal: {v.Internal.Describe()}");
                sb.AppendLine($"  public:   {v.Public.Describe()}");
            }
            sb.AppendLine();
        }

        if (r.Ndr.HasAnything)
        {
            sb.AppendLine("BOUNCE");
            sb.AppendLine(new string('-', 60));
            foreach (var s in r.Ndr.Statuses) sb.AppendLine($"  {s.ReplyCode} {s.Code}  {s.Context}");
            if (r.Ndr.DiagnosticText is not null) sb.AppendLine("  Diagnostic: " + r.Ndr.DiagnosticText);
            sb.AppendLine();
        }

        foreach (var p in r.Probes)
        {
            sb.AppendLine($"SMTP PROBE {p.Host} ({p.Address})");
            sb.AppendLine(new string('-', 60));
            foreach (var line in p.Transcript) sb.AppendLine("  " + line);
            if (p.Error is not null) sb.AppendLine("  ! " + p.Error);
            sb.AppendLine();
        }

        sb.AppendLine("TECHNICAL TRACE (one line per action; full responses in the JSON export)");
        sb.AppendLine(new string('-', 60));
        foreach (var e in r.Trace)
            sb.AppendLine($"{e.Seq,4} {e.TimeText} {e.MsText,7} {e.Step,-10} {e.Kind,-6} {e.OutcomeText,-8} {e.Action}  =>  {e.Result}");
        return sb.ToString();
    }

    private static void MailSection(StringBuilder sb, string title, MailEvidence b)
    {
        if (!b.HasAnything) return;
        sb.AppendLine(title);
        sb.AppendLine(new string('-', 60));
        sb.AppendLine($"From:        {b.From}");
        sb.AppendLine($"Return-Path: {b.ReturnPath}");
        sb.AppendLine($"Date:        {b.Date:yyyy-MM-dd HH:mm zzz}");
        sb.AppendLine($"Subject:     {b.Subject}");
        sb.AppendLine($"Sending IP:  {b.SendingIp} ({b.SendingIpSource})");
        if (b.PrimaryAuth is not null) sb.AppendLine($"Auth:        {b.PrimaryAuth.Raw}");
        foreach (var s in b.DkimSignatures) sb.AppendLine($"DKIM sig:    d={s.Domain} s={s.Selector} a={s.Algorithm}");
        sb.AppendLine("Hops (newest first):");
        foreach (var h in b.Hops)
            sb.AppendLine($"  {h.Index + 1,2}. {h.Time:yyyy-MM-dd HH:mm:ss}  from {h.FromHelo} [{h.FromIp}]  by {h.ByHost}  {h.Tls}");
        sb.AppendLine();
    }

    public static string Word(Severity s) => s switch
    {
        Severity.Critical => "Problem",
        Severity.Warning => "Warning",
        Severity.Inconclusive => "Inconclusive",
        Severity.Info => "Info",
        _ => "OK",
    };

    private static string Or(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s;

    private static string Pad(string s, int w) => w <= 1 ? s : s.Length > w ? s[..(w - 1)] + "~" : s.PadRight(w);

    private static void Wrap(StringBuilder sb, string text, string indent, int width = 96)
    {
        foreach (var paragraph in text.Split('\n'))
        {
            var line = new StringBuilder();
            foreach (var word in paragraph.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Length + word.Length + 1 > width && line.Length > 0)
                {
                    sb.AppendLine(indent + line);
                    line.Clear();
                }
                if (line.Length > 0) line.Append(' ');
                line.Append(word);
            }
            if (line.Length > 0) sb.AppendLine(indent + line);
        }
    }
}
