using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

/// <summary>
/// A single, self-contained HTML file: the report a third party can open in any browser,
/// with the full technical trace folded away underneath. No scripts, no external files.
/// Colours are the suite's (dark on screen); printing switches to black on white.
/// </summary>
public static class HtmlReport
{
    public static string Write(AnalysisResult r, string appName, string appVersion, byte[]? iconPng, bool includeEvidence)
    {
        var t = r.Targets;
        bool inbound = r.Input.Direction == Direction.Inbound;
        var sb = new StringBuilder();

        sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.Append("<title>").Append(H($"{appName}: {Or(t.SenderDomain)} to {Or(t.ReceiverDomain)}, {r.When:yyyy-MM-dd HH:mm}")).Append("</title>\n");
        sb.Append("<style>\n").Append(Css).Append("</style>\n</head>\n<body>\n");

        // ---------------------------------------------------------------- header
        sb.Append("<header class=\"head\">");
        if (iconPng is { Length: > 0 })
            sb.Append("<img class=\"icon\" alt=\"\" src=\"data:image/png;base64,").Append(Convert.ToBase64String(iconPng)).Append("\">");
        sb.Append("<div><h1>").Append(H(appName)).Append("</h1>");
        sb.Append("<p class=\"sub\"><b>S</b>uspicious <b>S</b>PF, <b>D</b>KIM, <b>D</b>MARC &middot; mail delivery diagnosis</p></div>");
        sb.Append("<div class=\"meta\">").Append(H($"version {appVersion}")).Append("<br>").Append(H($"{r.When:yyyy-MM-dd HH:mm}")).Append("</div>");
        sb.Append("</header>\n<main>\n");

        // ---------------------------------------------------------------- case
        sb.Append("<section><h2>Case</h2><table class=\"kv\">");
        Kv(sb, "Mail", $"from {Or(t.SenderDomain)} to {Or(t.ReceiverDomain)}");
        Kv(sb, "Direction", (inbound ? "incoming (analysed at the recipient's side)" : "outgoing (analysed at the sender's side)")
                            + (r.Input.ReverseCheck ? "; reverse-direction check, without evidence" : ""));
        Kv(sb, "Sender", $"{Or(t.SenderDomain)} (envelope {Or(t.EnvelopeDomain)}, sending IP {Or(t.SendingIp)})");
        Kv(sb, "Recipient", Or(t.ReceiverDomain));
        Kv(sb, "Analysed on", r.Input.Location == AnalysisLocation.Isolated
            ? "an isolated analysis system: public DNS and the evidence supplied"
            : $"inside the {(inbound ? "recipient" : "sender")}'s network: internal DNS, compared with the public view");
        if (r.Input.OtherMailWorks)
            Kv(sb, "Stated by the technician", inbound ? "the recipient's side receives other mail normally" : "the sender's other mail reaches other recipients normally");
        Kv(sb, "DNS", r.ResolverUsed + (r.Fallbacks.Count > 0 ? " (fallback: " + string.Join(" ", r.Fallbacks) + ")" : ""));
        sb.Append("</table></section>\n");

        // ---------------------------------------------------------------- likely cause
        if (r.Likely is { } likely)
        {
            sb.Append("<section><h2>Likely cause</h2>");
            sb.Append("<div class=\"callout ").Append(Cls(likely.Severity)).Append("\">");
            sb.Append("<div class=\"ctitle\">").Append(Pill(likely.Severity)).Append(' ').Append(H(likely.Title)).Append("</div>");
            sb.Append("<p>").Append(H(likely.Detail)).Append("</p>");
            if (likely.Because.Count > 0) sb.Append("<p class=\"muted\">Ranked first because: ").Append(H(string.Join("; ", likely.Because))).Append(".</p>");
            sb.Append("<div class=\"two\"><div><div class=\"label\">Who fixes it</div>").Append(H(likely.WhoFixes)).Append("</div>");
            sb.Append("<div><div class=\"label\">Next step</div>").Append(H(likely.NextStep)).Append("</div></div>");
            if (likely.Fix.Length > 0) sb.Append("<div class=\"label\" style=\"margin-top:10px\">Record to publish</div><pre>").Append(H(likely.Fix)).Append("</pre>");
            if (likely.Evidence.Count > 0) sb.Append("<pre>").Append(H(string.Join("\n", likely.Evidence))).Append("</pre>");
            sb.Append("</div></section>\n");
        }

        // ---------------------------------------------------------------- requests per party
        var requests = r.Findings
            .Where(x => x.Severity is Severity.Critical or Severity.Warning or Severity.Inconclusive)
            .Where(x => x.WhoFixes is { Length: > 1 } && x.NextStep is { Length: > 1 })
            .GroupBy(x => x.WhoFixes).ToList();
        if (requests.Count > 0)
        {
            sb.Append("<section><h2>Requests per party</h2>");
            foreach (var g in requests)
            {
                sb.Append("<h3>").Append(H(g.Key)).Append("</h3><ul>");
                foreach (var x in g)
                    sb.Append("<li>").Append(H(x.NextStep)).Append(" <span class=\"muted\">(").Append(H(x.Title)).Append(")</span></li>");
                sb.Append("</ul>");
            }
            sb.Append("</section>\n");
        }

        // ---------------------------------------------------------------- comparison
        if (r.Compare.Count > 0)
        {
            bool withFailing = r.Compare.Any(c => c.Failing.Length > 0);
            sb.Append("<section><h2>Working mail, failing mail and now</h2>");
            sb.Append("<p class=\"muted\">Working and failing mail: what the receiving server recorded in their headers. Now: the same check against today's DNS. ");
            sb.Append("<span class=\"chg-inline\">Amber</span> cells differ from the working mail in a way that can hurt delivery; <span class=\"chg-inline good\">teal</span> cells changed in favour of delivery. The difference is written underneath.</p>");
            sb.Append("<table class=\"grid\"><thead><tr><th>Check</th><th>Working mail</th>");
            if (withFailing) sb.Append("<th>").Append(r.FailingFromBounce ? "Returned in bounce" : "Failing mail").Append("</th>");
            sb.Append("<th>Now (live DNS)</th><th>Verdict</th></tr></thead><tbody>");
            foreach (var c in r.Compare)
            {
                sb.Append("<tr><td class=\"b\">").Append(H(c.Check)).Append("</td><td class=\"mono\">").Append(H(c.Then)).Append("</td>");
                if (withFailing) Cell(sb, c.Failing, c.FailingChanged ? "differs from the working mail" : null);
                Cell(sb, c.Now, c.NowChanged ? (c.ChangeHelps ? "changed, in favour of delivery: " : "changed: ") + c.ChangeNote : null, c.ChangeHelps);
                sb.Append("<td>").Append(Pill(c.Verdict)).Append("</td></tr>");
            }
            sb.Append("</tbody></table></section>\n");
        }

        // ---------------------------------------------------------------- findings
        sb.Append("<section><h2>All findings</h2>");
        int rank = 1;
        foreach (var f in r.Findings)
        {
            sb.Append("<div class=\"finding ").Append(Cls(f.Severity)).Append("\">");
            sb.Append("<div class=\"ftitle\"><span class=\"rank\">").Append(rank++).Append("</span>").Append(Pill(f.Severity))
              .Append(" <span class=\"tag\">").Append(H(f.Area)).Append("</span> <b>").Append(H(f.Title)).Append("</b></div>");
            sb.Append("<p>").Append(H(f.Detail)).Append("</p>");
            if (f.Severity is Severity.Critical or Severity.Warning or Severity.Inconclusive)
                sb.Append("<p class=\"muted\">Who fixes it: ").Append(H(f.WhoFixes)).Append(" &middot; Next: ").Append(H(f.NextStep)).Append("</p>");
            if (f.Fix.Length > 0) sb.Append("<pre>").Append(H(f.Fix)).Append("</pre>");
            if (f.Evidence.Count > 0)
                sb.Append("<details").Append(f.Severity == Severity.Critical ? " open" : "").Append("><summary>Evidence (").Append(f.Evidence.Count)
                  .Append(")</summary><pre>").Append(H(string.Join("\n", f.Evidence))).Append("</pre></details>");
            if (f.TraceSteps.Count > 0)
            {
                var steps = new HashSet<string>(f.TraceSteps);
                var entries = r.Trace.Where(e => steps.Contains(e.Step)).ToList();
                if (entries.Count > 0)
                {
                    sb.Append("<details><summary>Trace for this finding (").Append(entries.Count).Append(" entries)</summary>");
                    TraceTable(sb, entries);
                    sb.Append("</details>");
                }
            }
            sb.Append("</div>");
        }
        sb.Append("</section>\n");

        // ---------------------------------------------------------------- records
        var records = new List<(string, string)>();
        if (r.EnvelopeSpf?.Record is { } spf) records.Add(($"SPF {r.EnvelopeSpf.Domain}", spf));
        if (r.FromSpf?.Record is { } spf2) records.Add(($"SPF {r.FromSpf.Domain}", spf2));
        foreach (var k in r.Dkim) records.Add(($"DKIM {k.QueryName}", $"{k.Status}: {k.Detail}" + (k.Record is null ? "" : "\n" + k.Record)));
        if (r.Dmarc is { } d) records.Add(($"DMARC _dmarc.{d.QueriedDomain}", d.Record ?? "(none)"));
        if (r.EnvelopeSpf is { Tree.Count: > 0 } health) records.Add(("SPF tree", string.Join("\n", health.Tree)));
        if (records.Count > 0)
        {
            sb.Append("<section><h2>DNS records</h2><table class=\"kv\">");
            foreach (var (k, v) in records) sb.Append("<tr><th>").Append(H(k)).Append("</th><td><pre>").Append(H(v)).Append("</pre></td></tr>");
            sb.Append("</table></section>\n");
        }

        var atTime = Diagnoser.AtTheTimeLines(r);
        if (atTime.Count > 0)
        {
            sb.Append("<section><h2>Records at the time of the working mail</h2><table class=\"kv\">");
            foreach (var (k, v) in atTime) sb.Append("<tr><th>").Append(H(k)).Append("</th><td>").Append(H(v)).Append("</td></tr>");
            sb.Append("</table></section>\n");
        }

        // ---------------------------------------------------------------- evidence as read
        sb.Append("<section><h2>Evidence as read</h2>");
        MailBlock(sb, "Working mail", r.Baseline, includeEvidence);
        if (r.FailingEvidence is { } fe) MailBlock(sb, r.FailingFromBounce ? "Failing mail (returned in the bounce)" : "Failing mail", fe, includeEvidence);
        if (r.Ndr.HasAnything)
        {
            sb.Append("<h3>Bounce</h3><table class=\"kv\">");
            foreach (var st in r.Ndr.Statuses) Kv(sb, $"{st.ReplyCode} {st.Code}".Trim(), $"{st.Meaning?.Title ?? "not in the built-in list"} - {st.Context}");
            if (r.Ndr.DiagnosticText is not null) Kv(sb, "Diagnostic", r.Ndr.DiagnosticText);
            if (includeEvidence && r.Ndr.Recipients.Count > 0) Kv(sb, "Recipients", string.Join(", ", r.Ndr.Recipients));
            if (r.Ndr.RemoteHosts.Count > 0) Kv(sb, "Remote hosts", string.Join(", ", r.Ndr.RemoteHosts));
            sb.Append("</table>");
        }
        if (includeEvidence)
        {
            void Raw(string title, string text)
            {
                if (string.IsNullOrWhiteSpace(text)) return;
                sb.Append("<details><summary>").Append(H(title)).Append(" (as supplied)</summary><pre>").Append(H(text)).Append("</pre></details>");
            }
            Raw("Working mail headers", r.Input.BaselineText);
            Raw("Failing mail headers", r.Input.FailingText);
            Raw("Bounce", r.Input.NdrText);
        }
        sb.Append("</section>\n");

        // ---------------------------------------------------------------- trace
        sb.Append("<section><h2>Technical trace</h2><p class=\"muted\">")
          .Append(r.Trace.Count).Append(" actions in order. Open an entry for the request and the full response.</p>");
        TraceTable(sb, r.Trace);
        sb.Append("</section>\n");

        sb.Append("</main>\n<footer>").Append(H($"{appName} {appVersion} · generated {DateTime.Now:yyyy-MM-dd HH:mm}")).Append("</footer>\n</body>\n</html>\n");
        return sb.ToString();
    }

    // ================================================================== for the sender

    /// <summary>
    /// The version to hand to the sender: only what concerns the sending side, each point with
    /// what to change. No internal details of the recipient (internal hops, gateway names,
    /// port-25 tests of the analysis system, subjects).
    /// </summary>
    public static string WriteForSender(AnalysisResult r, string appName, string appVersion, byte[]? iconPng)
    {
        var t = r.Targets;
        var sender = Or(t.SenderDomain);
        var recipient = Or(t.ReceiverDomain);
        var mine = r.Findings.Where(x => x.Side == FindingSide.Sender).ToList();
        var sb = new StringBuilder();
        // Inside the site's network through its own resolver: the answers are the site's view, not the public one.
        bool siteView = r.Input.Location == AnalysisLocation.Internal && r.Options.Resolver.Kind == ResolverKind.Server;

        sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.Append("<title>").Append(H($"Mail from {sender} to {recipient}: findings on the sending side")).Append("</title>\n");
        sb.Append("<style>\n").Append(Css).Append("</style>\n</head>\n<body>\n");

        sb.Append("<header class=\"head\">");
        if (iconPng is { Length: > 0 })
            sb.Append("<img class=\"icon\" alt=\"\" src=\"data:image/png;base64,").Append(Convert.ToBase64String(iconPng)).Append("\">");
        sb.Append("<div><h1>").Append(H($"Mail from {sender} to {recipient}")).Append("</h1>");
        sb.Append("<p class=\"sub\">Findings on the sending side &middot; analysed with ").Append(H(appName))
          .Append(" (<b>S</b>uspicious <b>S</b>PF, <b>D</b>KIM, <b>D</b>MARC)</p></div>");
        sb.Append("<div class=\"meta\">").Append(H($"{r.When:yyyy-MM-dd HH:mm}")).Append("</div>");
        sb.Append("</header>\n<main>\n");

        // ---- what this is
        sb.Append("<section><h2>About this report</h2><p>");
        sb.Append(H($"Mail from {sender} to {recipient} is not arriving as expected. It was analysed using the headers of an earlier mail from {sender} that was delivered successfully, and the DNS records of both domains as they are today" + (siteView ? ", as seen from the recipient's site." : ".")));
        if (r.Input.OtherMailWorks && r.Input.Direction == Direction.Inbound)
            sb.Append(' ').Append(H($"The receiving side ({recipient}) handles its other incoming mail normally."));
        sb.Append("</p><p>").Append(H($"The points below concern the setup of {sender}. Each can be checked and corrected by whoever manages the DNS and the mail server of {sender} (often the hosting provider). Receiving filters judge a sender by these declarations; gaps make mail end up in junk or quarantine, often without any bounce."))
          .Append("</p></section>\n");

        // ---- most likely cause, when it is on the sending side
        var likely = r.Likely is { Side: FindingSide.Sender } l && l.Severity is Severity.Critical or Severity.Warning ? l : null;
        if (likely is not null)
        {
            sb.Append("<section><h2>Most likely cause</h2><div class=\"callout ").Append(Cls(likely.Severity)).Append("\">");
            sb.Append("<div class=\"ctitle\">").Append(Pill(likely.Severity)).Append(' ').Append(H(likely.Title)).Append("</div>");
            sb.Append("<p>").Append(H(likely.Detail)).Append("</p>");
            sb.Append("<div class=\"label\">What to do</div><p>").Append(H(likely.NextStep)).Append("</p>");
            if (likely.Fix.Length > 0) sb.Append("<div class=\"label\">Record to publish</div><pre>").Append(H(likely.Fix)).Append("</pre>");
            sb.Append("</div></section>\n");
        }

        // ---- to fix / worth improving / in order
        void Points(string title, IEnumerable<Finding> items, bool detailed)
        {
            var list = items.Where(x => x != likely).ToList();
            if (list.Count == 0) return;
            sb.Append("<section><h2>").Append(H(title)).Append("</h2>");
            foreach (var x in list)
            {
                sb.Append("<div class=\"finding ").Append(Cls(x.Severity)).Append("\"><div class=\"ftitle\">").Append(Pill(x.Severity))
                  .Append(" <b>").Append(H(x.Title)).Append("</b></div>");
                if (detailed)
                {
                    sb.Append("<p>").Append(H(x.Detail)).Append("</p>");
                    if (x.NextStep is { Length: > 1 }) sb.Append("<p><span class=\"label\">What to do</span><br>").Append(H(x.NextStep)).Append("</p>");
                    if (x.Fix.Length > 0) sb.Append("<pre>").Append(H(x.Fix)).Append("</pre>");
                    if (x.Evidence.Count > 0)
                        sb.Append("<details><summary>Details (").Append(x.Evidence.Count).Append(")</summary><pre>").Append(H(string.Join("\n", x.Evidence))).Append("</pre></details>");
                }
                sb.Append("</div>");
            }
            sb.Append("</section>\n");
        }
        Points("To fix", mine.Where(x => x.Severity is Severity.Critical or Severity.Warning), detailed: true);
        Points("Worth improving", mine.Where(x => x.Severity is Severity.Info or Severity.Inconclusive && x.NextStep is { Length: > 1 }), detailed: true);
        Points("Checked and in order", mine.Where(x => x.Severity == Severity.Ok), detailed: false);

        // ---- the sender's public DNS
        sb.Append("<section><h2>").Append(H(siteView ? $"DNS of {sender} as seen from the recipient's site on {r.When:yyyy-MM-dd}" : $"Public DNS of {sender} as seen on {r.When:yyyy-MM-dd}")).Append("</h2><table class=\"kv\">");
        if (r.EnvelopeSpf is { } spf) Kv(sb, $"SPF ({spf.Domain})", spf.Record ?? "(no SPF record)");
        if (r.FromSpf is { } spf2) Kv(sb, $"SPF ({spf2.Domain})", spf2.Record ?? "(no SPF record)");
        if (r.Dmarc is { } d) Kv(sb, $"DMARC (_dmarc.{d.QueriedDomain})", d.Record ?? "(no DMARC record)");
        foreach (var k in r.Dkim) Kv(sb, $"DKIM ({k.QueryName})", $"{k.Status}: {k.Detail}");
        if (r.SenderMx is { } mx) Kv(sb, $"MX ({mx.Domain})", mx.Detail);
        if (r.Ptr is { } ptr) Kv(sb, $"Reverse DNS of {ptr.Ip}", ptr.Detail);
        var listed = r.Blocklists.Where(x => x.Status == ListingStatus.Listed).ToList();
        if (r.Blocklists.Count > 0)
        {
            var clean = r.Blocklists.Where(x => x.Status == ListingStatus.NotListed).Select(x => x.Name).Distinct().ToList();
            if (clean.Count > 0) Kv(sb, "Not listed on", string.Join(", ", clean));
            foreach (var x in listed)
                Kv(sb, $"Listed: {x.Name}", $"{x.Subject} ({x.Role}) - {x.Detail}. {x.About} Removal / lookup: {x.DelistUrl}");
        }
        foreach (var (k, v) in Diagnoser.AtTheTimeLines(r)) Kv(sb, k, v);
        sb.Append("</table></section>\n");

        // ---- how the earlier mail arrived (sending side only)
        var b = r.Baseline;
        if (b.HasAnything)
        {
            sb.Append("<section><h2>How the earlier, delivered mail left the sender</h2><table class=\"kv\">");
            Kv(sb, "From", b.From);
            Kv(sb, "Envelope sender (Return-Path)", b.ReturnPath);
            Kv(sb, "Date", b.Date?.ToString("yyyy-MM-dd HH:mm zzz", CultureInfo.InvariantCulture));
            Kv(sb, "Sending server", b.SendingIp is null ? null : $"{b.SendingIp}" + (b.SendingHost is null ? "" : $" ({b.SendingHost})") + (b.SendingHelo is null ? "" : $", greeted as {b.SendingHelo}"));
            foreach (var sig in b.DkimSignatures) Kv(sb, "DKIM signature", $"d={sig.Domain} s={sig.Selector} a={sig.Algorithm}");
            if (b.DkimSignatures.Count == 0) Kv(sb, "DKIM signature", "none");
            Kv(sb, "Verdict of the receiving server", $"spf={b.SpfResult ?? "not reported"}, dkim={(b.DkimResults.Count > 0 ? string.Join("/", b.DkimResults.Select(x => x.Result)) : "not reported")}, dmarc={b.DmarcResult ?? "not reported"}");
            sb.Append("</table>");

            // Only the hops on the sender's side: up to and including the one that handed over to the recipient.
            var entry = b.SendingIp is null ? null : b.Hops.FirstOrDefault(h => h.FromIp is not null && h.FromIp.Equals(b.SendingIp));
            var senderHops = entry is null ? new List<SsddMailAnalyser.Core.Mail.ReceivedHop>() : b.Hops.Where(h => h.Index > entry.Index).ToList();
            if (entry is not null)
            {
                sb.Append("<table class=\"grid\"><thead><tr><th>Time</th><th>From</th><th>To</th><th>TLS</th></tr></thead><tbody>");
                foreach (var h in senderHops.Append(entry).OrderByDescending(h => h.Index))
                {
                    var to = h == entry ? "the recipient's mail server" : h.ByHost;
                    sb.Append("<tr><td class=\"mono\">").Append(H(h.Time?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)))
                      .Append("</td><td class=\"mono\">").Append(H($"{h.FromHelo} ({h.FromHost} [{h.FromIp}])"))
                      .Append("</td><td class=\"mono\">").Append(H(to)).Append("</td><td class=\"mono\">").Append(H(h.Tls)).Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
            }
            sb.Append("</section>\n");
        }

        // ---- the DNS queries behind it
        var steps = new HashSet<string> { "SPF", "DKIM", "DMARC", "Sender DNS", "PTR", "Blocklists" };
        var entries = r.Trace.Where(e => steps.Contains(e.Step) && e.Kind is not "Note").ToList();
        if (entries.Count > 0)
        {
            sb.Append("<section><h2>The DNS queries behind these findings</h2><p class=\"muted\">Asked directly of the authoritative name servers or the resolver named in each line. Open an entry for the full answer.</p>");
            TraceTable(sb, entries);
            sb.Append("</section>\n");
        }

        sb.Append("</main>\n<footer>").Append(H($"{appName} {appVersion} · generated {DateTime.Now:yyyy-MM-dd HH:mm}")).Append("</footer>\n</body>\n</html>\n");

        // The report leaves the site: its DNS servers and any non-public address are replaced, wherever they appear.
        return Scrub(sb.ToString(), SiteResolvers(r, siteView));
    }

    // ================================================================== keeping the site's internals out of the sender's report

    private const string SiteDnsLabel = "[analysing site's DNS server]";
    private const string InternalLabel = "[internal address]";

    // IPv4 and IPv6 literals as whole tokens (an IPv6 zone suffix such as %12 included). Not inside
    // longer dotted names such as reversed-IP query names, and not after "ip4:" / "ip6:" in SPF text.
    private static readonly Regex SiteAddress = new(@"(?<![\w.:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,8}(?:%\w+)?)(?![\w:]|\.\w)", RegexOptions.Compiled);

    /// <summary>The resolver the analysis used, if it belongs to the site, and this machine's own DNS servers.</summary>
    private static HashSet<IPAddress> SiteResolvers(AnalysisResult r, bool siteView)
    {
        var set = new HashSet<IPAddress>();
        if (r.Options.Resolver.Server is { } chosen && (siteView || !NetUtil.IsPublic(chosen))) set.Add(Plain(chosen));
        foreach (var (address, _) in NetUtil.SystemResolvers()) set.Add(Plain(address));
        return set;
    }

    /// <summary>The address without an IPv6 zone, so that fe80::1%12 and fe80::1 compare equal.</summary>
    private static IPAddress Plain(IPAddress ip) => new(ip.GetAddressBytes());

    /// <summary>The site's DNS servers and every non-public address replaced by a placeholder.</summary>
    private static string Scrub(string text, HashSet<IPAddress> site) => SiteAddress.Replace(text, m =>
    {
        var literal = m.Value;
        int zone = literal.IndexOf('%');
        if (zone >= 0) literal = literal[..zone];
        if (!IPAddress.TryParse(literal, out var ip)) return m.Value;
        var plain = Plain(ip);
        if (site.Contains(plain)) return SiteDnsLabel;
        return NetUtil.IsPublic(plain) ? m.Value : InternalLabel;
    });

    // ================================================================== pieces

    private static void TraceTable(StringBuilder sb, IEnumerable<TraceEntry> entries)
    {
        sb.Append("<table class=\"grid trace\"><thead><tr><th>#</th><th>Time</th><th>ms</th><th>Step</th><th>Kind</th><th>Outcome</th><th>Action and result</th></tr></thead><tbody>");
        foreach (var e in entries)
        {
            var cls = e.Outcome switch { TraceOutcome.Ok => "ok", TraceOutcome.Warn => "warn", TraceOutcome.Fail => "err", _ => "info" };
            sb.Append("<tr><td>").Append(e.Seq).Append("</td><td class=\"mono\">").Append(H(e.TimeText)).Append("</td><td class=\"mono r\">").Append(H(e.MsText))
              .Append("</td><td>").Append(H(e.Step)).Append("</td><td>").Append(H(e.Kind))
              .Append("</td><td><span class=\"dot ").Append(cls).Append("\"></span>").Append(H(e.OutcomeText)).Append("</td><td>");
            if (e.Details.Length > 0)
                sb.Append("<details><summary><span class=\"mono\">").Append(H(e.Action)).Append("</span><br>").Append(H(e.Result))
                  .Append("</summary><pre>").Append(H(e.Details)).Append("</pre></details>");
            else
                sb.Append("<span class=\"mono\">").Append(H(e.Action)).Append("</span><br>").Append(H(e.Result));
            sb.Append("</td></tr>");
        }
        sb.Append("</tbody></table>");
    }

    /// <summary>With the evidence left out, the subject is left out too: it is content, not a finding.</summary>
    private static void MailBlock(StringBuilder sb, string title, MailEvidence m, bool includeEvidence)
    {
        if (!m.HasAnything) return;
        sb.Append("<h3>").Append(H(title)).Append("</h3><table class=\"kv\">");
        Kv(sb, "From", m.From);
        Kv(sb, "Return-Path", m.ReturnPath);
        Kv(sb, "Date", m.Date?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
        if (includeEvidence) Kv(sb, "Subject", m.Subject);
        Kv(sb, "Sending IP", m.SendingIp is null ? null : $"{m.SendingIp} ({m.SendingIpSource})");
        Kv(sb, "Sending host", m.SendingHost is null && m.SendingHelo is null ? null : $"{m.SendingHost} (HELO {m.SendingHelo})");
        Kv(sb, "Result", $"spf={m.SpfResult ?? "-"}, dkim={(m.DkimResults.Count > 0 ? string.Join("/", m.DkimResults.Select(x => x.Result)) : "-")}, dmarc={m.DmarcResult ?? "-"}" +
                         (m.CompAuth is null ? "" : $", compauth={m.CompAuth}") + $"; DMARC carried by: {m.DmarcCarriedBy}");
        Kv(sb, "Authentication-Results used", m.PrimaryAuth?.Raw);
        foreach (var s in m.DkimSignatures) Kv(sb, "DKIM-Signature", $"d={s.Domain} s={s.Selector} a={s.Algorithm}");
        if (m.Scl is not null || m.SpamScore is not null) Kv(sb, "Spam rating", $"SCL {m.Scl} BCL {m.Bcl} {m.SpamVerdict} {m.SpamScore}");
        sb.Append("</table>");
        if (m.Hops.Count > 0)
        {
            sb.Append("<details><summary>Received hops (").Append(m.Hops.Count).Append(", newest first)</summary><table class=\"grid\"><thead><tr><th>#</th><th>Time</th><th>Delay</th><th>From</th><th>By</th><th>TLS</th></tr></thead><tbody>");
            foreach (var h in m.Hops)
                sb.Append("<tr><td>").Append(h.Index + 1).Append("</td><td class=\"mono\">").Append(H(h.Time?.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)))
                  .Append("</td><td class=\"mono\">").Append(H(h.DelayBefore?.ToString(@"hh\:mm\:ss")))
                  .Append("</td><td class=\"mono\">").Append(H($"{h.FromHelo} ({h.FromHost} [{h.FromIp}])"))
                  .Append("</td><td class=\"mono\">").Append(H(h.ByHost)).Append("</td><td class=\"mono\">").Append(H(h.Tls)).Append("</td></tr>");
            sb.Append("</tbody></table></details>");
        }
    }

    private static void Cell(StringBuilder sb, string text, string? change, bool helps = false)
    {
        if (change is null)
        {
            sb.Append("<td class=\"mono\">").Append(H(text)).Append("</td>");
            return;
        }
        sb.Append(helps ? "<td class=\"mono chg good\">" : "<td class=\"mono chg\">").Append(H(text)).Append("<div class=\"chgnote\">").Append(H(change)).Append("</div></td>");
    }

    private static void Kv(StringBuilder sb, string key, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        sb.Append("<tr><th>").Append(H(key)).Append("</th><td>").Append(H(value)).Append("</td></tr>");
    }

    private static string Pill(Severity s) =>
        $"<span class=\"pill {Cls(s)}\"><span class=\"dot {Cls(s)}\"></span>{H(ReportWriter.Word(s))}</span>";

    private static string Cls(Severity s) => s switch
    {
        Severity.Critical => "err",
        Severity.Warning => "warn",
        Severity.Inconclusive => "stale",
        Severity.Ok => "ok",
        _ => "info",
    };

    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");

    private static string Or(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s;

    // Suite palette (HueTheme, Teal family, neutral surfaces). Print: black on white.
    private const string Css = @"
:root{--base:#0B0D11;--chrome:#0F1217;--surface:#12151B;--raised:#191D25;--line-soft:#1C212A;--line:#2A3040;--line-strong:#3A4254;
--text:#E7EAF0;--dim:#A3ACBA;--muted:#8590A2;--accent:#2DD4BF;--accent-text:#5EEAD4;--accent-soft:rgba(45,212,191,.14);--accent-edge:rgba(45,212,191,.40);
--ok:#22C55E;--ok-text:#86EFAC;--ok-soft:rgba(34,197,94,.12);--ok-edge:rgba(34,197,94,.35);
--warn:#FBBF24;--warn-text:#FCD34D;--warn-soft:rgba(251,191,36,.12);--warn-edge:rgba(251,191,36,.35);
--err:#F87171;--err-text:#FCA5A5;--err-soft:rgba(248,113,113,.12);--err-edge:rgba(248,113,113,.40);
--stale:#8B95A5;--stale-text:#B4BDCA;--stale-soft:rgba(139,149,165,.12);--stale-edge:rgba(139,149,165,.35);
--mono:'Cascadia Mono','Consolas','Courier New',monospace;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--base);color:var(--text);font:14px/1.5 'Segoe UI Variable','Segoe UI',system-ui,sans-serif}
.head{display:flex;align-items:center;gap:18px;padding:18px 28px;background:var(--chrome);border-bottom:1px solid var(--line-soft)}
.head .icon{width:56px;height:56px;filter:drop-shadow(0 0 14px rgba(45,212,191,.35))}
.head h1{margin:0;font-size:22px;font-weight:600}
.head .sub{margin:2px 0 0;color:var(--dim)}
.head .sub b{color:var(--accent-text)}
.head .meta{margin-left:auto;text-align:right;color:var(--muted);font-size:12px}
main{max-width:1180px;margin:0 auto;padding:20px 28px 40px}
section{background:var(--surface);border:1px solid var(--line-soft);border-radius:12px;padding:18px 20px;margin:16px 0}
h2{margin:0 0 12px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
h3{margin:16px 0 8px;font-size:14px;color:var(--accent-text)}
p{margin:6px 0}
.muted{color:var(--muted)}
.mono,pre{font-family:var(--mono);font-size:12px}
pre{white-space:pre-wrap;word-break:break-word;margin:8px 0 0;color:var(--dim);background:var(--base);border:1px solid var(--line-soft);border-radius:6px;padding:8px 10px}
table{border-collapse:collapse;width:100%}
.kv th{text-align:left;vertical-align:top;color:var(--muted);font-weight:500;width:210px;padding:5px 12px 5px 0}
.kv td{padding:5px 0;color:var(--text);word-break:break-word}
.kv td pre{margin:0}
.grid th{text-align:left;font-size:11px;letter-spacing:.05em;text-transform:uppercase;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line)}
.grid td{padding:8px 10px;border-top:1px solid var(--line-soft);vertical-align:top;word-break:break-word}
.grid td.b{font-weight:600}
.grid td.r{text-align:right}
.chg{background:var(--warn-soft);color:var(--warn-text);box-shadow:inset 0 0 0 1px var(--warn-edge)}
.chg.good{background:var(--accent-soft);color:var(--accent-text);box-shadow:inset 0 0 0 1px var(--accent-edge)}
.chgnote{font-family:'Segoe UI',system-ui,sans-serif;font-size:11.5px;margin-top:3px}
.chg-inline.good{background:var(--accent-soft);color:var(--accent-text);border-color:var(--accent-edge)}
.chg-inline{background:var(--warn-soft);color:var(--warn-text);border:1px solid var(--warn-edge);border-radius:4px;padding:0 5px}
.pill{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 10px 0 8px;border-radius:11px;font-size:12px;font-weight:500;border:1px solid var(--line);background:var(--raised);color:var(--dim);white-space:nowrap}
.pill.ok{background:var(--ok-soft);border-color:var(--ok-edge);color:var(--ok-text)}
.pill.warn{background:var(--warn-soft);border-color:var(--warn-edge);color:var(--warn-text)}
.pill.err{background:var(--err-soft);border-color:var(--err-edge);color:var(--err-text)}
.pill.stale{background:var(--stale-soft);border-color:var(--stale-edge);color:var(--stale-text)}
.pill.info{background:var(--accent-soft);border-color:var(--accent-edge);color:var(--accent-text)}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--stale);margin-right:6px;vertical-align:middle}
.pill .dot{margin-right:0}
.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn)}.dot.err{background:var(--err)}.dot.info{background:var(--accent)}
.tag{display:inline-block;border:1px solid var(--line-strong);border-radius:5px;padding:0 7px;font-size:12px;color:var(--dim)}
.callout{border:1px solid var(--accent-edge);background:var(--accent-soft);border-radius:12px;padding:14px 16px}
.callout.err{border-color:var(--err-edge);background:var(--err-soft)}
.callout.warn{border-color:var(--warn-edge);background:var(--warn-soft)}
.callout.ok{border-color:var(--ok-edge);background:var(--ok-soft)}
.ctitle{font-size:16px;font-weight:600}
.two{display:grid;grid-template-columns:1fr 2fr;gap:20px;margin-top:12px}
.label{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin-bottom:3px}
.finding{border-top:1px solid var(--line-soft);padding:14px 0}
.finding:first-of-type{border-top:0}
.ftitle{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.rank{color:var(--muted);font-size:12px;min-width:18px}
details{margin-top:6px}
summary{cursor:pointer;color:var(--accent-text)}
.trace summary{color:var(--text)}
.trace td{font-size:12.5px}
footer{max-width:1180px;margin:0 auto;padding:0 28px 30px;color:var(--muted);font-size:12px}
@media (max-width:760px){.two{grid-template-columns:1fr}.kv th{width:130px}main{padding:12px}}
@media print{
:root{--base:#fff;--chrome:#fff;--surface:#fff;--raised:#f3f4f6;--line-soft:#e5e7eb;--line:#d1d5db;--line-strong:#9ca3af;
--text:#111;--dim:#333;--muted:#555;--accent-text:#0f766e;--accent-soft:#f0fdfa;--accent-edge:#5eead4;
--ok-text:#166534;--ok-soft:#f0fdf4;--warn-text:#92400e;--warn-soft:#fffbeb;--warn-edge:#f59e0b;--err-text:#991b1b;--err-soft:#fef2f2;--stale-text:#374151;--stale-soft:#f3f4f6;color-scheme:light}
section{break-inside:avoid-page}details{display:block}details>*{display:block}
.head .icon{filter:none}}
";
}
