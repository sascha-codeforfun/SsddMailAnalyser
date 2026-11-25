using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

/// <summary>
/// Machine-readable exports: JSON with everything (for tickets, scripts, a level-3 hand-over)
/// and CSV of the findings (for Excel). Built from explicit shapes rather than serialising the
/// live objects, so the format stays stable when the internals change.
/// </summary>
public static class Exporter
{
    public const int FormatVersion = 1;

    public static string ToJson(AnalysisResult r, string appName, string appVersion, bool includeEvidence)
    {
        var t = r.Targets;
        var doc = new Dictionary<string, object?>
        {
            ["format"] = "ssdd-mail-analysis",
            ["formatVersion"] = FormatVersion,
            ["app"] = appName,
            ["appVersion"] = appVersion,
            ["generated"] = DateTimeOffset.Now.ToString("o", CultureInfo.InvariantCulture),
            ["analysedAt"] = new DateTimeOffset(r.When).ToString("o", CultureInfo.InvariantCulture),
            ["case"] = new
            {
                direction = r.Input.Direction == Direction.Inbound ? "incoming (analysed at the recipient's side)" : "outgoing (analysed at the sender's side)",
                reverseCheck = r.Input.ReverseCheck,
                location = r.Input.Location.ToString(),
                otherMailWorksStated = r.Input.OtherMailWorks,
                senderAddress = r.Input.Direction == Direction.Inbound ? r.Input.TheirAddress : r.Input.OurAddress,
                recipientAddress = r.Input.Direction == Direction.Inbound ? r.Input.OurAddress : r.Input.TheirAddress,
            },
            ["dns"] = new
            {
                chosen = r.Options.Resolver.Display,
                used = r.ResolverUsed,
                fallbacks = r.Fallbacks,
            },
            ["options"] = new
            {
                r.Options.DohFallback,
                r.Options.AskAllNameServers,
                r.Options.Blocklists,
                r.Options.SmtpProbe,
                r.Options.MtaSts,
            },
            ["targets"] = new
            {
                senderDomain = t.SenderDomain,
                envelopeDomain = t.EnvelopeDomain,
                sendingIp = t.SendingIp,
                dkim = t.Dkim.Select(d => new { d.Selector, d.Domain, d.FromEvidence }),
                receiverDomain = t.ReceiverDomain,
                notes = t.Notes,
            },
            ["likelyCause"] = r.Likely is null ? null : FindingShape(r.Likely),
            ["findings"] = r.Findings.Select(FindingShape).ToList(),
            ["comparison"] = r.Compare.Select(c => new
            {
                check = c.Check,
                workingMail = c.Then,
                failingMail = c.Failing,
                now = c.Now,
                verdict = ReportWriter.Word(c.Verdict),
                failingDiffersFromWorking = c.FailingChanged,
                nowDiffersFromWorking = c.NowChanged,
                changeHelpsDelivery = c.ChangeHelps,
                change = c.ChangeNote,
            }).ToList(),
            ["records"] = new
            {
                spf = new[] { r.EnvelopeSpf, r.FromSpf }.Where(h => h is not null).Select(h => new
                {
                    domain = h!.Domain,
                    status = h.Status.ToString(),
                    record = h.Record,
                    lookups = h.TotalLookups,
                    all = h.AllTerm,
                    problems = h.Problems,
                    notes = h.Notes,
                    tree = h.Tree,
                }),
                spfEvaluations = new[] { r.SpfNow, r.SpfOther }.Where(e => e is not null).Select(e => new
                {
                    ip = e!.Ip?.ToString(),
                    domain = e.Domain,
                    verdict = e.Verdict.ToString(),
                    reason = e.Reason,
                    lookups = e.Lookups,
                    voidLookups = e.VoidLookups,
                    path = e.Trace,
                }),
                dkim = r.Dkim.Select(k => new
                {
                    name = k.QueryName,
                    status = k.Status.ToString(),
                    detail = k.Detail,
                    record = k.Record,
                    keyType = k.KeyType,
                    keyBits = k.KeyBits,
                    testing = k.Testing,
                    cname = k.CnameTarget,
                }),
                dmarc = r.Dmarc is not { } dmarcCheck ? null : new
                {
                    fromDomain = dmarcCheck.FromDomain,
                    queried = "_dmarc." + dmarcCheck.QueriedDomain,
                    found = dmarcCheck.Found,
                    record = dmarcCheck.Record,
                    problem = dmarcCheck.Problem,
                    policy = dmarcCheck.Policy,
                    p = dmarcCheck.P,
                    sp = dmarcCheck.Sp,
                    pct = dmarcCheck.Pct,
                    adkim = dmarcCheck.Adkim,
                    aspf = dmarcCheck.Aspf,
                    rua = dmarcCheck.Rua,
                },
                reverseDns = r.Ptr is not { } ptrCheck ? null : new
                {
                    ip = ptrCheck.Ip.ToString(),
                    names = ptrCheck.Names,
                    confirmed = ptrCheck.ConfirmedName,
                    looksGeneric = ptrCheck.LooksGeneric,
                },
                blocklists = r.Blocklists.Select(b => new
                {
                    list = b.Name,
                    zone = b.Zone,
                    tier = b.Tier.ToString(),
                    subject = b.Subject,
                    role = b.Role,
                    status = b.Status.ToString(),
                    detail = b.Detail,
                    verified = b.Verified,
                    selfTest = b.SelfTest,
                    delisting = b.DelistUrl,
                }),
                mx = new[] { r.SenderMx, r.ReceiverMx }.Where(m => m is not null).Select(m => new
                {
                    domain = m!.Domain,
                    status = m.Status.ToString(),
                    usable = m.Usable,
                    nullMx = m.NullMx,
                    hosts = m.Hosts.Select(h => new { h.Host, h.Preference, addresses = h.Addresses.Select(a => a.ToString()), h.Problem }),
                }),
                mtaSts = r.Sts is not { } stsCheck ? null : new
                {
                    stsCheck.Domain,
                    txt = stsCheck.TxtRecord,
                    tlsRpt = stsCheck.TlsRpt,
                    stsCheck.PolicyFetched,
                    stsCheck.Mode,
                    mxPatterns = stsCheck.MxPatterns,
                    uncoveredMx = stsCheck.UncoveredMx,
                    tlsa = stsCheck.Tlsa,
                    stsCheck.Problem,
                },
                atTheTimeOfTheWorkingMail = new[] { r.DmarcThen, r.DkimThen, r.SpfThen }.Where(t => t is not null).Select(t => new
                {
                    record = t!.Record,
                    state = t.State.ToString(),
                    value = t.Value,
                    source = t.Source,
                    explanation = t.Explanation,
                }),
                historyChanges = r.HistoryChanges,
                historyNames = r.History.Select(h => new
                {
                    h.Name,
                    added = h.Added?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    lastUpdated = h.LastUpdated?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                    values = h.Values.Select(v => new
                    {
                        v.Type,
                        from = v.From.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                        to = v.To.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
                        v.Value,
                    }),
                }),
                ttls = r.Ttls.Select(t => new { purpose = t.Purpose, name = t.Name, seconds = t.Seconds, negative = t.Negative }),
                zones = r.Zones.Select(z => new { z.Domain, z.Side, z.Serial, date = z.Date?.ToString("o", CultureInfo.InvariantCulture), z.Convention }),
                nameServers = r.NameServers.Select(c => new
                {
                    c.Purpose,
                    c.Name,
                    type = c.Type.ToString(),
                    c.Zone,
                    answers = c.Answers.Select(a => new { server = a.Server, ip = a.Ip?.ToString(), status = a.Response.Status.ToString(), answer = a.Response.Fingerprint() }),
                }),
                internalDnsVsPublic = r.Split.Select(v => new { v.Purpose, v.Name, type = v.Type.ToString(), internalView = v.Internal.Describe(), publicView = v.Public.Describe(), v.Differs }),
            },
            ["smtp"] = new
            {
                reachability = r.Reach is not { } reachResult ? null : new
                {
                    verdict = reachResult.Verdict.ToString(),
                    summary = reachResult.Summary,
                    publicIp = reachResult.PublicIp,
                    publicIpSource = reachResult.PublicIpSource,
                    publicIpListings = reachResult.PublicIpListings.Select(l => new { list = l.Name, status = l.Status.ToString(), detail = l.Detail }),
                    probes = reachResult.All.Select(pr => new
                    {
                        purpose = pr.Purpose,
                        host = pr.Host,
                        ip = pr.Result.Ip.ToString(),
                        port = pr.Result.Port,
                        outcome = pr.Result.Outcome.ToString(),
                        ms = Math.Round(pr.Result.Ms, 1),
                        error = pr.Result.Error,
                    }),
                },
                probes = r.Probes.Select(pr => new
                {
                    host = pr.Host,
                    ip = pr.Address?.ToString(),
                    connect = pr.Connect.ToString(),
                    connectMs = Math.Round(pr.ConnectMs, 1),
                    banner = pr.Banner,
                    capabilities = pr.Capabilities,
                    startTls = pr.StartTlsOffered,
                    tls = pr.TlsEstablished,
                    tlsProtocol = pr.TlsProtocol,
                    tlsCipher = pr.TlsCipher,
                    certSubject = pr.CertSubject,
                    certIssuer = pr.CertIssuer,
                    certNames = pr.CertNames,
                    certNotBefore = pr.CertNotBefore?.ToString("o", CultureInfo.InvariantCulture),
                    certNotAfter = pr.CertNotAfter?.ToString("o", CultureInfo.InvariantCulture),
                    certThumbprint = pr.CertThumbprint,
                    certNameMatches = pr.CertNameMatches,
                    certChainProblem = pr.CertChainProblem,
                    maxSize = pr.MaxSize,
                    error = pr.Error,
                    transcript = pr.Transcript,
                }),
            },
            ["evidenceParsed"] = new
            {
                workingMail = MailShape(r.Baseline, includeEvidence),
                failingMail = r.FailingEvidence is { } failEvidence ? MailShape(failEvidence, includeEvidence) : null,
                failingFromBounce = r.FailingFromBounce,
                bounce = !r.Ndr.HasAnything ? null : new
                {
                    statuses = r.Ndr.Statuses.Select(st => new { st.Code, st.ReplyCode, st.Context, meaning = st.Meaning?.Title }),
                    primary = r.Ndr.Primary?.Code,
                    category = r.Ndr.Category.ToString(),
                    delay = r.Ndr.LooksLikeDelay,
                    recipients = includeEvidence ? r.Ndr.Recipients : null,
                    remoteHosts = r.Ndr.RemoteHosts,
                    ips = r.Ndr.Ips.Select(i => i.ToString()),
                    reportingMta = r.Ndr.ReportingMta,
                    diagnostic = r.Ndr.DiagnosticText,
                    hints = r.Ndr.Hints.Select(h => h.Hint),
                },
            },
            ["trace"] = r.Trace.Select(e => new
            {
                seq = e.Seq,
                time = e.Time.ToString("o", CultureInfo.InvariantCulture),
                ms = e.Ms is { } ms ? Math.Round(ms, 1) : (double?)null,
                step = e.Step,
                kind = e.Kind,
                action = e.Action,
                outcome = e.OutcomeText,
                result = e.Result,
                details = e.Details,
            }).ToList(),
        };

        if (includeEvidence)
        {
            doc["evidenceRaw"] = new
            {
                workingMailHeaders = r.Input.BaselineText,
                failingMailHeaders = r.Input.FailingText,
                bounce = r.Input.NdrText,
            };
        }

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            NumberHandling = JsonNumberHandling.AllowNamedFloatingPointLiterals,
        };
        return JsonSerializer.Serialize(doc, options);
    }

    private static object FindingShape(Finding f) => new
    {
        severity = ReportWriter.Word(f.Severity),
        side = f.Side.ToString(),
        fix = f.Fix,
        area = f.Area,
        title = f.Title,
        detail = f.Detail,
        whoFixes = f.WhoFixes,
        nextStep = f.NextStep,
        score = f.Score,
        because = f.Because,
        evidence = f.Evidence,
        traceSteps = f.TraceSteps,
    };

    /// <summary>With the evidence left out, subject and recipient list are null: content, not findings.</summary>
    private static object? MailShape(MailEvidence m, bool includeEvidence) => !m.HasAnything ? null : new
    {
        from = m.From,
        returnPath = m.ReturnPath,
        to = includeEvidence ? m.To : null,
        subject = includeEvidence ? m.Subject : null,
        date = m.Date?.ToString("o", CultureInfo.InvariantCulture),
        messageId = m.MessageId,
        sendingIp = m.SendingIp?.ToString(),
        sendingIpSource = m.SendingIpSource,
        sendingHost = m.SendingHost,
        sendingHelo = m.SendingHelo,
        spf = m.SpfResult,
        spfDomain = m.SpfDomain,
        dkim = m.DkimResults.Select(d => new { result = d.Result, domain = d.Domain, selector = d.Selector }),
        dmarc = m.DmarcResult,
        dmarcAction = m.DmarcAction,
        dmarcPolicyThen = m.DmarcPolicyThen,
        dmarcCarriedBy = m.DmarcCarriedBy,
        compAuth = m.CompAuth,
        compAuthReason = m.CompAuthReason,
        scl = m.Scl,
        bcl = m.Bcl,
        spamVerdict = m.SpamVerdict,
        spamScore = m.SpamScore,
        authResultsUsed = m.PrimaryAuth?.Raw,
        dkimSignatures = m.DkimSignatures.Select(s => new { s.Domain, s.Selector, s.Algorithm }),
        hops = m.Hops.Select(h => new
        {
            index = h.Index + 1,
            time = h.Time?.ToString("o", CultureInfo.InvariantCulture),
            delaySeconds = h.DelayBefore?.TotalSeconds,
            fromHelo = h.FromHelo,
            fromHost = h.FromHost,
            fromIp = h.FromIp?.ToString(),
            by = h.ByHost,
            with = h.With,
            tls = h.Tls,
        }),
    };

    /// <summary>
    /// The findings as CSV for Excel: semicolon-separated with a UTF-8 BOM, so Excel in locales
    /// with a comma decimal separator opens it correctly by double-click. Multi-line fields are quoted.
    /// </summary>
    public static string FindingsCsv(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.Append('﻿');
        string[] header = { "Rank", "Severity", "Side", "Area", "Title", "Detail", "Who fixes it", "Next step", "Record to publish", "Score", "Ranked because", "Evidence", "Trace steps" };
        sb.AppendLine(string.Join(";", header));
        int rank = 1;
        foreach (var f in r.Findings)
        {
            var fields = new[]
            {
                rank++.ToString(CultureInfo.InvariantCulture),
                ReportWriter.Word(f.Severity),
                f.Side.ToString(),
                f.Area,
                f.Title,
                f.Detail,
                f.WhoFixes,
                f.NextStep,
                f.Fix,
                f.Score.ToString(CultureInfo.InvariantCulture),
                string.Join("; ", f.Because),
                string.Join("\n", f.Evidence),
                string.Join(", ", f.TraceSteps),
            };
            sb.AppendLine(string.Join(";", fields.Select(Csv)));
        }
        return sb.ToString();
    }

    /// <summary>The trace as CSV, for filtering in Excel.</summary>
    public static string TraceCsv(AnalysisResult r)
    {
        var sb = new StringBuilder();
        sb.Append('﻿');
        sb.AppendLine("Seq;Time;Ms;Step;Kind;Action;Outcome;Result;Details");
        foreach (var e in r.Trace)
        {
            var fields = new[]
            {
                e.Seq.ToString(CultureInfo.InvariantCulture),
                e.Time.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                e.Ms is { } ms ? ms.ToString("0.0", CultureInfo.InvariantCulture) : "",
                e.Step, e.Kind, e.Action, e.OutcomeText, e.Result, e.Details,
            };
            sb.AppendLine(string.Join(";", fields.Select(Csv)));
        }
        return sb.ToString();
    }

    private static string Csv(string? value)
    {
        value ??= "";
        // Formula injection guard: a field starting with = + - @ (or a tab or carriage return
        // in front of one) would be run by Excel.
        if (value.Length > 0 && "=+-@\t\r".Contains(value[0])) value = "'" + value;
        bool quote = value.IndexOfAny(new[] { ';', '"', '\n', '\r' }) >= 0;
        value = value.Replace("\"", "\"\"");
        return quote ? "\"" + value + "\"" : value;
    }
}
