using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

/// <summary>
/// Turns evidence and live results into ranked findings. Every rule names who fixes it and
/// the next step, because the reader is under time pressure.
/// </summary>
public static partial class Diagnoser
{
    private const int BaseCritical = 100;
    private const int BaseWarning = 50;
    private const int BaseInconclusive = 12;
    private const int BaseInfo = 5;
    private const int BonusBounce = 60;
    private const int BonusChanged = 25;
    private const int BonusDmarc = 30;

    /// <summary>The working mail is older than a list's memory: a listing seen now is newer than that mail.</summary>
    private static bool OlderThan(AnalysisResult r, TimeSpan memory) =>
        r.Baseline.Date is { } sent && DateTimeOffset.Now - sent > memory;

    public static void Diagnose(AnalysisResult r)
    {
        var f = r.Findings;
        bool inbound = r.Input.Direction == Direction.Inbound;
        string senderSide = "Sender's domain admin";
        string receiverSide = "Recipient's mail admin";

        Bounce(r, f);
        Spf(r, f, senderSide);
        Dkim(r, f, senderSide);
        Dmarc(r, f, senderSide);
        SenderDomain(r, f, senderSide);
        ReverseDns(r, f, inbound);
        Blocklists(r, f, inbound);
        Receiver(r, f, receiverSide);
        BaselineObservations(r, f);
        SenderSetup(r, f);
        ReachFindings(r, f);
        FailingMail(r, f, senderSide);
        DnsPath(r, f);
        NameServers(r, f, inbound);
        SplitDns(r, f, inbound);
        Zones(r, f);
        History(r, f);
        Timing(r, f);
        Corroborate(r);
        Compare(r);
        MarkChanges(r);
        NoDnsFromHere(r, f);

        foreach (var x in f)
        {
            x.Score += x.Severity switch
            {
                Severity.Critical => BaseCritical,
                Severity.Warning => BaseWarning,
                Severity.Inconclusive => BaseInconclusive,
                Severity.Info => BaseInfo,
                _ => 0,
            };
        }

        ReverseScope(r, f);

        foreach (var x in f) x.Side = SideOf(r, x);
        Attestation(r, f);

        var ordered = f.OrderByDescending(x => x.Score).ThenBy(x => x.Severity).ToList();
        f.Clear();
        f.AddRange(ordered);

        r.Likely = f.FirstOrDefault(x => x.Severity is Severity.Critical or Severity.Warning)
                   ?? NothingFound(r);

        foreach (var x in f.Append(r.Likely!))
        {
            if (x.TraceSteps.Count == 0) x.TraceSteps.AddRange(TraceStepsFor(x.Area));
        }
        if (r.Likely is { } likelyFinding && !f.Contains(likelyFinding)) likelyFinding.Side = SideOf(r, likelyFinding);
    }

    /// <summary>
    /// No resolver gave a usable answer: a failed lookup then says something about this
    /// machine's network, nothing about the domain, and must not be ranked as its fault.
    /// </summary>
    private static void NoDnsFromHere(AnalysisResult r, List<Finding> f)
    {
        if (r.DnsUnavailable is null) return;
        foreach (var x in f.Where(x => x.LookupFailure))
        {
            x.Severity = Severity.Inconclusive;
            x.Area = "DNS path";
            x.Score = 0;
            x.Because.Clear();
            x.Detail = "No DNS server could be used from this machine, so this lookup says nothing about the domain.";
            x.WhoFixes = "-";
            x.NextStep = "Run the checks again from a machine with working DNS.";
            x.Fix = "";
        }
    }

    // ================================================================== the bounce

    private static void Bounce(AnalysisResult r, List<Finding> f)
    {
        var n = r.Ndr;
        if (!n.HasAnything) return;

        var primary = n.Primary;
        if (primary is null)
        {
            var hintOnly = new Finding
            {
                Severity = n.Hints.Count > 0 ? Severity.Warning : Severity.Inconclusive,
                Area = "Bounce",
                Title = n.Hints.Count > 0 ? "Bounce without a status code: " + n.Hints[0].Hint : "The bounce text has no status code",
                Detail = "No enhanced status code (like 5.7.26) was found. Paste the whole bounce, including the part for administrators, or the delivery report attached to it.",
                WhoFixes = "-",
                NextStep = "Open the bounce, copy everything (Ctrl+A in the message body) and paste it again.",
            };
            hintOnly.Evidence.AddRange(n.Hints.Select(h => h.Hint));
            f.Add(hintOnly);
            return;
        }

        var m = primary.Meaning;
        var finding = new Finding
        {
            Severity = primary.IsPermanent && !n.LooksLikeDelay ? Severity.Critical : Severity.Warning,
            Area = "Bounce",
            Title = $"Bounce {primary.ReplyCode} {primary.Code}".Replace("  ", " ") + ": " + (m?.Title ?? "not in the built-in list"),
            Detail = m?.Meaning ?? "The code is not in the built-in list. The diagnostic text below is the best clue.",
            WhoFixes = m?.WhoFixes ?? "Depends on the text",
            NextStep = m?.NextStep ?? "Read the diagnostic text; search the code with the vendor name of the rejecting server.",
            Score = BonusBounce,
        };
        if (n.LooksLikeDelay)
            finding.Detail = "This is a delay notice, not a final failure: the sending server is still retrying. " + finding.Detail;
        if (!string.IsNullOrEmpty(n.DiagnosticText)) finding.Evidence.Add("Diagnostic: " + n.DiagnosticText);
        if (n.RemoteHosts.Count > 0) finding.Evidence.Add("Server: " + string.Join(", ", n.RemoteHosts.Take(4)));
        if (n.ReportingMta is not null) finding.Evidence.Add("Reported by: " + n.ReportingMta);
        if (n.Recipients.Count > 0) finding.Evidence.Add("Recipient: " + string.Join(", ", n.Recipients.Take(4)));
        foreach (var other in n.Statuses.Where(s => s != primary).Take(3)) finding.Evidence.Add($"Also: {other.Code} - {other.Context}");
        foreach (var h in n.Hints) finding.Evidence.Add("Text: " + h.Hint);
        finding.Because.Add("stated by the bounce");

        if (n.Category is NdrCategory.Recipient)
            finding.Detail += " This is not an SPF, DKIM or DMARC problem.";
        f.Add(finding);
    }

    // ================================================================== SPF

    private static void Spf(AnalysisResult r, List<Finding> f, string who)
    {
        var b = r.Baseline;
        var health = r.EnvelopeSpf;
        var envelope = string.IsNullOrEmpty(r.Targets.EnvelopeDomain) ? r.Targets.SenderDomain : r.Targets.EnvelopeDomain;
        bool spfCarried = b.HasAnything && b.DmarcCarriedBy is "SPF only";

        if (health is not null)
        {
            switch (health.Status)
            {
                case SpfVerdict.None:
                    f.Add(new Finding
                    {
                        Severity = Severity.Warning,
                        Area = "SPF",
                        Title = $"{envelope} publishes no SPF record",
                        Detail = "Receivers cannot tell which servers may send for this domain. Many large providers reject or junk such mail, and DMARC then depends on DKIM alone.",
                        WhoFixes = who,
                        NextStep = $"Publish a TXT record at {envelope} starting with v=spf1 that lists every sending service, ending in ~all or -all.",
                        Score = spfCarried ? BonusChanged + BonusDmarc : 0,
                    }.With(spfCarried ? "the working mail relied on SPF" : null));
                    break;
                case SpfVerdict.PermError:
                {
                    var x = new Finding
                    {
                        Severity = Severity.Critical,
                        Area = "SPF",
                        Title = $"The SPF record of {envelope} is broken",
                        Detail = "Receivers get a permanent error (permerror) instead of a pass. Most treat that as a fail, so DMARC loses its SPF leg.",
                        WhoFixes = who,
                        NextStep = "Fix the problems listed below; for too many lookups, flatten includes or move a service to a subdomain.",
                        Score = spfCarried ? BonusDmarc : 0,
                    };
                    x.Evidence.AddRange(health.Problems);
                    if (health.Record is not null) x.Evidence.Add("Record: " + health.Record);
                    if (spfCarried) x.Because.Add("the working mail relied on SPF");
                    f.Add(x);
                    break;
                }
                case SpfVerdict.TempError:
                {
                    var x = new Finding
                    {
                        Severity = Severity.Warning,
                        Area = "SPF",
                        LookupFailure = true,
                        Title = $"The SPF record of {envelope} cannot be fetched",
                        Detail = "The DNS lookup fails. Receivers answer with a temporary error (4.x) and retry; after a day or two the mail bounces as expired.",
                        WhoFixes = who + " (DNS hosting)",
                        NextStep = "Check the domain's name servers and DNSSEC; try the same query against another resolver.",
                    };
                    x.Evidence.AddRange(health.Problems);
                    f.Add(x);
                    break;
                }
                default:
                {
                    if (health.Notes.Count > 0)
                    {
                        var x = new Finding
                        {
                            Severity = Severity.Info,
                            Area = "SPF",
                            Title = $"SPF record of {envelope}: notes",
                            Detail = "Not errors, but worth knowing.",
                            WhoFixes = who,
                            NextStep = "-",
                        };
                        x.Evidence.AddRange(health.Notes);
                        x.Evidence.Add($"Lookups when fully expanded: {health.TotalLookups} of 10");
                        f.Add(x);
                    }
                    break;
                }
            }
        }

        var now = r.SpfNow;
        if (now is null)
        {
            if (r.SendingIp is null && health is not null && health.Status != SpfVerdict.None)
            {
                f.Add(new Finding
                {
                    Severity = Severity.Inconclusive,
                    Area = "SPF",
                    Title = "SPF not evaluated for a specific IP",
                    Detail = "No sending IP is known, so only the record itself was checked. With headers of a working mail (or the sender's outgoing IP entered on the Checks page), SPF is evaluated exactly as the receiver would.",
                    WhoFixes = "-",
                    NextStep = "Add the headers of a working mail, or enter the sending IP on the Checks page.",
                });
            }
            return;
        }

        bool passedThen = b.SpfPassed;
        string then = b.SpfResult is null ? "" : $" At the time the receiver said spf={b.SpfResult}.";

        switch (now.Verdict)
        {
            case SpfVerdict.Pass:
            {
                var x = new Finding
                {
                    Severity = Severity.Ok,
                    Area = "SPF",
                    Title = $"SPF still authorises {now.Ip} for {now.Domain}",
                    Detail = $"Today's evaluation passes ({now.Reason}).{then}",
                    WhoFixes = "-",
                    NextStep = "-",
                };
                x.Evidence.AddRange(now.Trace.Take(12));
                f.Add(x);
                break;
            }
            case SpfVerdict.Fail:
            case SpfVerdict.SoftFail:
            case SpfVerdict.Neutral:
            case SpfVerdict.None:
            {
                var x = new Finding
                {
                    Severity = now.Verdict is SpfVerdict.Fail || passedThen || spfCarried ? Severity.Critical : Severity.Warning,
                    Area = "SPF",
                    Title = passedThen
                        ? $"SPF no longer authorises {now.Ip}, the IP that sent the working mail"
                        : $"SPF for {now.Ip} at {now.Domain}: {now.Verdict.ToString().ToLowerInvariant()}",
                    Detail = $"Today's evaluation: {now.Verdict.ToString().ToLowerInvariant()} ({now.Reason}).{then}" +
                             (passedThen ? " The record changed since then, or the sender now uses a different path through the same IP." : ""),
                    WhoFixes = who,
                    NextStep = $"Add the service behind {now.Ip} to the SPF record of {now.Domain} (its include: or ip4:), or route the mail through an authorised server.",
                };
                if (passedThen) { x.Score += BonusChanged; x.Because.Add("passed in the working mail"); }
                if (spfCarried) { x.Score += BonusDmarc; x.Because.Add("the working mail passed DMARC through SPF alone"); }
                x.Evidence.AddRange(now.Trace.Take(14));
                f.Add(x);
                break;
            }
            case SpfVerdict.PermError:
            {
                if (health?.Status == SpfVerdict.PermError) break;   // already reported as a broken record
                var x = new Finding
                {
                    Severity = Severity.Critical,
                    Area = "SPF",
                    Title = $"SPF evaluation for {now.Ip} ends in a permanent error",
                    Detail = $"{now.Reason}. The record may work for other IPs, but for this one receivers see permerror.{then}",
                    WhoFixes = who,
                    NextStep = "Reduce DNS lookups (flatten includes, remove unused services) or fix the faulty term.",
                };
                if (passedThen) { x.Score += BonusChanged; x.Because.Add("passed in the working mail"); }
                if (spfCarried) { x.Score += BonusDmarc; x.Because.Add("the working mail passed DMARC through SPF alone"); }
                x.Evidence.AddRange(now.Trace.Take(14));
                f.Add(x);
                break;
            }
            case SpfVerdict.TempError:
                f.Add(new Finding
                {
                    Severity = Severity.Warning,
                    Area = "SPF",
                    Title = $"SPF evaluation for {now.Ip} hits a DNS failure",
                    Detail = now.Reason + ". Receivers defer the mail with a 4.x code.",
                    WhoFixes = who + " (DNS hosting)",
                    NextStep = "Find the failing lookup in the DNS log at the bottom of this page.",
                });
                break;
        }
    }

    // ================================================================== DKIM

    private static void Dkim(AnalysisResult r, List<Finding> f, string who)
    {
        var b = r.Baseline;
        bool dkimCarried = b.HasAnything && b.DmarcCarriedBy is "DKIM only";
        var from = r.Targets.SenderDomain;

        if (r.DkimProbed)
        {
            if (r.Dkim.Count == 0)
            {
                f.Add(new Finding
                {
                    Severity = Severity.Inconclusive,
                    Area = "DKIM",
                    Title = $"No DKIM selector known for {from}, and none of the common ones exists",
                    Detail = "Selectors can be any name, so this proves nothing. Without a selector the key cannot be checked.",
                    WhoFixes = "-",
                    NextStep = "Paste headers of a working mail (the DKIM-Signature header has s= and d=), or enter the selector on the Checks page.",
                });
            }
            else
            {
                var x = new Finding
                {
                    Severity = Severity.Info,
                    Area = "DKIM",
                    Title = $"Found {r.Dkim.Count} DKIM selector(s) at {from} by probing common names",
                    Detail = "These keys exist; whether the sending system signs with them is only visible in the headers of a sent mail.",
                    WhoFixes = "-",
                    NextStep = "-",
                };
                x.Evidence.AddRange(r.Dkim.Select(k => $"{k.QueryName}: {k.Status} - {k.Detail}"));
                f.Add(x);
            }
            return;
        }

        foreach (var key in r.Dkim)
        {
            var target = r.Targets.Dkim.FirstOrDefault(t => t.Selector.Equals(key.Selector, StringComparison.OrdinalIgnoreCase) && t.Domain == key.Domain);
            bool fromEvidence = target?.FromEvidence == true;
            bool aligned = DomainUtil.AlignedRelaxed(key.Domain, from);
            var thenResult = b.DkimResults.FirstOrDefault(d => d.Domain == key.Domain).Result;
            string then = thenResult is null ? "" : $" At the time the receiver said dkim={thenResult} for {key.Domain}.";

            switch (key.Status)
            {
                case DkimKeyStatus.Found:
                {
                    if (key.KeyType == "rsa" && key.KeyBits > 0 && key.KeyBits < 1024)
                    {
                        f.Add(new Finding
                        {
                            Severity = Severity.Critical,
                            Area = "DKIM",
                            Title = $"DKIM key {key.QueryName} is only {key.KeyBits} bits",
                            Detail = "Receivers ignore or fail RSA keys below 1024 bits.",
                            WhoFixes = who,
                            NextStep = "Generate a 2048-bit key, publish it under a new selector, and switch signing to it.",
                            Score = aligned && dkimCarried ? BonusDmarc : 0,
                        });
                        break;
                    }
                    var ok = new Finding
                    {
                        Severity = key.Testing ? Severity.Info : Severity.Ok,
                        Area = "DKIM",
                        Title = $"DKIM key {key.QueryName} is published",
                        Detail = key.Detail + "." + then + (key.Testing ? " t=y means the domain is testing DKIM; some receivers ignore failures but also passes." : "")
                                 + (key.KeyBits == 1024 ? " 1024 bits works, but 2048 is the current recommendation." : "")
                                 + (aligned ? "" : $" Note: {key.Domain} is not the From domain {from}, so this signature does not count for DMARC."),
                        WhoFixes = "-",
                        NextStep = "-",
                    };
                    if (key.CnameTarget is not null) ok.Evidence.Add("Via CNAME: " + key.CnameTarget);
                    f.Add(ok);
                    break;
                }
                case DkimKeyStatus.Missing:
                case DkimKeyStatus.Revoked:
                case DkimKeyStatus.Invalid:
                case DkimKeyStatus.NotDkim:
                {
                    var x = new Finding
                    {
                        Severity = fromEvidence || aligned ? Severity.Critical : Severity.Warning,
                        Area = "DKIM",
                        Title = key.Status switch
                        {
                            DkimKeyStatus.Missing when fromEvidence => $"The DKIM key the working mail was signed with is gone: {key.QueryName}",
                            DkimKeyStatus.Missing => $"DKIM key {key.QueryName} does not exist",
                            DkimKeyStatus.Revoked => $"DKIM key {key.QueryName} has been revoked",
                            _ => $"DKIM key record {key.QueryName} is damaged",
                        },
                        Detail = key.Detail + "." + then + " Mail signed with this selector now fails DKIM." +
                                 (key.Selector.StartsWith("selector", StringComparison.OrdinalIgnoreCase)
                                     ? " Microsoft 365 alternates between selector1 and selector2 when it rotates keys; both CNAMEs must exist."
                                     : " A key rotation where the old key was removed before signing switched, or a DNS migration that lost the record, are the usual causes."),
                        WhoFixes = who,
                        NextStep = key.Status == DkimKeyStatus.Missing
                            ? $"Republish the key at {key.QueryName} (or the CNAME the mail platform asks for), or make the platform sign with a selector that exists."
                            : "Republish the record exactly as the mail platform shows it; check for split or truncated strings.",
                    };
                    if (fromEvidence) { x.Score += BonusChanged; x.Because.Add("the working mail was signed with it"); }
                    if (dkimCarried && aligned) { x.Score += BonusDmarc; x.Because.Add("the working mail passed DMARC through DKIM alone"); }
                    if (key.CnameTarget is not null) x.Evidence.Add("CNAME target: " + key.CnameTarget);
                    if (key.Record is not null) x.Evidence.Add("Record: " + key.Record);
                    f.Add(x);
                    break;
                }
                case DkimKeyStatus.LookupFailed:
                    f.Add(new Finding
                    {
                        Severity = Severity.Warning,
                        Area = "DKIM",
                        LookupFailure = true,
                        Title = $"DKIM key {key.QueryName} cannot be fetched",
                        Detail = key.Detail + ". Receivers get a temporary error for DKIM.",
                        WhoFixes = who + " (DNS hosting)",
                        NextStep = "Check the domain's name servers and DNSSEC.",
                    });
                    break;
            }
        }

        // The working mail was signed, but not with the From domain.
        if (b.HasAnything && b.DkimSignatures.Count > 0 && !b.DkimSignatures.Any(s => DomainUtil.AlignedRelaxed(s.Domain, b.FromDomain)))
        {
            f.Add(new Finding
            {
                Severity = b.SpfPassed && b.SpfAligned ? Severity.Info : Severity.Warning,
                Area = "DKIM",
                Title = $"The working mail was signed by {string.Join(", ", b.DkimSignatures.Select(s => s.Domain).Distinct())}, not by {b.FromDomain}",
                Detail = "A signature from the mail platform's own domain does not count for DMARC. If SPF stops aligning, nothing carries DMARC any more.",
                WhoFixes = who,
                NextStep = $"Set up DKIM signing with {b.FromDomain} on the sending platform (custom DKIM / 'authenticated domain').",
            });
        }
    }

    // ================================================================== DMARC

    private static void Dmarc(AnalysisResult r, List<Finding> f, string who)
    {
        var d = r.Dmarc;
        if (d is null) return;
        var b = r.Baseline;
        var from = d.FromDomain;

        if (d.LookupFailed)
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "DMARC",
                LookupFailure = true,
                Title = $"The DMARC record of {from} cannot be fetched",
                Detail = (d.Problem ?? "") + ". Receivers may defer mail while DNS fails.",
                WhoFixes = who + " (DNS hosting)",
                NextStep = "Check the domain's name servers and DNSSEC.",
            });
            return;
        }

        if (!d.Found)
        {
            var org = DomainUtil.OrgDomain(from);
            var then = r.DmarcThen;
            bool hadWorking = r.Baseline.HasAnything;
            string previous = then?.Value is { } pv && pv.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase) ? pv : "";
            // Restoring what the domain had before is the safest record: its mail passed with it.
            string record = previous.Length > 0
                ? (previous.Contains("rua=", StringComparison.OrdinalIgnoreCase) ? previous : previous.TrimEnd().TrimEnd(';') + $"; rua=mailto:dmarc-reports@{org}")
                : $"v=DMARC1; p=none; rua=mailto:dmarc-reports@{org}; fo=1";

            var x = new Finding
            {
                Area = "DMARC",
                WhoFixes = who,
                Fix = $"_dmarc.{org}.  TXT  \"{record}\"",
            };

            const string weight = "A missing DMARC record alone rarely stops mail: DMARC only tells receivers what to do when SPF and DKIM fail. " +
                                  "Some filters add a small penalty without it, and the large providers require it from bulk senders. " +
                                  "It weighs in when other signals are bad: the domain then has nothing of its own to set against them.";

            if (then?.State == HistoryState.Present)
            {
                x.Severity = Severity.Critical;
                x.Title = $"The DMARC record of {from} was removed after the working mail";
                x.Detail = $"When the working mail was sent the record existed{(then.Value is null ? "" : $" ({then.Value})")} - {then.Source}{(then.Explanation.Length > 0 ? ": " + then.Explanation : "")}. Today there is none. " + weight;
                x.NextStep = $"Find out what changed the DNS zone of {org} (hosting panel, template, provider move) and restore the record.";
                x.Score = BonusChanged + BonusDmarc;
                x.Because.Add("the record existed when mail still arrived");
            }
            else if (then?.State == HistoryState.Absent)
            {
                x.Severity = Severity.Warning;
                x.Title = then.Likely
                    ? $"{from} publishes no DMARC record - most likely already missing when the working mail arrived"
                    : $"{from} publishes no DMARC record - already missing when the working mail arrived";
                x.Detail = then.Likely
                    ? $"The record was most likely already gone when the working mail was delivered ({then.Source}: {then.Explanation}), so its absence is probably not what changed. " + weight +
                      (previous.Length > 0 ? $" The domain had one before: {previous}." : "")
                    : $"The working mail was delivered without a DMARC record ({then.Source}{(then.Explanation.Length > 0 ? ": " + then.Explanation : "")}), so its absence is not what changed. " + weight +
                      (previous.Length > 0 ? $" The domain had one before: {previous}." : "");
                // Proven absent rules it out as the trigger; most likely absent only lowers it.
                x.Score = then.Likely ? -10 : -20;
                x.Because.Add(then.Likely ? "most likely already missing while mail still arrived" : "already missing while mail still arrived");
                x.NextStep = previous.Length > 0
                    ? $"Restore the previous DMARC record of {org} with a report address; find out why it disappeared."
                    : $"Publish a DMARC record for {org}, start with p=none and a report address, read the reports for a few weeks, then tighten.";
            }
            else
            {
                x.Severity = Severity.Warning;
                x.Title = $"{from} publishes no DMARC record";
                x.Detail = weight + (hadWorking
                    ? " Whether it existed when the working mail was sent is unknown; if it was missing then too, it is not what changed. Record history (pasted on the Evidence page) or an older mail received at a large provider can tell."
                    : "");
                x.NextStep = $"Publish a DMARC record for {org}, start with p=none and a report address, read the reports for a few weeks, then tighten.";
            }
            f.Add(x);
            return;
        }

        if (d.Problem is not null)
        {
            var x = new Finding
            {
                Severity = Severity.Warning,
                Area = "DMARC",
                Title = $"The DMARC record of {from} is invalid",
                Detail = d.Problem + ".",
                WhoFixes = who,
                NextStep = "Publish exactly one record starting with v=DMARC1 and containing p=.",
            };
            if (d.Record is not null) x.Evidence.Add("Record: " + d.Record);
            f.Add(x);
            return;
        }

        // What would DMARC conclude today, as far as DNS can tell?
        var envelope = string.IsNullOrEmpty(r.Targets.EnvelopeDomain) ? r.Targets.SenderDomain : r.Targets.EnvelopeDomain;
        bool spfAlignedNow = r.SpfNow?.Verdict == SpfVerdict.Pass &&
                             (d.Aspf == "s" ? DomainUtil.AlignedStrict(envelope, from) : DomainUtil.AlignedRelaxed(envelope, from));
        bool spfUnknown = r.SpfNow is null;
        var alignedKeys = r.Dkim.Where(k => k.Status == DkimKeyStatus.Found &&
                                            (d.Adkim == "s" ? DomainUtil.AlignedStrict(k.Domain, from) : DomainUtil.AlignedRelaxed(k.Domain, from))).ToList();
        bool dkimPossible = alignedKeys.Count > 0;
        bool dkimUnknown = r.Dkim.Count == 0;

        string policyText = $"p={d.Policy}" + (d.Pct < 100 ? $" pct={d.Pct}" : "") + (d.FromOrgDomain ? $" (inherited from {d.QueriedDomain})" : "");
        string thenText = b.DmarcResult is null
            ? ""
            : $"dmarc={b.DmarcResult}" + (b.DmarcAction is not null ? $" action={b.DmarcAction}" : "") + (b.DmarcPolicyThen is not null ? $" p={b.DmarcPolicyThen}" : "");

        if (d.Enforcing)
        {
            // Failed DMARC then without enforcement, enforced now: the policy change alone explains the rejection.
            bool failedThen = b.DmarcResult is "fail" or "permerror" or "none" && b.HasAnything && b.PrimaryAuth is not null;
            bool lenientThen = b.DmarcAction is "none" || b.DmarcPolicyThen is "none";
            // If SPF passes aligned today, DMARC passes regardless of what happened then.
            if (failedThen && (lenientThen || b.DmarcAction is null) && !spfAlignedNow)
            {
                var x = new Finding
                {
                    Severity = Severity.Critical,
                    Area = "DMARC",
                    Title = $"{from} now enforces DMARC ({policyText}), and the working mail already failed DMARC",
                    Detail = $"The receiver recorded {thenText} for the working mail: it was never properly authenticated, it was only let through because the policy was not enforced. Now it is.",
                    WhoFixes = who,
                    NextStep = "Make the sending platform pass SPF or DKIM aligned with the From domain; until then the domain owner can set p=none to restore delivery.",
                    Score = BonusChanged + BonusDmarc,
                };
                x.Because.Add("the policy tightened since the working mail");
                if (d.Record is not null) x.Evidence.Add("Record: " + d.Record);
                f.Add(x);
            }
            else if (!spfAlignedNow && !dkimPossible && !(spfUnknown && dkimUnknown))
            {
                var x = new Finding
                {
                    Severity = Severity.Critical,
                    Area = "DMARC",
                    Title = $"{from} enforces DMARC ({policyText}), and neither SPF nor DKIM can pass aligned today",
                    Detail = "SPF does not pass aligned for the sending IP, and no aligned DKIM key was found. Receivers that honour DMARC "
                             + (d.Policy == "reject" ? "reject" : "quarantine") + " this mail.",
                    WhoFixes = who,
                    NextStep = "Fix whichever leg the sending platform is meant to use (see the SPF and DKIM findings).",
                    Score = BonusDmarc,
                };
                if (b.DmarcResult is "pass") { x.Score += BonusChanged; x.Because.Add("DMARC passed in the working mail"); }
                if (d.Record is not null) x.Evidence.Add("Record: " + d.Record);
                f.Add(x);
            }
            else
            {
                var x = new Finding
                {
                    Severity = Severity.Ok,
                    Area = "DMARC",
                    Title = $"DMARC for {from}: {policyText}, and at least one leg can pass",
                    Detail = (spfAlignedNow ? "SPF passes aligned for the sending IP. " : "")
                             + (dkimPossible ? $"An aligned DKIM key exists ({string.Join(", ", alignedKeys.Select(k => k.Selector))}). " : "")
                             + (spfUnknown && dkimUnknown ? "Neither leg could be evaluated (no IP, no selector)." : "")
                             + (thenText.Length > 0 ? $" Then: {thenText}." : ""),
                    WhoFixes = "-",
                    NextStep = "-",
                };
                if (d.Record is not null) x.Evidence.Add("Record: " + d.Record);
                f.Add(x);
            }

            if (b.DmarcPolicyThen is { } pThen && pThen != d.Policy)
            {
                f.Add(new Finding
                {
                    Severity = Severity.Info,
                    Area = "DMARC",
                    Title = $"DMARC policy changed: p={pThen} then, p={d.Policy} now",
                    Detail = "The receiver recorded the policy it saw for the working mail.",
                    WhoFixes = "-",
                    NextStep = "-",
                    Score = BonusChanged,
                });
            }
        }
        else
        {
            var x = new Finding
            {
                Severity = Severity.Info,
                Area = "DMARC",
                Title = $"DMARC for {from}: {policyText} (monitoring only)",
                Detail = "With p=none DMARC never causes a rejection by itself. Receivers may still junk mail that fails authentication." + (thenText.Length > 0 ? $" Then: {thenText}." : ""),
                WhoFixes = "-",
                NextStep = "-",
            };
            if (d.Record is not null) x.Evidence.Add("Record: " + d.Record);
            f.Add(x);
        }
    }

    // ================================================================== sender domain DNS

    private static void SenderDomain(AnalysisResult r, List<Finding> f, string who)
    {
        var mx = r.SenderMx;
        if (mx is null) return;

        if (mx.Status is DnsStatus.ServFail or DnsStatus.Timeout or DnsStatus.Refused or DnsStatus.Error)
        {
            f.Add(new Finding
            {
                Severity = Severity.Critical,
                Area = "DNS",
                LookupFailure = true,
                Title = $"DNS for {mx.Domain} is failing ({mx.Status})",
                Detail = "Receivers cannot look anything up for this domain: SPF, DKIM and DMARC all give temporary errors, and many receivers refuse mail from a sender domain that does not resolve. A broken DNSSEC chain or dead name servers are the usual causes.",
                WhoFixes = who + " (DNS hosting)",
                NextStep = "Check the domain's NS delegation and DNSSEC (DS record at the registry vs. keys at the DNS host).",
                Score = BonusChanged,
            }.With("all lookups for the domain fail"));
            return;
        }
        if (mx.Status == DnsStatus.NxDomain)
        {
            f.Add(new Finding
            {
                Severity = Severity.Critical,
                Area = "DNS",
                Title = $"The sender domain {mx.Domain} does not exist in DNS",
                Detail = "Receivers reject mail from domains that do not resolve (often 5.1.8 or 5.7.1). The domain may have expired.",
                WhoFixes = who,
                NextStep = "Check the domain registration and its name servers.",
                Score = BonusChanged,
            });
            return;
        }
        if (!mx.Usable && !mx.NullMx && mx.Hosts.All(h => h.Addresses.Count == 0))
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "DNS",
                Title = $"The sender domain {mx.Domain} has no mail servers",
                Detail = "Receivers that verify the sender domain reject it (5.1.8 'sender domain must resolve'); bounces to the sender have nowhere to go.",
                WhoFixes = who,
                NextStep = "Publish an MX record for the sending domain.",
            });
        }
    }

    // ================================================================== reverse DNS

    private static void ReverseDns(AnalysisResult r, List<Finding> f, bool inbound)
    {
        var p = r.Ptr;
        if (p is null) return;
        string who = "Owner of the sending IP address (the sender or the sender's provider)";

        if (p.LookupFailed)
        {
            f.Add(new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "Reverse DNS",
                Title = $"Reverse DNS of {p.Ip} could not be checked",
                Detail = p.Detail,
                WhoFixes = "-",
                NextStep = "Try another resolver.",
            });
            return;
        }

        if (p.Ok && !p.LooksGeneric)
        {
            var ok = new Finding
            {
                Severity = Severity.Ok,
                Area = "Reverse DNS",
                Title = $"Reverse DNS of {p.Ip} is consistent",
                Detail = p.Detail + ".",
                WhoFixes = "-",
                NextStep = "-",
            };
            var thenHost = r.Baseline.SendingHost;
            if (!string.IsNullOrEmpty(thenHost) && !thenHost.Equals(p.ConfirmedName, StringComparison.OrdinalIgnoreCase))
                ok.Detail += $" The receiver saw '{thenHost}' at the time.";
            f.Add(ok);
            return;
        }

        f.Add(new Finding
        {
            Severity = Severity.Warning,
            Area = "Reverse DNS",
            Title = p.Names.Count == 0 ? $"{p.Ip} has no reverse DNS (PTR)"
                  : !p.Ok ? $"Reverse DNS of {p.Ip} does not resolve back"
                  : $"Reverse DNS of {p.Ip} looks like a dial-up or generic name",
            Detail = p.Detail + ". Gmail (5.7.25), Telekom/T-Online and many filters reject or score down mail from IPs without a matching PTR.",
            WhoFixes = who,
            NextStep = "Ask the IP owner to set a PTR to the server's mail host name, and an A record for that name pointing back.",
        });
    }

    // ================================================================== blocklists

    private static void Blocklists(AnalysisResult r, List<Finding> f, bool inbound)
    {
        if (r.Blocklists.Count == 0) return;
        string who = "Sender's mail admin (owner of the listed IP or domain)";
        string provider = "Sender's hosting provider (owner of the listed network)";

        var listed = r.Blocklists.Where(b => b.Status == ListingStatus.Listed).ToList();

        // ---- direct listings: the IP or domain itself
        foreach (var b in listed.Where(b => b.Tier != ListTier.Neighbourhood))
        {
            bool sendingIp = b.Role == "sending IP";
            bool pbl = b.Detail.Contains("PBL");
            var x = new Finding
            {
                Severity = b.Tier == ListTier.Major && (sendingIp || b.IsDomainList) && !pbl ? Severity.Critical : Severity.Warning,
                Area = "Reputation",
                Title = $"{b.Subject} ({b.Role}) is listed on {b.Name}",
                Detail = b.Detail + ". " + b.About +
                         (b.Tier == ListTier.Major ? " Receivers that use it reject or junk mail from this source." : " Only filters that use this list are affected.") +
                         (pbl ? " PBL is not a spam verdict: the range is not meant to send directly to MX servers; mail must go through the provider's relay." : ""),
                WhoFixes = who,
                NextStep = b.IsDomainList
                    ? $"Find out why the domain is listed (compromised website, abused forms or links), fix it, then request removal at {b.DelistUrl}."
                    : $"Find out why (compromised account or website, open relay, malware), fix it, then request removal at {b.DelistUrl}.",
            };
            if (!b.Verified) x.Evidence.Add($"{b.Name}: {b.SelfTest}");
            x.Evidence.Add($"Delisting: {b.DelistUrl}");
            if (b.Expiring && OlderThan(r, b.Zone.Contains("spamcop", StringComparison.OrdinalIgnoreCase) ? TimeSpan.FromDays(1) : TimeSpan.FromDays(7)))
            {
                x.Score += BonusChanged;
                x.Because.Add($"{b.Name} drops entries within days: the listing is new since the working mail");
            }
            f.Add(x);
        }

        // ---- neighbourhood listings: the network around the IP
        foreach (var group in listed.Where(b => b.Tier == ListTier.Neighbourhood).GroupBy(b => b.Subject))
        {
            var subject = group.Key;
            var role = group.First().Role;
            bool level3 = group.Any(b => b.Zone.StartsWith("dnsbl-3", StringComparison.Ordinal));
            bool level2 = group.Any(b => b.Zone.StartsWith("dnsbl-2", StringComparison.Ordinal));
            var self = r.Blocklists.FirstOrDefault(b => b.Subject == subject && b.Zone.StartsWith("dnsbl-1.uceprotect", StringComparison.Ordinal));
            string selfText = self?.Status switch
            {
                ListingStatus.NotListed => $"{subject} itself is not listed (Level 1).",
                ListingStatus.Listed => $"{subject} itself is listed too (Level 1).",
                _ => "",
            };

            var x = new Finding
            {
                Severity = Severity.Warning,
                Area = "Reputation",
                Title = level3 && level2
                    ? $"The network around {subject} ({role}) is listed on UCEPROTECT Level 2 and the provider's whole network on Level 3"
                    : level3
                        ? $"The provider's whole network containing {subject} ({role}) is listed on UCEPROTECT Level 3"
                        : $"The network range around {subject} ({role}) is listed on UCEPROTECT Level 2 - not the IP itself",
                Detail = (selfText.Length > 0 ? selfText + " " : "") +
                         "UCEPROTECT lists a provider's allocation (Level 2) or whole network (Level 3) when other addresses in it were caught spamming in the last 7 days. " +
                         "Every address in the range is affected, including well-behaved senders on a shared server. " +
                         "Large providers generally do not use these levels; some filter appliances and smaller mail services do, often as part of a spam score, so mail can land in junk or quarantine without a bounce. " +
                         "The listing expires automatically about 7 days after the last abuse in the range.",
                WhoFixes = provider,
                NextStep = "Ask the hosting provider to stop the abuse in the range; the listing then expires by itself. " +
                           "For business-critical mail consider a mail service with its own IP reputation. Paid express delisting does not remove the cause.",
                Score = 15,
            };
            foreach (var b in group) x.Evidence.Add($"{b.Name}: {b.Detail}");
            if (self is not null) x.Evidence.Add($"{self.Name}: {self.Detail}");
            x.Evidence.Add($"Lookup: {group.First().DelistUrl}?ipr={subject}");
            if (OlderThan(r, TimeSpan.FromDays(7)))
            {
                x.Score += BonusChanged;
                x.Because.Add("neighbourhood listings reflect the last 7 days: new since the working mail");
            }
            f.Add(x);

            // The receiving side's part, as its own request.
            var rx = new Finding
            {
                Severity = Severity.Warning,
                Area = "Reputation",
                Title = $"Check whether the receiving filter penalises UCEPROTECT {(level3 ? "Level 3" : "Level 2")} listings",
                Detail = $"The sender's network range around {subject} is listed (see the finding above). Whether this costs delivery depends on the receiving filter: " +
                         "many do not use these levels at all; those that do usually add it to a spam score.",
                WhoFixes = "Recipient's mail admin",
                NextStep = "Look up the filter verdict of a missing mail (quarantine entry or filter log; search for 'UCEPROTECT' or 'dnsbl-2'). " +
                           "If the listing tipped the score, release the mail and allow-list the sender's domain or IP until the listing expires; " +
                           "consider whether Level 2/3, which lists bystanders, should weigh that much.",
                Score = 10,
            };
            rx.Evidence.Add($"Listed: {string.Join(", ", group.Select(b => b.Name))} for {subject}");
            f.Add(rx);

            SpfVouchesForNeighbourhood(r, f, subject, level3 ? "Level 3" : "Level 2");
        }

        // ---- lists that could not be used
        var unusable = r.Blocklists.Where(b => b.Status is ListingStatus.Unusable or ListingStatus.Failed)
                                   .GroupBy(b => b.Zone).Select(g => g.First()).ToList();
        if (unusable.Count > 0)
        {
            var x = new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "Reputation",
                Title = $"{unusable.Count} blocklist(s) could not be used from here",
                Detail = "These lists failed their self-test or refused the queries: some refuse large public resolvers, some require registration, some are no longer maintained. Their results are left out rather than guessed.",
                WhoFixes = "-",
                NextStep = "If one of them matters, rerun with the authoritative mode or a non-public resolver, or check it on the list's own website.",
            };
            x.Evidence.AddRange(unusable.Select(u => $"{u.Name}: {u.Detail}"));
            f.Add(x);
        }

        // ---- clean
        var clean = r.Blocklists.Where(b => b.Status == ListingStatus.NotListed).ToList();
        if (listed.Count == 0 && clean.Count > 0)
        {
            int cleanLists = clean.Select(c => c.Zone).Distinct().Count();
            // "Not listed" from a list that did not answer its own test entry proves nothing:
            // the same silence comes from a resolver the list ignores.
            bool noneVerified = clean.All(c => !c.Verified);
            var x = new Finding
            {
                Severity = noneVerified ? Severity.Inconclusive : Severity.Ok,
                Area = "Reputation",
                Title = noneVerified
                    ? $"No listing found, but none of the {cleanLists} blocklist(s) passed its self-test"
                    : $"Not listed on the {cleanLists} usable blocklists",
                Detail = "Checked: " + string.Join(", ", clean.Select(c => c.Name).Distinct()) +
                         (noneVerified
                             ? ". None of them listed its own test entry when asked from here, so 'not listed' may only mean that the lists do not answer this resolver."
                             : ". Providers' own reputation systems (Microsoft, Google) are not public."),
                WhoFixes = "-",
                NextStep = noneVerified ? "Rerun with the authoritative mode or a non-public resolver, or check the address on the lists' own websites." : "-",
            };
            x.Evidence.AddRange(clean.GroupBy(c => c.Subject).Select(g => $"{g.Key} ({g.First().Role}): {g.Count()} lists"));
            var unverified = clean.Where(c => !c.Verified).Select(c => c.Name).Distinct().ToList();
            if (unverified.Count > 0) x.Evidence.Add("Self-test inconclusive (results kept): " + string.Join(", ", unverified));
            f.Add(x);
        }
    }

    /// <summary>The sender's SPF record vouches for a network range that a neighbourhood list has flagged.</summary>
    private static void SpfVouchesForNeighbourhood(AnalysisResult r, List<Finding> f, string subject, string level)
    {
        if (r.EnvelopeSpf?.Record is not { } record || !NetUtil.TryParseIp(subject, out var ip)) return;
        foreach (var term in record.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var t = term.TrimStart('+');
            if (!t.StartsWith("ip4:", StringComparison.OrdinalIgnoreCase)) continue;
            var parts = t[4..].Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var net)
                || !int.TryParse(parts[1], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var prefix)
                || prefix >= 32 || !NetUtil.InCidr(ip, net, prefix))
                continue;

            var title = $"The SPF record of {r.EnvelopeSpf!.Domain} authorises the whole range {t[4..]}, which contains the listed neighbourhood";
            if (f.Any(existing => existing.Title == title)) return;
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Sender setup",
                Title = title,
                Detail = $"The domain vouches for {Math.Pow(2, 32 - prefix):N0} addresses shared with other customers, and that neighbourhood is on UCEPROTECT {level}. " +
                         "Receivers see a domain that authorises a range known for abuse.",
                WhoFixes = "Sender's domain admin",
                NextStep = "Authorise only the actual sending host (ip4:<address>) or the provider's include:, and complete DKIM and DMARC.",
            });
            return;
        }
    }

    // ================================================================== receiving side

    private static void Receiver(AnalysisResult r, List<Finding> f, string who)
    {
        var mx = r.ReceiverMx;
        if (mx is null) return;
        var sts = r.Sts;
        bool stsEnforce = sts?.Mode == "enforce";

        if (mx.Status is DnsStatus.ServFail or DnsStatus.Timeout or DnsStatus.Refused or DnsStatus.Error)
        {
            f.Add(new Finding
            {
                Severity = Severity.Critical,
                Area = "Routing",
                LookupFailure = true,
                Title = $"The MX lookup for {mx.Domain} fails ({mx.Status})",
                Detail = "Sending servers cannot find where to deliver; they queue and eventually bounce with 4.4.3 / 4.4.7. Broken DNSSEC or name servers are the usual causes.",
                WhoFixes = who + " (DNS hosting)",
                NextStep = "Check the NS delegation and DNSSEC of the domain.",
            });
            return;
        }
        if (mx.Status == DnsStatus.NxDomain)
        {
            f.Add(new Finding
            {
                Severity = Severity.Critical,
                Area = "Routing",
                Title = $"The recipient domain {mx.Domain} does not exist",
                Detail = "Check the spelling of the address; the domain may also have expired.",
                WhoFixes = "Whoever typed the address, or the domain owner",
                NextStep = "Confirm the address with the recipient by another channel.",
            });
            return;
        }
        if (mx.NullMx || !mx.Usable)
        {
            f.Add(new Finding
            {
                Severity = Severity.Critical,
                Area = "Routing",
                Title = $"{mx.Domain} has no usable mail server",
                Detail = mx.Detail + ".",
                WhoFixes = who,
                NextStep = "The domain owner has to publish a working MX.",
            });
            return;
        }

        var hostProblems = mx.Hosts.Where(h => h.Problem is not null).ToList();
        var mxFinding = new Finding
        {
            Severity = hostProblems.Count > 0 ? Severity.Warning : Severity.Ok,
            Area = "Routing",
            Title = hostProblems.Count > 0 ? $"MX of {mx.Domain} has problems" : $"MX of {mx.Domain} resolves",
            Detail = mx.Detail + (mx.ImplicitMx ? "" : "."),
            WhoFixes = hostProblems.Count > 0 ? who : "-",
            NextStep = hostProblems.Count > 0 ? "Fix the host names listed below." : "-",
        };
        mxFinding.Evidence.AddRange(mx.Hosts.Select(h => $"{h.Preference} {h.Host}: {(h.Addresses.Count > 0 ? string.Join(", ", h.Addresses) : "-")}{(h.Problem is null ? "" : "  <- " + h.Problem)}"));
        f.Add(mxFinding);

        // MTA-STS
        if (sts is not null)
        {
            if (sts.TxtRecord is not null && sts.Problem is not null)
            {
                f.Add(new Finding
                {
                    Severity = Severity.Warning,
                    Area = "TLS",
                    Title = $"{mx.Domain} announces MTA-STS but the policy cannot be fetched",
                    Detail = sts.Problem + ". Senders with a cached policy keep enforcing it; new senders fall back to opportunistic TLS.",
                    WhoFixes = who,
                    NextStep = $"Fix https://mta-sts.{mx.Domain}/.well-known/mta-sts.txt (certificate, web server).",
                });
            }
            if (sts.PolicyFetched && sts.UncoveredMx.Count > 0)
            {
                f.Add(new Finding
                {
                    Severity = stsEnforce ? Severity.Critical : Severity.Warning,
                    Area = "TLS",
                    Title = $"MTA-STS policy of {mx.Domain} does not cover its MX host(s)",
                    Detail = $"Mode {sts.Mode}; MX not in the policy: {string.Join(", ", sts.UncoveredMx)}. " +
                             (stsEnforce ? "Senders that honour MTA-STS (Google, Microsoft) refuse to deliver to these hosts." : "In testing mode this is only reported."),
                    WhoFixes = who,
                    NextStep = "Add the MX host names to the policy's mx: lines, and bump the id= in the _mta-sts TXT record.",
                    Score = stsEnforce ? BonusChanged : 0,
                });
            }
            if (sts.Tlsa.Count > 0)
            {
                var x = new Finding
                {
                    Severity = Severity.Info,
                    Area = "TLS",
                    Title = $"{mx.Domain} publishes DANE (TLSA) records",
                    Detail = "Senders that validate DANE (Postfix with DNSSEC, many German providers) refuse delivery if the server certificate no longer matches the TLSA record, e.g. after a certificate renewal with a new key.",
                    WhoFixes = who,
                    NextStep = "After every certificate change, check that a TLSA record matches the new certificate or key.",
                };
                x.Evidence.AddRange(sts.Tlsa.Select(t => $"_25._tcp.{t.Key}: {t.Value}"));
                f.Add(x);
            }
        }

        if (r.SkippedProbes.Count > 0)
        {
            var x = new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "SMTP path",
                Title = $"{r.SkippedProbes.Count} mail server(s) of {mx.Domain} not probed: private address",
                Detail = "The MX host resolves only to addresses that are not public. Seen from outside the site's network those are addresses on this machine's own network, so no connection was made.",
                WhoFixes = "-",
                NextStep = "If this machine is inside the site's network, choose 'inside the site's network' on the first page and run again. " +
                           "Otherwise a public MX that points at a private address is itself the problem: outside senders cannot reach it.",
            };
            x.Evidence.AddRange(r.SkippedProbes);
            f.Add(x);
        }

        // SMTP probes: first the ones that never got a session, judged against the reachability test.
        if (r.Probes.Count == 0) return;
        foreach (var p in r.Probes.Where(probe => !probe.Connected))
            f.Add(ConnectFailure(r, p, who));

        foreach (var p in r.Probes.Where(probe => probe.Connected))
        {
            var label = $"{p.Host} ({p.Address})";
            if (p.BannerCode >= 400)
            {
                var x = new Finding
                {
                    Severity = Severity.Warning,
                    Area = "SMTP",
                    Title = $"{p.Host} refuses this machine at the greeting ({p.BannerCode})",
                    Detail = $"Greeting: {p.Banner}. The server decided on the connecting IP" +
                             (r.Reach?.PublicIp is { } ip ? $" ({ip})" : "") +
                             ", before any mail was offered. That is about this analysis system's address, not about the case - unless the text names a policy that also hits the real sender.",
                    WhoFixes = "-",
                    NextStep = "Read the greeting text; check this machine's IP on the blocklists (see the reachability finding).",
                };
                x.Evidence.AddRange(p.Transcript.Take(6));
                f.Add(x);
                continue;
            }
            if (p.Error is not null && !p.TlsEstablished)
            {
                bool tlsFailure = p.Error.StartsWith("TLS", StringComparison.Ordinal);
                f.Add(new Finding
                {
                    Severity = tlsFailure || stsEnforce ? Severity.Critical : Severity.Warning,
                    Area = "SMTP",
                    Title = tlsFailure ? $"TLS handshake with {p.Host} fails" : $"{p.Host} does not complete an SMTP session",
                    Detail = p.Error + ".",
                    WhoFixes = who,
                    NextStep = tlsFailure ? "Check the server's certificate and TLS configuration." : "Check the server and its firewall.",
                }.WithEvidence(p.Transcript.TakeLast(8)));
                continue;
            }

            if (!p.StartTlsOffered)
            {
                f.Add(new Finding
                {
                    Severity = stsEnforce ? Severity.Critical : Severity.Warning,
                    Area = "SMTP",
                    Title = $"{p.Host} does not offer STARTTLS",
                    Detail = "Senders that require TLS (MTA-STS, DANE, or connectors set to force TLS, common in Exchange Online partner connectors) cannot deliver.",
                    WhoFixes = who,
                    NextStep = "Enable STARTTLS with a valid certificate on the server.",
                }.WithEvidence(p.Transcript.Take(10)));
                continue;
            }

            var issues = new List<string>();
            var sev = Severity.Ok;
            if (p.CertNotAfter is { } notAfter)
            {
                if (notAfter < DateTime.Now) { issues.Add($"certificate expired on {notAfter:yyyy-MM-dd}"); sev = Severity.Critical; }
                else if (notAfter < DateTime.Now.AddDays(14)) { issues.Add($"certificate expires on {notAfter:yyyy-MM-dd}"); if (sev == Severity.Ok) sev = Severity.Warning; }
            }
            if (!p.CertNameMatches) { issues.Add($"certificate is for {string.Join(", ", p.CertNames.Take(4))}, not {p.Host}"); if (sev != Severity.Critical) sev = stsEnforce ? Severity.Critical : Severity.Warning; }
            if (p.CertChainProblem is not null) { issues.Add("chain: " + p.CertChainProblem); if (sev != Severity.Critical) sev = stsEnforce ? Severity.Critical : Severity.Warning; }

            var probeFinding = new Finding
            {
                Severity = sev,
                Area = "SMTP",
                Title = sev == Severity.Ok
                    ? $"{label} accepts connections with STARTTLS"
                    : $"{label}: TLS certificate problem",
                Detail = sev == Severity.Ok
                    ? $"{p.TlsProtocol}, certificate valid until {p.CertNotAfter:yyyy-MM-dd}." + (p.MaxSize is { } size ? $" Size limit {size / 1024 / 1024} MB." : "")
                    : string.Join("; ", issues) + ". Senders that verify certificates (MTA-STS, DANE, forced-TLS connectors) refuse to deliver; others still deliver.",
                WhoFixes = sev == Severity.Ok ? "-" : who,
                NextStep = sev == Severity.Ok ? "-" : "Renew or replace the certificate so it covers the MX host name and chains to a public root.",
            };
            if (p.Banner is not null) probeFinding.Evidence.Add("Banner: " + p.Banner);
            f.Add(probeFinding);
        }
    }

    // ================================================================== what the working mail itself shows

    private static void BaselineObservations(AnalysisResult r, List<Finding> f)
    {
        var b = r.Baseline;
        if (!b.HasAnything) return;

        if (b.PrimaryAuth is null)
        {
            f.Add(new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "Headers",
                Title = "The headers carry no Authentication-Results",
                Detail = "It cannot be seen how the receiving server judged the working mail. Internal mail, an on-premises server without anti-spam stamping, or a gateway in front of Exchange that removes the header are typical.",
                WhoFixes = "-",
                NextStep = "If there is a gateway, its own log or quarantine shows the authentication result.",
            });
        }

        if (b.PrimaryAuth is not null && b.DkimNotReported && b.HasAlignedSignature)
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Headers",
                Title = "The receiving server reported no DKIM result for the working mail",
                Detail = "The mail carried an aligned DKIM signature, but the trusted Authentication-Results lists only " +
                         string.Join(", ", b.PrimaryAuth.Methods.Select(m => m.Method).Distinct()) +
                         ". Whether DKIM passed there is unknown, not failed; comparisons treat it that way.",
                WhoFixes = "-",
                NextStep = "-",
            });
        }

        if (b.CompAuth is "fail" or "softfail")
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Headers",
                Title = $"Microsoft already rated the working mail compauth={b.CompAuth} (reason {b.CompAuthReason})",
                Detail = "Composite authentication failing means Microsoft treated the mail as possibly spoofed even then; it got through on other signals. Small changes tip it into junk or quarantine.",
                WhoFixes = "Sender's domain admin",
                NextStep = "Check the quarantine first; then fix SPF/DKIM alignment for the From domain.",
            });
        }

        bool borderline = b.Scl is >= 5 || b.SpamVerdict is "SFV:SPM" ||
                          (b.SpamScore is { } score && b.SpamThreshold is { } threshold && threshold > 0 && score >= threshold * 0.7);
        if (borderline)
        {
            var parts = new List<string>();
            if (b.Scl is { } scl) parts.Add($"SCL {scl}");
            if (b.Bcl is { } bcl) parts.Add($"BCL {bcl}");
            if (b.SpamVerdict is not null) parts.Add(b.SpamVerdict);
            if (b.SpamScore is { } sc) parts.Add($"score {sc.ToString(CultureInfo.InvariantCulture)}" + (b.SpamThreshold is { } th ? $" of {th.ToString(CultureInfo.InvariantCulture)}" : ""));
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Content",
                Title = "The working mail was already close to the spam threshold",
                Detail = $"{string.Join(", ", parts)}. Content filtering may now be quarantining or junking the sender's mail without any authentication change.",
                WhoFixes = "Recipient's mail admin (quarantine, allow lists)",
                NextStep = "Search the quarantine and the junk folder for the sender; check the message trace.",
            });
        }

        if (b.ArcInstances > 0 || b.IsListMail)
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Headers",
                Title = b.IsListMail ? "The working mail came through a mailing list" : $"The working mail passed through {b.ArcInstances} forwarding hop(s) with ARC",
                Detail = "Forwarders and lists break SPF (new sending IP) and often DKIM (modified subject or footer). If the failing mail took that route, DMARC fails there even though the sender's setup is fine.",
                WhoFixes = "The forwarder or list operator",
                NextStep = "Ask whether the failing mail was sent directly or via the list/forwarder.",
            });
        }

        var slow = b.Hops.Where(h => h.DelayBefore is { } dly && dly > TimeSpan.FromMinutes(20)).ToList();
        if (slow.Count > 0)
        {
            var x = new Finding
            {
                Severity = Severity.Info,
                Area = "Headers",
                Title = "The working mail was delayed in transit",
                Detail = "Long gaps between hops point to greylisting, queues or throttling. Mail that 'does not arrive' may only be late.",
                WhoFixes = "-",
                NextStep = "Ask whether the failing mail eventually arrived; check the queues.",
            };
            x.Evidence.AddRange(slow.Select(h => $"{h.DelayBefore!.Value:hh\\:mm\\:ss} before hop {h.Index + 1} ({h.ByHost})"));
            f.Add(x);
        }

        if (b.Date is { } date && (DateTimeOffset.Now - date).TotalDays > 90)
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Headers",
                Title = $"The working mail is {(int)(DateTimeOffset.Now - date).TotalDays} days old",
                Detail = "Sending platforms and IPs change; a more recent working mail gives a sharper comparison.",
                WhoFixes = "-",
                NextStep = "-",
            });
        }
    }

    // ================================================================== cross-checks with the bounce

    private static void Corroborate(AnalysisResult r)
    {
        var cat = r.Ndr.Category;
        if (!r.Ndr.HasAnything || r.Ndr.Primary is null && r.Ndr.Hints.Count == 0) return;

        string[] areas = cat switch
        {
            NdrCategory.Authentication => new[] { "SPF", "DKIM", "DMARC", "Failing mail", "Name servers" },
            NdrCategory.Reputation => new[] { "Reputation", "Content", "Failing mail" },
            NdrCategory.ReverseDns => new[] { "Reverse DNS" },
            NdrCategory.Transport => new[] { "SMTP", "TLS", "Routing" },
            NdrCategory.Routing => new[] { "Routing", "DNS" },
            _ => Array.Empty<string>(),
        };

        foreach (var x in r.Findings.Where(x => x.Area != "Bounce" && areas.Contains(x.Area) && x.Severity is Severity.Critical or Severity.Warning))
        {
            x.Score += 40;
            x.Because.Add("matches what the bounce says");
        }

        // The bounce says authentication but every live check passes: the failing mail took
        // another path. Say so instead of letting a green screen mislead.
        if (cat == NdrCategory.Authentication &&
            !r.Findings.Any(x => x.Area is "SPF" or "DKIM" or "DMARC" or "Failing mail" or "Name servers" && x.Severity is Severity.Critical or Severity.Warning))
        {
            r.Findings.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Path",
                Title = "The bounce cites authentication, but the checked path passes",
                Detail = "SPF, DKIM and DMARC look fine for the IP and selectors from the evidence. The failing mail most likely left through a different system: another IP (a new service, a CRM, a scanner, a forwarder), or without the DKIM signature.",
                WhoFixes = "Sender's domain admin",
                NextStep = "Get the headers of a failing mail (from the bounce's attachment or a test to a mailbox the sender controls) and compare the sending IP and DKIM d=/s=.",
                Score = 30,
            });
        }
    }

    // ================================================================== then vs now

    private static void Compare(AnalysisResult r)
    {
        var b = r.Baseline;
        var fl = r.FailingEvidence;
        var rows = r.Compare;

        // The failing mail's value for a row; empty when there is no failing mail at all.
        string F(Func<MailEvidence, string?> pick) => fl is null ? "" : pick(fl) ?? "-";

        if (r.SendingIp is not null)
        {
            rows.Add(new CompareRow
            {
                Check = "Sending IP",
                Then = b.SendingIp?.ToString() ?? "-",
                Failing = F(m => m.SendingIp?.ToString()),
                Now = r.SendingIp.ToString() + (b.SendingIp is null && fl?.SendingIp is null ? " (entered)" : ""),
                Verdict = Severity.Info,
            });
        }

        if (r.SpfNow is { } spf)
        {
            rows.Add(new CompareRow
            {
                Check = $"SPF ({spf.Domain})",
                Then = b.SpfResult is null ? Unreported(b, "spf") : $"{b.SpfResult}" + (b.SpfDomain is null ? "" : $" ({b.SpfDomain})"),
                Failing = F(m => m.SpfResult is null ? Unreported(m, "spf") : m.SpfResult + (m.SpfDomain is null ? "" : $" ({m.SpfDomain})")),
                Now = $"{spf.Verdict.ToString().ToLowerInvariant()} for {spf.Ip}",
                Verdict = spf.Verdict == SpfVerdict.Pass ? Severity.Ok
                        : spf.Verdict is SpfVerdict.TempError ? Severity.Warning
                        : Severity.Critical,
            });
        }
        if (r.SpfOther is { } other)
        {
            rows.Add(new CompareRow
            {
                Check = $"SPF ({other.Domain})",
                Then = "",
                Failing = "",
                Now = $"{other.Verdict.ToString().ToLowerInvariant()} for {other.Ip}",
                Verdict = other.Verdict == SpfVerdict.Pass ? Severity.Ok
                        : other.Verdict is SpfVerdict.TempError ? Severity.Warning
                        : Severity.Critical,
            });
        }
        if (r.SpfNow is null && r.EnvelopeSpf is { } spfHealth)
        {
            rows.Add(new CompareRow
            {
                Check = $"SPF record ({spfHealth.Domain})",
                Then = b.SpfResult ?? Unreported(b, "spf"),
                Now = spfHealth.Status switch
                {
                    SpfVerdict.None => "no record",
                    SpfVerdict.PermError => "broken",
                    SpfVerdict.TempError => "lookup fails",
                    _ => $"valid, {spfHealth.TotalLookups} lookups",
                },
                Verdict = spfHealth.Status switch
                {
                    SpfVerdict.Pass => Severity.Ok,
                    SpfVerdict.PermError => Severity.Critical,
                    _ => Severity.Warning,
                },
            });
        }

        foreach (var k in r.Dkim)
        {
            var then = b.DkimResults.FirstOrDefault(res => res.Domain == k.Domain);
            rows.Add(new CompareRow
            {
                Check = $"DKIM {k.Selector} ({k.Domain})",
                Then = then.Result ?? (r.DkimProbed ? "probe" : DkimThen(b, k)),
                Failing = F(m => m.DkimResults.FirstOrDefault(res => res.Domain == k.Domain).Result ?? DkimThen(m, k)),
                Now = k.Status switch
                {
                    DkimKeyStatus.Found => k.KeyBits > 0 ? $"key published ({k.KeyBits} bit)" : "key published",
                    DkimKeyStatus.Missing => "key missing",
                    DkimKeyStatus.Revoked => "key revoked",
                    DkimKeyStatus.LookupFailed => "lookup fails",
                    _ => "record damaged",
                },
                Verdict = k.Status switch
                {
                    DkimKeyStatus.Found => Severity.Ok,
                    DkimKeyStatus.LookupFailed => Severity.Warning,
                    _ => Severity.Critical,
                },
            });
        }

        if (r.Dmarc is { } dmarc)
        {
            var thenText = b.DmarcResult is null
                ? (r.DmarcThen is { State: not HistoryState.Unknown } known ? known.Short : Unreported(b, "dmarc"))
                : b.DmarcResult + (b.DmarcAction is not null ? $", action={b.DmarcAction}" : "") + (b.DmarcPolicyThen is not null ? $", p={b.DmarcPolicyThen}" : "");
            rows.Add(new CompareRow
            {
                Check = $"DMARC ({dmarc.FromDomain})",
                Then = thenText,
                Failing = F(m => m.DmarcResult is null ? Unreported(m, "dmarc") : m.DmarcResult + (m.DmarcAction is not null ? $", action={m.DmarcAction}" : "")),
                Now = !dmarc.Found ? "no record" : dmarc.Problem is not null ? "invalid record" : $"p={dmarc.Policy}" + (dmarc.Pct < 100 ? $" pct={dmarc.Pct}" : ""),
                Verdict = r.Findings.Any(x => x.Area == "DMARC" && x.Severity == Severity.Critical) ? Severity.Critical
                        : !dmarc.Found || dmarc.Problem is not null ? Severity.Warning
                        : Severity.Ok,
            });
            if (b.HasAnything && b.PrimaryAuth is not null)
            {
                rows.Add(new CompareRow
                {
                    Check = "DMARC carried by",
                    Then = b.DmarcCarriedBy,
                    Failing = F(m => m.PrimaryAuth is null ? null : m.DmarcCarriedBy),
                    Now = DmarcNow(r),
                    Verdict = DmarcNow(r) == "neither" ? Severity.Critical : Severity.Ok,
                });
            }
        }

        if (r.Ptr is { } ptr)
        {
            rows.Add(new CompareRow
            {
                Check = "Reverse DNS",
                Then = b.SendingHost ?? "-",
                Failing = F(m => m.SendingHost),
                Now = ptr.ConfirmedName ?? (ptr.Names.Count > 0 ? ptr.Names[0] + " (no match)" : "none"),
                Verdict = ptr.Ok && !ptr.LooksGeneric ? Severity.Ok : Severity.Warning,
            });
        }

        if (r.Blocklists.Count > 0)
        {
            var listedRows = r.Blocklists.Where(x => x.Status == ListingStatus.Listed).ToList();
            int usable = r.Blocklists.Where(x => x.Status is ListingStatus.Listed or ListingStatus.NotListed).Select(x => x.Zone).Distinct().Count();
            rows.Add(new CompareRow
            {
                Check = "Blocklists",
                Then = "-",
                Now = listedRows.Count == 0
                    ? $"not listed ({usable} lists)"
                    : string.Join(", ", listedRows.Select(x => x.Role == "sending IP" ? x.Name : $"{x.Name} ({x.Role})")),
                Verdict = listedRows.Count == 0 ? Severity.Ok
                        : listedRows.Any(x => x.Tier == ListTier.Major && !x.Detail.Contains("PBL")) ? Severity.Critical
                        : Severity.Warning,
            });
        }

        if (b.Scl is not null || b.SpamScore is not null || fl?.Scl is not null || fl?.SpamScore is not null)
        {
            static string Rating(MailEvidence m) =>
                m.Scl is { } scl ? $"SCL {scl}" + (m.Bcl is { } bcl ? $", BCL {bcl}" : "")
                : m.SpamScore is { } score ? $"score {score.ToString(CultureInfo.InvariantCulture)}"
                : "-";
            rows.Add(new CompareRow
            {
                Check = "Spam rating",
                Then = Rating(b),
                Failing = F(Rating),
                Now = "not visible from here",
                Verdict = b.Scl is >= 5 || fl?.Scl is >= 5 ? Severity.Warning : Severity.Info,
            });
        }

        foreach (var z in r.Zones)
        {
            var working = b.Date;
            bool after = z.Date is { } zd && working is { } wd && (z.Convention == "YYYYMMDDnn" ? zd.UtcDateTime.Date > wd.UtcDateTime.Date : zd > wd);
            bool stale = z.Date is { } zs && working is { } ws && z.Convention == "YYYYMMDDnn" && zs < ws.AddDays(-365);
            rows.Add(new CompareRow
            {
                Check = $"Zone {z.Domain} changed",
                Then = working is { } w ? $"mail of {w.ToLocalTime():yyyy-MM-dd}" : "-",
                Failing = F(m => m.Date is { } md ? $"mail of {md.ToLocalTime():yyyy-MM-dd}" : null),
                Now = z.Date is { } d
                    ? (z.Convention == "YYYYMMDDnn" ? d.ToString("yyyy-MM-dd") : d.ToLocalTime().ToString("yyyy-MM-dd HH:mm")) + (stale ? " (serial not maintained)" : "")
                    : $"serial {z.Serial} (no date)",
                Verdict = after ? Severity.Warning : stale ? Severity.Inconclusive : Severity.Info,
            });
        }

        if (r.NameServers.Count > 0)
        {
            int split = r.NameServers.Count(c => c.Variants > 1);
            int silent = r.NameServers.SelectMany(c => c.Silent).Select(a => a.Server).Distinct().Count();
            rows.Add(new CompareRow
            {
                Check = "Name servers agree",
                Then = "-",
                Failing = fl is null ? "" : "-",
                Now = split == 0 && silent == 0 ? $"yes ({r.NameServers.Count} records)" : $"{split} record(s) differ, {silent} server(s) silent",
                Verdict = split > 0 ? Severity.Critical : silent > 0 ? Severity.Warning : Severity.Ok,
            });
        }

        if (r.ReceiverMx is { } receiverMx)
        {
            rows.Add(new CompareRow
            {
                Check = $"MX ({receiverMx.Domain})",
                Then = "-",
                Now = receiverMx.Usable ? string.Join(", ", receiverMx.Hosts.Select(host => host.Host).Take(3)) : "not usable",
                Verdict = receiverMx.Usable ? Severity.Ok : Severity.Critical,
            });
        }

        if (r.Reach is { } reachRow)
        {
            rows.Add(new CompareRow
            {
                Check = "Port 25 from this machine",
                Then = "-",
                Failing = fl is null ? "" : "-",
                Now = reachRow.Verdict switch
                {
                    ReachVerdict.Open => "open (control hosts connect)",
                    ReachVerdict.Port25Blocked => "blocked here (587 passes)",
                    ReachVerdict.RejectedHere => "rejected near the analysis system",
                    ReachVerdict.NoOutbound => "no outbound mail ports",
                    _ => "not tested",
                },
                Verdict = reachRow.Verdict == ReachVerdict.Open ? Severity.Ok : Severity.Inconclusive,
            });
        }

        foreach (var probe in r.Probes)
        {
            bool testable = r.Reach?.Verdict == ReachVerdict.Open;
            rows.Add(new CompareRow
            {
                Check = $"SMTP {probe.Host}",
                Then = "-",
                Failing = fl is null ? "" : "-",
                Now = !probe.Connected
                        ? (testable ? $"{probe.Connect.ToString().ToLowerInvariant()} after {probe.ConnectMs:0} ms" : "not testable from here")
                    : probe.BannerCode >= 400 ? $"greeting {probe.BannerCode}"
                    : probe.TlsEstablished ? $"STARTTLS ok, cert until {probe.CertNotAfter:yyyy-MM-dd}"
                    : probe.StartTlsOffered ? "TLS failed" : "no STARTTLS",
                Verdict = !probe.Connected ? (testable ? Severity.Warning : Severity.Inconclusive)
                        : probe.TlsEstablished && probe.CertNameMatches && probe.CertChainProblem is null && probe.CertNotAfter > DateTime.Now ? Severity.Ok
                        : Severity.Warning,
            });
        }
    }

    /// <summary>
    /// What a header cell says when it has no result: the receiving server did not stamp this
    /// check, or wrote no Authentication-Results at all. Neither is a result, so neither is
    /// compared as one.
    /// </summary>
    private static string Unreported(MailEvidence m, string method)
    {
        if (!m.HasAnything) return "-";
        if (m.PrimaryAuth is null) return "no Authentication-Results";
        return m.PrimaryAuth.Methods.Any(x => x.Method == method) ? "-" : "not reported";
    }

    private static string DkimThen(MailEvidence m, DkimKeyCheck k)
    {
        if (!m.HasAnything) return "-";
        bool signedWith = m.DkimSignatures.Any(sig => sig.Domain == k.Domain && sig.Selector.Equals(k.Selector, StringComparison.OrdinalIgnoreCase));
        var reported = Unreported(m, "dkim");
        if (signedWith) return reported == "-" ? "signed" : $"signed, {reported}";
        if (m.DkimSignatures.Count == 0) return "not signed";
        return "other selector";
    }

    private static string DmarcNow(AnalysisResult r)
    {
        var d = r.Dmarc;
        if (d is null) return "-";
        var from = d.FromDomain;
        var envelope = string.IsNullOrEmpty(r.Targets.EnvelopeDomain) ? r.Targets.SenderDomain : r.Targets.EnvelopeDomain;
        bool spf = r.SpfNow?.Verdict == SpfVerdict.Pass && DomainUtil.AlignedRelaxed(envelope, from);
        bool dkim = r.Dkim.Any(k => k.Status == DkimKeyStatus.Found && DomainUtil.AlignedRelaxed(k.Domain, from));
        if (r.SpfNow is null && r.Dkim.Count == 0) return "unknown";
        return (spf, dkim) switch
        {
            (true, true) => "SPF and DKIM (key present)",
            (true, false) => "SPF only",
            (false, true) => "DKIM only (key present)",
            _ => "neither",
        };
    }

    // ================================================================== nothing wrong

    /// <summary>What a reverse-direction check did not look at, said once, whatever else it found.</summary>
    private static void ReverseScope(AnalysisResult r, List<Finding> f)
    {
        if (!r.Input.ReverseCheck) return;
        f.Add(new Finding
        {
            Severity = Severity.Info,
            Area = "Summary",
            Title = "Reverse-direction check: a health check of the opposite path, without evidence",
            Detail = $"The two domains of the case were swapped: {Name(r.Targets.SenderDomain)} as the sender, {Name(r.Targets.ReceiverDomain)} as the receiver. " +
                     "Checked: the sender domain's SPF and DMARC records, name servers and zone, domain blocklists, and the receiver's MX, MTA-STS and mail servers. " +
                     "Not checked, because no mail of this direction was given: whether a particular sending server passes SPF, its reverse DNS, IP blocklists, and DKIM keys (no selector is known).",
            WhoFixes = "-",
            NextStep = "To diagnose a mail that failed in this direction, start a new case with its headers or its bounce.",
        });

        static string Name(string s) => s.Length == 0 ? "(none)" : s;
    }

    private static Finding NothingFound(AnalysisResult r)
    {
        if (r.Input.ReverseCheck && r.DnsUnavailable is not null)
        {
            return new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "Summary",
                Title = "Reverse direction: nothing could be checked from this machine",
                Detail = "No DNS server gave a usable answer, so the reverse path was not looked at. This says nothing about either domain.",
                WhoFixes = "-",
                NextStep = "Check this machine's network (see the DNS path findings), then check the reverse direction again.",
            };
        }

        if (r.Input.ReverseCheck)
        {
            return new Finding
            {
                Severity = Severity.Ok,
                Area = "Summary",
                Title = "Reverse direction: no SPF, DMARC or DNS problem found",
                Detail = "The published sender authentication of the sending domain and the mail servers of the receiving domain look healthy for mail going the other way. " +
                         "This is a health check without evidence: see the reverse-direction note below for what it did not look at.",
                WhoFixes = "-",
                NextStep = "Nothing to fix on this path as far as it can be seen from here. To diagnose a mail that failed in this direction, start a new case with its headers or its bounce.",
            };
        }

        bool isolated = r.Input.Location == AnalysisLocation.Isolated;
        var x = new Finding
        {
            Severity = Severity.Ok,
            Area = "Summary",
            Title = "No SPF, DKIM, DMARC or DNS problem found on the checked path",
            Detail = "Sender authentication, the sender's DNS and the recipient's mail servers look healthy in the public view. " +
                     "The mail was most likely accepted and then filtered at the recipient, or it never left the sender's system." +
                     (isolated ? " The remaining checks need access to the mail systems themselves, which this analysis system does not have." : ""),
            WhoFixes = "Recipient's mail admin; sender's mail admin",
            NextStep = "Recipient's mail admin: search quarantine and junk for the sender's address, run a message trace for the time and sender, check mailbox and transport rules. " +
                       "Sender's mail admin: check the outgoing queue / message trace for the recipient and any bounce. " +
                       "A test from the sender to a freemail mailbox shows how the sender's mail is judged elsewhere.",
        };
        if (r.Input.OtherMailWorks)
        {
            bool inbound = r.Input.Direction == Direction.Inbound;
            x.Detail += inbound
                ? " The recipient's side is stated to receive other mail normally, so the sender should check its outgoing log for this recipient and look for a bounce."
                : " The sender's other mail is stated to reach other recipients, so the recipient's filtering is the most likely place to look.";
        }
        if (r.Ndr.HasAnything && r.Ndr.Primary is null) x.Because.Add("the bounce had no status code");
        return x;
    }

    // ================================================================== helpers

    private static Finding With(this Finding f, string? because)
    {
        if (!string.IsNullOrEmpty(because)) f.Because.Add(because);
        return f;
    }

    private static Finding WithEvidence(this Finding f, IEnumerable<string> lines)
    {
        f.Evidence.AddRange(lines);
        return f;
    }
}
