using System;
using System.Collections.Generic;
using System.Linq;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

/// <summary>
/// The rules that only need public DNS and the evidence: the failing mail against the working
/// one, which DNS path was used, whether a zone's name servers agree, the site's DNS against the
/// public view, and when a zone last changed.
/// </summary>
public static partial class Diagnoser
{
    // ================================================================== the failing mail

    private static void FailingMail(AnalysisResult r, List<Finding> f, string who)
    {
        var fail = r.FailingEvidence;
        if (fail is null || !fail.HasAnything) return;
        bool fromBounce = r.FailingFromBounce;
        var b = r.Baseline;
        string src = fromBounce ? "the returned message in the bounce" : "the failing mail";

        // ---- how the receiving server judged the failing copy (a released or junked copy, a test to freemail)
        if (!fromBounce && fail.PrimaryAuth is not null)
        {
            string results = $"spf={fail.SpfResult ?? "-"}, dkim={(fail.DkimResults.Count > 0 ? string.Join("/", fail.DkimResults.Select(d => d.Result)) : "none")}, dmarc={fail.DmarcResult ?? "-"}"
                             + (fail.CompAuth is null ? "" : $", compauth={fail.CompAuth}");

            if (fail.DmarcResult is "fail" or "permerror")
            {
                var x = new Finding
                {
                    Severity = Severity.Critical,
                    Area = "Failing mail",
                    Title = $"The receiver recorded dmarc={fail.DmarcResult} for the failing mail",
                    Detail = $"Its Authentication-Results say {results}. DMARC was carried by: {fail.DmarcCarriedBy}." +
                             (b.HasAnything && b.PrimaryAuth is not null ? $" The working mail was carried by: {b.DmarcCarriedBy}." : ""),
                    WhoFixes = who,
                    NextStep = "Compare the failing mail's sending IP and DKIM d=/s= with the working one (see below) and fix the leg that broke.",
                    Score = BonusBounce,
                };
                x.Because.Add("recorded by the receiving server for the failing mail itself");
                x.Evidence.Add(fail.PrimaryAuth.Raw);
                f.Add(x);
            }
            else if (fail.CompAuth is "fail" or "softfail")
            {
                var x = new Finding
                {
                    Severity = Severity.Warning,
                    Area = "Failing mail",
                    Title = $"Microsoft rated the failing mail compauth={fail.CompAuth} (reason {fail.CompAuthReason})",
                    Detail = $"Its Authentication-Results say {results}. Composite authentication failing sends mail to junk or quarantine even without a DMARC reject.",
                    WhoFixes = who,
                    NextStep = "Check quarantine; then make SPF or DKIM pass aligned with the From domain.",
                    Score = BonusBounce / 2,
                };
                x.Evidence.Add(fail.PrimaryAuth.Raw);
                f.Add(x);
            }
            else if (fail.DmarcResult is "pass")
            {
                f.Add(new Finding
                {
                    Severity = Severity.Info,
                    Area = "Failing mail",
                    Title = "The failing mail passed DMARC at the receiver",
                    Detail = $"Its Authentication-Results say {results}. For this copy authentication was not the problem; look at the spam rating, quarantine and transport rules.",
                    WhoFixes = "-",
                    NextStep = "-",
                });
            }

            bool spam = fail.Scl is >= 5 || fail.SpamVerdict is "SFV:SPM" ||
                        (fail.SpamScore is { } fs && fail.SpamThreshold is { } ft && ft > 0 && fs >= ft);
            if (spam)
            {
                var x = new Finding
                {
                    Severity = Severity.Warning,
                    Area = "Content",
                    Title = "The failing mail was rated as spam",
                    Detail = string.Join(", ", new[]
                             {
                                 fail.Scl is { } scl ? $"SCL {scl}" : null,
                                 fail.Bcl is { } bcl ? $"BCL {bcl}" : null,
                                 fail.SpamVerdict,
                                 fail.SpamScore is { } sc ? $"score {sc}" : null,
                             }.Where(s => s is not null))
                             + (b.Scl is { } bs ? $" (the working mail: SCL {bs})" : "")
                             + ". It went to junk or quarantine on content or reputation, not on DNS.",
                    WhoFixes = "Receiver's mail admin (quarantine, allow list); sender (content)",
                    NextStep = "Release it from quarantine and check which rule or score fired.",
                    Score = fail.SpamVerdict is "SFV:SPM" ? BonusBounce : BonusChanged,
                };
                x.Because.Add("recorded by the receiving server for the failing mail itself");
                f.Add(x);
            }
        }

        if (!b.HasAnything) return;

        // ---- the path, compared field by field
        var fIp = fail.SendingIp;
        var bIp = b.SendingIp;
        if (fIp is not null && bIp is not null && NetUtil.IsPublic(fIp) && NetUtil.IsPublic(bIp) && !fIp.Equals(bIp))
        {
            var spf = r.SpfFor(fIp);
            bool authorised = spf?.Verdict == SpfVerdict.Pass;
            var x = new Finding
            {
                Severity = spf is null ? Severity.Warning : authorised ? Severity.Info : Severity.Critical,
                Area = "Failing mail",
                Title = authorised
                    ? $"The failing mail left from a different IP ({fIp}), which SPF authorises"
                    : $"The failing mail left from {fIp}, the working one from {bIp}" + (spf is null ? "" : $"; SPF says {spf.Verdict.ToString().ToLowerInvariant()} for {fIp}"),
                Detail = authorised
                    ? "Different server or pool member of the same service; SPF covers it."
                    : "The mail now goes out through a different server or service. " +
                      (spf is null ? "SPF was not evaluated for this IP." : $"SPF for it: {spf.Reason}.") +
                      " A new CRM, scanner, cloud service or a changed relay is the usual reason.",
                WhoFixes = authorised ? "-" : who,
                NextStep = authorised ? "-" : $"Authorise {fIp} in SPF (the service's include:), or send through the server that worked.",
                Score = authorised ? 0 : BonusChanged,
            };
            if (!authorised) x.Because.Add("the sending path changed");
            if (fail.SendingHost is not null || fail.SendingHelo is not null) x.Evidence.Add($"Failing: {fail.SendingHost ?? "-"} (HELO {fail.SendingHelo ?? "-"})");
            if (b.SendingHost is not null || b.SendingHelo is not null) x.Evidence.Add($"Working: {b.SendingHost ?? "-"} (HELO {b.SendingHelo ?? "-"})");
            f.Add(x);
        }
        else if (fIp is not null && bIp is not null && fIp.Equals(bIp))
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Failing mail",
                Title = $"Working and failing mail left from the same IP ({fIp})",
                Detail = "The sending path did not change; look at DNS records, content and the receiver.",
                WhoFixes = "-",
                NextStep = "-",
            });
        }

        var fEnv = fail.SpfDomain ?? fail.EnvelopeDomain;
        var bEnv = b.SpfDomain ?? b.EnvelopeDomain;
        if (!string.IsNullOrEmpty(fEnv) && !string.IsNullOrEmpty(bEnv) && !DomainUtil.AlignedStrict(fEnv, bEnv))
        {
            f.Add(new Finding
            {
                Severity = DomainUtil.AlignedRelaxed(fEnv, fail.FromDomain) ? Severity.Warning : Severity.Critical,
                Area = "Failing mail",
                Title = $"The failing mail uses a different envelope sender: {fEnv} (working: {bEnv})",
                Detail = "SPF is checked against the envelope domain. " +
                         (DomainUtil.AlignedRelaxed(fEnv, fail.FromDomain)
                             ? "It still aligns with the From domain."
                             : $"{fEnv} does not align with the From domain {fail.FromDomain}, so SPF no longer counts for DMARC."),
                WhoFixes = who,
                NextStep = "Configure the sending service to use the domain's own bounce address (custom Return-Path / MAIL FROM domain).",
                Score = BonusChanged,
            });
        }

        if (!string.IsNullOrEmpty(fail.FromDomain) && !string.IsNullOrEmpty(b.FromDomain) && !DomainUtil.AlignedRelaxed(fail.FromDomain, b.FromDomain))
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Failing mail",
                Title = $"The failing mail has a different From domain: {fail.FromDomain} (working: {b.FromDomain})",
                Detail = "DMARC and DKIM alignment follow the From domain, so the checks above may be about the wrong domain.",
                WhoFixes = "-",
                NextStep = $"Check the targets on the Checks page and run again for {fail.FromDomain} if needed.",
            });
        }

        // DKIM: signed then, unsigned or signed differently now?
        var bAligned = b.DkimSignatures.Where(s => DomainUtil.AlignedRelaxed(s.Domain, b.FromDomain)).ToList();
        var fAligned = fail.DkimSignatures.Where(s => DomainUtil.AlignedRelaxed(s.Domain, fail.FromDomain)).ToList();
        if (bAligned.Count > 0 && fail.DkimSignatures.Count == 0)
        {
            var x = new Finding
            {
                Severity = fromBounce ? Severity.Info : Severity.Critical,
                Area = "Failing mail",
                Title = $"{(fromBounce ? "The returned message" : "The failing mail")} carries no DKIM signature; the working one was signed by {bAligned[0].Domain}",
                Detail = fromBounce
                    ? "Bounces sometimes return the headers as they were before signing, so this is only a hint."
                    : "Signing is not happening on the new path: a different outgoing server, a connector that bypasses the signing gateway, or DKIM switched off.",
                WhoFixes = who,
                NextStep = "Find where the failing mail left (see the sending IP) and enable DKIM signing there.",
                Score = fromBounce ? 0 : BonusChanged + (b.DmarcCarriedBy == "DKIM only" ? BonusDmarc : 0),
            };
            if (!fromBounce) x.Because.Add("the working mail was signed, the failing one is not");
            f.Add(x);
        }
        else if (bAligned.Count > 0 && fail.DkimSignatures.Count > 0 && fAligned.Count == 0)
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Failing mail",
                Title = $"The failing mail is signed by {string.Join(", ", fail.DkimSignatures.Select(s => s.Domain).Distinct())}, not by {fail.FromDomain}",
                Detail = $"The working mail had an aligned signature ({bAligned[0].Domain}). A platform's own signature does not count for DMARC.",
                WhoFixes = who,
                NextStep = "Set up DKIM with the From domain on the platform the failing mail came from.",
                Score = BonusChanged,
            });
        }
        else if (bAligned.Count > 0 && fAligned.Count > 0 &&
                 !fAligned.Any(fs => bAligned.Any(bs => bs.Selector.Equals(fs.Selector, StringComparison.OrdinalIgnoreCase) && bs.Domain == fs.Domain)))
        {
            var sel = fAligned[0];
            var key = r.Dkim.FirstOrDefault(k => k.Selector.Equals(sel.Selector, StringComparison.OrdinalIgnoreCase) && k.Domain == sel.Domain);
            f.Add(new Finding
            {
                Severity = key is not null && key.Status != DkimKeyStatus.Found ? Severity.Critical : Severity.Info,
                Area = "Failing mail",
                Title = $"The failing mail is signed with selector {sel.Selector} (working: {bAligned[0].Selector})",
                Detail = key is null ? "The new selector's key was not checked." : $"Key {key.QueryName}: {key.Status} - {key.Detail}.",
                WhoFixes = key is not null && key.Status != DkimKeyStatus.Found ? who : "-",
                NextStep = key is not null && key.Status != DkimKeyStatus.Found ? $"Publish the key for {sel.Selector}._domainkey.{sel.Domain}." : "-",
                Score = key is not null && key.Status != DkimKeyStatus.Found ? BonusChanged : 0,
            });
        }

        // Forwarding or list on the failing path only.
        bool fForwarded = fail.ArcInstances > 0 || fail.IsListMail;
        bool bForwarded = b.ArcInstances > 0 || b.IsListMail;
        if (fForwarded && !bForwarded)
        {
            f.Add(new Finding
            {
                Severity = Severity.Warning,
                Area = "Failing mail",
                Title = fail.IsListMail ? "The failing mail went through a mailing list" : "The failing mail was forwarded (ARC headers)",
                Detail = "The working one came directly. Forwarding changes the sending IP (SPF fails) and lists often change subject or footer (DKIM fails).",
                WhoFixes = "The forwarder or list operator; or the recipient (send directly)",
                NextStep = "Ask how the failing mail was addressed: to a list, an alias or a forwarding mailbox?",
                Score = BonusChanged,
            });
        }

        // A different sending system, from the oldest hops and the mailer.
        var fOrigin = fail.Hops.LastOrDefault()?.FromHelo;
        var bOrigin = b.Hops.LastOrDefault()?.FromHelo;
        if (!fromBounce && !string.IsNullOrEmpty(fOrigin) && !string.IsNullOrEmpty(bOrigin) &&
            !DomainUtil.AlignedRelaxed(fOrigin, bOrigin) && !fOrigin.Equals(bOrigin, StringComparison.OrdinalIgnoreCase))
        {
            f.Add(new Finding
            {
                Severity = Severity.Info,
                Area = "Failing mail",
                Title = "The failing mail started on a different system",
                Detail = $"First hop: {fOrigin} (working: {bOrigin})." +
                         (fail.Mailer is not null && fail.Mailer != b.Mailer ? $" Mailer: {fail.Mailer} (working: {b.Mailer ?? "-"})." : ""),
                WhoFixes = "-",
                NextStep = "-",
            });
        }
    }

    // ================================================================== which DNS was used

    private static void DnsPath(AnalysisResult r, List<Finding> f)
    {
        if (r.RejectedNames.Count > 0)
        {
            var x = new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "DNS path",
                Title = $"{r.RejectedNames.Count} target(s) not checked: not a domain name",
                Detail = "A domain name is made of letters, digits, hyphens and underscores, with dots between the parts. These contain something else, so nothing was looked up or connected to for them.",
                WhoFixes = "-",
                NextStep = "Correct the name on the Checks page and run again.",
            };
            x.Evidence.AddRange(r.RejectedNames);
            f.Add(x);
        }

        if (r.DnsInterception is { } intercepted)
        {
            bool moved = r.Fallbacks.Count > 0 && r.DnsUnavailable is null;
            var x = new Finding
            {
                Severity = moved ? Severity.Info : Severity.Inconclusive,
                Area = "DNS path",
                Title = "Port 53 is intercepted on this network",
                Detail = "A question sent to a root or top-level name server came back as a recursive resolver's answer: something on this network " +
                         "(firewall DNS proxy, captive portal, provider) answers DNS in place of the servers asked. The authoritative view cannot be had from here. " +
                         (moved ? $"Those answers were not used; DNS came from {r.ResolverUsed} instead."
                                : "Those answers were not used, and there was no other resolver to move to: the DNS checks could not be run."),
                WhoFixes = "-",
                NextStep = moved
                    ? "For the authoritative view (no caches, every name server asked), run from a network with unfiltered port 53."
                    : "Run from a network with unfiltered port 53, or switch on the DNS over HTTPS fallback on the Checks page.",
            };
            x.Evidence.Add(intercepted);
            f.Add(x);
        }

        if (r.DnsUnavailable is { } unavailable && r.DnsPathProblems.Count == 0)
        {
            var x = new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "DNS path",
                Title = "No DNS server could be used from this machine",
                Detail = "None of the resolvers gave a usable answer, so the DNS checks say nothing about the domains. Only the pasted evidence was weighed.",
                WhoFixes = "-",
                NextStep = "Check this machine's network (DNS on port 53, HTTPS to the DNS over HTTPS providers), then run the checks again.",
            };
            x.Evidence.Add(unavailable);
            f.Add(x);
        }

        foreach (var problem in r.DnsPathProblems)
        {
            f.Add(new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "DNS path",
                Title = "The DNS answers on this machine cannot be trusted",
                Detail = problem,
                WhoFixes = "-",
                NextStep = "Run from another network, or switch on the DNS over HTTPS fallback on the Checks page.",
            });
        }

        if (r.Fallbacks.Count > 0)
        {
            var x = new Finding
            {
                Severity = Severity.Info,
                Area = "DNS path",
                Title = $"DNS answers came from {r.ResolverUsed}",
                Detail = "The chosen resolver could not be used from this machine, so the next one in line was used.",
                WhoFixes = "-",
                NextStep = "-",
            };
            x.Evidence.AddRange(r.Fallbacks);
            f.Add(x);
        }

        if (r.NameServersSkipped)
        {
            f.Add(new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "Name servers",
                Title = "The authoritative name servers could not be asked one by one",
                Detail = (r.Options.Resolver.Kind == ResolverKind.Authoritative || r.Input.Location == AnalysisLocation.Internal
                             ? $"That needs UDP or TCP port 53 to the internet, which is not open from here (answers came via {r.ResolverUsed})."
                             : $"That needs the authoritative mode (answers came via {r.ResolverUsed}).")
                         + " Disagreeing name servers, a cause of mail that fails only sometimes, cannot be ruled out.",
                WhoFixes = "-",
                NextStep = "Run again from a machine that may send DNS queries directly, or ask the domain's DNS host.",
            });
        }
    }

    // ================================================================== do the name servers agree?

    private static void NameServers(AnalysisResult r, List<Finding> f, bool inbound)
    {
        if (r.NameServers.Count == 0) return;
        string sender = "Sender's DNS host";
        string receiver = "Recipient's DNS host";
        bool anyProblem = false;

        foreach (var c in r.NameServers.Where(c => c.Variants > 1))
        {
            anyProblem = true;
            bool auth = c.Purpose.StartsWith("SPF") || c.Purpose.StartsWith("DKIM") || c.Purpose.StartsWith("DMARC");
            var x = new Finding
            {
                Severity = auth || c.Purpose.Contains("receiver") ? Severity.Critical : Severity.Warning,
                Area = "Name servers",
                Title = $"The name servers of {c.Zone} give different {c.Purpose} answers",
                Detail = "Receivers ask one of them at random, so the same mail passes or fails depending on which server answered. " +
                         "Usually a secondary that no longer receives zone transfers, or a change made at only one of two DNS providers.",
                WhoFixes = c.Purpose.Contains("receiver") ? receiver : sender,
                NextStep = $"Make every name server of {c.Zone} serve the same record (check zone transfers / the second DNS provider).",
                Score = BonusChanged + (auth ? BonusDmarc : 0),
            };
            x.Because.Add("explains mail that fails only some of the time");
            foreach (var a in c.Responding) x.Evidence.Add($"{a.Server} ({a.Ip}): {a.Response.Fingerprint()}");
            f.Add(x);
        }

        // Silent or lame servers, one finding per zone.
        foreach (var zone in r.NameServers.GroupBy(c => c.Zone))
        {
            var silent = zone.SelectMany(c => c.Silent).GroupBy(a => a.Server).Select(g => g.First()).ToList();
            if (silent.Count == 0) continue;
            anyProblem = true;
            int total = zone.SelectMany(c => c.Answers).Select(a => a.Server).Distinct().Count();
            bool all = silent.Count >= total;
            var x = new Finding
            {
                Severity = all ? Severity.Critical : Severity.Warning,
                Area = "Name servers",
                Title = all
                    ? $"None of the name servers of {zone.Key} answers properly"
                    : $"{silent.Count} of {total} name servers of {zone.Key} do not answer properly",
                Detail = all
                    ? "Receivers get SERVFAIL for every record of this zone: SPF, DKIM and DMARC all fail temporarily and mail is deferred, then bounced."
                    : "Receivers that pick the broken server time out and retry, or give up: delays and occasional failures.",
                WhoFixes = zone.Any(c => c.Purpose.Contains("receiver")) ? receiver : sender,
                NextStep = "Fix or remove the broken server in the NS delegation at the registrar.",
                Score = all ? BonusChanged : 0,
            };
            foreach (var a in silent) x.Evidence.Add($"{a.Server} ({a.Ip?.ToString() ?? "no address"}): {a.Response.Describe()}");
            f.Add(x);
        }

        if (!anyProblem)
        {
            var zones = r.NameServers.Select(c => c.Zone).Distinct().ToList();
            var x = new Finding
            {
                Severity = Severity.Ok,
                Area = "Name servers",
                Title = $"All name servers agree ({string.Join(", ", zones)})",
                Detail = $"{r.NameServers.Count} key records asked of every authoritative server; the answers are identical.",
                WhoFixes = "-",
                NextStep = "-",
            };
            foreach (var c in r.NameServers) x.Evidence.Add($"{c.Purpose}: {c.Answers.Count} servers, {c.Responding.FirstOrDefault()?.Response.Fingerprint()}");
            f.Add(x);
        }
    }

    // ================================================================== the site's DNS against the public view

    private static void SplitDns(AnalysisResult r, List<Finding> f, bool inbound)
    {
        if (r.Split.Count == 0) return;
        string site = inbound ? "recipient" : "sender";
        var diffs = r.Split.Where(s => s.Differs).ToList();

        foreach (var s in diffs)
        {
            bool oursBroken = s.Internal.IsTransient && !s.Public.IsTransient;
            var x = new Finding
            {
                Severity = oursBroken && inbound ? Severity.Critical : Severity.Warning,
                Area = "Internal DNS",
                Title = oursBroken
                    ? $"The internal DNS at the {site}'s site cannot resolve {s.Name} ({s.Purpose}); the public DNS can"
                    : $"The internal DNS at the {site}'s site answers {s.Purpose} for {s.Name} differently than the public DNS",
                Detail = oursBroken
                    ? (inbound
                        ? "If the recipient's mail gateway uses this resolver, it cannot check the sender's SPF/DKIM/DMARC and defers or rejects the sender's mail. Typical: a forwarder that blocks or mangles TXT answers, or DNSSEC validation failing locally."
                        : "Systems at the sender's site cannot see this record, though external receivers can.")
                    : "Split DNS, or a stale cache in a forwarder. External receivers see the public answer; internal systems see the internal one. Admins checking from inside see a record the rest of the internet does not.",
                WhoFixes = $"DNS admin at the {site}'s site",
                NextStep = oursBroken
                    ? "Check the internal resolver and its forwarders for this name; flush its cache; compare with an outside query."
                    : "Decide which answer is right; fix the internal zone or flush the forwarder cache.",
                Score = oursBroken && inbound ? BonusChanged : 0,
            };
            x.Evidence.Add("Internal: " + s.Internal.Describe());
            x.Evidence.Add("Public:   " + s.Public.Describe());
            f.Add(x);
        }

        if (diffs.Count == 0)
        {
            f.Add(new Finding
            {
                Severity = Severity.Ok,
                Area = "Internal DNS",
                Title = $"The internal DNS at the {site}'s site and the public DNS agree on {r.Split.Count} key records",
                Detail = "No split DNS or stale cache for the records that matter here.",
                WhoFixes = "-",
                NextStep = "-",
            });
        }
    }

    // ================================================================== when did the zones change?

    private static void Zones(AnalysisResult r, List<Finding> f)
    {
        var working = r.Baseline.Date;
        foreach (var z in r.Zones.Where(z => z.Date is not null))
        {
            var date = z.Date!.Value;
            bool dayOnly = z.Convention == "YYYYMMDDnn";
            string when = dayOnly ? date.ToString("yyyy-MM-dd") : date.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            string serial = $"SOA serial {z.Serial} ({z.Convention})";

            // A date serial far older than the working mail on a zone in use: the host does not
            // maintain the serial, so it says nothing about edits.
            if (dayOnly && working is { } wStale && date < wStale.AddDays(-365))
            {
                f.Add(new Finding
                {
                    Severity = Severity.Inconclusive,
                    Area = "DNS",
                    Title = $"The SOA serial of {z.Domain} is not maintained ({when})",
                    Detail = $"{serial} is more than a year older than the working mail ({wStale.ToLocalTime():yyyy-MM-dd}). The DNS host evidently does not update the serial when records change, so the zone's change history cannot be read from it.",
                    WhoFixes = "-",
                    NextStep = $"Ask the owner of {z.Domain} whether DNS records were changed recently; a passive-DNS service can show record history.",
                });
                continue;
            }

            if (working is { } w)
            {
                bool after = dayOnly ? date.UtcDateTime.Date > w.UtcDateTime.Date : date > w;
                bool justNow = !dayOnly && (DateTimeOffset.UtcNow - date) < TimeSpan.FromHours(24);
                if (after)
                {
                    f.Add(new Finding
                    {
                        Severity = justNow ? Severity.Info : Severity.Warning,
                        Area = "DNS",
                        Title = $"The DNS zone {z.Domain} changed after the working mail",
                        Detail = $"{serial} reads as {when}; the working mail is from {w.ToLocalTime():yyyy-MM-dd HH:mm}. A record that broke delivery may have changed then." +
                                 (justNow ? " The change is from the last 24 hours, which for timestamp serials is often automatic re-signing (DNSSEC), not an edit." : "") +
                                 " Some DNS hosts bump the serial without a real change, so this is a lead, not proof.",
                        WhoFixes = z.Side == "sender" ? "Owner of the sending domain" : "Owner of the receiving domain",
                        NextStep = $"Ask what was changed in {z.Domain} around {when} (new mail service, DKIM rotation, SPF edit, DNS provider move).",
                        Score = justNow ? 0 : 15,
                    });
                }
                else
                {
                    f.Add(new Finding
                    {
                        Severity = Severity.Info,
                        Area = "DNS",
                        Title = $"The DNS zone {z.Domain} has not changed since the working mail",
                        Detail = $"{serial} reads as {when}, before the working mail ({w.ToLocalTime():yyyy-MM-dd}). If the host bumps the serial on every edit, the records are the same as when it worked; look at the sending path, content and the receiver.",
                        WhoFixes = "-",
                        NextStep = "-",
                    });
                }
            }
            else
            {
                f.Add(new Finding
                {
                    Severity = Severity.Info,
                    Area = "DNS",
                    Title = $"The DNS zone {z.Domain} was last changed {when}",
                    Detail = $"{serial}. With headers of a working mail this could be compared with its date.",
                    WhoFixes = "-",
                    NextStep = "-",
                });
            }
        }
    }

    // ================================================================== pasted record history

    private static void History(AnalysisResult r, List<Finding> f)
    {
        var w = r.Baseline.Date;
        if (r.HistoryChanges.Count > 0 && w is { } sent)
        {
            var changed = new Finding
            {
                Severity = Severity.Warning,
                Area = "History",
                Title = $"Records changed after the working mail ({r.HistoryChanges.Count} change(s) in the pasted history)",
                Detail = $"The pasted record history shows values that appeared or disappeared after {sent.ToLocalTime():yyyy-MM-dd}. " +
                         "A change in that window is a candidate trigger; one before it is not, because mail still arrived afterwards. " +
                         "Archives look at a name every few days, so a date marks when the archive noticed, not the exact moment.",
                WhoFixes = "Owner of the sending domain",
                NextStep = "Ask the sender who made these changes and why; restoring the previous value is the quickest test.",
                Score = BonusChanged,
            };
            changed.Evidence.AddRange(r.HistoryChanges.Take(12));
            if (r.HistoryChanges.Count > 12) changed.Evidence.Add($"... {r.HistoryChanges.Count - 12} more in the trace (step History)");
            changed.Because.Add("changed after the working mail");
            f.Add(changed);
        }

        // Then versus now, where the history says something the headers did not.
        var lines = new List<string>();
        if (r.SpfThen is { State: HistoryState.Present, Value: { } spfThen } && r.EnvelopeSpf is { } spfNow)
        {
            var now = spfNow.Record ?? "";
            if (!Same(spfThen, now)) lines.Add($"SPF then: {spfThen}\nSPF now: {(now.Length > 0 ? now : "no record")}");
        }
        if (r.DkimThen is { State: HistoryState.Absent } dkAbsent)
            lines.Add($"DKIM key did not exist when the working mail was sent ({dkAbsent.Source}): mail worked without that key.");
        if (lines.Count > 0)
        {
            var info = new Finding
            {
                Severity = Severity.Info,
                Area = "History",
                Title = "Records at the time of the working mail differ from today",
                Detail = "From the pasted record history: what was published when the working mail arrived, next to what is published now.",
                WhoFixes = "-",
                NextStep = "-",
            };
            info.Evidence.AddRange(lines);
            f.Add(info);
        }
    }

    private static bool Same(string a, string b) =>
        string.Join(' ', a.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Equals(string.Join(' ', b.Split(' ', StringSplitOptions.RemoveEmptyEntries)), StringComparison.OrdinalIgnoreCase);

    // ================================================================== how fast a DNS change takes effect

    private static void Timing(AnalysisResult r, List<Finding> f)
    {
        if (r.Ttls.Count == 0) return;
        var finding = new Finding
        {
            Severity = Severity.Info,
            Area = "DNS timing",
            Title = $"A fix in DNS is visible everywhere within {Duration(r.Ttls.Max(t => t.Seconds))}",
            Detail = "Resolvers keep an answer for its TTL. After a record is published or changed, every resolver sees the new value at the latest once the old answer expires. " +
                     "A record that does not exist yet is cached as \"no record\" for the zone's negative TTL. Receivers that cache longer than the TTL are rare.",
            WhoFixes = "-",
            NextStep = "After the sender publishes a fix, wait this long before testing with a new mail.",
        };
        foreach (var t in r.Ttls)
            finding.Evidence.Add($"{t.Purpose} ({t.Name}): {(t.Negative ? "no record, cached as such for" : "TTL")} {Duration(t.Seconds)} -> changes visible everywhere within {Duration(t.Seconds)}");
        f.Add(finding);

        // Append the propagation time to DMARC findings that carry a record to publish, once.
        var dmarcTtl = r.Ttls.FirstOrDefault(t => t.Purpose == "DMARC");
        if (dmarcTtl.Name is not null)
        {
            foreach (var x in f.Where(x => x.Area == "DMARC" && x.Fix.Length > 0 && !x.Fix.Contains("visible everywhere")))
                x.Fix += $"\n(Visible everywhere within {Duration(dmarcTtl.Seconds)} of publishing.)";
        }
    }

    /// <summary>The records at the time of the working mail and the TTLs, as label/value pairs for the reports.</summary>
    internal static List<(string Label, string Value)> AtTheTimeLines(AnalysisResult r)
    {
        var list = new List<(string, string)>();
        foreach (var t in new[] { r.DmarcThen, r.DkimThen, r.SpfThen })
        {
            if (t is null) continue;
            var state = t.State switch { HistoryState.Present => "existed", HistoryState.Absent => t.Likely ? "most likely did not exist" : "did not exist", _ => "unknown" };
            list.Add(($"{t.Record} when the working mail was sent", $"{state}{(t.Value is { Length: > 0 } v ? ": " + v : "")} ({t.Source})" + (t.Explanation.Length > 0 ? $"; {t.Explanation}" : "")));
        }
        foreach (var c in r.HistoryChanges) list.Add(("Changed after the working mail", c));
        foreach (var t in r.Ttls)
            list.Add(($"TTL {t.Purpose}", $"{t.Name}: {(t.Negative ? "no record, cached for " : "")}{Duration(t.Seconds)} (changes visible everywhere within that time)"));
        return list;
    }

    internal static string Duration(uint seconds)
    {
        if (seconds < 120) return $"{seconds} s";
        if (seconds < 7200) return $"{seconds / 60} min";
        if (seconds < 172800) return seconds % 3600 == 0 ? $"{seconds / 3600} h" : $"{seconds / 3600.0:0.#} h";
        return $"{seconds / 86400.0:0.#} days";
    }

    // ================================================================== can this machine reach port 25?

    private static void ReachFindings(AnalysisResult r, List<Finding> f)
    {
        var reach = r.Reach;
        if (reach is null) return;

        var evidence = reach.All.Select(p => $"{p.Purpose,-28} {p.Host} [{p.Result.Ip}]:{p.Result.Port}  {p.Result.Describe()}").ToList();
        evidence.Add($"This machine's public IP: {reach.PublicIp ?? "unknown (needs port 53)"}{(reach.PublicIp is null ? "" : $"  ({reach.PublicIpSource})")}");

        var x = new Finding
        {
            Severity = reach.Verdict == ReachVerdict.Open ? Severity.Ok : Severity.Inconclusive,
            Area = "SMTP path",
            Title = reach.Verdict switch
            {
                ReachVerdict.Open => "Outbound port 25 works from this machine",
                ReachVerdict.Port25Blocked => "Port 25 is blocked on this machine's path (firewall or ISP); other ports pass",
                ReachVerdict.RejectedHere => "A device near the analysis system rejects port 25",
                ReachVerdict.NoOutbound => "No outbound mail ports open from this machine",
                _ => "Outbound port 25 could not be tested",
            },
            Detail = reach.Summary + (reach.Verdict == ReachVerdict.Open ? "" : " SMTP probes from here say nothing about the recipient; use the evidence and DNS findings."),
            WhoFixes = "-",
            NextStep = reach.Verdict == ReachVerdict.Open ? "-" : "To probe the recipient, run from a host that may send on port 25 (or open TCP/25 outbound for this machine).",
        };
        x.Evidence.AddRange(evidence);
        f.Add(x);

        var listed = reach.PublicIpListings.Where(l => l.Status == ListingStatus.Listed).ToList();
        if (listed.Count > 0)
        {
            var y = new Finding
            {
                Severity = Severity.Info,
                Area = "SMTP path",
                Title = $"This machine's public IP {reach.PublicIp} is on {string.Join(", ", listed.Select(l => l.Name))}",
                Detail = "Mail servers may refuse this machine at the greeting. That concerns the analysis system only, not the case. A PBL listing is normal for access lines.",
                WhoFixes = "-",
                NextStep = "-",
            };
            y.Evidence.AddRange(listed.Select(l => $"{l.Name}: {l.Detail}"));
            f.Add(y);
        }
    }

    /// <summary>A probe that never got an SMTP session, read against the control connections.</summary>
    private static Finding ConnectFailure(AnalysisResult r, SmtpProbeResult p, string who)
    {
        var reach = r.Reach;
        var label = $"{p.Host} [{p.Address}]:25";
        var baseline = reach?.TargetBaseline?.Result;
        double? rtt = baseline is { Outcome: TcpOutcome.Connected or TcpOutcome.Refused } ? baseline.Ms : null;
        var evidence = new List<string> { $"{label}: {p.Error}" };
        if (baseline is not null) evidence.Add($"Baseline {p.Host}:443: {baseline.Describe()}");
        if (reach is not null) evidence.Add($"Reachability from here: {reach.Verdict}");

        // The path from here is not open: nothing can be said about the target.
        if (reach is null || reach.Verdict != ReachVerdict.Open)
        {
            return new Finding
            {
                Severity = Severity.Inconclusive,
                Area = "SMTP",
                Title = $"Probe of {p.Host} not possible from here",
                Detail = (reach is null ? "Port 25 could not be checked against control hosts." : reach.Summary) + " The failed connection to the recipient is therefore not evidence against it.",
                WhoFixes = "-",
                NextStep = "Probe from a host that may send on port 25.",
            }.WithEvidence(evidence);
        }

        // Port 25 works from here (the controls connect), so this is about the target side.
        string myIp = reach.PublicIp ?? "this machine's IP";
        switch (p.Connect)
        {
            case TcpOutcome.Timeout:
                return new Finding
                {
                    Severity = Severity.Warning,
                    Area = "SMTP",
                    Title = $"{p.Host} silently drops port 25 (control hosts connect fine)",
                    Detail = "A firewall on the recipient's side drops the connection without answering. Either port 25 is closed to everyone (the MX record points to a host that no longer receives mail), " +
                             "or it accepts only certain senders - typically only its own filtering service (Mimecast, Proofpoint, Hornetsecurity, EOP) when the MX was moved there but this host is still published.",
                    WhoFixes = who,
                    NextStep = $"Ask the recipient's mail admin: does {p.Address} accept TCP/25 from the internet, or only from a filtering service? The probe came from {myIp}.",
                    Score = BonusChanged,
                }.WithEvidence(evidence);

            case TcpOutcome.Refused:
            {
                bool local = rtt is { } t ? p.ConnectMs < t * 0.4 : p.ConnectMs < 3;
                return new Finding
                {
                    Severity = local ? Severity.Inconclusive : Severity.Warning,
                    Area = "SMTP",
                    Title = local
                        ? $"Port 25 to {p.Host} is reset near the analysis system ({p.ConnectMs:0.0} ms, faster than a round trip)"
                        : $"{p.Host} refuses port 25 (TCP reset after {p.ConnectMs:0} ms)",
                    Detail = local
                        ? "The control hosts connect, but this destination is reset faster than the round trip" + (rtt is { } t2 ? $" ({t2:0} ms)" : "") + ": a rule in the analysis system's network blocks exactly this destination."
                        : "The reset arrives with normal round-trip timing" + (rtt is { } t3 ? $" (443 baseline {t3:0} ms)" : "") + ", so it comes from the target host or its perimeter: nothing listens on port 25, or a firewall rejects it.",
                    WhoFixes = local ? "Firewall admin of the analysis system's network" : who,
                    NextStep = local ? "Check the analysis network's firewall rules for this destination." : $"Ask the recipient's mail admin whether {p.Host} ({p.Address}) should receive mail; if not, the MX record is stale.",
                    Score = local ? 0 : BonusChanged,
                }.WithEvidence(evidence);
            }

            case TcpOutcome.Unreachable:
                return new Finding
                {
                    Severity = Severity.Warning,
                    Area = "SMTP",
                    Title = $"Port 25 to {p.Host} ends in an ICMP reject",
                    Detail = "A router or firewall along the path answered 'unreachable'. Its address is in the ICMP packet: the analysis network's firewall log shows the source. If it belongs to the recipient's network, they block it; if to a provider in between, the route is broken.",
                    WhoFixes = "Depends on the ICMP source",
                    NextStep = "Look up the ICMP source address in the analysis network's firewall log (whois / ASN) to see whose network rejected it.",
                }.WithEvidence(evidence);

            default:
                return new Finding
                {
                    Severity = Severity.Inconclusive,
                    Area = "SMTP",
                    Title = $"Probe of {p.Host} failed",
                    Detail = p.Error ?? "unknown error",
                    WhoFixes = "-",
                    NextStep = "See the trace.",
                }.WithEvidence(evidence);
        }
    }

    // ================================================================== finding -> trace steps

    private static string[] TraceStepsFor(string area) => area switch
    {
        "Bounce" or "Headers" or "Content" or "Failing mail" => new[] { "Evidence" },
        "SPF" => new[] { "SPF", "Evidence", "History" },
        "DKIM" => new[] { "DKIM", "Evidence", "History" },
        "DMARC" => new[] { "DMARC", "SPF", "DKIM", "Evidence", "History" },
        "History" => new[] { "History", "Evidence" },
        "DNS timing" => new[] { "SPF", "DMARC", "DKIM", "Zone" },
        "DNS" => new[] { "Sender DNS", "Zone" },
        "Reverse DNS" => new[] { "PTR" },
        "Reputation" => new[] { "Blocklists" },
        "Routing" => new[] { "MX" },
        "TLS" => new[] { "MTA-STS", "SMTP" },
        "SMTP" => new[] { "SMTP", "Reach" },
        "SMTP path" => new[] { "Reach" },
        "Name servers" => new[] { "NS" },
        "Internal DNS" => new[] { "Split" },
        "Sender setup" => new[] { "SPF", "DKIM", "PTR", "Evidence" },
        "DNS path" => new[] { "Setup", "Diagnosis" },
        "Path" => new[] { "Evidence", "SPF", "DKIM" },
        _ => Array.Empty<string>(),
    };

    // ================================================================== what differs from the working mail

    /// <summary>
    /// Marks, per comparison row, where the failing mail and today's live result differ from
    /// the working mail. Only where both sides are known: a dash is not a change.
    /// </summary>
    private static void MarkChanges(AnalysisResult r)
    {
        var b = r.Baseline;
        var fl = r.FailingEvidence;
        foreach (var row in r.Compare)
        {
            row.FailingChanged = fl is not null && Known(row.Then) && Known(row.Failing)
                                 && !row.Then.Equals(row.Failing, StringComparison.OrdinalIgnoreCase)
                                 && !row.Then.Contains("not reported") && !row.Failing.Contains("not reported");

            string? note = null;
            bool helps = false;   // true: the change is in favour of delivery
            if (row.Check == "Sending IP")
            {
                if (b.SendingIp is not null && r.SendingIp is not null && !b.SendingIp.Equals(r.SendingIp))
                    note = $"checked {r.SendingIp}, the working mail came from {b.SendingIp}";
            }
            else if (row.Check.StartsWith("SPF (") && r.SpfNow is { } spf && row.Now.EndsWith($"for {spf.Ip}"))
            {
                var nowWord = spf.Verdict.ToString().ToLowerInvariant();
                if (b.SpfResult is { } then && !then.Equals(nowWord, StringComparison.OrdinalIgnoreCase))
                {
                    note = $"spf={then} then, {nowWord} now";
                    helps = spf.Verdict == SpfVerdict.Pass;
                }
            }
            else if (row.Check.StartsWith("DKIM "))
            {
                var key = r.Dkim.FirstOrDefault(k => row.Check == $"DKIM {k.Selector} ({k.Domain})");
                if (key is not null && row.Then.Equals("pass", StringComparison.OrdinalIgnoreCase) && key.Status != DkimKeyStatus.Found)
                    note = $"passed then, key now {key.Status.ToString().ToLowerInvariant()}";
            }
            else if (row.Check.StartsWith("DMARC (") && r.Dmarc is { } d)
            {
                if (!d.Found && r.DmarcThen?.State != HistoryState.Absent
                    && (r.DmarcThen?.State == HistoryState.Present || b.DmarcPolicyThen is not null
                        || (b.DmarcResult is { } res && res.ToLowerInvariant() is not ("none" or "bestguesspass" or "temperror"))))
                    note = r.DmarcThen is { State: HistoryState.Present, Source.Length: > 0 } dt
                        ? $"record existed then ({dt.Source}), gone now"
                        : "record existed then, gone now";
                else if (b.DmarcPolicyThen is { } pThen && d.Found && !pThen.Equals(d.Policy, StringComparison.OrdinalIgnoreCase))
                {
                    note = $"policy p={pThen} then, p={d.Policy} now";
                    helps = PolicyRank(d.Policy) < PolicyRank(pThen);
                }
                else if (b.DmarcResult == "pass" && row.Verdict == Severity.Critical)
                    note = "passed then, cannot pass now";
            }
            else if (row.Check == "DMARC carried by")
            {
                // "not reported" is not a result: nothing to compare against.
                var now = row.Now.Replace(" (key present)", "");
                if (Known(row.Then) && !row.Then.Contains("not reported") && now != "unknown" && Known(now)
                    && !now.Equals(row.Then, StringComparison.OrdinalIgnoreCase))
                {
                    note = $"{row.Then} then, {now} now";
                    helps = Legs(now) > Legs(row.Then);
                    if (helps && row.Now.Contains("(key present)"))
                        note += " (a key is published; whether the mail is signed shows only in a current mail's headers)";
                }
            }
            else if (row.Check == "Reverse DNS" && r.Ptr is { } p)
            {
                if (b.SendingHost is { } host && b.SendingIp is not null && b.SendingIp.Equals(p.Ip)
                    && !host.Equals(p.ConfirmedName ?? "", StringComparison.OrdinalIgnoreCase))
                    note = $"{host} then, {p.ConfirmedName ?? "no confirmed name"} now";
            }
            else if (row.Check.StartsWith("Zone ") && row.Verdict == Severity.Warning)
            {
                note = "zone changed after the working mail";
            }

            if (note is not null)
            {
                row.NowChanged = true;
                row.ChangeHelps = helps;
                row.ChangeNote = note;
            }
        }
    }

    private static int PolicyRank(string? p) => p switch { "reject" => 2, "quarantine" => 1, _ => 0 };

    private static int Legs(string carried) =>
        carried.StartsWith("SPF and DKIM", StringComparison.OrdinalIgnoreCase) ? 2
        : carried.StartsWith("SPF only", StringComparison.OrdinalIgnoreCase) || carried.StartsWith("DKIM only", StringComparison.OrdinalIgnoreCase) ? 1
        : 0;

    private static bool Known(string? s) =>
        !string.IsNullOrWhiteSpace(s) && s != "-" && s != "probe"
        && !s.Contains("not reported", StringComparison.OrdinalIgnoreCase)
        && !s.StartsWith("no Authentication-Results", StringComparison.OrdinalIgnoreCase);
}
