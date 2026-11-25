using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

public static class CaseAnalyzer
{
    // ================================================================== suggestions

    /// <summary>
    /// Works out which domains, IP and selectors to check from what the technician supplied.
    /// Inbound: the external party sends, the supported site receives.
    /// Outbound: the supported site sends, the external party receives.
    /// A failing mail, when given, outranks the working one for the sending side: its path is
    /// the one that has to be checked.
    /// </summary>
    public static CheckTargets Suggest(CaseInput input, MailEvidence baseline, MailEvidence failing, NdrInfo ndr)
    {
        var t = new CheckTargets();
        var their = DomainUtil.DomainOf(input.TheirAddress);
        var ours = DomainUtil.DomainOf(input.OurAddress);
        var embedded = ndr.Embedded;

        // The evidence that describes the sending side, best first.
        var senderSide = new List<(MailEvidence Mail, string Label)>();

        if (input.Direction == Direction.Inbound)
        {
            // Inbound: both the working and the failing mail come from the external sender.
            if (failing.HasAnything) senderSide.Add((failing, "the failing mail"));
            if (baseline.HasAnything) senderSide.Add((baseline, "the working mail"));
            if (embedded is not null) senderSide.Add((embedded, "the returned message in the bounce"));

            t.SenderDomain = Pick(their, failing.FromDomain, baseline.FromDomain, embedded?.FromDomain);
            var ourFromHeaders = baseline.To.Concat(failing.To).Select(DomainUtil.DomainOf).FirstOrDefault(d => d.Length > 0);
            t.ReceiverDomain = Pick(ours, ourFromHeaders, ndr.Recipients.Select(DomainUtil.DomainOf).FirstOrDefault());

            if (!string.IsNullOrEmpty(their) && !string.IsNullOrEmpty(baseline.FromDomain)
                && !DomainUtil.AlignedRelaxed(their, baseline.FromDomain))
                t.Notes.Add($"The working mail is from {baseline.FromDomain}, but you named {their}. Checking {t.SenderDomain}; correct it below if the headers belong to another sender.");
        }
        else
        {
            if (string.IsNullOrEmpty(ours))
            {
                var guess = Pick(failing.FromDomain, embedded?.FromDomain);
                if (guess.Length > 0)
                {
                    ours = guess;
                    t.Notes.Add($"Sender domain taken from {(failing.HasAnything ? "the failing mail" : "the returned message in the bounce")}: {ours}.");
                }
            }

            bool baselineIsOurs = ours.Length > 0 && DomainUtil.AlignedRelaxed(ours, baseline.FromDomain);
            if (failing.HasAnything && DomainUtil.AlignedRelaxed(ours, failing.FromDomain)) senderSide.Add((failing, "the failing mail"));
            if (baselineIsOurs) senderSide.Add((baseline, "the sender's working mail as received by the recipient"));
            if (embedded is not null) senderSide.Add((embedded, "the returned message in the bounce"));

            t.SenderDomain = Pick(ours, failing.FromDomain, embedded?.FromDomain);
            if (baselineIsOurs)
            {
                t.ReceiverDomain = Pick(their, ndr.Recipients.Select(DomainUtil.DomainOf).FirstOrDefault(),
                                        baseline.To.Concat(failing.To).Select(DomainUtil.DomainOf).FirstOrDefault(d => !DomainUtil.AlignedRelaxed(d, ours)));
            }
            else
            {
                // A reply from the external party names its domain, not the sending side.
                t.ReceiverDomain = Pick(their, ndr.Recipients.Select(DomainUtil.DomainOf).FirstOrDefault(),
                                        failing.To.Select(DomainUtil.DomainOf).FirstOrDefault(d => !DomainUtil.AlignedRelaxed(d, ours)),
                                        baseline.FromDomain);
                if (baseline.HasAnything)
                    t.Notes.Add("The working-mail headers are of a mail from the recipient to the sender: they describe the recipient's servers, not the sender's sending path.");
            }
        }

        // Envelope domain and IP: from the best sender-side evidence that has them.
        foreach (var (mail, label) in senderSide)
        {
            if (t.EnvelopeDomain.Length == 0 && !string.IsNullOrEmpty(mail.SpfDomain ?? mail.EnvelopeDomain)
                && DomainUtil.AlignedRelaxed(mail.FromDomain ?? t.SenderDomain, t.SenderDomain))
                t.EnvelopeDomain = Pick(mail.SpfDomain, mail.EnvelopeDomain);

            if (t.SendingIp.Length == 0 && mail.SendingIp is not null && NetUtil.IsPublic(mail.SendingIp))
            {
                t.SendingIp = mail.SendingIp.ToString();
                t.Notes.Add($"Sending IP from {label}: {mail.SendingIpSource}.");
            }
            AddDkimFromEvidence(t, mail, input.Direction == Direction.Outbound ? t.SenderDomain : null);
        }

        if (t.SendingIp.Length == 0 && senderSide.Count > 0)
            t.Notes.Add("No public sending IP in the evidence: SPF is checked as a record only. Enter the IP if you know it.");

        if (failing.HasAnything && baseline.HasAnything && failing.SendingIp is not null && baseline.SendingIp is not null
            && !failing.SendingIp.Equals(baseline.SendingIp) && input.Direction == Direction.Inbound)
            t.Notes.Add($"The failing mail left from {failing.SendingIp}, the working one from {baseline.SendingIp}. SPF is evaluated for both.");

        if (string.IsNullOrEmpty(t.EnvelopeDomain)) t.EnvelopeDomain = t.SenderDomain;
        return t;
    }

    private static void AddDkimFromEvidence(CheckTargets t, MailEvidence e, string? onlyDomain)
    {
        foreach (var sig in e.DkimSignatures)
        {
            if (string.IsNullOrEmpty(sig.Selector) || string.IsNullOrEmpty(sig.Domain)) continue;
            if (onlyDomain is not null && !DomainUtil.AlignedRelaxed(sig.Domain, onlyDomain)) continue;
            if (t.Dkim.Any(d => d.Selector.Equals(sig.Selector, StringComparison.OrdinalIgnoreCase) && d.Domain == sig.Domain)) continue;
            t.Dkim.Add(new DkimTarget { Selector = sig.Selector, Domain = sig.Domain, FromEvidence = true });
        }
        foreach (var (_, domain, selector) in e.DkimResults)
        {
            if (string.IsNullOrEmpty(selector) || string.IsNullOrEmpty(domain)) continue;
            if (onlyDomain is not null && !DomainUtil.AlignedRelaxed(domain, onlyDomain)) continue;
            if (t.Dkim.Any(d => d.Selector.Equals(selector, StringComparison.OrdinalIgnoreCase) && d.Domain == domain)) continue;
            t.Dkim.Add(new DkimTarget { Selector = selector, Domain = domain, FromEvidence = true });
        }
    }

    private static string Pick(params string?[] candidates) =>
        candidates.FirstOrDefault(c => !string.IsNullOrWhiteSpace(c))?.Trim().ToLowerInvariant() ?? "";

    /// <summary>Parses "selector._domainkey.domain", "selector:domain" or "selector@domain" lines.</summary>
    public static List<DkimTarget> ParseDkimLines(string text, string defaultDomain, IEnumerable<DkimTarget> known)
    {
        var list = new List<DkimTarget>();
        foreach (var raw in text.Split(new[] { '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            string selector, domain;
            int dk = line.IndexOf("._domainkey.", StringComparison.OrdinalIgnoreCase);
            if (dk > 0)
            {
                selector = line[..dk];
                domain = line[(dk + 12)..];
            }
            else
            {
                var parts = line.Split(new[] { ':', '@', ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) continue;
                selector = parts[0];
                domain = parts.Length > 1 ? parts[1] : defaultDomain;
            }
            selector = selector.Trim();
            domain = DomainUtil.Normalize(domain);
            if (selector.Length == 0 || domain.Length == 0) continue;
            if (list.Any(d => d.Selector.Equals(selector, StringComparison.OrdinalIgnoreCase) && d.Domain == domain)) continue;
            bool fromEvidence = known.Any(k => k.Selector.Equals(selector, StringComparison.OrdinalIgnoreCase) && k.Domain == domain && k.FromEvidence);
            list.Add(new DkimTarget { Selector = selector, Domain = domain, FromEvidence = fromEvidence });
        }
        return list;
    }

    // ================================================================== run

    /// <summary>
    /// Runs every live check. Called on the busy overlay's worker thread: touches no control,
    /// reports through <paramref name="say"/>.
    /// </summary>
    /// <summary>
    /// The same two parties with the mail going the other way: the receiver becomes the
    /// sender and the sender the receiver. Everything that described the original direction
    /// stays behind (headers, bounce, record history, the sending IP, DKIM selectors, the
    /// statement about other mail): none of it says anything about this path.
    /// </summary>
    public static (CaseInput Input, CheckTargets Targets) Reverse(CaseInput input, CheckTargets targets)
    {
        var reversedInput = new CaseInput
        {
            Direction = input.Direction == Direction.Inbound ? Direction.Outbound : Direction.Inbound,
            Location = input.Location,
            TheirAddress = input.TheirAddress,
            OurAddress = input.OurAddress,
            ReverseCheck = true,
        };

        // Mail is addressed to the From domain; the envelope domain only stands in when there is none.
        var oldSender = targets.SenderDomain.Length > 0 ? targets.SenderDomain : targets.EnvelopeDomain;
        var reversedTargets = new CheckTargets
        {
            SenderDomain = targets.ReceiverDomain,
            ReceiverDomain = oldSender,
        };
        reversedTargets.Notes.Add($"Reverse of {Dash(oldSender)} -> {Dash(targets.ReceiverDomain)}: domains swapped, no evidence, no sending IP, no DKIM selector.");
        return (reversedInput, reversedTargets);

        static string Dash(string s) => s.Length == 0 ? "-" : s;
    }

    public static AnalysisResult Run(CaseInput input, CheckTargets targets, CheckOptions options,
                                     Action<string, int?, int?> say, CancellationToken cancel)
    {
        var baseline = HeaderAnalyzer.Analyze(input.BaselineText);
        var failing = HeaderAnalyzer.Analyze(input.FailingText);
        var ndr = NdrParser.Parse(input.NdrText);
        var result = new AnalysisResult
        {
            Input = input,
            Targets = targets,
            Options = options,
            Baseline = baseline,
            Failing = failing,
            Ndr = ndr,
            When = DateTime.Now,
        };

        // Names come from pasted evidence, which is somebody else's text. Anything that is not
        // made of name characters goes no further: not into a query, a URL or a connection.
        string Vet(string name, string role)
        {
            if (string.IsNullOrEmpty(name) || DomainUtil.IsNameSafe(name)) return name;
            result.RejectedNames.Add($"{role}: {name}");
            return "";
        }
        targets.SenderDomain = Vet(targets.SenderDomain, "sender domain");
        targets.EnvelopeDomain = Vet(targets.EnvelopeDomain, "envelope domain");
        targets.ReceiverDomain = Vet(targets.ReceiverDomain, "receiver domain");
        foreach (var bad in targets.Dkim.Where(d => !DomainUtil.IsNameSafe(d.Domain) || !DomainUtil.IsNameSafe(d.Selector)).ToList())
        {
            result.RejectedNames.Add($"DKIM key: {bad}");
            targets.Dkim.Remove(bad);
        }

        var trace = new TraceLog();
        TraceEvidence(trace, baseline, failing, ndr);
        trace.Step = "Setup";
        trace.Add("Note", "analysis settings", TraceOutcome.Info,
                  $"{input.Direction}, {input.Location}, resolver: {options.Resolver.Display}",
                  $"Direction:      {input.Direction}\nLocation:       {input.Location}\nResolver:       {options.Resolver.Display}\n" +
                  $"DoH fallback:   {options.DohFallback}\nAsk all NS:     {options.AskAllNameServers}\nBlocklists:     {options.Blocklists}\n" +
                  $"SMTP probe:     {options.SmtpProbe}\nMTA-STS fetch:  {options.MtaSts}\n\n" +
                  $"Sender domain:  {targets.SenderDomain}\nEnvelope:       {targets.EnvelopeDomain}\nSending IP:     {targets.SendingIp}\n" +
                  $"DKIM:           {string.Join(", ", targets.Dkim)}\nReceiver:       {targets.ReceiverDomain}\n\n" +
                  $"This machine:   {Environment.OSVersion}");

        var dns = new DnsClient(ResolverChoice.Chain(options.Resolver, options.DohFallback, trace));

        // Internal: a second, public view to compare the site's DNS against.
        DnsClient? publicDns = null;
        if (input.Location == AnalysisLocation.Internal && options.Resolver.Kind != ResolverKind.Authoritative)
            publicDns = new DnsClient(ResolverChoice.Chain(ResolverChoice.Authoritative(), options.DohFallback, trace));

        // Before anything is concluded from DNS: does the resolver in use give real answers?
        say("Checking the DNS path", null, null);
        dns.Probe(cancel);
        publicDns?.Probe(cancel);

        result.SendingIp = NetUtil.TryParseIp(targets.SendingIp, out var parsedIp) ? parsedIp : null;
        var sendingIp = result.SendingIp;
        var sender = targets.SenderDomain;
        var envelope = string.IsNullOrEmpty(targets.EnvelopeDomain) ? sender : targets.EnvelopeDomain;
        var receiver = targets.ReceiverDomain;

        // The sender-side mail whose Return-Path and HELO feed SPF macros, and the other IP.
        var senderMails = new[] { failing, baseline, ndr.Embedded }
            .Where(m => m is not null && m.HasAnything && DomainUtil.AlignedRelaxed(m.FromDomain, sender))
            .Select(m => m!)
            .ToList();
        var macroSource = senderMails.FirstOrDefault();
        var otherIp = senderMails
            .Select(m => m.SendingIp)
            .FirstOrDefault(ip => ip is not null && NetUtil.IsPublic(ip) && (sendingIp is null || !ip.Equals(sendingIp)));

        bool publicOnly = input.Location == AnalysisLocation.Isolated;

        // All steps are planned up front so the overlay can report progress as step i of n.
        var steps = new List<(string Label, Action Work)>();

        if (!string.IsNullOrEmpty(envelope))
        {
            var spf = new SpfEvaluator(dns, cancel);
            steps.Add(($"SPF record of {envelope}", () => result.EnvelopeSpf = spf.Health(envelope)));
            if (sendingIp is not null)
                steps.Add(($"SPF for {sendingIp} at {envelope}", () =>
                    result.SpfNow = spf.Evaluate(sendingIp, envelope, macroSource?.ReturnPath, macroSource?.SendingHelo)));
            if (otherIp is not null)
                steps.Add(($"SPF for {otherIp} at {envelope}", () =>
                    result.SpfOther = new SpfEvaluator(dns, cancel).Evaluate(otherIp, envelope, macroSource?.ReturnPath, null)));
        }
        if (!string.IsNullOrEmpty(sender) && !DomainUtil.AlignedStrict(sender, envelope))
        {
            var spf2 = new SpfEvaluator(dns, cancel);
            steps.Add(($"SPF record of {sender}", () => result.FromSpf = spf2.Health(sender)));
        }

        if (targets.Dkim.Count > 0)
        {
            foreach (var d in targets.Dkim)
                steps.Add(($"DKIM key {d}", () => result.Dkim.Add(DkimChecker.Check(dns, d.Selector, d.Domain, cancel))));
        }
        else if (!string.IsNullOrEmpty(sender))
        {
            result.DkimProbed = true;
            steps.Add(($"Probing common DKIM selectors at {sender}", () =>
            {
                foreach (var selector in DkimChecker.CommonSelectors)
                {
                    var check = DkimChecker.Check(dns, selector, sender, cancel);
                    if (check.Status is not (DkimKeyStatus.Missing or DkimKeyStatus.LookupFailed)) result.Dkim.Add(check);
                }
            }));
        }

        if (!string.IsNullOrEmpty(sender))
        {
            steps.Add(($"DMARC policy of {sender}", () => result.Dmarc = DmarcChecker.Check(dns, sender, cancel)));
            steps.Add(($"Mail records of {sender}", () => result.SenderMx = MxChecker.Check(dns, sender, cancel)));
        }

        if (sendingIp is not null)
        {
            var ip = sendingIp;
            steps.Add(($"Reverse DNS of {ip}", () => result.Ptr = ReverseDnsChecker.Check(dns, ip, cancel)));
        }

        if (options.Blocklists)
        {
            // IP subjects: the sending IP and the other sending IP of working vs failing mail.
            // The sender's MX hosts (often the same machine) get their own step, after the MX lookup.
            var ipSubjects = new List<(IPAddress Ip, string Role)>();
            void AddIp(IPAddress? ip, string role)
            {
                if (ip is null || !NetUtil.IsPublic(ip) || ipSubjects.Any(x => x.Ip.Equals(ip))) return;
                ipSubjects.Add((ip, role));
            }
            AddIp(sendingIp, "sending IP");
            AddIp(otherIp, "other sending IP (working vs failing mail)");

            if (ipSubjects.Count > 0)
            {
                steps.Add(($"Blocklists for {string.Join(", ", ipSubjects.Select(x => x.Ip))}", () =>
                {
                    foreach (var (ip, role) in ipSubjects)
                        result.Blocklists.AddRange(BlocklistChecker.CheckIp(dns, ip, role, null, cancel));
                }));
            }
            if (!string.IsNullOrEmpty(sender))
            {
                steps.Add(($"Blocklists for the sender's MX hosts", () =>
                {
                    if (result.SenderMx is not { } smx) return;
                    foreach (var host in smx.Hosts.Take(2))
                    {
                        foreach (var ip in host.Addresses.Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Take(1))
                        {
                            if (!NetUtil.IsPublic(ip)) continue;
                            if (ipSubjects.Any(x => x.Ip.Equals(ip)) || result.Blocklists.Any(x => x.Subject == ip.ToString()))
                            {
                                trace.Add("Note", $"blocklists for the sender's MX host {host.Host} ({ip})", TraceOutcome.Info,
                                          "same address as an IP already checked; not queried twice");
                                continue;
                            }
                            result.Blocklists.AddRange(BlocklistChecker.CheckIp(dns, ip, $"sender's MX host {host.Host}", null, cancel));
                        }
                    }
                }));
            }

            // Domain subjects: the From domain, the envelope domain and every DKIM signing domain.
            var domainSubjects = new List<(string Domain, string Role)>();
            void AddDomain(string? domain, string role)
            {
                var d = DomainUtil.OrgDomain(domain);
                if (string.IsNullOrEmpty(d) || !d.Contains('.') || domainSubjects.Any(x => x.Domain == d)) return;
                domainSubjects.Add((d, role));
            }
            AddDomain(sender, "sender domain (From)");
            AddDomain(envelope, "envelope sender domain (Return-Path)");
            foreach (var k in targets.Dkim) AddDomain(k.Domain, "DKIM signing domain");
            foreach (var m in senderMails)
                foreach (var sig in m.DkimSignatures) AddDomain(sig.Domain, "DKIM signing domain");

            if (domainSubjects.Count > 0)
            {
                steps.Add(($"Domain blocklists for {string.Join(", ", domainSubjects.Take(4).Select(x => x.Domain))}", () =>
                {
                    foreach (var (domain, role) in domainSubjects.Take(4))
                        result.Blocklists.AddRange(BlocklistChecker.CheckDomain(dns, domain, role, cancel));
                }));
            }
        }

        if (!string.IsNullOrEmpty(receiver))
        {
            steps.Add(($"MX records of {receiver}", () => result.ReceiverMx = MxChecker.Check(dns, receiver, cancel)));
            steps.Add(($"MTA-STS and DANE for {receiver}", () =>
            {
                if (result.ReceiverMx is { } mx) result.Sts = MtaStsChecker.Check(dns, receiver, mx, options.MtaSts, cancel, trace);
            }));
            if (options.SmtpProbe)
            {
                steps.Add(("SMTP reachability from this machine (control hosts)", () =>
                    result.Reach = Reachability.Run(dns, trace, result.ReceiverMx, cancel, publicOnly)));
                steps.Add(($"SMTP probe of {receiver}'s mail servers", () =>
                {
                    if (result.ReceiverMx is not { } mx) return;
                    var announce = NetUtil.TryParseIp(result.Reach?.PublicIp, out var mine) ? mine : null;
                    foreach (var host in mx.Hosts.Where(h => h.Addresses.Count > 0).Take(2))
                    {
                        // From outside the site, a mail server "at" a private address is one of this
                        // machine's own neighbours, named by somebody else's DNS. It is not connected to.
                        var usable = publicOnly ? host.Addresses.Where(NetUtil.IsPublic).ToList() : host.Addresses.ToList();
                        if (usable.Count == 0)
                        {
                            var skipped = $"{host.Host} ({string.Join(", ", host.Addresses)})";
                            result.SkippedProbes.Add(skipped);
                            trace.Add("Note", $"SMTP probe of {host.Host}", TraceOutcome.Info, "not connected: private address, analysis from outside the site",
                                      $"{skipped}\nThe MX host resolves only to addresses that are not public. Seen from outside the site's network such an address is on this machine's own network, so no connection is made. Choose 'inside the site's network' on the first page if this machine can reach the site's internal mail server.");
                            continue;
                        }
                        var address = usable.FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ?? usable[0];
                        say($"Connecting to {host.Host} ({address}) on port 25", null, null);
                        var probe = SmtpProbe.Probe(host.Host, address, cancel, trace, publicIp: announce);
                        result.Probes.Add(probe);
                        // If the first one cannot even connect, port 25 is blocked here; don't wait twice.
                        if (probe.PortBlockedLocally && result.Reach?.Verdict != ReachVerdict.Open) break;
                    }
                }));
            }
        }

        // When were the zones last changed? (SOA serial, where it is a date)
        var zoneDomains = new List<(string Domain, string Side)>();
        foreach (var (domain, side) in new[] { (sender, "sender"), (envelope, "sender"), (receiver, "receiver") })
        {
            if (string.IsNullOrEmpty(domain)) continue;
            var org = DomainUtil.OrgDomain(domain);
            if (!zoneDomains.Any(z => z.Domain == org)) zoneDomains.Add((org, side));
        }
        if (zoneDomains.Count > 0)
        {
            steps.Add(("Zone serials (when DNS last changed)", () =>
            {
                foreach (var (domain, side) in zoneDomains)
                {
                    var soa = dns.Query(domain, DnsType.SOA, cancel).OfType(DnsType.SOA).FirstOrDefault();
                    if (soa is null) continue;
                    var date = DnsWire.SerialAsDate(soa.Serial, out var convention);
                    result.Zones.Add(new ZoneChange { Domain = domain, Side = side, Serial = soa.Serial, Date = date, Convention = convention });
                }
            }));
        }

        // Key records, needed by the two comparisons below. Built when they run, because the
        // DMARC lookup decides which _dmarc name exists.
        List<(string Purpose, string Name, DnsType Type)> KeyRecords()
        {
            var keys = new List<(string, string, DnsType)>();
            if (!string.IsNullOrEmpty(envelope)) keys.Add(("SPF", envelope, DnsType.TXT));
            if (!string.IsNullOrEmpty(sender))
            {
                var dmarcDomain = result.Dmarc?.Found == true ? result.Dmarc.QueriedDomain : sender;
                keys.Add(("DMARC", "_dmarc." + dmarcDomain, DnsType.TXT));
            }
            foreach (var k in result.Dkim.Where(k => k.Status != DkimKeyStatus.LookupFailed).Take(6))
                keys.Add(($"DKIM {k.Selector}", k.QueryName, DnsType.TXT));
            if (!string.IsNullOrEmpty(sender)) keys.Add(("MX (sender)", sender, DnsType.MX));
            if (!string.IsNullOrEmpty(receiver)) keys.Add(("MX (receiver)", receiver, DnsType.MX));
            return keys;
        }

        if (options.AskAllNameServers)
        {
            steps.Add(("Asking every authoritative name server", () =>
            {
                var iterative = dns.Authoritative;
                if (iterative is null && publicDns is not null)
                {
                    // The public view starts with the root walk; one query decides whether port 53 works.
                    var probe = !string.IsNullOrEmpty(sender) ? sender : receiver;
                    if (!string.IsNullOrEmpty(probe)) publicDns.Query(probe, DnsType.SOA, cancel);
                    iterative = publicDns.Authoritative;
                }
                if (iterative is null || !iterative.HasAnswered)
                {
                    result.NameServersSkipped = true;
                    return;
                }
                foreach (var (purpose, name, type) in KeyRecords())
                {
                    cancel.ThrowIfCancellationRequested();
                    var (zone, answers) = iterative.AskAll(name, type, cancel);
                    if (zone is null || answers.Count == 0) continue;
                    var check = new NsConsistency { Purpose = purpose, Name = name, Type = type, Zone = zone.Zone };
                    check.Answers.AddRange(answers);
                    result.NameServers.Add(check);
                    foreach (var a in answers)
                        dns.Note($"NS    {name} {type} @ {a.Server} ({a.Ip})  ->  {a.Response.Describe()}");
                }
            }));
        }

        if (publicDns is not null)
        {
            steps.Add(("Comparing the internal DNS with the public view", () =>
            {
                foreach (var (purpose, name, type) in KeyRecords())
                {
                    cancel.ThrowIfCancellationRequested();
                    result.Split.Add(new SplitView
                    {
                        Purpose = purpose,
                        Name = name,
                        Type = type,
                        Internal = dns.Query(name, type, cancel),
                        Public = publicDns.Query(name, type, cancel),
                    });
                }
            }));
        }

        var summarized = new HashSet<object>(ReferenceEqualityComparer.Instance);
        for (int i = 0; i < steps.Count; i++)
        {
            cancel.ThrowIfCancellationRequested();
            say(steps[i].Label, i, steps.Count);
            trace.Step = StepKey(steps[i].Label);
            var started = System.Diagnostics.Stopwatch.StartNew();
            steps[i].Work();
            Summarize(result, trace, summarized);
            trace.Add("Note", "step finished: " + steps[i].Label, TraceOutcome.Info, $"{started.Elapsed.TotalMilliseconds:0} ms", "", started.Elapsed.TotalMilliseconds);
        }
        say("Weighing the evidence", steps.Count, steps.Count);
        trace.Step = "History";
        AtTheTime(result, baseline, targets, sender, envelope, trace);
        trace.Step = "Diagnosis";
        CollectTtls(result, dns, sender, envelope, receiver, cancel);
        foreach (var fb in dns.Fallbacks) trace.Add("Note", "resolver fallback", TraceOutcome.Warn, fb);

        result.ResolverUsed = dns.Active.Label;
        result.Fallbacks = dns.Fallbacks;
        result.DnsInterception = dns.Interception ?? publicDns?.Interception;
        result.DnsUnavailable = dns.Unavailable;
        result.DnsPathProblems = dns.PathProblems.Concat(publicDns?.PathProblems ?? Array.Empty<string>()).Distinct().ToList();
        var log = dns.Log.ToList();
        if (publicDns is not null) log.AddRange(publicDns.Log.Select(l => "[public] " + l));
        result.DnsLog = log;
        result.Trace = trace.Entries;

        Diagnoser.Diagnose(result);
        return result;
    }

    // ================================================================== trace helpers

    /// <summary>The trace step a plan entry belongs to; findings link to these names.</summary>
    private static string StepKey(string label) =>
        label.StartsWith("SPF") ? "SPF"
        : label.Contains("DKIM") ? "DKIM"
        : label.StartsWith("DMARC") ? "DMARC"
        : label.StartsWith("Mail records of") ? "Sender DNS"
        : label.StartsWith("Reverse DNS") ? "PTR"
        : label.StartsWith("Blocklists") || label.StartsWith("Domain blocklists") ? "Blocklists"
        : label.StartsWith("MX records") ? "MX"
        : label.StartsWith("MTA-STS") ? "MTA-STS"
        : label.StartsWith("SMTP reachability") ? "Reach"
        : label.StartsWith("SMTP probe") ? "SMTP"
        : label.StartsWith("Zone") ? "Zone"
        : label.StartsWith("Asking every") ? "NS"
        : label.StartsWith("Comparing the internal DNS") ? "Split"
        : "Other";

    /// <summary>How the evidence was read: which header was trusted, where the IP came from.</summary>
    private static void TraceEvidence(TraceLog trace, MailEvidence baseline, MailEvidence failing, NdrInfo ndr)
    {
        trace.Step = "Evidence";
        void ReadMail(string what, MailEvidence m)
        {
            if (!m.HasAnything) { trace.Add("Parse", $"read {what}", TraceOutcome.Info, "not given"); return; }
            var d = new System.Text.StringBuilder();
            d.AppendLine($"Header fields:  {m.Headers.Fields.Count}");
            d.AppendLine($"From:           {m.From}");
            d.AppendLine($"Return-Path:    {m.ReturnPath}");
            d.AppendLine($"Date:           {m.Date:yyyy-MM-dd HH:mm:ss zzz}");
            d.AppendLine($"Message-ID:     {m.MessageId}");
            d.AppendLine($"Sending IP:     {m.SendingIp}  <- {m.SendingIpSource}");
            d.AppendLine($"Sending host:   {m.SendingHost} (HELO {m.SendingHelo})");
            d.AppendLine($"SPF/DKIM/DMARC: spf={m.SpfResult} ({m.SpfDomain}), dkim={string.Join("/", m.DkimResults.Select(x => $"{x.Result}:{x.Domain}"))}, dmarc={m.DmarcResult} action={m.DmarcAction} p={m.DmarcPolicyThen}");
            d.AppendLine($"DMARC carried by: {m.DmarcCarriedBy}");
            d.AppendLine($"Spam rating:    SCL {m.Scl} BCL {m.Bcl} {m.SpamVerdict} score {m.SpamScore}/{m.SpamThreshold}");
            d.AppendLine();
            d.AppendLine($"Authentication-Results headers ({m.AuthResults.Count}); the one used is marked:");
            foreach (var a in m.AuthResults)
                d.AppendLine($"  {(a == m.PrimaryAuth ? "*" : " ")} [{a.Source}{(a.AuthServId is null ? "" : " by " + a.AuthServId)}] {a.Raw}");
            d.AppendLine();
            d.AppendLine($"DKIM-Signature headers ({m.DkimSignatures.Count}):");
            foreach (var sig in m.DkimSignatures) d.AppendLine($"  d={sig.Domain} s={sig.Selector} a={sig.Algorithm} h={sig.SignedHeaders}");
            d.AppendLine();
            d.AppendLine($"Received hops ({m.Hops.Count}, newest first):");
            foreach (var h in m.Hops)
                d.AppendLine($"  {h.Index + 1,2}. {h.Time:yyyy-MM-dd HH:mm:ss zzz}  +{h.DelayBefore?.ToString(@"hh\:mm\:ss") ?? "-"}  from {h.FromHelo} ({h.FromHost} [{h.FromIp}]) by {h.ByHost} with {h.With} {h.Tls}");
            trace.Add("Parse", $"read {what}", m.PrimaryAuth is null ? TraceOutcome.Warn : TraceOutcome.Ok,
                      $"{m.Headers.Fields.Count} fields, {m.Hops.Count} hops, sending IP {m.SendingIp?.ToString() ?? "-"}" +
                      (m.PrimaryAuth is null ? ", no Authentication-Results" : $", {m.SpfResult ?? "-"}/{(m.DkimResults.Count > 0 ? m.DkimResults[0].Result : "-")}/{m.DmarcResult ?? "-"}"),
                      d.ToString());
        }
        ReadMail("working mail headers", baseline);
        ReadMail("failing mail headers", failing);

        if (!ndr.HasAnything) { trace.Add("Parse", "read bounce", TraceOutcome.Info, "not given"); return; }
        var n = new System.Text.StringBuilder();
        n.AppendLine("Status codes found:");
        foreach (var st in ndr.Statuses) n.AppendLine($"  {st.ReplyCode} {st.Code}  {st.Meaning?.Title ?? "(not in the list)"}   <- \"{st.Context}\"");
        n.AppendLine($"Primary:        {ndr.Primary?.Code}");
        n.AppendLine($"Category:       {ndr.Category}");
        n.AppendLine($"Delay notice:   {ndr.LooksLikeDelay}");
        n.AppendLine($"Recipients:     {string.Join(", ", ndr.Recipients)}");
        n.AppendLine($"Remote hosts:   {string.Join(", ", ndr.RemoteHosts)}");
        n.AppendLine($"IPs:            {string.Join(", ", ndr.Ips)}");
        n.AppendLine($"Reporting MTA:  {ndr.ReportingMta}");
        n.AppendLine($"Diagnostic:     {ndr.DiagnosticText}");
        n.AppendLine("Keyword hints:");
        foreach (var hnt in ndr.Hints) n.AppendLine($"  {hnt.Category}: {hnt.Hint}");
        n.AppendLine($"Returned message headers: {(ndr.Embedded is null ? "none" : $"from {ndr.Embedded.From}, {ndr.Embedded.DkimSignatures.Count} DKIM signature(s)")}");
        trace.Add("Parse", "read bounce", ndr.Primary is null ? TraceOutcome.Warn : TraceOutcome.Ok,
                  ndr.Primary is null ? "no status code found" : $"{ndr.Primary.ReplyCode} {ndr.Primary.Code} {ndr.Primary.Meaning?.Title}", n.ToString());
    }

    /// <summary>Check-level conclusions, logged once each, right after the step that produced them.</summary>
    private static void Summarize(AnalysisResult r, TraceLog trace, HashSet<object> done)
    {
        bool First(object? o) => o is not null && done.Add(o);

        foreach (var h in new[] { r.EnvelopeSpf, r.FromSpf })
        {
            if (h is null || !First(h)) continue;
            var d = new System.Text.StringBuilder();
            d.AppendLine($"Record: {h.Record ?? "(none)"}");
            d.AppendLine($"DNS-querying terms when fully expanded: {h.TotalLookups} (limit 10)");
            d.AppendLine($"Final 'all': {h.AllTerm ?? "(none)"}");
            if (h.Problems.Count > 0) { d.AppendLine("Problems:"); foreach (var x in h.Problems) d.AppendLine("  " + x); }
            if (h.Notes.Count > 0) { d.AppendLine("Notes:"); foreach (var x in h.Notes) d.AppendLine("  " + x); }
            d.AppendLine("Tree:");
            foreach (var x in h.Tree) d.AppendLine("  " + x);
            trace.Add("SPF", $"SPF record of {h.Domain}, fully expanded",
                      h.Status == SpfVerdict.Pass ? TraceOutcome.Ok : h.Status == SpfVerdict.None ? TraceOutcome.Warn : TraceOutcome.Fail,
                      h.Status == SpfVerdict.Pass ? $"valid, {h.TotalLookups} lookups" : $"{h.Status}: {string.Join("; ", h.Problems)}", d.ToString());
        }
        foreach (var e in new[] { r.SpfNow, r.SpfOther })
        {
            if (e is null || !First(e)) continue;
            trace.Add("SPF", $"evaluate SPF for {e.Ip} at {e.Domain} (RFC 7208 check_host)",
                      e.Verdict == SpfVerdict.Pass ? TraceOutcome.Ok : e.Verdict is SpfVerdict.TempError or SpfVerdict.Neutral or SpfVerdict.None ? TraceOutcome.Warn : TraceOutcome.Fail,
                      $"{e.Verdict.ToString().ToLowerInvariant()}: {e.Reason}",
                      $"Lookups used: {e.Lookups} (limit 10), void lookups: {e.VoidLookups} (limit 2)\n\nEvaluation path:\n  " + string.Join("\n  ", e.Trace));
        }
        foreach (var k in r.Dkim)
        {
            if (!First(k)) continue;
            trace.Add("DKIM", $"DKIM key {k.QueryName}",
                      k.Status == DkimKeyStatus.Found ? TraceOutcome.Ok : k.Status == DkimKeyStatus.LookupFailed ? TraceOutcome.Warn : TraceOutcome.Fail,
                      $"{k.Status}: {k.Detail}",
                      $"Record:  {k.Record ?? "(none)"}\nCNAME:   {k.CnameTarget ?? "-"}\nKey:     {k.KeyType} {k.KeyBits} bit\nTesting: {k.Testing}");
        }
        if (First(r.Dmarc) && r.Dmarc is { } dm)
        {
            trace.Add("DMARC", $"DMARC policy for {dm.FromDomain}",
                      !dm.Found ? TraceOutcome.Warn : dm.Problem is not null ? TraceOutcome.Fail : TraceOutcome.Ok,
                      !dm.Found ? "no record" : dm.Problem ?? $"p={dm.Policy} pct={dm.Pct} adkim={dm.Adkim} aspf={dm.Aspf}",
                      $"Queried:   _dmarc.{dm.QueriedDomain}{(dm.FromOrgDomain ? " (organisational domain fallback)" : "")}\nRecord:    {dm.Record ?? "(none)"}\n" +
                      $"p={dm.P} sp={dm.Sp} pct={dm.Pct} adkim={dm.Adkim} aspf={dm.Aspf}\nrua={dm.Rua}\nEffective policy for {dm.FromDomain}: {dm.Policy}");
        }
        foreach (var m in new[] { r.SenderMx, r.ReceiverMx })
        {
            if (m is null || !First(m)) continue;
            trace.Add("MX", $"mail servers of {m.Domain}", m.Usable ? TraceOutcome.Ok : TraceOutcome.Fail, m.Detail,
                      string.Join("\n", m.Hosts.Select(h => $"{h.Preference,5} {h.Host}  {string.Join(", ", h.Addresses)}{(h.Problem is null ? "" : "   <- " + h.Problem)}")) +
                      (m.NullMx ? "\nnull MX" : "") + (m.ImplicitMx ? "\n(implicit MX: no MX record, A record used)" : ""));
        }
        if (First(r.Ptr) && r.Ptr is { } p)
        {
            trace.Add("PTR", $"reverse DNS of {p.Ip}", p.Ok && !p.LooksGeneric ? TraceOutcome.Ok : TraceOutcome.Warn, p.Detail,
                      $"PTR names: {string.Join(", ", p.Names)}\nForward-confirmed: {p.ConfirmedName ?? "no"}\nLooks generic: {p.LooksGeneric}");
        }
        foreach (var b in r.Blocklists)
        {
            if (!First(b)) continue;
            trace.Add("Blocklist", $"{b.Name} ({b.Zone}) for {b.Subject} ({b.Role})",
                      b.Status == ListingStatus.Listed ? TraceOutcome.Fail : b.Status == ListingStatus.NotListed ? TraceOutcome.Ok : TraceOutcome.Warn,
                      $"{b.Status}: {b.Detail}",
                      $"List:      {b.Name} ({b.Zone}), tier {b.Tier}\nAbout:     {b.About}\nSubject:   {b.Subject} ({b.Role})\n" +
                      $"Self-test: {b.SelfTest}\nResult:    {b.Status}: {b.Detail}\nDelisting: {b.DelistUrl}");
        }
        if (First(r.Sts) && r.Sts is { } sts)
        {
            trace.Add("MTA-STS", $"MTA-STS / TLS-RPT / DANE for {sts.Domain}", sts.Problem is null && sts.UncoveredMx.Count == 0 ? TraceOutcome.Info : TraceOutcome.Warn,
                      sts.TxtRecord is null ? "no MTA-STS record" : $"mode {sts.Mode ?? "?"}{(sts.Problem is null ? "" : ", " + sts.Problem)}",
                      $"_mta-sts:   {sts.TxtRecord ?? "(none)"}\n_smtp._tls: {sts.TlsRpt ?? "(none)"}\nPolicy:     {(sts.PolicyFetched ? "fetched" : "not fetched")}, mode {sts.Mode}\n" +
                      $"mx patterns: {string.Join(", ", sts.MxPatterns)}\nMX not covered: {string.Join(", ", sts.UncoveredMx)}\n" +
                      "TLSA:\n" + string.Join("\n", sts.Tlsa.Select(t => $"  _25._tcp.{t.Key}: {t.Value}")));
        }
        foreach (var z in r.Zones)
        {
            if (!First(z)) continue;
            trace.Add("Zone", $"SOA serial of {z.Domain}", TraceOutcome.Info,
                      z.Date is { } dt ? $"serial {z.Serial} = {dt:yyyy-MM-dd HH:mm} UTC ({z.Convention})" : $"serial {z.Serial} (no date convention)");
        }
        foreach (var c in r.NameServers)
        {
            if (!First(c)) continue;
            trace.Add("NS", $"{c.Purpose}: {c.Name} {c.Type} asked of every name server of {c.Zone}",
                      c.Variants > 1 ? TraceOutcome.Fail : c.Silent.Count > 0 ? TraceOutcome.Warn : TraceOutcome.Ok,
                      c.Variants > 1 ? $"{c.Variants} different answers" : c.Silent.Count > 0 ? $"{c.Silent.Count} server(s) did not answer properly" : $"all {c.Answers.Count} agree",
                      string.Join("\n", c.Answers.Select(a => $"{a.Server} [{a.Ip}]: {a.Response.Describe()}")));
        }
        foreach (var v in r.Split)
        {
            if (!First(v)) continue;
            trace.Add("Split", $"{v.Purpose}: {v.Name} {v.Type}, internal DNS vs public", v.Differs ? TraceOutcome.Warn : TraceOutcome.Ok,
                      v.Differs ? "differs" : "same", $"Internal: {v.Internal.Describe()}\nPublic:   {v.Public.Describe()}");
        }
    }

    // ================================================================== the state at the time of the working mail

    /// <summary>
    /// What the DMARC record, the DKIM key and the SPF record looked like when the working mail
    /// was sent: stated by the technician, read from the receiver's verdict in the headers, or
    /// read from pasted record history. Without any of these it stays unknown, never assumed.
    /// </summary>
    private static void AtTheTime(AnalysisResult r, MailEvidence baseline, CheckTargets targets, string sender, string envelope, TraceLog trace)
    {
        r.History.AddRange(RecordHistory.Parse(r.Input.HistoryText));
        if (r.History.Count > 0)
            trace.Add("Parse", "read pasted record history", TraceOutcome.Ok,
                      $"{r.History.Count} name(s): {string.Join(", ", r.History.Select(h => h.Name))}",
                      string.Join("\n", r.History.SelectMany(h =>
                          new[] { $"{h.Name}: added {h.Added:yyyy-MM-dd}, last updated {h.LastUpdated:yyyy-MM-dd}, complete types: {string.Join(",", h.CompleteTypes)}, history counts: {string.Join(",", h.HistoryCounts.Select(c => c.Key + "=" + c.Value))}" }
                          .Concat(h.Values.Select(v => $"  {v.Type} {v.From:yyyy-MM-dd} -> {v.To:yyyy-MM-dd} {v.Value}")))));

        // Stated by the technician: holds even without a dated working mail.
        if (targets.DmarcThen != KnownState.Auto)
            r.DmarcThen = new RecordThen
            {
                Record = "DMARC",
                State = targets.DmarcThen == KnownState.Existed ? HistoryState.Present : HistoryState.Absent,
                Source = "stated by the technician",
            };
        if (targets.DkimThen != KnownState.Auto)
            r.DkimThen = new RecordThen
            {
                Record = "DKIM key",
                State = targets.DkimThen == KnownState.Existed ? HistoryState.Present : HistoryState.Absent,
                Source = "stated by the technician",
            };

        if (!baseline.HasAnything || baseline.Date is not { } sent || string.IsNullOrEmpty(sender))
        {
            foreach (var t in new[] { r.DmarcThen, r.DkimThen })
                if (t is not null) trace.Add("History", $"{t.Record} when the working mail was sent", TraceOutcome.Info, $"{t.State} ({t.Source})", "");
            return;
        }
        var at = sent.LocalDateTime;
        var org = DomainUtil.OrgDomain(sender);

        // ---- DMARC: the receiver's verdict, else the pasted history.
        // "none" and Microsoft's "bestguesspass" mean no record was found; "temperror" says nothing.
        var verdict = baseline.DmarcResult?.ToLowerInvariant();
        if (r.DmarcThen is null && verdict is not null && verdict != "temperror")
        {
            bool none = verdict is "none" or "bestguesspass" && baseline.DmarcPolicyThen is null;
            r.DmarcThen = new RecordThen
            {
                Record = "DMARC",
                State = none ? HistoryState.Absent : HistoryState.Present,
                Value = baseline.DmarcPolicyThen is { } p ? $"p={p}" : null,
                Source = "receiver's verdict in the working mail",
                Explanation = $"dmarc={verdict}" + (baseline.DmarcPolicyThen is null ? "" : $" (p={baseline.DmarcPolicyThen})"),
            };
        }
        else if (r.DmarcThen is null)
        {
            // The record at the From domain applies; without one, the organisational domain's.
            // Present if either existed; absent only if both are known absent.
            var names = new[] { "_dmarc." + sender, "_dmarc." + org }.Distinct().ToList();
            // Live DNS today, only when the lookup worked: no DMARC record at either name.
            bool? dmarcNow = r.Dmarc is { Found: false, LookupFailed: false } ? false : null;
            var verdicts = names.Select(n => (Name: n, V: RecordHistory.StateAt(r.History, n, "TXT", at, t => t.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase), dmarcNow))).ToList();
            var present = verdicts.FirstOrDefault(x => x.V.State == HistoryState.Present);
            if (present.Name is not null)
                r.DmarcThen = new RecordThen { Record = "DMARC", State = HistoryState.Present, Value = present.V.Value, Source = "pasted record history", Explanation = $"{present.Name}: {present.V.Explanation}" };
            else if (verdicts.All(x => x.V.State == HistoryState.Absent))
                r.DmarcThen = new RecordThen { Record = "DMARC", State = HistoryState.Absent, Likely = verdicts.Any(x => x.V.Likely), Source = "pasted record history" + (verdicts.Any(x => x.V.Likely) ? " and live DNS" : ""), Explanation = string.Join("; ", verdicts.Select(x => $"{x.Name}: {x.V.Explanation}")) };
            else if (r.History.Count > 0)
                r.DmarcThen = new RecordThen { Record = "DMARC", State = HistoryState.Unknown, Source = "pasted record history", Explanation = string.Join("; ", verdicts.Select(x => $"{x.Name}: {x.V.Explanation}")) };
        }

        // ---- DKIM: the key of the selector the working mail was signed with
        var sig = baseline.DkimSignatures.FirstOrDefault(s => DomainUtil.AlignedRelaxed(s.Domain, baseline.FromDomain)) ?? baseline.DkimSignatures.FirstOrDefault();
        if (r.DkimThen is null && sig is not null)
        {
            var passed = baseline.DkimResults.FirstOrDefault(d => d.Domain == sig.Domain && d.Result.Equals("pass", StringComparison.OrdinalIgnoreCase));
            if (passed.Result is not null)
                r.DkimThen = new RecordThen { Record = "DKIM key", State = HistoryState.Present, Source = "receiver's verdict in the working mail", Explanation = $"dkim=pass for {sig.Domain}" };
            else
            {
                var name = $"{sig.Selector}._domainkey.{sig.Domain}";
                var v = RecordHistory.StateAt(r.History, name, "TXT", at, t => t.Contains("p=", StringComparison.OrdinalIgnoreCase),
                                            r.Dkim.FirstOrDefault(k => string.Equals(k.QueryName, name, StringComparison.OrdinalIgnoreCase))?.Status switch { DkimKeyStatus.Found => true, DkimKeyStatus.Missing => false, _ => null });
                r.DkimThen = new RecordThen { Record = "DKIM key", State = v.State, Likely = v.Likely, Value = v.State != HistoryState.Present ? null : v.Value is { Length: > 60 } keyText ? keyText[..57] + "..." : v.Value, Source = "pasted record history", Explanation = $"{name}: {v.Explanation}" };
            }
        }

        // ---- SPF at the envelope domain
        if (!string.IsNullOrEmpty(envelope))
        {
            var v = RecordHistory.StateAt(r.History, envelope, "TXT", at, t => t.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase),
                                        r.EnvelopeSpf is { } spfNow && spfNow.Status != SpfVerdict.TempError ? spfNow.Record is not null : null);
            if (v.State != HistoryState.Unknown)
                r.SpfThen = new RecordThen { Record = "SPF", State = v.State, Likely = v.Likely, Value = v.State == HistoryState.Present ? v.Value : null, Source = "pasted record history", Explanation = $"{envelope}: {v.Explanation}" };
        }

        r.HistoryChanges.AddRange(RecordHistory.ChangesBetween(r.History, at, DateTime.Now));

        foreach (var t in new[] { r.DmarcThen, r.DkimThen, r.SpfThen })
        {
            if (t is null) continue;
            trace.Add("History", $"{t.Record} when the working mail was sent ({at:yyyy-MM-dd})",
                      t.State == HistoryState.Unknown ? TraceOutcome.Warn : TraceOutcome.Info,
                      $"{t.State}" + (t.Likely ? " (most likely)" : "") + (t.Value is null ? "" : $": {t.Value}") + $" ({t.Source})", t.Explanation);
        }
        if (r.HistoryChanges.Count > 0)
            trace.Add("History", "record changes after the working mail", TraceOutcome.Warn,
                      $"{r.HistoryChanges.Count} change(s)", string.Join("\n", r.HistoryChanges));
    }

    /// <summary>TTLs of the records that matter, from answers already in the cache (no extra queries).</summary>
    private static void CollectTtls(AnalysisResult r, DnsClient dns, string sender, string envelope, string receiver, CancellationToken cancel)
    {
        void Take(string purpose, string name, DnsType type)
        {
            if (string.IsNullOrEmpty(name) || !dns.IsCached(name, type)) return;
            var resp = dns.Query(name, type, cancel);
            if (resp.IsOk)
            {
                var ttl = resp.OfType(type).Select(a => a.Ttl).DefaultIfEmpty(0u).Min();
                r.Ttls.Add((purpose, DnsWire.Normalize(name), ttl, false));
                return;
            }
            if (!resp.IsEmpty) return;
            // RFC 2308 section 5: "no record" is cached for min(SOA TTL, SOA minimum).
            var zoneName = name;
            int dk = name.IndexOf("._domainkey.", StringComparison.Ordinal);
            if (dk >= 0) zoneName = name[(dk + 12)..];
            else if (name.StartsWith("_dmarc.", StringComparison.Ordinal)) zoneName = name[7..];
            var org = DomainUtil.OrgDomain(zoneName);
            if (!dns.IsCached(org, DnsType.SOA)) return;
            var soa = dns.Query(org, DnsType.SOA, cancel).OfType(DnsType.SOA).FirstOrDefault();
            if (soa is null) return;
            r.Ttls.Add((purpose, DnsWire.Normalize(name), Math.Min(soa.Ttl, soa.SoaMinimum), true));
        }

        Take("SPF", envelope, DnsType.TXT);
        if (r.Dmarc is { } d) Take("DMARC", "_dmarc." + d.QueriedDomain, DnsType.TXT);
        foreach (var k in r.Dkim.Take(3)) Take($"DKIM {k.Selector}", k.QueryName, DnsType.TXT);
        Take("MX (sender)", sender, DnsType.MX);
        Take("MX (recipient)", receiver, DnsType.MX);
    }
}
