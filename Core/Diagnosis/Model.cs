using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using SsddMailAnalyser.Core.Checks;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser.Core.Diagnosis;

public enum Direction
{
    /// <summary>An external sender's mail no longer reaches the supported site.</summary>
    Inbound,

    /// <summary>The supported site's mail no longer reaches an external recipient.</summary>
    Outbound,
}

/// <summary>Where the analysis runs, which decides what "DNS" means here.</summary>
public enum AnalysisLocation
{
    /// <summary>Internet access, but no access to either side's servers or DNS: public view only.</summary>
    Isolated,

    /// <summary>Inside the supported site's network: its DNS server is used and compared with the public view.</summary>
    Internal,
}

public enum Severity { Critical, Warning, Inconclusive, Info, Ok }

public sealed class CaseInput
{
    public Direction Direction { get; set; } = Direction.Inbound;
    public AnalysisLocation Location { get; set; } = AnalysisLocation.Isolated;
    public string TheirAddress { get; set; } = "";
    public string OurAddress { get; set; } = "";
    public string BaselineText { get; set; } = "";
    public string FailingText { get; set; } = "";
    public string NdrText { get; set; } = "";

    /// <summary>
    /// Stated by the technician: the supported site's side handles other mail normally
    /// (incoming: the recipient receives plenty of other mail; outgoing: the sender's other
    /// mail reaches other recipients). Moves the weight onto the other party's setup.
    /// </summary>
    public bool OtherMailWorks { get; set; }

    /// <summary>Record-history pages pasted from an archive (optional).</summary>
    public string HistoryText { get; set; } = "";

    /// <summary>
    /// The opposite path of a case that was just checked: the two domains swapped, no
    /// evidence. A health check of that path, not the diagnosis of a mail that failed on it.
    /// </summary>
    public bool ReverseCheck { get; set; }
}

public sealed class DkimTarget
{
    public string Selector { get; set; } = "";
    public string Domain { get; set; } = "";
    public bool FromEvidence { get; set; }

    public override string ToString() => $"{Selector}._domainkey.{Domain}";
}

/// <summary>What the live checks will look at. Suggested from the evidence, editable by the technician.</summary>
public sealed class CheckTargets
{
    /// <summary>The domain in the From header of the mail that fails.</summary>
    public string SenderDomain { get; set; } = "";

    /// <summary>The envelope sender (Return-Path) domain: what SPF checks.</summary>
    public string EnvelopeDomain { get; set; } = "";

    /// <summary>The IP the mail leaves from, if known.</summary>
    public string SendingIp { get; set; } = "";

    public List<DkimTarget> Dkim { get; } = new();

    /// <summary>The domain whose mail servers must accept the mail.</summary>
    public string ReceiverDomain { get; set; } = "";

    /// <summary>Where each suggestion came from, for the Checks page.</summary>
    public List<string> Notes { get; } = new();

    /// <summary>What the technician knows about the DMARC record when the working mail was sent.</summary>
    public KnownState DmarcThen { get; set; } = KnownState.Auto;

    /// <summary>The same for the DKIM key the working mail was signed with.</summary>
    public KnownState DkimThen { get; set; } = KnownState.Auto;
}

/// <summary>A record's state at the time of the working mail: from the evidence, or stated.</summary>
public enum KnownState { Auto, Existed, Absent }

/// <summary>What is known about a record at the time of the working mail, and from where.</summary>
public sealed class RecordThen
{
    public string Record { get; init; } = "";
    public HistoryState State { get; init; }
    public string? Value { get; init; }
    public string Source { get; init; } = "";
    public string Explanation { get; init; } = "";

    /// <summary>Inferred with today's live DNS, not proven: weighs less than a proven state.</summary>
    public bool Likely { get; init; }

    public string Short => State switch
    {
        HistoryState.Present => Value is { Length: > 0 } v ? $"record: {v}" : "record existed",
        HistoryState.Absent => Likely ? "most likely no record" : "no record",
        _ => "unknown",
    } + $" ({Source})";
}

public sealed class CheckOptions
{
    public ResolverChoice Resolver { get; set; } = ResolverChoice.Authoritative();
    public bool DohFallback { get; set; } = true;
    public bool AskAllNameServers { get; set; } = true;
    public bool Blocklists { get; set; } = true;
    public bool SmtpProbe { get; set; } = true;
    public bool MtaSts { get; set; } = true;
}

/// <summary>Whose setup a finding concerns: decides what goes into the report for the sender.</summary>
public enum FindingSide { Sender, Recipient, Analysis, General }

public sealed class Finding
{
    public FindingSide Side { get; set; } = FindingSide.General;

    /// <summary>Raised because a DNS lookup failed (as opposed to: answered, and the answer is bad).</summary>
    public bool LookupFailure { get; set; }

    /// <summary>A concrete change, e.g. a DNS record to publish, when there is one.</summary>
    public string Fix { get; set; } = "";

    public Severity Severity { get; set; }
    public string Area { get; set; } = "";
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public List<string> Evidence { get; } = new();
    public string WhoFixes { get; set; } = "";
    public string NextStep { get; set; } = "";

    /// <summary>Ranking weight: severity plus corroboration (bounce, baseline change, DMARC impact).</summary>
    public int Score { get; set; }

    /// <summary>Short reasons for the ranking, shown next to the likely cause.</summary>
    public List<string> Because { get; } = new();

    /// <summary>The trace steps behind this finding, for "Show trace".</summary>
    public List<string> TraceSteps { get; } = new();
}

public sealed class CompareRow
{
    public string Check { get; init; } = "";
    public string Then { get; init; } = "";
    public string Failing { get; init; } = "";
    public string Now { get; init; } = "";
    public Severity Verdict { get; init; }

    /// <summary>The failing mail differs from the working mail in this check.</summary>
    public bool FailingChanged { get; set; }

    /// <summary>Today's live result differs from what the working mail recorded.</summary>
    public bool NowChanged { get; set; }

    /// <summary>The change is in favour of delivery (marked neutral, not amber).</summary>
    public bool ChangeHelps { get; set; }

    /// <summary>What changed, in words, for the mark next to the cell.</summary>
    public string ChangeNote { get; set; } = "";
}

/// <summary>One record asked of every authoritative name server of its zone.</summary>
public sealed class NsConsistency
{
    public string Purpose { get; init; } = "";        // "SPF", "DMARC", "DKIM selector1", "MX"
    public string Name { get; init; } = "";
    public DnsType Type { get; init; }
    public string Zone { get; init; } = "";
    public List<AuthorityAnswer> Answers { get; } = new();

    public List<AuthorityAnswer> Responding => Answers.Where(a => a.Response.Status is DnsStatus.Ok or DnsStatus.NoData or DnsStatus.NxDomain).ToList();
    public List<AuthorityAnswer> Silent => Answers.Except(Responding).ToList();
    public int Variants => Responding.Select(a => a.Response.Fingerprint()).Distinct().Count();
}

/// <summary>The same name through the site's DNS and through the public view.</summary>
public sealed class SplitView
{
    public string Purpose { get; init; } = "";
    public string Name { get; init; } = "";
    public DnsType Type { get; init; }
    public DnsResponse Internal { get; init; } = new();
    public DnsResponse Public { get; init; } = new();
    public bool Differs => Internal.Fingerprint() != Public.Fingerprint();
}

/// <summary>A zone's SOA serial, read as a change date where the convention allows.</summary>
public sealed class ZoneChange
{
    public string Domain { get; init; } = "";
    public string Side { get; init; } = "";           // "sender" or "receiver"
    public uint Serial { get; init; }
    public DateTimeOffset? Date { get; init; }
    public string Convention { get; init; } = "";
}

public sealed class AnalysisResult
{
    public CaseInput Input { get; init; } = new();
    public CheckTargets Targets { get; init; } = new();
    public CheckOptions Options { get; init; } = new();
    public DateTime When { get; init; } = DateTime.Now;

    public MailEvidence Baseline { get; init; } = new();
    public MailEvidence Failing { get; init; } = new();
    public NdrInfo Ndr { get; init; } = new();

    /// <summary>The failing mail's headers: from the failing-mail box, else the returned message in the bounce.</summary>
    public MailEvidence? FailingEvidence => Failing.HasAnything ? Failing : Ndr.Embedded;
    public bool FailingFromBounce => !Failing.HasAnything && Ndr.Embedded is not null;

    public string ResolverUsed { get; set; } = "";
    public IReadOnlyList<string> Fallbacks { get; set; } = Array.Empty<string>();

    /// <summary>Port 53 on this network is answered by something other than the servers asked.</summary>
    public string? DnsInterception { get; set; }

    /// <summary>Why no resolver gave a usable answer, when none did: lookups then say nothing about the domains.</summary>
    public string? DnsUnavailable { get; set; }

    /// <summary>The resolver in use gives wrong answers and there was none better to move to.</summary>
    public IReadOnlyList<string> DnsPathProblems { get; set; } = Array.Empty<string>();

    public IPAddress? SendingIp { get; set; }
    public SpfHealth? EnvelopeSpf { get; set; }
    public SpfHealth? FromSpf { get; set; }
    public SpfEvaluation? SpfNow { get; set; }

    /// <summary>SPF for the other IP when the working and the failing mail left from different addresses.</summary>
    public SpfEvaluation? SpfOther { get; set; }

    public List<DkimKeyCheck> Dkim { get; } = new();
    public bool DkimProbed { get; set; }
    public DmarcCheck? Dmarc { get; set; }
    public MxCheck? SenderMx { get; set; }
    public ReverseDnsCheck? Ptr { get; set; }
    public List<BlocklistResult> Blocklists { get; } = new();
    public MxCheck? ReceiverMx { get; set; }
    public MtaStsCheck? Sts { get; set; }
    public List<SmtpProbeResult> Probes { get; } = new();

    /// <summary>MX hosts not probed: private addresses only, seen from outside the site.</summary>
    public List<string> SkippedProbes { get; } = new();

    /// <summary>Targets that were not names at all, and so were not checked ("role: text").</summary>
    public List<string> RejectedNames { get; } = new();
    public ReachabilityResult? Reach { get; set; }

    public List<NsConsistency> NameServers { get; } = new();
    public bool NameServersSkipped { get; set; }
    public List<SplitView> Split { get; } = new();
    public List<ZoneChange> Zones { get; } = new();

    /// <summary>Pasted record history, and what it says about the time of the working mail.</summary>
    public List<HistoryName> History { get; } = new();
    public RecordThen? DmarcThen { get; set; }
    public RecordThen? DkimThen { get; set; }
    public RecordThen? SpfThen { get; set; }
    public List<string> HistoryChanges { get; } = new();

    /// <summary>TTLs of the key records: how fast a change takes effect everywhere.</summary>
    public List<(string Purpose, string Name, uint Seconds, bool Negative)> Ttls { get; } = new();

    public IReadOnlyList<string> DnsLog { get; set; } = Array.Empty<string>();

    /// <summary>Everything the analysis did and what came back, in order.</summary>
    public IReadOnlyList<SsddMailAnalyser.Core.TraceEntry> Trace { get; set; } = Array.Empty<SsddMailAnalyser.Core.TraceEntry>();

    public List<Finding> Findings { get; } = new();
    public List<CompareRow> Compare { get; } = new();
    public Finding? Likely { get; set; }

    public SpfEvaluation? SpfFor(IPAddress? ip) =>
        ip is null ? null
        : SpfNow?.Ip is { } a && a.Equals(ip) ? SpfNow
        : SpfOther?.Ip is { } b && b.Equals(ip) ? SpfOther
        : null;
}
