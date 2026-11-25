using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace SsddMailAnalyser.Core;

public enum TraceOutcome { Ok, Info, Warn, Fail }

/// <summary>One thing the analysis did, and what came back, at the detail level-3 support needs.</summary>
public sealed class TraceEntry
{
    public int Seq { get; init; }
    public DateTime Time { get; init; }

    /// <summary>How long the action took, in milliseconds; null where timing means nothing.</summary>
    public double? Ms { get; init; }

    /// <summary>The analysis step it belongs to: "SPF", "DKIM", "SMTP", "Reach", ... Findings link to it.</summary>
    public string Step { get; init; } = "";

    /// <summary>DNS, DoH, TCP, SMTP, TLS, HTTP, SPF, DKIM, Parse, Note.</summary>
    public string Kind { get; init; } = "";

    public string Action { get; init; } = "";
    public TraceOutcome Outcome { get; init; }
    public string Result { get; init; } = "";
    public string Details { get; init; } = "";

    public string TimeText => Time.ToString("HH:mm:ss.fff");
    public string MsText => Ms is { } ms ? (ms < 10 ? ms.ToString("0.0") : ms.ToString("0")) : "";
    public string OutcomeText => Outcome switch
    {
        TraceOutcome.Ok => "OK",
        TraceOutcome.Warn => "Warning",
        TraceOutcome.Fail => "Failed",
        _ => "Info",
    };

    public string FullText =>
        $"#{Seq}  {Time:yyyy-MM-dd HH:mm:ss.fff}  {(Ms is null ? "" : MsText + " ms  ")}[{Step}] {Kind}\n" +
        $"Action:  {Action}\nResult:  {OutcomeText} - {Result}" +
        (Details.Length > 0 ? "\n\n" + Details : "");
}

/// <summary>
/// The running log of an analysis. Written from the worker thread (and only from there while
/// the analysis runs), read by the UI afterwards.
/// </summary>
public sealed class TraceLog
{
    private readonly List<TraceEntry> _entries = new();
    private readonly object _gate = new();

    /// <summary>The step whose work is running now; stamped on every entry.</summary>
    public string Step { get; set; } = "Setup";

    public TraceEntry Add(string kind, string action, TraceOutcome outcome, string result, string details = "", double? ms = null)
    {
        lock (_gate)
        {
            var entry = new TraceEntry
            {
                Seq = _entries.Count + 1,
                Time = DateTime.Now,
                Ms = ms,
                Step = Step,
                Kind = kind,
                Action = action,
                Outcome = outcome,
                Result = result,
                Details = details,
            };
            _entries.Add(entry);
            return entry;
        }
    }

    public IReadOnlyList<TraceEntry> Entries
    {
        get { lock (_gate) return _entries.ToList(); }
    }

    public static double Elapsed(Stopwatch sw) => sw.Elapsed.TotalMilliseconds;
}
