using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace SsddMailAnalyser.Core.Dns;

/// <summary>One value of one record, as a history archive saw it: first and last observation.</summary>
public sealed class HistoryValue
{
    public string Name { get; init; } = "";
    public string Type { get; init; } = "";
    public DateTime From { get; init; }
    public DateTime To { get; init; }
    public string Value { get; set; } = "";
}

/// <summary>What a history archive knows about one DNS name.</summary>
public sealed class HistoryName
{
    public string Name { get; init; } = "";
    public DateTime? Added { get; set; }
    public DateTime? LastUpdated { get; set; }
    public List<HistoryValue> Values { get; } = new();

    /// <summary>Record types the page marks with "(history: N)": earlier values exist beyond those shown.</summary>
    public Dictionary<string, int> HistoryCounts { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Record types whose full history was pasted (a "historical records" page).</summary>
    public HashSet<string> CompleteTypes { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Record types whose history page says "No historical ... records are available": the record
    /// never changed or was never published. History pages list only values no longer published;
    /// the current value and the archive's dates are on the name's overview page.
    /// </summary>
    public HashSet<string> EmptyHistory { get; } = new(StringComparer.OrdinalIgnoreCase);
}

public enum HistoryState { Unknown, Present, Absent }

/// <summary>A record's state at a moment, as far as the pasted history can tell.</summary>
public sealed class HistoryVerdict
{
    public HistoryState State { get; init; }
    public string? Value { get; init; }
    public string Explanation { get; init; } = "";

    /// <summary>Inferred with the help of today's live DNS, not proven by the archive alone.</summary>
    public bool Likely { get; init; }
}

/// <summary>
/// Reads record-history pages that the technician copied from a history archive in the browser
/// (dnshistory.org's layout and plain "date -> date value" lists). Nothing is fetched: the
/// archives forbid automated access, and an isolated system may not reach them anyway.
/// </summary>
public static class RecordHistory
{
    private static readonly Regex Range = new(@"^\s*(\d{4}-\d{2}-\d{2})\s*(?:->|→|–|-|to)\s*(\d{4}-\d{2}-\d{2})\s*(.*)$", RegexOptions.Compiled);
    private static readonly Regex TypeHeader = new(@"^\s*(SOA|NS|MX|A|AAAA|CNAME|PTR|TXT|CAA|SRV)\b\s*(?:-\s*\(\s*\[?history\]?(?:\([^)]*\))?\s*:\s*(\d+)\s*\))?\s*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DomainLine = new(@"^\s*Domain:\s*(.+)$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex RecordLine = new(@"^\s*Record:\s*([A-Za-z]+)\s*$", RegexOptions.Compiled);
    private static readonly Regex DateField = new(@"^\s*(Added|Last updated):\s*(\d{4}-\d{2}-\d{2})", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex LinkUrlName = new(@"dns-records/([^)\s/]+)\)", RegexOptions.Compiled);
    private static readonly Regex MdLink = new(@"\[([^\]]*)\]\([^)]*\)", RegexOptions.Compiled);
    private static readonly Regex NoHistory = new(@"^\s*No historical\s+([A-Za-z]+)\s+records are available", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static List<HistoryName> Parse(string? text)
    {
        var names = new List<HistoryName>();
        if (string.IsNullOrWhiteSpace(text)) return names;

        HistoryName? current = null;
        string? type = null;
        HistoryValue? last = null;

        foreach (var raw in text.Replace("\r\n", "\n").Split('\n'))
        {
            var line = raw.TrimEnd();

            var dm = DomainLine.Match(line);
            if (dm.Success)
            {
                var name = DomainName(dm.Groups[1].Value);
                if (name.Length == 0) continue;
                current = names.FirstOrDefault(n => n.Name == name);
                if (current is null)
                {
                    current = new HistoryName { Name = name };
                    names.Add(current);
                }
                type = null;
                last = null;
                continue;
            }
            if (current is null) continue;

            var df = DateField.Match(line);
            if (df.Success && TryDate(df.Groups[2].Value, out var fieldDate))
            {
                if (df.Groups[1].Value.StartsWith("Added", StringComparison.OrdinalIgnoreCase)) current.Added = fieldDate;
                else current.LastUpdated = fieldDate;
                continue;
            }

            var nh = NoHistory.Match(line);
            if (nh.Success)
            {
                var empty = nh.Groups[1].Value.ToUpperInvariant();
                current.CompleteTypes.Add(empty);
                current.EmptyHistory.Add(empty);
                continue;
            }

            var rl = RecordLine.Match(line);
            if (rl.Success)
            {
                // A "historical records" page: this is the complete list for one type.
                type = rl.Groups[1].Value.ToUpperInvariant();
                current.CompleteTypes.Add(type);
                last = null;
                continue;
            }

            var th = TypeHeader.Match(line);
            if (th.Success)
            {
                type = th.Groups[1].Value.ToUpperInvariant();
                if (th.Groups[2].Success && int.TryParse(th.Groups[2].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var count))
                    current.HistoryCounts[type] = count;
                last = null;
                continue;
            }

            var rm = Range.Match(line);
            if (rm.Success && type is not null && TryDate(rm.Groups[1].Value, out var from) && TryDate(rm.Groups[2].Value, out var to))
            {
                last = new HistoryValue
                {
                    Name = current.Name,
                    Type = type,
                    From = from,
                    To = to,
                    Value = CleanValue(rm.Groups[3].Value),
                };
                current.Values.Add(last);
                continue;
            }

            // SOA details follow their range on separate lines.
            if (last is not null && last.Type == "SOA" && line.TrimStart().StartsWith("Serial:", StringComparison.OrdinalIgnoreCase))
                last.Value = (last.Value + " " + line.Trim()).Trim();
        }
        return names;
    }

    /// <summary>
    /// The state of a record at a moment. Ranges are observations, so a moment between two
    /// observations of the same value counts as that value; a moment after the last observation
    /// counts as "absent" only if the archive looked at the name again later.
    /// </summary>
    /// <param name="presentNow">
    /// What live DNS says today, when the lookup succeeded. A record last seen before the moment,
    /// noticed gone by the archive and still gone today, was most likely absent at the moment too.
    /// </param>
    public static HistoryVerdict StateAt(List<HistoryName> history, string name, string type, DateTime at, Func<string, bool>? isRecord = null, bool? presentNow = null)
    {
        name = DnsWire.Normalize(name);
        var entry = history.FirstOrDefault(h => h.Name == name);
        if (entry is null)
            return new HistoryVerdict { State = HistoryState.Unknown, Explanation = $"no history pasted for {name}" };

        var values = entry.Values.Where(v => v.Type.Equals(type, StringComparison.OrdinalIgnoreCase) && (isRecord?.Invoke(v.Value) ?? true))
                                 .OrderBy(v => v.From).ToList();
        bool complete = entry.CompleteTypes.Contains(type) || !entry.HistoryCounts.ContainsKey(type);
        string day = at.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        var covering = values.FirstOrDefault(v => v.From.Date <= at.Date && at.Date <= v.To.Date);
        if (covering is not null)
            return new HistoryVerdict
            {
                State = HistoryState.Present,
                Value = covering.Value,
                Explanation = $"seen {covering.From:yyyy-MM-dd} to {covering.To:yyyy-MM-dd}, which includes {day}",
            };

        var before = values.LastOrDefault(v => v.To.Date < at.Date);
        var after = values.FirstOrDefault(v => v.From.Date > at.Date);

        if (before is not null && after is not null)
        {
            if (before.Value == after.Value)
                return new HistoryVerdict
                {
                    State = HistoryState.Present,
                    Value = before.Value,
                    Explanation = $"same value seen up to {before.To:yyyy-MM-dd} and again from {after.From:yyyy-MM-dd}",
                };
            return new HistoryVerdict
            {
                State = HistoryState.Unknown,
                Explanation = $"the value changed between {before.To:yyyy-MM-dd} and {after.From:yyyy-MM-dd}; {day} falls in that gap",
            };
        }

        if (!complete)
            return new HistoryVerdict
            {
                State = HistoryState.Unknown,
                Explanation = $"the archive has earlier {type} values for {name} that were not pasted (open its {type} history page)",
            };

        if (before is not null && after is null)
        {
            // Last seen before the moment. Absent only if the archive kept looking after it.
            var lastLook = entry.LastUpdated;
            if (lastLook is { } look && look.Date > at.Date)
                return new HistoryVerdict
                {
                    State = HistoryState.Absent,
                    Value = before.Value,
                    Explanation = $"last seen {before.To:yyyy-MM-dd}; the archive checked the name until {look:yyyy-MM-dd} and found no {type} value after that",
                };
            // The archive saw it gone, and it is still gone today: coming back and vanishing again
            // in between, unseen by the archive, would be unusual.
            if (presentNow == false && lastLook is { } noticed && noticed.Date > before.To.Date)
                return new HistoryVerdict
                {
                    State = HistoryState.Absent,
                    Likely = true,
                    Explanation = $"most likely: last seen {before.To:yyyy-MM-dd}, gone when the archive looked on {noticed:yyyy-MM-dd}, and still gone in live DNS today",
                };
            return new HistoryVerdict
            {
                State = HistoryState.Unknown,
                Explanation = $"last seen {before.To:yyyy-MM-dd}; the archive's last check of the name is not known to be after {day}"
                              + (entry.LastUpdated is null ? " (the name's overview page carries that date)" : ""),
            };
        }

        if (after is not null)
        {
            bool tracked = entry.Added is { } added && added.Date <= at.Date;
            return new HistoryVerdict
            {
                State = tracked ? HistoryState.Absent : HistoryState.Unknown,
                Explanation = tracked
                    ? $"first seen {after.From:yyyy-MM-dd}; the archive tracked the name since {entry.Added:yyyy-MM-dd} without a {type} value before that"
                    : $"first seen {after.From:yyyy-MM-dd}; the archive started tracking the name only then",
            };
        }

        // No values of this type at all.
        if (entry.Added is { } since && since.Date <= at.Date && entry.LastUpdated is { } until && until.Date >= at.Date)
            return new HistoryVerdict
            {
                State = HistoryState.Absent,
                Explanation = $"the archive tracked the name from {since:yyyy-MM-dd} to {until:yyyy-MM-dd} and never saw a {type} value",
            };
        return new HistoryVerdict
        {
            State = HistoryState.Unknown,
            Explanation = entry.EmptyHistory.Contains(type) && entry.LastUpdated is null
                ? $"the archive lists no earlier {type} values (unchanged, or never published); its current value and the archive's dates are on the name's overview page, which is not pasted"
                : $"no {type} values in the pasted history",
        };
    }

    /// <summary>Values of a record that started or ended between two moments: changes in that window.</summary>
    public static List<string> ChangesBetween(List<HistoryName> history, DateTime from, DateTime to)
    {
        var list = new List<string>();
        foreach (var h in history)
        {
            // SOA values change with every serial bump: noise, not a record change.
            foreach (var v in h.Values.Where(v => v.Type != "SOA"))
            {
                if (v.From.Date > from.Date && v.From.Date <= to.Date && v.From.Date > (h.Added?.Date ?? DateTime.MinValue))
                    list.Add($"{h.Name} {v.Type}: value first seen {v.From:yyyy-MM-dd}: {Short(v.Value)}");
                if (v.To.Date >= from.Date && v.To.Date < to.Date && h.LastUpdated is { } lu && lu.Date > v.To.Date)
                    list.Add($"{h.Name} {v.Type}: value last seen {v.To:yyyy-MM-dd}: {Short(v.Value)}");
            }
        }
        return list.Distinct().ToList();
    }

    /// <summary>The archive's own pages for a name, for opening in the browser.</summary>
    public static string RecordsUrl(string name) => $"https://dnshistory.org/dns-records/{Uri.EscapeDataString(DnsWire.Normalize(name))}";

    public static string TypeHistoryUrl(string type, string name) =>
        $"https://dnshistory.org/historical-dns-records/{Uri.EscapeDataString(type.ToLowerInvariant())}/{Uri.EscapeDataString(DnsWire.Normalize(name))}";

    // ------------------------------------------------------------------ helpers

    private static string DomainName(string rest)
    {
        // Linked layout: the first link's target is the full name ("…/dns-records/_dmarc.example.com").
        var link = LinkUrlName.Match(rest);
        if (link.Success) return DnsWire.Normalize(Uri.UnescapeDataString(link.Groups[1].Value));
        var plain = MdLink.Replace(rest, "$1").Trim().TrimEnd('.');
        var token = plain.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        return DnsWire.Normalize(token);
    }

    private static string CleanValue(string value)
    {
        var v = MdLink.Replace(value, "$1").Trim();
        if (v.Length >= 2 && v[0] == '"' && v[^1] == '"') v = v[1..^1];
        return v.Trim();
    }

    private static bool TryDate(string s, out DateTime date) =>
        DateTime.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out date);

    private static string Short(string s) => s.Length > 90 ? s[..87] + "..." : s;
}
