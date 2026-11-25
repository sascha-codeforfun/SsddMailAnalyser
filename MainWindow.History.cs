using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using HueThemeKit;
using SsddMailAnalyser.Core.Diagnosis;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser;

/// <summary>
/// The record-history tab: one row per archive page that matters for this case. The technician
/// opens a page in the browser, copies it, and pastes it into the same row; the row checks that
/// the page is for its name. All rows together are the history the analysis reads.
/// A record's history page lists only values that are no longer published; the current value and
/// the archive's dates are on the name's overview page. A record row therefore holds both.
/// </summary>
public partial class MainWindow
{
    private enum HistoryKind { Overview, Spf, Dmarc, Dkim, Other }

    private sealed class HistorySlot
    {
        public string Key { get; init; } = "";
        public string Label { get; init; } = "";
        public string Why { get; init; } = "";
        public string Name { get; init; } = "";
        public bool TypePage { get; init; }
        public HistoryKind Kind { get; init; }
        public string Url { get; init; } = "";
        public string Text { get; set; } = "";

        /// <summary>The overview page of the row's name, for its current value and the archive's dates (record rows only).</summary>
        public string OverviewText { get; set; } = "";

        public bool HasAny => Text.Length > 0 || OverviewText.Length > 0;
        public IEnumerable<string> Pages => new[] { Text, OverviewText }.Where(t => t.Length > 0);
    }

    private readonly List<HistorySlot> _historySlots = new();

    /// <summary>Every pasted page, one after another: what the analysis parses.</summary>
    private string CombinedHistory() =>
        string.Join(Environment.NewLine + Environment.NewLine,
                    _historySlots.SelectMany(s => s.Pages).Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.TrimEnd()));

    // ------------------------------------------------------------------ the rows

    private void UpdateHistory()
    {
        RebuildHistorySlots();
        RenderHistoryRows();
    }

    /// <summary>The pages this case needs, from the evidence; pasted text is kept across rebuilds.</summary>
    private void RebuildHistorySlots()
    {
        var baseline = HeaderAnalyzer.Analyze(BaselineBox.Text);
        var failing = HeaderAnalyzer.Analyze(FailingBox.Text);

        string? domain = baseline.FromDomain ?? failing.FromDomain;
        if (string.IsNullOrEmpty(domain) && SenderBox.Text.Contains('@')) domain = DomainUtil.DomainOf(SenderBox.Text);
        domain = string.IsNullOrEmpty(domain) ? null : DnsWire.Normalize(domain);

        var wanted = new List<HistorySlot>();
        if (domain is not null)
        {
            var org = DomainUtil.OrgDomain(domain);
            var envelope = baseline.SpfDomain ?? baseline.EnvelopeDomain ?? failing.SpfDomain ?? failing.EnvelopeDomain;
            var spfName = string.IsNullOrEmpty(envelope) ? domain : DnsWire.Normalize(envelope);

            wanted.Add(Slot(HistoryKind.Overview, $"All records of {domain}", "Overview: since when the archive knows the domain and when it last looked", domain, false));
            wanted.Add(Slot(HistoryKind.Spf, "SPF record over time", "TXT history of the envelope domain", spfName, true));
            wanted.Add(Slot(HistoryKind.Dmarc, "DMARC record over time", "TXT history of the DMARC name", "_dmarc." + domain, true));
            if (org != domain)
                wanted.Add(Slot(HistoryKind.Dmarc, "DMARC record of the parent domain", "Applies when the subdomain has none of its own", "_dmarc." + org, true));

            var selectors = baseline.DkimSignatures.Concat(failing.DkimSignatures)
                .Where(s => s.Selector.Length > 0 && s.Domain.Length > 0)
                .Select(s => (Selector: DnsWire.Normalize(s.Selector), Domain: DnsWire.Normalize(s.Domain)))
                .Distinct().Take(3);
            foreach (var (selector, signer) in selectors)
                wanted.Add(Slot(HistoryKind.Dkim, $"DKIM key over time (selector {selector})", "TXT history of the key the working mail was signed with", $"{selector}._domainkey.{signer}", true));
        }

        // Keep what was pasted; pages that fit no suggested row stay as their own rows.
        foreach (var w in wanted)
        {
            var old = _historySlots.FirstOrDefault(s => s.Key == w.Key);
            if (old is null) continue;
            w.Text = old.Text;
            w.OverviewText = old.OverviewText;
        }
        var extras = _historySlots.Where(s => s.HasAny && wanted.All(w => w.Key != s.Key)).ToList();

        _historySlots.Clear();
        _historySlots.AddRange(wanted);
        _historySlots.AddRange(extras);
    }

    private static HistorySlot Slot(HistoryKind kind, string label, string why, string name, bool typePage) => new()
    {
        Key = $"{name}|{(typePage ? "txt" : "all")}",
        Label = label,
        Why = why,
        Name = name,
        TypePage = typePage,
        Kind = kind,
        Url = typePage ? RecordHistory.TypeHistoryUrl("TXT", name) : RecordHistory.RecordsUrl(name),
    };

    private void RenderHistoryRows()
    {
        HistoryRows.Children.Clear();
        var sent = HeaderAnalyzer.Analyze(BaselineBox.Text).Date;
        var all = RecordHistory.Parse(CombinedHistory());

        if (_historySlots.Count == 0)
        {
            HistoryRows.Children.Add(Caption("The rows appear once the sender's address (first page) or the headers of a working mail are given."));
        }
        foreach (var slot in _historySlots) HistoryRows.Children.Add(HistoryRow(slot, sent, all));

        int filled = _historySlots.Count(s => s.HasAny);
        HistoryFooter.Text = sent is { } d
            ? $"{filled} of {_historySlots.Count} row(s) filled. Each record is judged as of the working mail of {d.ToLocalTime():yyyy-MM-dd}."
            : $"{filled} of {_historySlots.Count} row(s) filled. The working mail's headers are needed for its date; without them the history is shown but not judged.";
    }

    private FrameworkElement HistoryRow(HistorySlot slot, DateTimeOffset? sent, List<HistoryName> all)
    {
        var row = new Border { BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(0, 10, 0, 12) };
        row.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");

        var grid = new Grid();
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        row.Child = grid;

        // ---- left: what the row is, and what the pasted page says
        var left = new StackPanel { Margin = new Thickness(0, 0, 16, 0) };
        grid.Children.Add(left);

        var title = new StackPanel { Orientation = Orientation.Horizontal };
        if (slot.HasAny)
        {
            var check = new Path { Data = (Geometry)FindResource("Icon.Check"), Margin = new Thickness(0, 0, 6, 0), VerticalAlignment = VerticalAlignment.Center };
            check.SetResourceReference(StyleProperty, "Hue.Icon");
            check.SetResourceReference(Shape.StrokeProperty, "Brush.Ok");
            title.Children.Add(check);
        }
        title.Children.Add(new TextBlock { Text = slot.Label, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center });
        left.Children.Add(title);

        var name = MonoText(slot.Name);
        name.Margin = new Thickness(0, 2, 0, 0);
        left.Children.Add(name);
        var why = Caption(slot.Why);
        why.TextWrapping = TextWrapping.Wrap;
        left.Children.Add(why);

        var status = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
        left.Children.Add(status);
        foreach (var line in DescribePaste(slot, sent, all, status)) left.Children.Add(PreviewLine(line));

        // ---- right: the row's buttons
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Top };
        Grid.SetColumn(buttons, 1);
        grid.Children.Add(buttons);
        buttons.Children.Add(GhostButton("Open page", "Icon.Open", slot.Url, () => OpenLink(slot.Url)));
        // A record row also needs its name's overview, unless the domain's own overview row covers it.
        if (slot.TypePage && !_historySlots.Any(s => !s.TypePage && s.Name == slot.Name))
        {
            var overviewUrl = RecordHistory.RecordsUrl(slot.Name);
            buttons.Children.Add(GhostButton("Open overview", "Icon.Open", overviewUrl + "\nThe current value and when the archive last looked", () => OpenLink(overviewUrl)));
        }
        buttons.Children.Add(GhostButton("Paste", null, "Paste the copied page into this row", () => PasteIntoSlot(slot)));
        if (slot.HasAny)
            buttons.Children.Add(GhostButton("Clear", null, "Remove the pages of this row", () =>
            {
                slot.Text = "";
                slot.OverviewText = "";
                RebuildHistorySlots();
                HistoryChanged();
            }));
        return row;
    }

    /// <summary>The status pills for a row, and the lines worth showing from its pages.</summary>
    private IEnumerable<string> DescribePaste(HistorySlot slot, DateTimeOffset? sent, List<HistoryName> all, WrapPanel status)
    {
        // The overview of this name may sit in the domain's own row.
        bool overviewElsewhere = slot.TypePage && _historySlots.Any(s => !s.TypePage && s.Name == slot.Name && s.Text.Length > 0);
        if (!slot.HasAny && !overviewElsewhere)
        {
            status.Children.Add(Pill("Not pasted", Severity.Inconclusive));
            return Array.Empty<string>();
        }

        // Each pasted page on its own: recognised, and for this name?
        foreach (var text in slot.Pages)
        {
            var own = RecordHistory.Parse(text);
            if (own.Count == 0)
            {
                status.Children.Add(Pill("Not recognised as a history page", Severity.Warning));
                status.Children.Add(Caption("  Copy the whole page (Ctrl+A in the browser), not a part of it."));
            }
            else if (own.All(n => n.Name != slot.Name))
            {
                status.Children.Add(Pill($"This page is for {own[0].Name}", Severity.Warning));
                status.Children.Add(Caption(_historySlots.FirstOrDefault(r => r.Name == own[0].Name) is { } right
                    ? $"  Clear it here and paste it in the row \"{right.Label}\"."
                    : "  Clear it here; this page is not for one of the names this case needs."));
            }
        }

        // What all pasted pages together say about this name.
        var entry = all.FirstOrDefault(n => n.Name == slot.Name);
        if (entry is null) return Array.Empty<string>();

        var values = entry.Values.Where(v => Relevant(slot.Kind, v)).OrderBy(v => v.From).ToList();
        bool hasDates = entry.Added is not null && entry.LastUpdated is not null;

        if (slot.Kind == HistoryKind.Overview || !slot.TypePage)
        {
            status.Children.Add(Pill($"{entry.Values.Count} value(s)", Severity.Ok));
            status.Children.Add(Caption("  " + (hasDates ? $"archive tracked it {entry.Added:yyyy-MM-dd} to {entry.LastUpdated:yyyy-MM-dd}" : "archive dates not on the page")));
            var counts = entry.Values.GroupBy(v => v.Type).Select(g => $"{g.Key} {g.Count()}");
            return new[] { "Types: " + string.Join(", ", counts) };
        }

        bool hasHistory = entry.CompleteTypes.Contains("TXT");
        bool neverChanged = entry.EmptyHistory.Contains("TXT");
        status.Children.Add(Pill(!hasHistory ? "History page not pasted"
                                 : neverChanged ? "History: no earlier values"
                                 : "History pasted",
                                 hasHistory ? Severity.Ok : Severity.Inconclusive));
        status.Children.Add(Pill(hasDates ? $"Overview: archive looked {entry.Added:yyyy-MM-dd} to {entry.LastUpdated:yyyy-MM-dd}" : "Overview not pasted",
                                 hasDates ? Severity.Ok : Severity.Inconclusive));

        var lines = new List<string>();
        if (sent is { } d && slot.Kind is HistoryKind.Spf or HistoryKind.Dmarc or HistoryKind.Dkim)
        {
            var at = d.LocalDateTime;
            var verdict = RecordHistory.StateAt(all, slot.Name, "TXT", at, t => IsRecord(slot.Kind, t));
            var word = verdict.State switch { HistoryState.Present => "existed", HistoryState.Absent => "did not exist", _ => "unknown" };
            lines.Add($"On {at:yyyy-MM-dd} (working mail): {word}"
                      + (verdict.State == HistoryState.Present && verdict.Value is { Length: > 0 } then ? $": {Shorten(then, 80)}" : "")
                      + $"  ({verdict.Explanation})");
        }
        foreach (var v in values.TakeLast(5)) lines.Add($"{v.From:yyyy-MM-dd} -> {v.To:yyyy-MM-dd}  {Shorten(v.Value, 90)}");
        if (values.Count > 5) lines.Add($"... {values.Count - 5} earlier value(s)");

        if (neverChanged)
            lines.Add("No earlier values: the record is unchanged since the archive first saw it, or was never published.");
        if (!hasDates)
            lines.Add(_historySlots.Any(s => !s.TypePage && s.Name == slot.Name)
                ? "The current value and the archive's dates are on the overview page: paste it into the row \"" + _historySlots.First(s => !s.TypePage && s.Name == slot.Name).Label + "\"."
                : "The current value and the archive's dates are on the overview page: Open overview, copy it and paste it into this row.");
        else if (!hasHistory)
            lines.Add("Earlier values are on the history page: Open page, copy it and paste it into this row.");
        else if (values.Count == 0 && !neverChanged)
            lines.Add("No such record on the pasted pages.");
        return lines;
    }

    private static bool Relevant(HistoryKind kind, HistoryValue v) =>
        kind == HistoryKind.Overview || (v.Type == "TXT" && (kind == HistoryKind.Other || IsRecord(kind, v.Value)));

    private static bool IsRecord(HistoryKind kind, string value) => kind switch
    {
        HistoryKind.Spf => value.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase),
        HistoryKind.Dmarc => value.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase),
        HistoryKind.Dkim => value.Contains("p=", StringComparison.OrdinalIgnoreCase),
        _ => true,
    };

    private static string Shorten(string s, int max) => s.Length > max ? s[..(max - 3)] + "..." : s;

    private static TextBlock PreviewLine(string text)
    {
        var tb = MonoText(text);
        tb.Margin = new Thickness(0, 4, 0, 0);
        tb.FontSize = 12;
        return tb;
    }

    private Button GhostButton(string text, string? icon, string tip, Action click)
    {
        var content = new StackPanel { Orientation = Orientation.Horizontal };
        if (icon is not null)
        {
            var path = new Path { Data = (Geometry)FindResource(icon), Margin = new Thickness(0, 0, 6, 0) };
            path.SetResourceReference(StyleProperty, "Hue.Icon");
            content.Children.Add(path);
        }
        // A TextBlock, not a string: an underscore in a name (_dmarc) would become an access key.
        content.Children.Add(new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center });
        var b = new Button { Content = content, ToolTip = tip, Margin = new Thickness(6, 0, 0, 0) };
        b.SetResourceReference(StyleProperty, "Hue.Button.Ghost");
        b.Click += (_, _) => click();
        return b;
    }

    // ------------------------------------------------------------------ pasting

    /// <summary>A record row takes either of its two pages: the overview goes beside the history.</summary>
    private void PasteIntoSlot(HistorySlot slot)
    {
        var text = ClipboardText();
        if (text is null) return;
        var parsed = RecordHistory.Parse(text);
        bool overview = parsed.Count > 0 && parsed[0].CompleteTypes.Count == 0;
        if (slot.TypePage && overview) slot.OverviewText = text;
        else slot.Text = text;
        HistoryChanged();
    }

    private string? ClipboardText()
    {
        try
        {
            if (Clipboard.ContainsText()) return Clipboard.GetText();
            SetStatus("The clipboard holds no text. Copy the page in the browser first (Ctrl+A, Ctrl+C).", Severity.Warning);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            SetStatus("The clipboard is busy; try again.", Severity.Warning);
        }
        return null;
    }

    private void HistoryChanged()
    {
        RenderHistoryRows();
        UpdateTabMarks();
        OnEvidenceToggle(this, new RoutedEventArgs());
    }

    // ------------------------------------------------------------------ tab marks

    /// <summary>A check mark on every evidence tab that holds something.</summary>
    private void UpdateTabMarks()
    {
        BaselineCheck.Visibility = Mark(!string.IsNullOrWhiteSpace(BaselineBox.Text));
        FailingCheck.Visibility = Mark(!string.IsNullOrWhiteSpace(FailingBox.Text));
        NdrCheck.Visibility = Mark(!string.IsNullOrWhiteSpace(NdrBox.Text));
        HistoryCheck.Visibility = Mark(_historySlots.Any(s => s.Pages.Any(t => RecordHistory.Parse(t).Count > 0)));
    }

    private static Visibility Mark(bool filled) => filled ? Visibility.Visible : Visibility.Collapsed;
}
