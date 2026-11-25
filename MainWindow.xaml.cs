using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using HueThemeKit;
using Microsoft.Win32;
using SsddMailAnalyser.Core;
using SsddMailAnalyser.Core.Diagnosis;
using SsddMailAnalyser.Core.Dns;
using SsddMailAnalyser.Core.Mail;

namespace SsddMailAnalyser;

public partial class MainWindow : Window
{
    private const string AppName = "SsddMailAnalyser";

    private readonly bool _ready;
    private readonly DispatcherTimer _parseTimer;

    private CheckTargets? _targets;
    private string? _targetsSignature;
    private string? _resultSignature;
    private AnalysisResult? _result;

    // _result is what is on screen: the diagnosis of the case, or the check of its reverse direction.
    private AnalysisResult? _forward;
    private AnalysisResult? _reverse;
    private bool _switchingShown;

    // The operator's own domains and the busy-animation switch, from SsddMailAnalyser.json next to the exe.
    private readonly string _settingsPath = AppSettings.DefaultPath;
    private AppSettings _settings = new();
    private string? _domainToAdd;
    private bool _fillingDomains;

    public MainWindow()
    {
        InitializeComponent();
        HueTitleBar.Attach(this);

        VersionText.Text = HueVersion.Text;
        SdkText.Text = HueVersion.Sdk is { } sdk ? "built with SDK " + sdk : "";
        SdkText.Visibility = HueVersion.Sdk is null ? Visibility.Collapsed : Visibility.Visible;
        RuntimeText.Text = "runtime " + HueVersion.Runtime;

        _parseTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(350) };
        _parseTimer.Tick += (_, _) =>
        {
            _parseTimer.Stop();
            UpdateEvidenceSummaries();
            UpdateHeaderPills();
        };

        FillResolvers();
        _settings = AppSettings.Load(_settingsPath);
        ApplySettings();
        _ready = true;
        UpdateDirectionTexts();
        UpdateEvidenceSummaries();
    }

    // ================================================================== navigation

    private void ShowPage(int page)
    {
        if (!_ready) return;
        PageProblem.Visibility = page == 1 ? Visibility.Visible : Visibility.Collapsed;
        PageEvidence.Visibility = page == 2 ? Visibility.Visible : Visibility.Collapsed;
        PageChecks.Visibility = page == 3 ? Visibility.Visible : Visibility.Collapsed;
        PageDiagnosis.Visibility = page == 4 ? Visibility.Visible : Visibility.Collapsed;

        var nav = page switch { 1 => NavProblem, 2 => NavEvidence, 3 => NavChecks, _ => NavDiagnosis };
        if (nav.IsChecked != true) nav.IsChecked = true;

        if (page == 2) UpdateHistory();
        if (page == 3) PrepareChecks();
        if (page == 4) StaleNotice.Visibility = _resultSignature is not null && _resultSignature != ResultSignature() ? Visibility.Visible : Visibility.Collapsed;
        UpdateHeaderPills();

        var scroller = page switch { 1 => PageProblem, 2 => PageEvidence, 3 => PageChecks, _ => DiagnosisScroll };
        scroller.ScrollToTop();
    }

    private void OnNavChecked(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        if (sender == NavProblem) ShowPage(1);
        else if (sender == NavEvidence) ShowPage(2);
        else if (sender == NavChecks) ShowPage(3);
        else if (sender == NavDiagnosis) ShowPage(4);
    }

    private void OnNextToEvidence(object sender, RoutedEventArgs e) => ShowPage(2);
    private void OnBackToProblem(object sender, RoutedEventArgs e) => ShowPage(1);
    private void OnNextToChecks(object sender, RoutedEventArgs e) => ShowPage(3);
    private void OnBackToEvidence(object sender, RoutedEventArgs e) => ShowPage(2);
    private void OnBackToChecks(object sender, RoutedEventArgs e) => ShowPage(3);

    private Direction CurrentDirection => DirOutbound.IsChecked == true ? Direction.Outbound : Direction.Inbound;

    private void OnDirectionChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        UpdateDirectionTexts();
        UpdateMyDomainHint();

        // The picked domain is the side that is "here". Turning the direction round turns the
        // two addresses round with it, if the picked one still sits where it was put.
        if (MyDomainBox.SelectedItem is string mine)
        {
            bool inbound = CurrentDirection == Direction.Inbound;
            var was = inbound ? SenderBox : RecipientBox;
            var now = inbound ? RecipientBox : SenderBox;
            if (string.Equals(was.Text.Trim(), mine, StringComparison.OrdinalIgnoreCase))
            {
                var other = now.Text;
                now.Text = mine;
                was.Text = other;
            }
        }
    }

    // ================================================================== settings: my domains

    /// <summary>Puts the loaded or just-saved settings to work: the picker on step 1 and the busy rings.</summary>
    private void ApplySettings()
    {
        _fillingDomains = true;   // refilling the picker must not count as picking
        MyDomainBox.Items.Clear();
        foreach (var domain in _settings.Domains) MyDomainBox.Items.Add(domain);
        MyDomainBox.SelectedIndex = -1;
        _fillingDomains = false;

        bool any = _settings.Domains.Count > 0;
        MyDomainRow.Visibility = any ? Visibility.Visible : Visibility.Collapsed;
        MyDomainEmpty.Visibility = any ? Visibility.Collapsed : Visibility.Visible;
        UpdateMyDomainHint();

        // Ticked: the rings turn whatever Windows says. Unticked: they follow Windows.
        Busy.AnimateOverride = _settings.AlwaysTurn ? true : null;
    }

    private void UpdateMyDomainHint()
    {
        MyDomainHint.Text = CurrentDirection == Direction.Inbound
            ? "fills in the recipient: incoming mail arrives here"
            : "fills in the sender: outgoing mail leaves from here";
    }

    /// <summary>One of the operator's domains was picked: it is the side that is "here".</summary>
    private void OnMyDomainPicked(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || _fillingDomains || MyDomainBox.SelectedItem is not string domain) return;
        if (CurrentDirection == Direction.Inbound) RecipientBox.Text = domain;
        else SenderBox.Text = domain;
    }

    private void OnSettings(object sender, RoutedEventArgs e)
    {
        var dialog = new SettingsWindow(_settings, _settingsPath) { Owner = this };
        if (dialog.ShowDialog() != true) return;

        _settings = new AppSettings { Domains = dialog.Domains.ToList(), AlwaysTurn = dialog.AlwaysTurn };
        SaveSettings("Settings saved.");
        ApplySettings();
        UpdateAddDomainOffer();
    }

    /// <summary>Rule: if the app's folder cannot be written, the settings last for the session, without an error.</summary>
    private void SaveSettings(string saved)
    {
        if (_settings.Save(_settingsPath)) SetStatus(saved, Severity.Ok);
        else SetStatus("Settings kept for this session only: the program's folder cannot be written.", Severity.Inconclusive);
    }

    /// <summary>
    /// After a run: if the side that is "here" is a domain not yet in the list, offer to add
    /// it. Nothing is written without that click.
    /// </summary>
    private void UpdateAddDomainOffer()
    {
        _domainToAdd = null;
        if (_result is not null)
        {
            var here = _result.Input.Direction == Direction.Inbound ? _result.Targets.ReceiverDomain : _result.Targets.SenderDomain;
            var clean = AppSettings.Clean(here);
            if (clean is not null && !_settings.Has(clean)) _domainToAdd = clean;
        }

        // A TextBlock, not a string: in a button's text an underscore would be taken as its access key.
        AddDomainButton.Content = _domainToAdd is null ? null : new TextBlock { Text = $"Add {_domainToAdd} to my domains" };
        AddDomainButton.Visibility = _domainToAdd is null ? Visibility.Collapsed : Visibility.Visible;
    }

    private void OnAddMyDomain(object sender, RoutedEventArgs e)
    {
        if (_domainToAdd is null || !_settings.Add(_domainToAdd)) { UpdateAddDomainOffer(); return; }
        SaveSettings($"{_domainToAdd} added to my domains.");
        ApplySettings();
        UpdateAddDomainOffer();
    }

    private void UpdateDirectionTexts()
    {
        bool inbound = CurrentDirection == Direction.Inbound;
        BaselineHint.Text = inbound
            ? "An earlier mail from this sender that reached the recipient."
            : "An earlier mail from the sender as the recipient received it (ask the recipient for its headers), or any reply from the recipient.";
        FailingHint.Text = inbound
            ? "A copy of the sender's failing mail: released from quarantine, found in junk, or a test the sender sent to a freemail mailbox you can read."
            : "The sender's failing mail as received somewhere: a test to a freemail mailbox, or a copy the recipient found in junk.";
        NdrHint.Text = inbound
            ? "The bounce the sender got, if they forwarded it to you."
            : "The bounce the sender got back.";
        OtherMailWorksText.Text = inbound
            ? "The recipient's side receives other mail normally (many messages daily, no general problem)"
            : "The sender's other mail reaches other recipients normally";
        OtherMailWorksHint.Text = inbound
            ? "Your statement, recorded in the report. Gaps in the sender's setup are then ranked as the likely cause."
            : "Your statement, recorded in the report. Gaps on the recipient's side are then ranked as the likely cause.";
        SenderSideTitle.Text = inbound ? "SENDER (EXTERNAL)" : "SENDER (SUPPORTED SITE)";
        ReceiverSideTitle.Text = inbound ? "RECIPIENT (SUPPORTED SITE)" : "RECIPIENT (EXTERNAL)";
    }

    // ================================================================== evidence input

    private void OnPasteBaseline(object sender, RoutedEventArgs e) => PasteInto(BaselineBox);
    private void OnPasteNdr(object sender, RoutedEventArgs e) => PasteInto(NdrBox);
    private void OnClearBaseline(object sender, RoutedEventArgs e) => BaselineBox.Clear();
    private void OnClearNdr(object sender, RoutedEventArgs e) => NdrBox.Clear();
    private void OnPasteFailing(object sender, RoutedEventArgs e) => PasteInto(FailingBox);
    private void OnClearFailing(object sender, RoutedEventArgs e) => FailingBox.Clear();
    private void OnOpenFailing(object sender, RoutedEventArgs e) => OpenInto(FailingBox);
    private void OnFailingDrop(object sender, DragEventArgs e) => DropInto(FailingBox, e);
    private void OnOpenBaseline(object sender, RoutedEventArgs e) => OpenInto(BaselineBox);
    private void OnOpenNdr(object sender, RoutedEventArgs e) => OpenInto(NdrBox);
    /// <summary>Opens an archive page in the browser. The technician reads and copies it; the app fetches nothing.</summary>
    private void OpenLink(string url)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            HueMessage.Show(this, "Could not open the browser", $"Open this address by hand:\n{url}\n\n{ex.Message}");
        }
    }

    private void PasteInto(TextBox box)
    {
        try
        {
            if (Clipboard.ContainsText())
            {
                box.Text = Clipboard.GetText();
                return;
            }
            if (Clipboard.ContainsFileDropList())
            {
                var file = Clipboard.GetFileDropList().Cast<string>().FirstOrDefault();
                if (file is not null) LoadFileInto(box, file);
                return;
            }
            SetStatus("The clipboard holds no text.", Severity.Warning);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            SetStatus("The clipboard is busy; try again.", Severity.Warning);
        }
    }

    private void OpenInto(TextBox box)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open a saved mail or bounce",
            Filter = "Mail and text (*.eml;*.txt;*.log)|*.eml;*.txt;*.log|Outlook message (*.msg)|*.msg|All files (*.*)|*.*",
        };
        if (dialog.ShowDialog(this) == true) LoadFileInto(box, dialog.FileName);
    }

    private void OnBoxDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }
    }

    private void OnBaselineDrop(object sender, DragEventArgs e) => DropInto(BaselineBox, e);
    private void OnNdrDrop(object sender, DragEventArgs e) => DropInto(NdrBox, e);

    private void DropInto(TextBox box, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
        {
            e.Handled = true;
            LoadFileInto(box, files[0]);
        }
    }

    private void LoadFileInto(TextBox box, string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Length > 60 * 1024 * 1024)
            {
                HueMessage.Show(this, "File too large", "That file is over 60 MB. Headers and bounces are a few KB; save the message without its attachments.");
                return;
            }
            var bytes = File.ReadAllBytes(path);
            if (MsgReader.LooksLikeMsg(bytes))
            {
                LoadMsgInto(box, MsgReader.Read(bytes), Path.GetFileName(path));
                return;
            }
            string text;
            try
            {
                text = new UTF8Encoding(false, true).GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                text = Encoding.Latin1.GetString(bytes);
            }
            box.Text = text.TrimStart('﻿');
            SetStatus($"Loaded {Path.GetFileName(path)}.", Severity.Ok);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            HueMessage.Show(this, "Could not open the file", ex.Message);
        }
    }

    /// <summary>
    /// An Outlook .msg: its Internet headers go into a header box, its body into the bounce
    /// box. A bounce dropped on a header box is moved to the bounce box, because that is what
    /// the technician meant.
    /// </summary>
    private void LoadMsgInto(TextBox box, MsgReader.Result msg, string fileName)
    {
        bool isBounceBox = box == NdrBox;
        if (isBounceBox || msg.IsBounce)
        {
            NdrBox.Text = msg.AsBounceText();
            SetStatus(isBounceBox ? $"Loaded {fileName}." : $"{fileName} is a bounce: loaded into the bounce box.", Severity.Ok);
            if (!isBounceBox) NdrBox.Focus();
            return;
        }

        if (string.IsNullOrWhiteSpace(msg.Headers))
        {
            HueMessage.Show(this, "No Internet headers in this message",
                $"{fileName} carries no Internet headers. Outlook keeps them only for mail that arrived from outside; a sent item, a draft or a mail forwarded as an attachment by some clients has none. Use the original received mail.");
            return;
        }
        box.Text = msg.Headers;
        SetStatus($"Loaded the Internet headers of {fileName}" + (string.IsNullOrEmpty(msg.Subject) ? "." : $" ({msg.Subject})."), Severity.Ok);
    }

    /// <summary>An input the result depends on changed: show the stale notice until the checks run again.</summary>
    private void OnEvidenceToggle(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        if (_resultSignature is not null)
            StaleNotice.Visibility = _resultSignature != ResultSignature() ? Visibility.Visible : Visibility.Collapsed;
        UpdateHeaderPills();
    }

    private void OnThenChanged(object sender, SelectionChangedEventArgs e) => OnEvidenceToggle(sender, e);

    private void OnEvidenceChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready) return;
        _parseTimer.Stop();
        _parseTimer.Start();
    }

    /// <summary>What was understood from each box, shown under it while typing.</summary>
    private void UpdateEvidenceSummaries()
    {
        UpdateHistory();
        UpdateTabMarks();
        NdrSummary.Children.Clear();
        SummarizeHeaders(BaselineSummary, BaselineBox.Text, "Nothing yet.");
        SummarizeHeaders(FailingSummary, FailingBox.Text, "Nothing yet. Optional, but the strongest evidence there is.");

        if (string.IsNullOrWhiteSpace(NdrBox.Text))
        {
            NdrSummary.Children.Add(Caption("Nothing yet. Optional."));
        }
        else
        {
            var ndr = NdrParser.Parse(NdrBox.Text);
            if (ndr.Primary is { } p)
            {
                NdrSummary.Children.Add(Pill($"{p.ReplyCode} {p.Code}".Trim(), p.IsPermanent && !ndr.LooksLikeDelay ? Severity.Critical : Severity.Warning));
                NdrSummary.Children.Add(Text(p.Meaning?.Title ?? "Code not in the built-in list", margin: new Thickness(10, 0, 18, 0)));
            }
            else
            {
                NdrSummary.Children.Add(Pill("No status code found", Severity.Inconclusive));
            }
            if (ndr.LooksLikeDelay) NdrSummary.Children.Add(Pill("Delay, still retrying", Severity.Warning));
            AddFact(NdrSummary, "Recipient", ndr.Recipients.FirstOrDefault());
            AddFact(NdrSummary, "Server", ndr.RemoteHosts.FirstOrDefault() ?? ndr.ReportingMta);
            if (ndr.Embedded?.From is { } embeddedFrom) AddFact(NdrSummary, "Returned mail from", embeddedFrom);
        }
    }

    private void SummarizeHeaders(WrapPanel panel, string text, string emptyText)
    {
        panel.Children.Clear();
        var mail = HeaderAnalyzer.Analyze(text);
        if (string.IsNullOrWhiteSpace(text))
        {
            panel.Children.Add(Caption(emptyText));
            return;
        }
        if (!mail.HasAnything)
        {
            panel.Children.Add(Pill("No header fields found", Severity.Warning));
            panel.Children.Add(Caption("  Header lines look like 'Received: from ...'. Did the copy include them?"));
            return;
        }
        AddFact(panel, "From", mail.From);
        AddFact(panel, "Envelope", mail.ReturnPath ?? mail.SpfDomain);
        AddFact(panel, "Sending IP", mail.SendingIp?.ToString());
        AddFact(panel, "Date", mail.Date?.ToLocalTime().ToString("yyyy-MM-dd HH:mm"));
        AddResult(panel, "SPF", mail.SpfResult);
        if (mail.DkimResults.Count > 0)
            foreach (var d in mail.DkimResults.Take(3)) AddResult(panel, $"DKIM {d.Domain}", d.Result);
        else
            AddResult(panel, "DKIM", mail.DkimSignatures.Count > 0 ? "signed" : "none");
        AddResult(panel, "DMARC", mail.DmarcResult ?? (mail.PrimaryAuth is not null && !mail.PrimaryAuth.Methods.Any(m => m.Method == "dmarc") ? "not reported" : null));
        if (mail.Scl is { } scl) AddResult(panel, "SCL", scl >= 5 ? $"{scl} (spam)" : scl.ToString());
        if (mail.PrimaryAuth is not null)
            AddFact(panel, "DMARC carried by", mail.DmarcCarriedBy);
        else
            panel.Children.Add(Pill("No Authentication-Results", Severity.Inconclusive));
    }

    private void AddFact(WrapPanel panel, string label, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 20, 4), VerticalAlignment = VerticalAlignment.Center };
        sp.Children.Add(Caption(label + ": "));
        var v = new TextBlock { Text = value, VerticalAlignment = VerticalAlignment.Center };
        v.SetResourceReference(StyleProperty, "Text.Mono");
        sp.Children.Add(v);
        panel.Children.Add(sp);
    }

    private void AddResult(WrapPanel panel, string label, string? result)
    {
        if (string.IsNullOrWhiteSpace(result)) return;
        var r = result.ToLowerInvariant();
        var sev = r is "pass" or "bestguesspass" or "signed" ? Severity.Ok
                : r is "fail" or "permerror" || r.EndsWith("(spam)") ? Severity.Critical
                : r is "softfail" or "temperror" ? Severity.Warning
                : Severity.Inconclusive;
        var pill = Pill($"{label}: {r}", sev);
        pill.Margin = new Thickness(0, 4, 10, 4);
        panel.Children.Add(pill);
    }

    // ================================================================== checks page

    private string Signature() => string.Join("\u0001",
        CurrentDirection, CurrentLocation, OtherMailWorksBox.IsChecked == true, SenderBox.Text.Trim(), RecipientBox.Text.Trim(), BaselineBox.Text, FailingBox.Text, NdrBox.Text);

    /// <summary>
    /// Everything the result depends on beyond the suggested targets: the pasted history and the
    /// "at that time" choices. Kept apart so that changing them does not refill the Checks fields.
    /// </summary>
    private string ResultSignature() => string.Join("\u0001", Signature(), CombinedHistory(), DmarcThenBox.SelectedIndex, DkimThenBox.SelectedIndex,
        SenderDomainBox.Text.Trim(), EnvelopeBox.Text.Trim(), SendingIpBox.Text.Trim(), DkimBox.Text.Trim(), ReceiverBox.Text.Trim(),
        (ResolverBox.Text ?? "").Trim(), OptAskAll.IsChecked == true, OptDoh.IsChecked == true, OptBlocklists.IsChecked == true,
        OptProbe.IsChecked == true, OptMtaSts.IsChecked == true);

    /// <summary>The result no longer matches what is on screen: ask before handing it on.</summary>
    private bool ConfirmIfStale(string what)
    {
        if (_resultSignature is null || _resultSignature == ResultSignature()) return true;
        return HueConfirm.Ask(this, "The result is out of date",
            $"Evidence or check settings changed after the last run. The {what} would show the earlier result, not what is on screen now. Run the checks again first, or continue anyway?",
            "Continue anyway");
    }

    private static KnownState ThenChoice(ComboBox box) => box.SelectedIndex switch
    {
        1 => KnownState.Existed,
        2 => KnownState.Absent,
        _ => KnownState.Auto,
    };

    private void PrepareChecks()
    {
        var sig = Signature();
        if (_targets is not null && _targetsSignature == sig) return;

        var input = BuildInput();
        var baseline = HeaderAnalyzer.Analyze(input.BaselineText);
        var failing = HeaderAnalyzer.Analyze(input.FailingText);
        var ndr = NdrParser.Parse(input.NdrText);
        _targets = CaseAnalyzer.Suggest(input, baseline, failing, ndr);
        _targetsSignature = sig;

        SenderDomainBox.Text = _targets.SenderDomain;
        EnvelopeBox.Text = _targets.EnvelopeDomain;
        SendingIpBox.Text = _targets.SendingIp;
        DkimBox.Text = string.Join(Environment.NewLine, _targets.Dkim.Select(d => $"{d.Selector}:{d.Domain}"));
        ReceiverBox.Text = _targets.ReceiverDomain;

        NotesPanel.Children.Clear();
        var notes = _targets.Notes.ToList();
        if (_targets.Dkim.Count > 0) notes.Add("DKIM selectors from the DKIM-Signature headers of the evidence.");
        if (!baseline.HasAnything && !failing.HasAnything && !ndr.HasAnything) notes.Add("No evidence given: only what you typed on the first page is used.");
        if (notes.Count == 0) notes.Add("Domains taken from the From, Return-Path and To headers.");
        foreach (var n in notes)
        {
            var tb = new TextBlock { Text = "- " + n, Margin = new Thickness(0, 2, 0, 2) };
            tb.SetResourceReference(StyleProperty, "Text.Body");
            NotesPanel.Children.Add(tb);
        }
    }

    private CaseInput BuildInput() => new()
    {
        Direction = CurrentDirection,
        Location = CurrentLocation,
        OtherMailWorks = OtherMailWorksBox.IsChecked == true,
        // The engine thinks in "external party" and "supported site"; the screen in sender and recipient.
        TheirAddress = (CurrentDirection == Direction.Inbound ? SenderBox : RecipientBox).Text.Trim(),
        OurAddress = (CurrentDirection == Direction.Inbound ? RecipientBox : SenderBox).Text.Trim(),
        BaselineText = BaselineBox.Text,
        FailingText = FailingBox.Text,
        NdrText = NdrBox.Text,
        HistoryText = CombinedHistory(),
    };

    private List<ResolverChoice> _resolvers = new();

    private void FillResolvers()
    {
        _resolvers = ResolverChoice.All();
        ResolverBox.ItemsSource = _resolvers;
        SelectDefaultResolver();
    }

    /// <summary>Isolated: authoritative resolution. Internal: this computer's DNS server, which sees what the site's mail gateway sees.</summary>
    private void SelectDefaultResolver()
    {
        var choice = CurrentLocation == AnalysisLocation.Internal
            ? _resolvers.FirstOrDefault(r => r.IsSystem) ?? _resolvers[0]
            : _resolvers[0];
        ResolverBox.SelectedItem = choice;
        ResolverHint.Text = CurrentLocation == AnalysisLocation.Internal
            ? "The site's own DNS server sees what its mail gateway sees; the public view is queried as well and compared. You can type any resolver IP."
            : "Authoritative asks each domain's own name servers directly: no caches, and blocklists like Spamhaus answer. If port 53 is blocked here, DNS over HTTPS takes over. You can type any resolver IP.";
    }

    private void OnLocationChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready) return;
        SelectDefaultResolver();
    }

    private AnalysisLocation CurrentLocation => LocInternal.IsChecked == true ? AnalysisLocation.Internal : AnalysisLocation.Isolated;

    private ResolverChoice? ReadResolver()
    {
        if (ResolverBox.SelectedItem is ResolverChoice selected && selected.Display == (ResolverBox.Text ?? "").Trim())
            return selected;
        var text = (ResolverBox.Text ?? "").Trim();
        var match = _resolvers.FirstOrDefault(r => r.Display.Equals(text, StringComparison.OrdinalIgnoreCase));
        if (match is not null) return match;
        var first = text.Split(new[] { ' ', '\t', '(' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        if (IPAddress.TryParse(first, out var ip) && ip is not null && (ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            return ResolverChoice.ForServer(ip);
        return null;
    }

    private async void OnRun(object sender, RoutedEventArgs e)
    {
        var resolver = ReadResolver();
        if (resolver is null)
        {
            HueMessage.Show(this, "Which DNS server?", "Pick a resolver from the list or type its IP address.");
            ResolverBox.Focus();
            return;
        }

        var input = BuildInput();
        var targets = new CheckTargets
        {
            SenderDomain = DomainUtil.DomainOf(SenderDomainBox.Text),
            EnvelopeDomain = DomainUtil.DomainOf(EnvelopeBox.Text),
            SendingIp = SendingIpBox.Text.Trim(),
            ReceiverDomain = DomainUtil.DomainOf(ReceiverBox.Text),
            DmarcThen = ThenChoice(DmarcThenBox),
            DkimThen = ThenChoice(DkimThenBox),
        };
        targets.Dkim.AddRange(CaseAnalyzer.ParseDkimLines(DkimBox.Text, targets.SenderDomain, _targets?.Dkim ?? new List<DkimTarget>()));
        if (_targets is not null) targets.Notes.AddRange(_targets.Notes);

        if (targets.SendingIp.Length > 0 && !NetUtil.TryParseIp(targets.SendingIp, out _))
        {
            HueMessage.Show(this, "Sending IP not understood", $"'{targets.SendingIp}' is not an IPv4 or IPv6 address. Correct it or clear the field.");
            SendingIpBox.Focus();
            return;
        }
        if (targets.SenderDomain.Length == 0 && targets.ReceiverDomain.Length == 0 && targets.SendingIp.Length == 0)
        {
            HueMessage.Show(this, "Nothing to check", "Give at least a domain or an IP, or paste headers on the Evidence page.");
            return;
        }

        var options = new CheckOptions
        {
            Resolver = resolver,
            DohFallback = OptDoh.IsChecked == true,
            AskAllNameServers = OptAskAll.IsChecked == true,
            Blocklists = OptBlocklists.IsChecked == true,
            SmtpProbe = OptProbe.IsChecked == true,
            MtaSts = OptMtaSts.IsChecked == true,
        };
        var signature = ResultSignature();

        using var cancel = new CancellationTokenSource();
        SetStatus("Checking...", Severity.Info);
        try
        {
            var result = await Busy.RunAsync("Checking the mail path",
                report => CaseAnalyzer.Run(input, targets, options, report.Say, cancel.Token),
                cancel);

            _result = result;
            _forward = result;
            _reverse = null;   // it was the reverse of the previous run
            _resultSignature = signature;
            RenderDiagnosis(result);
            UpdateShownRow();
            NavDiagnosis.IsEnabled = true;
            NavDiagnosis.ToolTip = null;
            ShowPage(4);

            int problems = result.Findings.Count(f => f.Severity == Severity.Critical);
            int warnings = result.Findings.Count(f => f.Severity == Severity.Warning);
            SetStatus($"Checked at {result.When:HH:mm}: {problems} problem(s), {warnings} warning(s). DNS via {result.ResolverUsed}"
                      + (result.Fallbacks.Count > 0 ? " (fallback)" : "") + ".",
                problems > 0 ? Severity.Critical : warnings > 0 ? Severity.Warning : Severity.Ok);
            UpdateHeaderPills();
            UpdateAddDomainOffer();
        }
        catch (OperationCanceledException)
        {
            SetStatus("Checks cancelled.", Severity.Inconclusive);
        }
        catch (Exception ex)
        {
            // async void: anything escaping here would take the whole app down mid-case.
            SetStatus("The checks stopped with an error.", Severity.Critical);
            HueMessage.Show(this, "The checks stopped", ex.GetBaseException().Message);
        }
    }

    // ================================================================== reverse direction

    /// <summary>
    /// The same two parties, mail going the other way: swaps the domains of the case that was
    /// checked and runs the checks again with the same settings. The diagnosis of the case
    /// stays; the two can be switched between.
    /// </summary>
    private async void OnReverse(object sender, RoutedEventArgs e)
    {
        if (_forward is null) return;

        var (input, targets) = CaseAnalyzer.Reverse(_forward.Input, _forward.Targets);
        if (targets.SenderDomain.Length == 0 || targets.ReceiverDomain.Length == 0)
        {
            HueMessage.Show(this, "Both domains are needed",
                "The reverse direction can only be checked when the case has a sender domain and a receiver domain. Fill in both on the Checks page and run the checks first.");
            return;
        }
        var options = _forward.Options;

        using var cancel = new CancellationTokenSource();
        SetStatus("Checking the reverse direction...", Severity.Info);
        try
        {
            var result = await Busy.RunAsync("Checking the reverse direction",
                report => CaseAnalyzer.Run(input, targets, options, report.Say, cancel.Token),
                cancel);

            _reverse = result;
            ShowResult(result);

            int problems = result.Findings.Count(f => f.Severity == Severity.Critical);
            int warnings = result.Findings.Count(f => f.Severity == Severity.Warning);
            SetStatus($"Reverse direction checked at {result.When:HH:mm}: {problems} problem(s), {warnings} warning(s). DNS via {result.ResolverUsed}"
                      + (result.Fallbacks.Count > 0 ? " (fallback)" : "") + ".",
                problems > 0 ? Severity.Critical : warnings > 0 ? Severity.Warning : Severity.Ok);
        }
        catch (OperationCanceledException)
        {
            SetStatus("Reverse check cancelled.", Severity.Inconclusive);
        }
        catch (Exception ex)
        {
            // async void: anything escaping here would take the whole app down mid-case.
            SetStatus("The reverse check stopped with an error.", Severity.Critical);
            HueMessage.Show(this, "The checks stopped", ex.GetBaseException().Message);
        }
    }

    /// <summary>Puts one of the two results on screen; everything on the page, the pills, copy and export follow it.</summary>
    private void ShowResult(AnalysisResult result)
    {
        _result = result;
        RenderDiagnosis(result);
        // Rendering clears the notice; whether the evidence changed since the run has not changed.
        StaleNotice.Visibility = _resultSignature is not null && _resultSignature != ResultSignature() ? Visibility.Visible : Visibility.Collapsed;
        UpdateHeaderPills();
        UpdateAddDomainOffer();
        UpdateShownRow();
    }

    private void OnShownChanged(object sender, RoutedEventArgs e)
    {
        if (!_ready || _switchingShown) return;
        var wanted = ShowReverse.IsChecked == true ? _reverse : _forward;
        if (wanted is null || ReferenceEquals(wanted, _result)) return;
        ShowResult(wanted);
        SetStatus(ReferenceEquals(wanted, _reverse) ? "Showing the reverse-direction check." : "Showing the diagnosis of the case.", Severity.Ok);
    }

    /// <summary>The switch between the two results: there once the reverse direction has been checked.</summary>
    private void UpdateShownRow()
    {
        if (ShownRow is null) return;   // a navigation event while the window is still loading
        _switchingShown = true;
        ShownRow.Visibility = _forward is not null && _reverse is not null ? Visibility.Visible : Visibility.Collapsed;
        // TextBlocks, not strings: an underscore in a domain must not turn into an access key.
        ShowForward.Content = _forward is null ? null : new TextBlock { Text = PathOf(_forward) };
        ShowReverse.Content = _reverse is null ? null : new TextBlock { Text = PathOf(_reverse) + "  (reverse check)" };
        bool reverseShown = _reverse is not null && ReferenceEquals(_result, _reverse);
        ShowForward.IsChecked = !reverseShown;
        ShowReverse.IsChecked = reverseShown;
        _switchingShown = false;

        ReverseButton.IsEnabled = _forward is not null;
    }

    private static string PathOf(AnalysisResult r) => $"{Or(r.Targets.SenderDomain)}  \u2192  {Or(r.Targets.ReceiverDomain)}";

    // ================================================================== diagnosis page

    private void RenderDiagnosis(AnalysisResult r)
    {
        var t = r.Targets;
        CaseLine.Text = (r.Input.ReverseCheck ? "Reverse check  ·  " : "")
                        + (r.Input.Direction == Direction.Inbound ? "Incoming" : "Outgoing")
                        + $"  ·  sender {Or(t.SenderDomain)}"
                        + (t.SendingIp.Length > 0 ? $" ({t.SendingIp})" : "")
                        + $"  ·  receiver {Or(t.ReceiverDomain)}"
                        + $"  ·  {r.When:yyyy-MM-dd HH:mm}";
        StaleNotice.Visibility = Visibility.Collapsed;

        LikelyHost.Content = r.Likely is null ? null : BuildLikely(r.Likely);
        BuildCompare(r);
        BuildFindings(r);

        BindTrace(r);
        ParsedBox.Text = DescribeEvidence(r);
    }

    private UIElement BuildLikely(Finding f)
    {
        var callout = new ContentControl { Focusable = false };
        callout.SetResourceReference(StyleProperty, f.Severity switch
        {
            Severity.Critical => "Hue.Callout.Critical",
            Severity.Warning => "Hue.Callout.Warn",
            Severity.Ok => "Hue.Callout.Ok",
            _ => "Hue.Callout",
        });

        var stack = new StackPanel();
        stack.Children.Add(new TextBlock
        {
            Text = (f.Severity is Severity.Critical or Severity.Warning ? "Likely cause: " : "") + f.Title,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
        });

        var detail = new TextBlock { Text = f.Detail, Margin = new Thickness(0, 6, 0, 0) };
        detail.SetResourceReference(StyleProperty, "Text.Body");
        stack.Children.Add(detail);

        if (f.Because.Count > 0)
        {
            var because = new TextBlock { Text = "Ranked first because: " + string.Join("; ", f.Because) + ".", Margin = new Thickness(0, 6, 0, 0) };
            because.SetResourceReference(StyleProperty, "Text.Caption");
            stack.Children.Add(because);
        }

        var grid = new Grid { Margin = new Thickness(0, 14, 0, 0) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(24) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        var who = Labeled("WHO FIXES IT", f.WhoFixes);
        var next = Labeled("NEXT STEP", f.NextStep);
        Grid.SetColumn(next, 2);
        grid.Children.Add(who);
        grid.Children.Add(next);
        stack.Children.Add(grid);

        if (f.Evidence.Count > 0)
        {
            var ev = new TextBlock { Text = string.Join(Environment.NewLine, f.Evidence), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 14, 0, 0) };
            ev.SetResourceReference(StyleProperty, "Text.Mono");
            stack.Children.Add(ev);
        }

        if (f.Fix.Length > 0) stack.Children.Add(FixBlock(f.Fix, new Thickness(0, 14, 0, 0)));

        var traceButton = TraceButton(f);
        if (traceButton is not null)
        {
            traceButton.HorizontalAlignment = HorizontalAlignment.Left;
            traceButton.Margin = new Thickness(0, 12, 0, 0);
            stack.Children.Add(traceButton);
        }

        callout.Content = stack;
        return callout;
    }

    /// <summary>The record to publish, selectable so it can be copied.</summary>
    private static FrameworkElement FixBlock(string fix, Thickness margin)
    {
        var panel = new StackPanel { Margin = margin };
        var label = new TextBlock { Text = "RECORD TO PUBLISH" };
        label.SetResourceReference(StyleProperty, "Text.Section");
        panel.Children.Add(label);
        var box = new TextBox
        {
            Text = fix,
            IsReadOnly = true,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 4, 0, 0),
            FontFamily = (System.Windows.Media.FontFamily)Application.Current.FindResource("Font.Mono"),
        };
        System.Windows.Automation.AutomationProperties.SetName(box, "Record to publish");
        panel.Children.Add(box);
        return panel;
    }

    private FrameworkElement Labeled(string label, string text)
    {
        var sp = new StackPanel();
        var l = new TextBlock { Text = label };
        l.SetResourceReference(StyleProperty, "Text.Section");
        sp.Children.Add(l);
        var v = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) };
        v.SetResourceReference(TextBlock.ForegroundProperty, "Brush.Text");
        sp.Children.Add(v);
        return sp;
    }

    private void BuildCompare(AnalysisResult r)
    {
        var g = CompareGrid;
        g.Children.Clear();
        g.RowDefinitions.Clear();
        g.ColumnDefinitions.Clear();

        bool withFailing = r.Compare.Any(c => c.Failing.Length > 0);
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.2, GridUnitType.Star), MinWidth = 150 });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        if (withFailing) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.3, GridUnitType.Star) });
        g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto, MinWidth = 120 });

        if (r.Compare.Count == 0)
        {
            var empty = Caption("Nothing to compare: no headers of a working mail, or no live checks that relate to them.");
            Grid.SetColumnSpan(empty, g.ColumnDefinitions.Count);
            g.Children.Add(empty);
            return;
        }

        var header = new List<UIElement> { Section("CHECK"), Section("WORKING MAIL") };
        if (withFailing) header.Add(Section(r.FailingFromBounce ? "RETURNED IN BOUNCE" : "FAILING MAIL"));
        header.Add(Section("NOW (LIVE DNS)"));
        header.Add(Section("VERDICT"));
        AddRow(g, 0, header, separator: false);

        int row = 1;
        foreach (var c in r.Compare)
        {
            var cells = new List<UIElement>
            {
                new TextBlock { Text = c.Check, TextWrapping = TextWrapping.Wrap, FontWeight = FontWeights.SemiBold },
                MonoText(c.Then),
            };
            if (withFailing) cells.Add(c.FailingChanged ? ChangedCell(c.Failing, "differs from the working mail", helps: false) : MonoText(c.Failing));
            cells.Add(c.NowChanged
                ? ChangedCell(c.Now, (c.ChangeHelps ? "changed, in favour of delivery: " : "changed: ") + c.ChangeNote, c.ChangeHelps)
                : MonoText(c.Now));
            cells.Add(Pill(ReportWriter.Word(c.Verdict), c.Verdict));
            AddRow(g, row++, cells, separator: true);
        }
    }

    /// <summary>
    /// A comparison cell that differs from the working mail: amber tint and edge, and the
    /// difference in words underneath, so the colour is never the only cue.
    /// </summary>
    private static Border ChangedCell(string text, string note, bool helps)
    {
        // Amber for a change against delivery or of unknown effect; the neutral accent tint for
        // a change in favour of delivery. The words say which; colour only ranks it.
        string fg = helps ? "Brush.AccentText" : "Brush.WarnText";
        var value = MonoText(text);
        value.SetResourceReference(TextBlock.ForegroundProperty, fg);
        var caption = new TextBlock { Text = note, TextWrapping = TextWrapping.Wrap, FontSize = 11.5, Margin = new Thickness(0, 3, 0, 0) };
        caption.SetResourceReference(TextBlock.ForegroundProperty, fg);
        var stack = new StackPanel();
        stack.Children.Add(value);
        stack.Children.Add(caption);
        var border = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(5), Padding = new Thickness(8, 5, 8, 5), Child = stack };
        border.SetResourceReference(Border.BackgroundProperty, helps ? "Brush.AccentSoft" : "Brush.WarnSoft");
        border.SetResourceReference(Border.BorderBrushProperty, helps ? "Brush.AccentEdge" : "Brush.WarnEdge");
        return border;
    }

    private static void AddRow(Grid g, int row, IReadOnlyList<UIElement> cells, bool separator)
    {
        g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        if (separator)
        {
            var line = new Border { BorderThickness = new Thickness(0, 1, 0, 0) };
            line.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");
            Grid.SetRow(line, row);
            Grid.SetColumnSpan(line, cells.Count);
            g.Children.Add(line);
        }
        for (int i = 0; i < cells.Count; i++)
        {
            if (cells[i] is FrameworkElement fe)
            {
                fe.Margin = new Thickness(i == 0 ? 0 : 10, 9, 10, 9);
                fe.VerticalAlignment = VerticalAlignment.Center;
            }
            Grid.SetRow(cells[i], row);
            Grid.SetColumn(cells[i], i);
            g.Children.Add(cells[i]);
        }
    }

    private void BuildFindings(AnalysisResult r)
    {
        FindingsPanel.Children.Clear();
        bool first = true;
        foreach (var f in r.Findings)
        {
            var row = new Grid { Margin = new Thickness(0, first ? 6 : 0, 0, 0) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(130) });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            var border = new Border { BorderThickness = new Thickness(0, first ? 0 : 1, 0, 0), Padding = new Thickness(0, 14, 0, 14) };
            border.SetResourceReference(Border.BorderBrushProperty, "Brush.LineSoft");
            first = false;

            var pill = Pill(ReportWriter.Word(f.Severity), f.Severity);
            pill.VerticalAlignment = VerticalAlignment.Top;
            pill.Margin = new Thickness(0, 1, 0, 0);
            row.Children.Add(pill);

            var body = new StackPanel();
            Grid.SetColumn(body, 1);

            var titleLine = new DockPanel();
            var tag = new ContentControl { Content = f.Area, Margin = new Thickness(10, 0, 0, 0), VerticalAlignment = VerticalAlignment.Top };
            tag.SetResourceReference(StyleProperty, "Hue.Tag");
            DockPanel.SetDock(tag, Dock.Right);
            titleLine.Children.Add(tag);
            titleLine.Children.Add(new TextBlock { Text = f.Title, FontWeight = FontWeights.SemiBold, TextWrapping = TextWrapping.Wrap });
            body.Children.Add(titleLine);

            var detail = new TextBlock { Text = f.Detail, Margin = new Thickness(0, 4, 0, 0) };
            detail.SetResourceReference(StyleProperty, "Text.Body");
            body.Children.Add(detail);

            if (f.Severity is Severity.Critical or Severity.Warning or Severity.Inconclusive)
            {
                var who = new TextBlock { Margin = new Thickness(0, 6, 0, 0) };
                who.SetResourceReference(StyleProperty, "Text.Caption");
                who.Text = $"Who fixes it: {f.WhoFixes}    Next: {f.NextStep}";
                body.Children.Add(who);
            }

            if (f.Evidence.Count > 0)
            {
                var ev = new TextBlock { Text = string.Join(Environment.NewLine, f.Evidence), TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
                ev.SetResourceReference(StyleProperty, "Text.Mono");
                var expander = new Expander
                {
                    Header = $"Evidence ({f.Evidence.Count})",
                    Content = ev,
                    Margin = new Thickness(0, 8, 0, 0),
                    IsExpanded = f.Severity == Severity.Critical,
                };
                body.Children.Add(expander);
            }

            if (f.Fix.Length > 0) body.Children.Add(FixBlock(f.Fix, new Thickness(0, 8, 0, 0)));

            var traceButton = TraceButton(f);
            if (traceButton is not null)
            {
                traceButton.HorizontalAlignment = HorizontalAlignment.Left;
                traceButton.Margin = new Thickness(-8, 6, 0, 0);
                body.Children.Add(traceButton);
            }

            row.Children.Add(body);
            border.Child = row;
            FindingsPanel.Children.Add(border);
        }
    }

    private static string DescribeEvidence(AnalysisResult r)
    {
        var text = DescribeMail("WORKING MAIL", r.Baseline);
        if (r.FailingEvidence is { } failing)
            text += Environment.NewLine + DescribeMail(r.FailingFromBounce ? "RETURNED MESSAGE IN THE BOUNCE" : "FAILING MAIL", failing);
        return text;
    }

    private static string DescribeMail(string title, MailEvidence b)
    {
        if (!b.HasAnything) return title + ": (no headers given)" + Environment.NewLine;
        var sb = new StringBuilder();
        sb.AppendLine(title);
        sb.AppendLine(new string('=', title.Length));
        sb.AppendLine($"From:          {b.From}  {(b.FromDisplay is null ? "" : "(" + b.FromDisplay + ")")}");
        sb.AppendLine($"Return-Path:   {b.ReturnPath}");
        sb.AppendLine($"To:            {string.Join(", ", b.To)}");
        sb.AppendLine($"Subject:       {b.Subject}");
        sb.AppendLine($"Date:          {b.Date:yyyy-MM-dd HH:mm:ss zzz}");
        sb.AppendLine($"Message-ID:    {b.MessageId}");
        sb.AppendLine($"Sending IP:    {b.SendingIp}   <- {b.SendingIpSource}");
        sb.AppendLine($"Sending host:  {b.SendingHost} (HELO {b.SendingHelo})");
        if (b.TotalTransit is { } transit) sb.AppendLine($"Transit:       {transit}");
        if (b.Scl is not null || b.Bcl is not null) sb.AppendLine($"Spam rating:   SCL {b.Scl}  BCL {b.Bcl}  {b.SpamVerdict}");
        else if (b.SpamVerdict is not null) sb.AppendLine($"Spam rating:   {b.SpamVerdict}");
        sb.AppendLine();
        sb.AppendLine("Authentication-Results (newest first):");
        foreach (var a in b.AuthResults)
        {
            sb.AppendLine($"  [{a.Source}{(a.AuthServId is null ? "" : " by " + a.AuthServId)}]{(a == b.PrimaryAuth ? "  <- used" : "")}");
            foreach (var m in a.Methods) sb.AppendLine("    " + m);
        }
        sb.AppendLine();
        sb.AppendLine("DKIM-Signature:");
        foreach (var s in b.DkimSignatures) sb.AppendLine($"  d={s.Domain} s={s.Selector} a={s.Algorithm} signed {s.Signed:yyyy-MM-dd HH:mm}");
        sb.AppendLine();
        sb.AppendLine("Received (newest first):");
        foreach (var h in b.Hops)
        {
            sb.AppendLine($"  {h.Index + 1,2}. {h.Time:yyyy-MM-dd HH:mm:ss}  +{h.DelayBefore?.ToString(@"hh\:mm\:ss") ?? "        "}");
            sb.AppendLine($"      from {h.FromHelo} ({h.FromHost} [{h.FromIp}])");
            sb.AppendLine($"      by   {h.ByHost}  with {h.With}  {h.Tls}");
        }
        return sb.ToString();
    }

    // ================================================================== report

    private void OnCopyReport(object sender, RoutedEventArgs e)
    {
        if (_result is null || !ConfirmIfStale("copied report")) return;
        try
        {
            Clipboard.SetText(ReportWriter.Write(_result, AppName));
            SetStatus("Report copied to the clipboard.", Severity.Ok);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            SetStatus("The clipboard is busy; try again.", Severity.Warning);
        }
    }

    private static string AppVersion => typeof(App).Assembly.GetName().Version?.ToString(3) ?? "?";

    /// <summary>HTML (for sharing), JSON (everything), CSV of findings, CSV of the trace, or the text report.</summary>
    private void OnExport(object sender, RoutedEventArgs e)
    {
        if (_result is null || !ConfirmIfStale("export")) return;
        var name = string.IsNullOrEmpty(_result.Targets.SenderDomain) ? "case" : _result.Targets.SenderDomain;
        var stem = $"SSDD-{name}-{_result.When:yyyyMMdd-HHmm}";
        var dialog = new SaveFileDialog
        {
            Title = "Export the analysis",
            Filter = "Full report, opens in any browser (HTML)|*.html|" +
                     "Report for the sender: sending-side findings only (HTML)|*.html|" +
                     "Findings, comparison and full trace (JSON)|*.json|" +
                     "Findings for Excel (CSV)|*.csv|" +
                     "Technical trace for Excel (CSV)|*.csv|" +
                     "Report (text)|*.txt",
            FilterIndex = 1,
            FileName = stem + ".html",
            AddExtension = true,
        };
        if (dialog.ShowDialog(this) != true) return;

        // The extension follows the chosen format, whatever the name field still says.
        var wanted = dialog.FilterIndex switch { 1 or 2 => ".html", 3 => ".json", 6 => ".txt", _ => ".csv" };
        var chosen = dialog.FileName;
        if (dialog.FilterIndex == 2 && !Path.GetFileNameWithoutExtension(chosen).EndsWith("-for-sender", StringComparison.OrdinalIgnoreCase))
            chosen = Path.Combine(Path.GetDirectoryName(chosen) ?? "", Path.GetFileNameWithoutExtension(chosen) + "-for-sender");
        var fileName = Path.ChangeExtension(chosen, wanted);

        // The dialog asked about the name as typed. The file written can be another one
        // (extension by format, "-for-sender"), and that one has not been asked about.
        if (!string.Equals(fileName, dialog.FileName, StringComparison.OrdinalIgnoreCase) && File.Exists(fileName)
            && !HueConfirm.Ask(this, "Replace the existing file?",
                   $"{Path.GetFileName(fileName)} already exists in that folder. The export would replace it.", "Replace", destructive: true))
            return;

        bool? AskEvidence()
        {
            var choice = HueMessage.Choose(this, "Include the evidence?",
                "The pasted headers and the bounce text contain addresses, server names and subjects. Include them for a level-3 hand-over. Leave them out to drop the raw text, the subject lines and the recipient lists; the addresses, server names and IPs that the findings and the trace are about stay.",
                "Include", "Leave out");
            return choice == HueChoice.Cancel ? null : choice == HueChoice.Yes;
        }

        string content;
        Encoding encoding = new UTF8Encoding(false);
        switch (dialog.FilterIndex)
        {
            case 1:
            {
                if (AskEvidence() is not { } include) return;
                content = HtmlReport.Write(_result, AppName, AppVersion, LoadIconBytes(), include);
                break;
            }
            case 2:
                content = HtmlReport.WriteForSender(_result, AppName, AppVersion, LoadIconBytes());
                break;
            case 3:
            {
                if (AskEvidence() is not { } include) return;
                content = Exporter.ToJson(_result, AppName, AppVersion, includeEvidence: include);
                break;
            }
            case 4:
                content = Exporter.FindingsCsv(_result);
                break;
            case 5:
                content = Exporter.TraceCsv(_result);
                break;
            default:
                content = ReportWriter.Write(_result, AppName);
                encoding = new UTF8Encoding(true);
                break;
        }

        try
        {
            File.WriteAllText(fileName, content, encoding);
            SetStatus($"Exported: {fileName}", Severity.Ok);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            HueMessage.Show(this, "Could not write the file", ex.Message);
        }
    }

    /// <summary>The header image, embedded into the HTML report so the file stands alone.</summary>
    private static byte[]? LoadIconBytes()
    {
        try
        {
            var info = Application.GetResourceStream(new Uri("pack://application:,,,/app_256.png", UriKind.Absolute));
            if (info is null) return null;
            using var stream = info.Stream;
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ms.ToArray();
        }
        catch (Exception ex) when (ex is IOException or UriFormatException or InvalidOperationException)
        {
            return null;
        }
    }

    // ================================================================== technical trace

    /// <summary>An entry in the step filter: all, one step, or the steps behind one finding.</summary>
    private sealed class StepChoice
    {
        public string Label { get; init; } = "";
        public HashSet<string>? Steps { get; init; }
        public override string ToString() => Label;
    }

    private System.ComponentModel.ICollectionView? _traceView;
    private List<StepChoice> _stepChoices = new();

    private void BindTrace(AnalysisResult r)
    {
        _stepChoices = new List<StepChoice> { new() { Label = "All steps" } };
        foreach (var step in r.Trace.Select(t => t.Step).Distinct())
            _stepChoices.Add(new StepChoice { Label = step, Steps = new HashSet<string> { step } });
        TraceStepFilter.ItemsSource = _stepChoices;
        TraceStepFilter.SelectedIndex = 0;

        _traceView = System.Windows.Data.CollectionViewSource.GetDefaultView(r.Trace.ToList());
        _traceView.Filter = TraceFilter;
        TraceGrid.ItemsSource = _traceView;
        TraceDetail.Text = "Select an entry to see the request and the full response.";
        UpdateTraceCount();
    }

    private bool TraceFilter(object item)
    {
        if (item is not SsddMailAnalyser.Core.TraceEntry entry) return false;
        if (TraceStepFilter.SelectedItem is StepChoice { Steps: { } steps } && !steps.Contains(entry.Step)) return false;
        switch (TraceOutcomeFilter.SelectedIndex)
        {
            case 1 when entry.Outcome is not (SsddMailAnalyser.Core.TraceOutcome.Warn or SsddMailAnalyser.Core.TraceOutcome.Fail):
            case 2 when entry.Outcome is not SsddMailAnalyser.Core.TraceOutcome.Fail:
                return false;
        }
        var find = TraceSearch.Text.Trim();
        if (find.Length > 0 &&
            entry.Action.IndexOf(find, StringComparison.OrdinalIgnoreCase) < 0 &&
            entry.Result.IndexOf(find, StringComparison.OrdinalIgnoreCase) < 0 &&
            entry.Details.IndexOf(find, StringComparison.OrdinalIgnoreCase) < 0)
            return false;
        return true;
    }

    private void OnTraceFilterChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready || _traceView is null) return;
        _traceView.Refresh();
        UpdateTraceCount();
    }

    private void OnTraceSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (!_ready || _traceView is null) return;
        _traceView.Refresh();
        UpdateTraceCount();
    }

    private void UpdateTraceCount()
    {
        if (_traceView is null || _result is null) { TraceCount.Text = ""; return; }
        int shown = _traceView.Cast<object>().Count();
        TraceCount.Text = $"{shown} of {_result.Trace.Count} entries";
    }

    private void OnTraceSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (TraceGrid.SelectedItem is SsddMailAnalyser.Core.TraceEntry entry)
            TraceDetail.Text = entry.FullText;
    }

    private void OnCopyTraceEntry(object sender, RoutedEventArgs e)
    {
        if (TraceGrid.SelectedItem is not SsddMailAnalyser.Core.TraceEntry entry) return;
        try
        {
            Clipboard.SetText(entry.FullText);
            SetStatus($"Trace entry #{entry.Seq} copied.", Severity.Ok);
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            SetStatus("The clipboard is busy; try again.", Severity.Warning);
        }
    }

    /// <summary>A quiet "Show trace" button for a finding, when the trace has entries for it.</summary>
    private Button? TraceButton(Finding f)
    {
        if (_result is null || f.TraceSteps.Count == 0) return null;
        var steps = new HashSet<string>(f.TraceSteps);
        int count = _result.Trace.Count(t => steps.Contains(t.Step));
        if (count == 0) return null;

        var content = new StackPanel { Orientation = Orientation.Horizontal };
        var icon = new System.Windows.Shapes.Path { Data = (System.Windows.Media.Geometry)FindResource("Icon.Search") };
        icon.SetResourceReference(StyleProperty, "Hue.Icon");
        content.Children.Add(icon);
        content.Children.Add(new TextBlock { Text = $"Show trace ({count})", Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });

        var button = new Button { Content = content, ToolTip = "What was asked, of whom, and what came back: " + string.Join(", ", f.TraceSteps) };
        button.SetResourceReference(StyleProperty, "Hue.Button.Ghost");
        System.Windows.Automation.AutomationProperties.SetName(button, "Show trace for: " + f.Title);
        button.Click += (_, _) => ShowTraceFor(f, steps);
        return button;
    }

    private void ShowTraceFor(Finding f, HashSet<string> steps)
    {
        var title = f.Title.Length > 60 ? f.Title[..57] + "..." : f.Title;
        var choice = new StepChoice { Label = "For: " + title, Steps = steps };
        _stepChoices.RemoveAll(c => c.Label.StartsWith("For: ", StringComparison.Ordinal));
        _stepChoices.Insert(1, choice);
        TraceStepFilter.ItemsSource = null;
        TraceStepFilter.ItemsSource = _stepChoices;
        TraceOutcomeFilter.SelectedIndex = 0;
        TraceSearch.Text = "";
        TraceStepFilter.SelectedItem = choice;
        DiagnosisTabs.SelectedItem = TraceTab;
        _traceView?.Refresh();
        UpdateTraceCount();
    }

    // ================================================================== new case

    private void OnNewCase(object sender, RoutedEventArgs e)
    {
        bool hasWork = BaselineBox.Text.Length > 0 || FailingBox.Text.Length > 0 || NdrBox.Text.Length > 0 || CombinedHistory().Length > 0
                       || SenderBox.Text.Length > 0 || RecipientBox.Text.Length > 0 || _result is not null
                       || SenderDomainBox.Text.Length > 0 || ReceiverBox.Text.Length > 0 || SendingIpBox.Text.Length > 0
                       || DmarcThenBox.SelectedIndex != 0 || DkimThenBox.SelectedIndex != 0 || LocInternal.IsChecked == true;
        if (hasWork && !HueConfirm.Ask(this, "Start a new case?",
                "The evidence, the check settings and the results of this case are cleared.", "Clear", destructive: true))
            return;

        // Nothing of the previous case may remain anywhere.
        _parseTimer.Stop();
        SenderBox.Clear();
        RecipientBox.Clear();
        BaselineBox.Clear();
        NdrBox.Clear();
        _historySlots.Clear();
        EvidenceTabs.SelectedIndex = 0;
        DmarcThenBox.SelectedIndex = 0;
        DkimThenBox.SelectedIndex = 0;
        // Check settings back to their defaults: a new case must not inherit the previous
        // case's location, a resolver typed by hand, or switched-off checks.
        LocIsolated.IsChecked = true;
        ResolverBox.SelectedItem = null;
        SelectDefaultResolver();
        if (ResolverBox.SelectedItem is ResolverChoice defaultResolver) ResolverBox.Text = defaultResolver.Display;
        OptAskAll.IsChecked = true;
        OptDoh.IsChecked = true;
        OptBlocklists.IsChecked = true;
        OptProbe.IsChecked = true;
        OptMtaSts.IsChecked = true;
        SenderDomainBox.Clear();
        EnvelopeBox.Clear();
        SendingIpBox.Clear();
        DkimBox.Clear();
        ReceiverBox.Clear();
        NotesPanel.Children.Clear();
        DirInbound.IsChecked = true;
        OtherMailWorksBox.IsChecked = false;
        FailingBox.Clear();
        _targets = null;
        _targetsSignature = null;
        _result = null;
        _forward = null;
        _reverse = null;
        _resultSignature = null;
        StaleNotice.Visibility = Visibility.Collapsed;
        UpdateHeaderPills();
        UpdateAddDomainOffer();
        UpdateShownRow();
        MyDomainBox.SelectedIndex = -1;
        CaseLine.Text = "";
        LikelyHost.Content = null;
        CompareGrid.Children.Clear();
        FindingsPanel.Children.Clear();
        TraceGrid.ItemsSource = null;
        _traceView = null;
        _stepChoices = new List<StepChoice>();
        TraceStepFilter.ItemsSource = null;
        TraceSearch.Text = "";
        TraceOutcomeFilter.SelectedIndex = 0;
        TraceDetail.Clear();
        TraceCount.Text = "";
        DiagnosisTabs.SelectedItem = SummaryTab;
        ParsedBox.Clear();
        NavDiagnosis.IsEnabled = false;
        NavDiagnosis.ToolTip = "Run the checks first";
        UpdateEvidenceSummaries();
        PageEvidence.ScrollToTop();
        PageChecks.ScrollToTop();
        DiagnosisScroll.ScrollToTop();
        ShowPage(1);
        SetStatus("Ready", Severity.Ok);
    }

    // ================================================================== small builders

    /// <summary>
    /// The header's three pills: what the last run found, counted from its findings. None
    /// before a run. A count of zero is plain grey, so colour shows only where it means
    /// something; once the evidence has changed since the run, all three are grey.
    /// </summary>
    private void UpdateHeaderPills()
    {
        if (HeaderPills is null) return;   // a navigation event while the window is still loading
        if (_result is null)
        {
            HeaderPills.Visibility = Visibility.Collapsed;
            return;
        }

        bool stale = _resultSignature is not null && _resultSignature != ResultSignature();
        SetCountPill(PassedPill, "Passed", _result.Findings.Count(f => f.Severity == Severity.Ok), "Hue.Pill.Ok", stale);
        SetCountPill(WarningsPill, "Warnings", _result.Findings.Count(f => f.Severity == Severity.Warning), "Hue.Pill.Warn", stale);
        SetCountPill(ProblemsPill, "Problems", _result.Findings.Count(f => f.Severity == Severity.Critical), "Hue.Pill.Error", stale);
        HeaderPills.Visibility = Visibility.Visible;
    }

    private static void SetCountPill(ContentControl pill, string word, int count, string style, bool stale)
    {
        pill.Content = $"{word} {count}";
        pill.SetResourceReference(StyleProperty, stale ? "Hue.Pill.Stale" : count == 0 ? "Hue.Pill" : style);
        System.Windows.Automation.AutomationProperties.SetName(pill, $"{word}: {count}" + (stale ? " (out of date)" : ""));
    }

    private void SetStatus(string text, Severity severity)
    {
        StatusText.Text = text;
        StatusDot.SetResourceReference(ForegroundProperty, severity switch
        {
            Severity.Critical => "Brush.Error",
            Severity.Warning => "Brush.Warn",
            Severity.Inconclusive => "Brush.Stale",
            Severity.Info => "Brush.Accent",
            _ => "Brush.Ok",
        });
    }

    private static ContentControl Pill(string text, Severity severity)
    {
        var pill = new ContentControl { Content = text, Focusable = false, Margin = new Thickness(0, 4, 10, 4) };
        pill.SetResourceReference(StyleProperty, severity switch
        {
            Severity.Critical => "Hue.Pill.Error",
            Severity.Warning => "Hue.Pill.Warn",
            Severity.Inconclusive => "Hue.Pill.Stale",
            Severity.Ok => "Hue.Pill.Ok",
            _ => "Hue.Pill",
        });
        return pill;
    }

    private static TextBlock Caption(string text)
    {
        var tb = new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center };
        tb.SetResourceReference(StyleProperty, "Text.Caption");
        return tb;
    }

    private static TextBlock Section(string text)
    {
        var tb = new TextBlock { Text = text };
        tb.SetResourceReference(StyleProperty, "Text.Section");
        return tb;
    }

    private static TextBlock Text(string text, Thickness margin)
    {
        var tb = new TextBlock { Text = text, Margin = margin, VerticalAlignment = VerticalAlignment.Center };
        tb.SetResourceReference(StyleProperty, "Text.Body");
        return tb;
    }

    private static TextBlock MonoText(string text)
    {
        var tb = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap };
        tb.SetResourceReference(StyleProperty, "Text.Mono");
        return tb;
    }

    private static string Or(string? s) => string.IsNullOrWhiteSpace(s) ? "-" : s;
}
