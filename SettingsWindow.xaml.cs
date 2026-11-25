using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using HueThemeKit;
using SsddMailAnalyser.Core;

namespace SsddMailAnalyser;

/// <summary>
/// The operator's own domains and the busy-animation switch. Works on a copy: nothing
/// reaches the settings, or the file, unless Save is pressed.
/// </summary>
public partial class SettingsWindow : Window
{
    private readonly AppSettings _draft = new();
    private readonly ObservableCollection<string> _domains = new();

    public SettingsWindow(AppSettings current, string path)
    {
        InitializeComponent();
        HueTitleBar.Attach(this);

        foreach (var domain in current.Domains)
            if (_draft.Add(domain)) _domains.Add(_draft.Domains[^1]);
        DomainList.ItemsSource = _domains;
        AlwaysTurnBox.IsChecked = current.AlwaysTurn;
        PathText.Text = "Saved next to the program, as " + path;

        Loaded += (_, _) => NewDomainBox.Focus();
    }

    /// <summary>The list as it stood when Save was pressed.</summary>
    public IReadOnlyList<string> Domains => _draft.Domains.ToList();

    public bool AlwaysTurn => AlwaysTurnBox.IsChecked == true;

    private void OnAdd(object sender, RoutedEventArgs e)
    {
        var text = NewDomainBox.Text.Trim();
        if (text.Length == 0) return;

        var clean = AppSettings.Clean(text);
        if (clean is null)
        {
            HueMessage.Show(this, "Not a domain name",
                "A domain name is made of letters, digits, hyphens and underscores, with dots between the parts, for example example.com.");
            return;
        }

        if (_draft.Add(clean)) _domains.Add(clean);
        DomainList.SelectedItem = clean;
        DomainList.ScrollIntoView(clean);
        NewDomainBox.Clear();
        NewDomainBox.Focus();
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (DomainList.SelectedItem is not string domain) return;
        _draft.Domains.Remove(domain);
        _domains.Remove(domain);
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        // A name still sitting in the box was meant to be in the list.
        var typed = NewDomainBox.Text.Trim();
        if (typed.Length > 0)
        {
            var pending = AppSettings.Clean(typed);
            if (pending is null)
            {
                HueMessage.Show(this, "Not a domain name",
                    "The text in the box is not a domain name. Correct it or clear the box, then save.");
                return;
            }
            if (_draft.Add(pending)) _domains.Add(pending);
        }
        DialogResult = true;
    }
}
