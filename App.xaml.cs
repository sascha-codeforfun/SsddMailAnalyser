using System.Globalization;
using System.Text;
using System.Windows;
using System.Windows.Threading;
using HueThemeKit;

namespace SsddMailAnalyser;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // windows-1252, iso-8859-15 and friends for RFC 2047 encoded words and MIME parts.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);

        // The app and its reports are in English: numbers and times are written the same way
        // on every machine ("1,024", "2041.5 ms"), not in the Windows display language.
        CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
        CultureInfo.CurrentCulture = CultureInfo.InvariantCulture;

        // Pasted evidence is arbitrary text. A parser bug on some odd header must cost one
        // message box, not the case the technician has typed in.
        DispatcherUnhandledException += OnUnhandled;

        base.OnStartup(e);
        HueContrast.Follow(this);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        e.Handled = true;
        HueMessage.Show(MainWindow, "Something went wrong",
            "The last action failed: " + e.Exception.GetBaseException().Message +
            "\n\nYour input is still there. If this repeats with the same evidence, save the evidence and report it.");
    }
}
