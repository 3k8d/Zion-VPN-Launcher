using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using Zion.Services;

namespace Zion;

public partial class App : System.Windows.Application
{
    private static Mutex? _singleInstanceMutex;
    private const string MutexName = "Global\\Zion_SingleInstance_Mutex_2026";

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint RegisterWindowMessage(string lpString);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    private static readonly IntPtr HWND_BROADCAST = (IntPtr)0xffff;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Diagnostic mode: Zion.exe --killswitch-selftest [report path]
        // Runs before the single-instance check so it works while Zion itself is running.
        int selfTestIdx = Array.IndexOf(e.Args, "--killswitch-selftest");
        if (selfTestIdx >= 0)
        {
            string reportPath = e.Args.Length > selfTestIdx + 1
                ? e.Args[selfTestIdx + 1]
                : Path.Combine(Path.GetTempPath(), "zion-killswitch-selftest.txt");

            bool passed = false;
            string report;
            try
            {
                (passed, report) = KillSwitchFirewall.SelfTest();
            }
            catch (Exception ex)
            {
                report = "Self-test crashed: " + ex;
            }
            finally
            {
                KillSwitchFirewall.Disarm();
            }

            try { File.WriteAllText(reportPath, report); } catch { }

            // Hard exit: Shutdown() would still let WPF build the main window from StartupUri.
            Environment.Exit(passed ? 0 : 1);
            return;
        }

        _singleInstanceMutex = new Mutex(true, MutexName, out bool isFirstInstance);

        if (!isFirstInstance)
        {
            // 🔒 Already running! Notify existing instance to restore and focus
            try
            {
                uint showMsg = RegisterWindowMessage("ZION_SHOW_WINDOW_MESSAGE_2026");
                PostMessage(HWND_BROADCAST, showMsg, IntPtr.Zero, IntPtr.Zero);
            }
            catch { }

            // Shut down 2nd instance immediately
            Shutdown();
            return;
        }

        // Initialize and ensure %AppData%\Zion folders exist
        EnsureZionFolders();

        base.OnStartup(e);

        DispatcherUnhandledException += (s, args) =>
        {
            try
            {
                string logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Zion", "logs");
                if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);
                string log = Path.Combine(logDir, "error.log");
                File.AppendAllText(log, $"[{DateTime.Now}] Dispatcher Error: {args.Exception}\r\n");
            }
            catch { }
            args.Handled = true; // Prevent app from unexpectedly crashing
        };

        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            try
            {
                string logDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Zion", "logs");
                if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);
                string log = Path.Combine(logDir, "error.log");
                File.AppendAllText(log, $"[{DateTime.Now}] Domain Error: {args.ExceptionObject}\r\n");
            }
            catch { }
        };
    }

    private static void EnsureZionFolders()
    {
        try
        {
            string zionDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Zion");
            Directory.CreateDirectory(zionDir);
            Directory.CreateDirectory(Path.Combine(zionDir, "Core"));
            Directory.CreateDirectory(Path.Combine(zionDir, "logs"));

            // Extract core files
            TunRoutingEngine.EnsureCoreFiles();
        }
        catch { }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        // Never leave the machine blocked after Zion is gone. (Windows also drops the
        // filters on its own when the process ends; this just makes it immediate.)
        try { KillSwitchFirewall.Disarm(); } catch { }

        try
        {
            if (_singleInstanceMutex != null)
            {
                _singleInstanceMutex.ReleaseMutex();
                _singleInstanceMutex.Dispose();
                _singleInstanceMutex = null;
            }
        }
        catch { }

        base.OnExit(e);
    }
}

