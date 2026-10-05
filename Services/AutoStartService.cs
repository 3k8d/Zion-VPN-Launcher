using Microsoft.Win32;

namespace Zion.Services;

/// <summary>
/// "Start with Windows" was removed: Zion needs administrator rights, and Windows silently skips such
/// programs in the ordinary Run list. Older versions may have left an entry there; it is cleaned up.
/// </summary>
public static class AutoStartService
{
    private const string AppName = "Zion";
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    public static void RemoveLegacyEntry()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
            key?.DeleteValue(AppName, throwOnMissingValue: false);
        }
        catch { }
    }
}
