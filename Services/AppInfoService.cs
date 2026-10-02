using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Zion.Services;

/// <summary>A program found on the machine: what the user sees in the picker.</summary>
public sealed record AppCandidate(string Path, string ProcessName, string DisplayName, bool HasWindow);

/// <summary>Readable names, icons and the list of running programs for the "programs bypassing the VPN" screen.</summary>
public static class AppInfoService
{
    private static readonly Dictionary<string, ImageSource?> _iconCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>"Steam" instead of "steam.exe" when the file says so; otherwise the file name without .exe.</summary>
    public static string ReadableName(string path, string processName)
    {
        try
        {
            if (File.Exists(path))
            {
                var info = FileVersionInfo.GetVersionInfo(path);
                string? name = !string.IsNullOrWhiteSpace(info.FileDescription) ? info.FileDescription : info.ProductName;
                if (!string.IsNullOrWhiteSpace(name)) return name.Trim();
            }
        }
        catch { }
        return System.IO.Path.GetFileNameWithoutExtension(processName);
    }

    /// <summary>The program's own icon (32 px), or null if it cannot be read. Cached.</summary>
    public static ImageSource? Icon(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        lock (_iconCache)
        {
            if (_iconCache.TryGetValue(path, out var cached)) return cached;
        }

        ImageSource? image = null;
        try
        {
            if (File.Exists(path))
            {
                var info = new SHFILEINFO();
                IntPtr ok = SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFO>(), SHGFI_ICON | SHGFI_LARGEICON);
                if (ok != IntPtr.Zero && info.hIcon != IntPtr.Zero)
                {
                    try
                    {
                        var bmp = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                        bmp.Freeze();
                        image = bmp;
                    }
                    finally
                    {
                        DestroyIcon(info.hIcon);
                    }
                }
            }
        }
        catch { }

        lock (_iconCache) { _iconCache[path] = image; }
        return image;
    }

    /// <summary>
    /// Running programs a user would recognise: not part of Windows, one entry per exe,
    /// programs with a window first. Zion and its core are left out.
    /// </summary>
    public static List<AppCandidate> RunningPrograms()
    {
        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string self = Environment.ProcessPath ?? "";
        var byPath = new Dictionary<string, AppCandidate>(StringComparer.OrdinalIgnoreCase);

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                string? path = ImagePath(process.Id);
                if (string.IsNullOrEmpty(path) || !path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
                if (path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)) continue;
                if (path.Equals(self, StringComparison.OrdinalIgnoreCase)) continue;

                string exe = System.IO.Path.GetFileName(path);
                if (TunRoutingEngine.SanitizeDirectApps(new[] { exe }).Count == 0) continue; // Zion / sing-box

                bool hasWindow = false;
                try { hasWindow = process.MainWindowHandle != IntPtr.Zero; } catch { }

                if (byPath.TryGetValue(path, out var known))
                {
                    if (hasWindow && !known.HasWindow) byPath[path] = known with { HasWindow = true };
                    continue;
                }
                byPath[path] = new AppCandidate(path, exe, ReadableName(path, exe), hasWindow);
            }
            catch { }
            finally
            {
                process.Dispose();
            }
        }

        // The bypass rule works by exe name, so two copies of the same exe are one choice
        return byPath.Values
            .GroupBy(a => a.ProcessName, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(a => a.HasWindow).First())
            .OrderByDescending(a => a.HasWindow)
            .ThenBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static string? ImagePath(int pid)
    {
        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    // ------------------------------------------------------------------ interop

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SHGFI_ICON = 0x100;
    private const uint SHGFI_LARGEICON = 0x0;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
