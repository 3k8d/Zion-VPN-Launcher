using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Zion.Models;
using Zion.ViewModels;

namespace Zion.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private bool _isRealExit = false;
    private IntPtr _hwnd;
    private HwndSource? _hwndSource;

    private const int WM_USER = 0x0400;
    private const int WM_TRAYICON = WM_USER + 100;
    private const int WM_LBUTTONUP = 0x0202;
    private const int WM_LBUTTONDBLCLK = 0x0203;
    private const int WM_RBUTTONUP = 0x0205;

    private const int NIM_ADD = 0x00000000;
    private const int NIM_MODIFY = 0x00000001;
    private const int NIM_DELETE = 0x00000002;

    private const int NIF_MESSAGE = 0x00000001;
    private const int NIF_ICON = 0x00000002;
    private const int NIF_TIP = 0x00000004;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public int uID;
        public int uFlags;
        public int uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ICONINFO
    {
        public bool fIcon;
        public int xHotspot;
        public int yHotspot;
        public IntPtr hbmMask;
        public IntPtr hbmColor;
    }

    private const uint WM_NULL = 0x0000;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern bool Shell_NotifyIcon(int dwMessage, ref NOTIFYICONDATA lpData);

    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    private static extern bool DestroyIcon(IntPtr handle);

    [DllImport("user32.dll")]
    private static extern IntPtr CreateIconIndirect(ref ICONINFO icon);

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateBitmap(int nWidth, int nHeight, uint cPlanes, uint cBitsPerPel, IntPtr lpvBits);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);

    private const int GWL_STYLE = -16;
    private const int WS_MINIMIZEBOX = 0x00020000;
    private const int WS_SYSMENU = 0x00080000;

    [DllImport("user32.dll", EntryPoint = "GetWindowLong")]
    private static extern int GetWindowLong32(IntPtr hWnd, int nIndex);

    [DllImport("user32.dll", EntryPoint = "SetWindowLong")]
    private static extern int SetWindowLong32(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    private IntPtr _currentHIcon = IntPtr.Zero;
    private ContextMenu? _trayContextMenu;

    public MainWindow()
    {
        InitializeComponent();
        _vm = (MainViewModel)DataContext;
        _vm.PropertyChanged += Vm_PropertyChanged;
        InitTrayMenu();
    }

    private void Vm_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.IsConnected))
        {
            UpdateTrayIcon();
        }
    }

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern uint RegisterWindowMessage(string lpString);

    private uint _wmShowMe = 0;
    private uint _wmTaskbarCreated = 0;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ChangeWindowMessageFilterEx(IntPtr hwnd, uint message, uint action, IntPtr changeFilterStruct);
    private const uint MSGFLT_ALLOW = 1;

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        try
        {
            _hwnd = new WindowInteropHelper(this).Handle;
            _hwndSource = HwndSource.FromHwnd(_hwnd);
            _hwndSource?.AddHook(WndProc);

            // Enable Taskbar minimize/restore click toggle
            int style = GetWindowLong32(_hwnd, GWL_STYLE);
            SetWindowLong32(_hwnd, GWL_STYLE, style | WS_MINIMIZEBOX | WS_SYSMENU);

            // Register single-instance wakeup message
            _wmShowMe = RegisterWindowMessage("ZION_SHOW_WINDOW_MESSAGE_2026");

            // Explorer broadcasts this after it restarts; every tray icon has to be added again.
            // Zion runs elevated and Explorer does not, so the message must be let through explicitly.
            _wmTaskbarCreated = RegisterWindowMessage("TaskbarCreated");
            if (_wmTaskbarCreated != 0)
                ChangeWindowMessageFilterEx(_hwnd, _wmTaskbarCreated, MSGFLT_ALLOW, IntPtr.Zero);

            int useDarkMode = 1;
            DwmSetWindowAttribute(_hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDarkMode, sizeof(int));

            AddTrayIcon();
        }
        catch { }
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (_wmShowMe != 0 && (uint)msg == _wmShowMe)
        {
            RestoreFromTray();
            SetForegroundWindow(_hwnd);
            handled = true;
            return IntPtr.Zero;
        }

        if (_wmTaskbarCreated != 0 && (uint)msg == _wmTaskbarCreated)
        {
            if (!_isRealExit) AddTrayIcon();
            return IntPtr.Zero;
        }

        if (msg == WM_TRAYICON)
        {
            int action = lParam.ToInt32();
            if (action == WM_LBUTTONUP || action == WM_LBUTTONDBLCLK)
            {
                RestoreFromTray();
                handled = true;
            }
            else if (action == WM_RBUTTONUP)
            {
                ShowTrayContextMenu();
                handled = true;
            }
        }
        return IntPtr.Zero;
    }

    private void InitTrayMenu()
    {
        _trayContextMenu = Resources["TrayContextMenu"] as ContextMenu;
        if (_trayContextMenu != null)
        {
            _trayContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint;
            _trayContextMenu.StaysOpen = false;
            _trayContextMenu.Closed += (_, _) =>
            {
                if (_hwnd != IntPtr.Zero)
                {
                    PostMessage(_hwnd, WM_NULL, IntPtr.Zero, IntPtr.Zero);
                }
            };
        }
    }

    private void TrayOpen_Click(object sender, RoutedEventArgs e)
    {
        RestoreFromTray();
    }

    private void TrayToggle_Click(object sender, RoutedEventArgs e)
    {
        if (_vm.ToggleConnectionCommand.CanExecute(null))
        {
            _vm.ToggleConnectionCommand.Execute(null);
        }
    }

    private void TrayExit_Click(object sender, RoutedEventArgs e)
    {
        _isRealExit = true;
        _vm.Disconnect();
        RemoveTrayIcon();
        Application.Current.Shutdown();
    }

    private void ShowTrayContextMenu()
    {
        if (_trayContextMenu == null) return;
        if (_hwnd != IntPtr.Zero)
        {
            SetForegroundWindow(_hwnd);
        }
        _trayContextMenu.Placement = System.Windows.Controls.Primitives.PlacementMode.MousePoint;
        _trayContextMenu.IsOpen = true;
    }

    private void AddTrayIcon()
    {
        if (_hwnd == IntPtr.Zero) return;

        // Called again after an Explorer restart: the previous icon handle is no longer shown
        IntPtr oldIcon = _currentHIcon;
        _currentHIcon = GenerateTrayHIcon(_vm.IsConnected);
        if (oldIcon != IntPtr.Zero) DestroyIcon(oldIcon);

        var nid = new NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = _hwnd,
            uID = 1001,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_TRAYICON,
            hIcon = _currentHIcon,
            szTip = _vm.IsConnected ? "Zion • Туннель активен" : "Zion • Отключено"
        };

        // If the icon somehow survived, adding fails - then just refresh it
        if (!Shell_NotifyIcon(NIM_ADD, ref nid))
            Shell_NotifyIcon(NIM_MODIFY, ref nid);
    }

    private void UpdateTrayIcon()
    {
        if (_hwnd == IntPtr.Zero) return;

        IntPtr oldIcon = _currentHIcon;
        _currentHIcon = GenerateTrayHIcon(_vm.IsConnected);

        var nid = new NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = _hwnd,
            uID = 1001,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_TRAYICON,
            hIcon = _currentHIcon,
            szTip = _vm.IsConnected ? "Zion • Туннель активен" : "Zion • Отключено"
        };

        Shell_NotifyIcon(NIM_MODIFY, ref nid);

        if (oldIcon != IntPtr.Zero)
        {
            DestroyIcon(oldIcon);
        }
    }

    private void RemoveTrayIcon()
    {
        if (_hwnd == IntPtr.Zero) return;

        var nid = new NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = _hwnd,
            uID = 1001
        };

        Shell_NotifyIcon(NIM_DELETE, ref nid);

        if (_currentHIcon != IntPtr.Zero)
        {
            DestroyIcon(_currentHIcon);
            _currentHIcon = IntPtr.Zero;
        }
    }

    private static IntPtr GenerateTrayHIcon(bool isConnected)
    {
        int width = 32;
        int height = 32;
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen())
        {
            // Mint when the tunnel is up, violet when idle (same palette as the window)
            var topColor = isConnected ? Color.FromRgb(75, 235, 176) : Color.FromRgb(157, 143, 255);
            var botColor = isConnected ? Color.FromRgb(12, 155, 107) : Color.FromRgb(91, 75, 232);

            // Circle background
            var brush = new LinearGradientBrush(topColor, botColor, new Point(0, 0), new Point(0, 1));
            dc.DrawEllipse(brush, null, new Point(16, 16), 14, 14);

            // White Power symbol
            var pen = new Pen(Brushes.White, 2.5) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round };

            // Pin
            dc.DrawLine(pen, new Point(16, 7), new Point(16, 16));

            // Arc
            var pathGeo = new PathGeometry();
            var fig = new PathFigure { StartPoint = new Point(11, 11), IsClosed = false };
            fig.Segments.Add(new ArcSegment(new Point(21, 11), new Size(6, 6), 0, true, SweepDirection.Clockwise, true));
            pathGeo.Figures.Add(fig);
            dc.DrawGeometry(null, pen, pathGeo);
        }

        var rtb = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        rtb.Render(dv);

        int stride = width * 4;
        byte[] pixelData = new byte[height * stride];
        rtb.CopyPixels(pixelData, stride, 0);

        IntPtr hbmColor = IntPtr.Zero;
        IntPtr hbmMask = IntPtr.Zero;
        GCHandle handle = GCHandle.Alloc(pixelData, GCHandleType.Pinned);
        try
        {
            hbmColor = CreateBitmap(width, height, 1, 32, handle.AddrOfPinnedObject());
            byte[] maskBits = new byte[(width * height) / 8];
            hbmMask = CreateBitmap(width, height, 1, 1, Marshal.UnsafeAddrOfPinnedArrayElement(maskBits, 0));

            var iconInfo = new ICONINFO
            {
                fIcon = true,
                xHotspot = 0,
                yHotspot = 0,
                hbmMask = hbmMask,
                hbmColor = hbmColor
            };

            return CreateIconIndirect(ref iconInfo);
        }
        finally
        {
            handle.Free();
            if (hbmColor != IntPtr.Zero) DeleteObject(hbmColor);
            if (hbmMask != IntPtr.Zero) DeleteObject(hbmMask);
        }
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    // Any free spot drags the window (sheets mark clicks on themselves handled, so those never get here)
    private void Window_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            DragMove();
        }
    }

    protected override void OnDeactivated(EventArgs e)
    {
        base.OnDeactivated(e);
        if (_vm != null && _vm.IsDnsModalOpen)
        {
            _vm.IsDnsModalOpen = false;
        }
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_isRealExit)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        _vm.Disconnect();
        RemoveTrayIcon();
        base.OnClosing(e);
    }

    // Escape steps back: closes an open sheet first, then goes one screen up
    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            if (_vm.IsDnsModalOpen)
            {
                _vm.IsDnsModalOpen = false;
                e.Handled = true;
                return;
            }

            if (_vm.ServerListVm.IsDeleteAllConfirmOpen)
            {
                _vm.ServerListVm.IsDeleteAllConfirmOpen = false;
                e.Handled = true;
                return;
            }

            if (_vm.ExcludedAppsVm.IsPickerOpen)
            {
                _vm.ExcludedAppsVm.IsPickerOpen = false;
                e.Handled = true;
                return;
            }

            if (_vm.IsExclusionsVisible || _vm.IsExcludedSitesVisible)
            {
                _vm.CurrentScreen = AppScreen.Settings;
                e.Handled = true;
            }
            else if (_vm.IsSubscriptionsVisible)
            {
                _vm.CurrentScreen = AppScreen.ServerList;
                e.Handled = true;
            }
            else if (_vm.IsSettingsVisible)
            {
                _vm.CurrentScreen = AppScreen.Dashboard;
                e.Handled = true;
            }
            else if (_vm.IsServerEditVisible)
            {
                _vm.CurrentScreen = AppScreen.ServerList;
                e.Handled = true;
            }
            else if (_vm.IsServerListVisible)
            {
                _vm.CurrentScreen = AppScreen.Dashboard;
                e.Handled = true;
            }
        }
    }
}
