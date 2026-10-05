using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Zion.Models;
using Zion.Services;
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

        Shell_NotifyIcon(NIM_ADD, ref nid);
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

    private void Window_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            if (_vm != null && _vm.IsDnsModalOpen && DnsModalCard != null && DnsModalCard.IsMouseOver)
            {
                return;
            }
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

    private void BtnMinimize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e)
    {
        Hide();
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

    // =========================================================================
    // DNS MODAL HANDLERS
    // =========================================================================

    private void DnsOverlay_MouseDown(object sender, MouseButtonEventArgs e)
    {
        _vm.IsDnsModalOpen = false;
    }

    private void DnsModalCard_MouseDown(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
    }

    private void PickerOverlay_MouseDown(object sender, MouseButtonEventArgs e)
    {
        _vm.ExcludedAppsVm.IsPickerOpen = false;
    }

    private void DeleteAllOverlay_MouseDown(object sender, MouseButtonEventArgs e)
    {
        // A click next to the sheet means "never mind"
        _vm.ServerListVm.IsDeleteAllConfirmOpen = false;
    }

    private void DnsOption_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is DnsOptionItem item)
        {
            _vm.SelectDnsCommand.Execute(item.Provider);
        }
    }

    // =========================================================================
    // NAVIGATION & SEAMLESS SCREEN HANDLERS
    // =========================================================================

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

    private void BtnOpenServerList_Click(object sender, RoutedEventArgs e)
    {
        _vm.CurrentScreen = AppScreen.ServerList;
    }

    private void BtnBackToDashboard_Click(object sender, RoutedEventArgs e)
    {
        _vm.CurrentScreen = AppScreen.Dashboard;
    }

    private void BtnOpenAddServer_Click(object sender, RoutedEventArgs e)
    {
        _vm.EditingProxy = null;
        PopulateEditForm(null);
        _vm.CurrentScreen = AppScreen.ServerEdit;
    }

    private void BtnEditServer_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if ((sender as FrameworkElement)?.DataContext is ProxyItem proxy)
        {
            _vm.EditingProxy = proxy;
            PopulateEditForm(proxy);
            _vm.CurrentScreen = AppScreen.ServerEdit;
        }
    }

    private void BtnDeleteServer_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if ((sender as FrameworkElement)?.DataContext is ProxyItem proxy)
        {
            _vm.ServerListVm.DeleteProxy(proxy);
        }
    }

    private void Card_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is ProxyItem proxy)
        {
            _vm.SelectProxy(proxy);
            _vm.CurrentScreen = AppScreen.Dashboard;
        }
    }

    private void BtnBackToServerList_Click(object sender, RoutedEventArgs e)
    {
        _vm.CurrentScreen = AppScreen.ServerList;
    }

    // =========================================================================
    // SERVER FORM LOGIC & LIVE SYNC
    // =========================================================================

    private bool _isPopulatingEdit = false;
    private bool _isUpdatingEditFromForm = false;
    private ProxyItem? _currentParsedEditItem;

    private void PopulateEditForm(ProxyItem? p)
    {
        _isPopulatingEdit = true;
        try
        {
            _currentParsedEditItem = p;
            if (p != null)
            {
                EditNameTextBox.Text = p.Name;
                EditHostTextBox.Text = p.CleanHost;
                EditPortTextBox.Text = p.Port > 0 ? p.Port.ToString() : "443";
                SelectComboItem(EditProtocolComboBox, p.Protocol.ToString());

                if (p.Protocol == ProxyProtocol.Vless)
                {
                    EditUuidTextBox.Text = p.Uuid;
                    SelectComboItem(EditTransportComboBox, p.TransportType);
                    SelectComboItem(EditSecurityComboBox, p.Security);
                    SelectComboItem(EditFingerprintComboBox, !string.IsNullOrEmpty(p.Fingerprint) ? p.Fingerprint : "chrome");
                    EditSniTextBox.Text = p.Sni;
                    EditPublicKeyTextBox.Text = p.PublicKey;
                    EditShortIdTextBox.Text = p.ShortId;
                    EditServiceOrPathTextBox.Text = p.TransportType == "grpc" ? p.GrpcServiceName : p.WsPath;
                }
                else if (p.Protocol == ProxyProtocol.Trojan)
                {
                    EditUuidTextBox.Text = !string.IsNullOrEmpty(p.Password) ? p.Password : p.Uuid;
                    SelectComboItem(EditTransportComboBox, p.TransportType);
                    SelectComboItem(EditSecurityComboBox, "TLS");
                    SelectComboItem(EditFingerprintComboBox, !string.IsNullOrEmpty(p.Fingerprint) ? p.Fingerprint : "chrome");
                    EditSniTextBox.Text = p.Sni;
                    EditServiceOrPathTextBox.Text = p.TransportType == "grpc" ? p.GrpcServiceName : p.WsPath;
                    EditPassTextBox.Text = p.Password;
                }
                else if (p.Protocol == ProxyProtocol.Shadowsocks)
                {
                    EditPassTextBox.Text = p.Password;
                    SelectComboItem(EditSecurityComboBox, p.Security);
                }
                else if (p.Protocol == ProxyProtocol.Vmess)
                {
                    EditUuidTextBox.Text = p.Uuid;
                    SelectComboItem(EditTransportComboBox, p.TransportType);
                    SelectComboItem(EditSecurityComboBox, p.Security);
                    SelectComboItem(EditFingerprintComboBox, !string.IsNullOrEmpty(p.Fingerprint) ? p.Fingerprint : "chrome");
                    EditSniTextBox.Text = p.Sni;
                    EditServiceOrPathTextBox.Text = p.TransportType == "grpc" ? p.GrpcServiceName : p.WsPath;
                }
                else
                {
                    EditUserTextBox.Text = p.Username;
                    EditPassTextBox.Text = p.Password;
                }

                _isUpdatingEditFromForm = true;
                EditQuickInputTextBox.Text = p.ToShareableUrl();
                _isUpdatingEditFromForm = false;
            }
            else
            {
                EditNameTextBox.Text = "";
                EditHostTextBox.Text = "";
                EditPortTextBox.Text = "";
                SelectComboItem(EditProtocolComboBox, "VLESS");
                EditUuidTextBox.Text = "";
                SelectComboItem(EditTransportComboBox, "TCP");
                SelectComboItem(EditSecurityComboBox, "Reality");
                SelectComboItem(EditFingerprintComboBox, "Chrome");
                EditSniTextBox.Text = "";
                EditPublicKeyTextBox.Text = "";
                EditShortIdTextBox.Text = "";
                EditServiceOrPathTextBox.Text = "";
                EditUserTextBox.Text = "";
                EditPassTextBox.Text = "";
                EditQuickInputTextBox.Text = "";
            }

            UpdateEditPanelVisibility();
        }
        finally
        {
            _isPopulatingEdit = false;
        }
    }

    private void SelectComboItem(ComboBox? combo, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || combo == null) return;
        foreach (ComboBoxItem item in combo.Items)
        {
            string itemStr = item.Content.ToString() ?? "";
            if (itemStr.Equals(value, StringComparison.OrdinalIgnoreCase) ||
                itemStr.StartsWith(value, StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedItem = item;
                break;
            }
        }
    }

    private void EditProtocolComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateEditPanelVisibility();
        OnEditFormFieldChanged(sender, e);
    }

    private void UpdateEditPanelVisibility()
    {
        if (EditVlessPanel == null || EditAuthPanel == null || EditProtocolComboBox == null) return;

        string val = (EditProtocolComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "VLESS";
        bool isVlessLike = val.Equals("VLESS", StringComparison.OrdinalIgnoreCase) ||
                           val.Equals("Trojan", StringComparison.OrdinalIgnoreCase) ||
                           val.Equals("VMess", StringComparison.OrdinalIgnoreCase);

        EditVlessPanel.Visibility = isVlessLike ? Visibility.Visible : Visibility.Collapsed;
        EditAuthPanel.Visibility = isVlessLike ? Visibility.Collapsed : Visibility.Visible;
    }

    private void EditHostTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        OnEditFormFieldChanged(sender, e);
    }

    private void OnEditFormFieldChanged(object sender, RoutedEventArgs e)
    {
        if (_isPopulatingEdit) return;
        var proxy = BuildProxyFromEditFields();
        if (proxy != null && !string.IsNullOrWhiteSpace(proxy.Host))
        {
            _isUpdatingEditFromForm = true;
            EditQuickInputTextBox.Text = proxy.ToShareableUrl();
            _isUpdatingEditFromForm = false;
        }
    }

    private async void EditCopyLink_Click(object sender, RoutedEventArgs e)
    {
        var proxy = BuildProxyFromEditFields();
        string url = proxy?.ToShareableUrl() ?? EditQuickInputTextBox.Text.Trim();
        if (!string.IsNullOrWhiteSpace(url))
        {
            Clipboard.SetText(url);
            EditCopyToastText.Visibility = Visibility.Visible;
            await Task.Delay(2000);
            EditCopyToastText.Visibility = Visibility.Collapsed;
        }
    }

    private async void EditPasteFromClipboard_Click(object sender, RoutedEventArgs e)
    {
        if (!Clipboard.ContainsText()) return;

        string clip = Clipboard.GetText().Trim();
        string subCandidate = ProxyParser.ExtractActualSubscriptionUrl(clip);

        if (ProxyParser.IsSubscriptionUrl(subCandidate))
        {
            EditQuickInputTextBox.Text = subCandidate;
            Mouse.OverrideCursor = Cursors.Wait;
            bool success = false;
            string? errorMsg = null;
            try
            {
                success = await _vm.RefreshSubscriptionAsync(subCandidate);
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }

            if (success)
            {
                _vm.AutoResolveMissingCountries();
                _vm.SaveConfig();
                MessageBox.Show("Серверы из подписки успешно импортированы и обновлены!", "Умная подписка", MessageBoxButton.OK, MessageBoxImage.Information);
                _vm.CurrentScreen = AppScreen.Dashboard;
            }
            else
            {
                string msg = errorMsg != null ? $"Не удалось загрузить подписку: {errorMsg}" : "Не удалось загрузить подписку. Проверьте URL или соединение.";
                MessageBox.Show(msg, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            return;
        }

        var bulkItems = ProxyParser.ParseBulk(clip);
        if (bulkItems.Count > 1)
        {
            foreach (var b in bulkItems) _vm.Proxies.Add(b);
            _vm.SelectProxy(bulkItems[0]);
            _vm.SaveConfig();
            MessageBox.Show($"Импортировано {bulkItems.Count} серверов!", "Пакетный импорт", MessageBoxButton.OK, MessageBoxImage.Information);
            _vm.CurrentScreen = AppScreen.Dashboard;
            return;
        }
        else if (bulkItems.Count == 1)
        {
            PopulateEditForm(bulkItems[0]);
        }
    }

    private void EditQuickInputTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_isUpdatingEditFromForm) return;

        string text = EditQuickInputTextBox.Text.Trim();
        if (ProxyParser.IsSubscriptionUrl(text)) return;

        var parsed = ProxyParser.ParseSingle(text);
        if (parsed != null)
        {
            PopulateEditForm(parsed);
        }
    }

    private ProxyItem? BuildProxyFromEditFields()
    {
        string host = EditHostTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(host)) return null;

        if (!int.TryParse(EditPortTextBox.Text.Trim(), out int port) || port <= 0 || port > 65535)
            port = 443;

        string name = EditNameTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(name)) name = host;

        string protoStr = (EditProtocolComboBox.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "VLESS";
        ProxyProtocol proto = protoStr.ToUpperInvariant() switch
        {
            "VLESS" => ProxyProtocol.Vless,
            "TROJAN" => ProxyProtocol.Trojan,
            "SHADOWSOCKS" => ProxyProtocol.Shadowsocks,
            "VMESS" => ProxyProtocol.Vmess,
            "SOCKS5" => ProxyProtocol.Socks5,
            _ => ProxyProtocol.Http
        };

        var proxy = new ProxyItem
        {
            Name = name,
            Host = host,
            Port = port,
            Protocol = proto
        };

        if (proto == ProxyProtocol.Vless)
        {
            proxy.Uuid = EditUuidTextBox.Text.Trim();
            proxy.TransportType = (EditTransportComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "tcp";
            proxy.Security = (EditSecurityComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "reality";
            proxy.Fingerprint = (EditFingerprintComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "chrome";
            proxy.Sni = EditSniTextBox.Text.Trim();
            proxy.PublicKey = EditPublicKeyTextBox.Text.Trim();
            proxy.ShortId = EditShortIdTextBox.Text.Trim();

            string sp = EditServiceOrPathTextBox.Text.Trim();
            if (proxy.TransportType == "grpc")
                proxy.GrpcServiceName = sp;
            else
                proxy.WsPath = sp;
        }
        else if (proto == ProxyProtocol.Trojan)
        {
            string pass = !string.IsNullOrEmpty(EditPassTextBox.Text) ? EditPassTextBox.Text.Trim() : EditUuidTextBox.Text.Trim();
            proxy.Password = pass;
            proxy.Uuid = pass;
            proxy.Security = "tls";
            proxy.TransportType = (EditTransportComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "tcp";
            proxy.Fingerprint = (EditFingerprintComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "chrome";
            proxy.Sni = EditSniTextBox.Text.Trim();

            string sp = EditServiceOrPathTextBox.Text.Trim();
            if (proxy.TransportType == "grpc")
                proxy.GrpcServiceName = sp;
            else
                proxy.WsPath = sp;
        }
        else if (proto == ProxyProtocol.Shadowsocks)
        {
            string pass = !string.IsNullOrEmpty(EditPassTextBox.Text) ? EditPassTextBox.Text.Trim() : EditUuidTextBox.Text.Trim();
            proxy.Password = pass;
            proxy.Security = (EditSecurityComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "aes-256-gcm";
        }
        else if (proto == ProxyProtocol.Vmess)
        {
            proxy.Uuid = EditUuidTextBox.Text.Trim();
            proxy.TransportType = (EditTransportComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "tcp";
            proxy.Security = (EditSecurityComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "auto";
            proxy.Fingerprint = (EditFingerprintComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "chrome";
            proxy.Sni = EditSniTextBox.Text.Trim();

            string sp = EditServiceOrPathTextBox.Text.Trim();
            if (proxy.TransportType == "grpc")
                proxy.GrpcServiceName = sp;
            else
                proxy.WsPath = sp;
        }
        else
        {
            proxy.Username = EditUserTextBox.Text.Trim();
            proxy.Password = EditPassTextBox.Text.Trim();
        }

        var source = _vm.EditingProxy ?? _currentParsedEditItem;
        if (source != null)
        {
            proxy.WsHost = source.WsHost;
            proxy.AlterId = source.AlterId;
            proxy.Flow = source.Flow;
            proxy.SpiderX = source.SpiderX;
            proxy.Alpn = source.Alpn;
            proxy.RawLink = source.RawLink;
        }

        return proxy;
    }

    private async void BtnSaveServer_Click(object sender, RoutedEventArgs e)
    {
        string quick = EditQuickInputTextBox.Text.Trim();
        string subCandidate = ProxyParser.ExtractActualSubscriptionUrl(quick);
        if (ProxyParser.IsSubscriptionUrl(subCandidate))
        {
            Mouse.OverrideCursor = Cursors.Wait;
            bool success = false;
            string? errorMsg = null;
            try
            {
                success = await _vm.RefreshSubscriptionAsync(subCandidate);
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
            }
            finally
            {
                Mouse.OverrideCursor = null;
            }

            if (success)
            {
                _vm.AutoResolveMissingCountries();
                _vm.SaveConfig();
                MessageBox.Show("Серверы из подписки успешно импортированы и обновлены!", "Умная подписка", MessageBoxButton.OK, MessageBoxImage.Information);
                _vm.CurrentScreen = AppScreen.Dashboard;
            }
            else
            {
                string msg = errorMsg != null ? $"Не удалось загрузить подписку: {errorMsg}" : "Не удалось загрузить подписку. Проверьте URL или соединение.";
                MessageBox.Show(msg, "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            return;
        }

        string host = EditHostTextBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(host))
        {
            MessageBox.Show("Пожалуйста, укажите Хост или IP-адрес сервера.", "Ошибка валидации", MessageBoxButton.OK, MessageBoxImage.Warning);
            EditHostTextBox.Focus();
            return;
        }

        if (!int.TryParse(EditPortTextBox.Text.Trim(), out int port) || port <= 0 || port > 65535)
        {
            MessageBox.Show("Укажите корректный порт сервера (от 1 до 65535).", "Ошибка валидации", MessageBoxButton.OK, MessageBoxImage.Warning);
            EditPortTextBox.Focus();
            return;
        }

        var built = BuildProxyFromEditFields();
        if (built == null) return;

        if (_vm.EditingProxy != null)
        {
            // Update existing proxy
            _vm.EditingProxy.Name = built.Name;
            _vm.EditingProxy.Host = built.Host;
            _vm.EditingProxy.Port = built.Port;
            _vm.EditingProxy.Protocol = built.Protocol;
            _vm.EditingProxy.Uuid = built.Uuid;
            _vm.EditingProxy.TransportType = built.TransportType;
            _vm.EditingProxy.Security = built.Security;
            _vm.EditingProxy.Fingerprint = built.Fingerprint;
            _vm.EditingProxy.Sni = built.Sni;
            _vm.EditingProxy.PublicKey = built.PublicKey;
            _vm.EditingProxy.ShortId = built.ShortId;
            _vm.EditingProxy.GrpcServiceName = built.GrpcServiceName;
            _vm.EditingProxy.WsPath = built.WsPath;
            _vm.EditingProxy.WsHost = built.WsHost;
            _vm.EditingProxy.AlterId = built.AlterId;
            _vm.EditingProxy.Flow = built.Flow;
            _vm.EditingProxy.SpiderX = built.SpiderX;
            _vm.EditingProxy.Alpn = built.Alpn;
            _vm.EditingProxy.Username = built.Username;
            _vm.EditingProxy.Password = built.Password;

            _vm.SelectProxy(_vm.EditingProxy);
            _vm.SaveConfig();
        }
        else
        {
            // Add new proxy
            _vm.AddProxy(built);
        }

        // Auto resolve country asynchronously
        var targetProxy = _vm.EditingProxy ?? built;
        _ = Task.Run(async () =>
        {
            string resolved = await GeoIpService.ResolveCountryForHostAsync(targetProxy.CleanHost);
            if (!string.IsNullOrWhiteSpace(resolved))
            {
                targetProxy.Country = resolved;
                Application.Current?.Dispatcher?.Invoke(() =>
                {
                    _vm.SaveConfig();
                });
            }
        });

        _vm.CurrentScreen = AppScreen.Dashboard;
    }
}

