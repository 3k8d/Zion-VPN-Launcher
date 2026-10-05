using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Zion.Models;
using Zion.Services;
using Zion.ViewModels;

namespace Zion.Views.Screens;

/// <summary>
/// The server form. Fills itself whenever the view model asks for it (<see cref="MainViewModel.OpenEditor"/>),
/// keeps the share link and the fields in sync both ways, and saves into the server list.
/// </summary>
public partial class ServerEditView : UserControl
{
    public ServerEditView()
    {
        InitializeComponent();
        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is MainViewModel old) old.EditorRequested -= PopulateEditForm;
            if (e.NewValue is MainViewModel vm) vm.EditorRequested += PopulateEditForm;
        };
    }

    private MainViewModel? Vm => DataContext as MainViewModel;

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
                else if (p.UsesUdpTransport)
                {
                    EditTuicUuidTextBox.Text = p.Uuid;
                    EditQuicPasswordTextBox.Text = p.Password;
                    EditQuicSniTextBox.Text = p.Sni;
                    EditObfsPasswordTextBox.Text = p.ObfsPassword;
                    EditHopPortsTextBox.Text = p.ServerPorts;
                    SelectComboItem(EditCongestionComboBox, !string.IsNullOrEmpty(p.CongestionControl) ? p.CongestionControl : "bbr");
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
                EditTuicUuidTextBox.Text = "";
                EditQuicPasswordTextBox.Text = "";
                EditQuicSniTextBox.Text = "";
                EditObfsPasswordTextBox.Text = "";
                EditHopPortsTextBox.Text = "";
                SelectComboItem(EditCongestionComboBox, "BBR");
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

        bool isHysteria = val.Equals("Hysteria2", StringComparison.OrdinalIgnoreCase);
        bool isTuic = val.Equals("TUIC", StringComparison.OrdinalIgnoreCase);
        bool isQuic = isHysteria || isTuic;

        EditVlessPanel.Visibility = isVlessLike ? Visibility.Visible : Visibility.Collapsed;
        EditAuthPanel.Visibility = isVlessLike || isQuic ? Visibility.Collapsed : Visibility.Visible;
        EditQuicPanel.Visibility = isQuic ? Visibility.Visible : Visibility.Collapsed;
        EditTuicUuidPanel.Visibility = isTuic ? Visibility.Visible : Visibility.Collapsed;
        EditCongestionPanel.Visibility = isTuic ? Visibility.Visible : Visibility.Collapsed;
        EditObfsPanel.Visibility = isHysteria ? Visibility.Visible : Visibility.Collapsed;
        EditHopPortsPanel.Visibility = isHysteria ? Visibility.Visible : Visibility.Collapsed;
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
        if (Vm is not { } vm || !Clipboard.ContainsText()) return;

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
                success = await vm.RefreshSubscriptionAsync(subCandidate);
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
                vm.AutoResolveMissingCountries();
                vm.SaveConfig();
                MessageBox.Show("Серверы из подписки успешно импортированы и обновлены!", "Умная подписка", MessageBoxButton.OK, MessageBoxImage.Information);
                vm.CurrentScreen = AppScreen.Dashboard;
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
            foreach (var b in bulkItems) vm.Proxies.Add(b);
            vm.SelectProxy(bulkItems[0]);
            vm.SaveConfig();
            MessageBox.Show($"Импортировано {bulkItems.Count} серверов!", "Пакетный импорт", MessageBoxButton.OK, MessageBoxImage.Information);
            vm.CurrentScreen = AppScreen.Dashboard;
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
            "HYSTERIA2" => ProxyProtocol.Hysteria2,
            "TUIC" => ProxyProtocol.Tuic,
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
        else if (proxy.UsesUdpTransport)
        {
            proxy.Security = "tls";
            proxy.TransportType = "";
            proxy.Fingerprint = "";
            proxy.Password = EditQuicPasswordTextBox.Text.Trim();
            proxy.Sni = EditQuicSniTextBox.Text.Trim();
            if (proto == ProxyProtocol.Tuic)
            {
                proxy.Uuid = EditTuicUuidTextBox.Text.Trim();
                proxy.CongestionControl = (EditCongestionComboBox.SelectedItem as ComboBoxItem)?.Content.ToString()?.ToLowerInvariant() ?? "bbr";
            }
            else
            {
                proxy.ObfsPassword = EditObfsPasswordTextBox.Text.Trim();
                proxy.ServerPorts = EditHopPortsTextBox.Text.Trim();
            }
        }
        else
        {
            proxy.Username = EditUserTextBox.Text.Trim();
            proxy.Password = EditPassTextBox.Text.Trim();
        }

        var source = Vm?.EditingProxy ?? _currentParsedEditItem;
        if (source != null)
        {
            proxy.WsHost = source.WsHost;
            proxy.AlterId = source.AlterId;
            proxy.Flow = source.Flow;
            proxy.SpiderX = source.SpiderX;
            proxy.Alpn = source.Alpn;
            proxy.RawLink = source.RawLink;
            // Not in the form: kept from the link or the saved server
            proxy.Insecure = source.Insecure;
            proxy.UdpRelayMode = source.UdpRelayMode;
        }

        return proxy;
    }

    private async void BtnSaveServer_Click(object sender, RoutedEventArgs e)
    {
        if (Vm is not { } vm) return;

        string quick = EditQuickInputTextBox.Text.Trim();
        string subCandidate = ProxyParser.ExtractActualSubscriptionUrl(quick);
        if (ProxyParser.IsSubscriptionUrl(subCandidate))
        {
            Mouse.OverrideCursor = Cursors.Wait;
            bool success = false;
            string? errorMsg = null;
            try
            {
                success = await vm.RefreshSubscriptionAsync(subCandidate);
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
                vm.AutoResolveMissingCountries();
                vm.SaveConfig();
                MessageBox.Show("Серверы из подписки успешно импортированы и обновлены!", "Умная подписка", MessageBoxButton.OK, MessageBoxImage.Information);
                vm.CurrentScreen = AppScreen.Dashboard;
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

        if (vm.EditingProxy != null)
        {
            // Update existing proxy
            vm.EditingProxy.Name = built.Name;
            vm.EditingProxy.Host = built.Host;
            vm.EditingProxy.Port = built.Port;
            vm.EditingProxy.Protocol = built.Protocol;
            vm.EditingProxy.Uuid = built.Uuid;
            vm.EditingProxy.TransportType = built.TransportType;
            vm.EditingProxy.Security = built.Security;
            vm.EditingProxy.Fingerprint = built.Fingerprint;
            vm.EditingProxy.Sni = built.Sni;
            vm.EditingProxy.PublicKey = built.PublicKey;
            vm.EditingProxy.ShortId = built.ShortId;
            vm.EditingProxy.GrpcServiceName = built.GrpcServiceName;
            vm.EditingProxy.WsPath = built.WsPath;
            vm.EditingProxy.WsHost = built.WsHost;
            vm.EditingProxy.AlterId = built.AlterId;
            vm.EditingProxy.Flow = built.Flow;
            vm.EditingProxy.SpiderX = built.SpiderX;
            vm.EditingProxy.Alpn = built.Alpn;
            vm.EditingProxy.Username = built.Username;
            vm.EditingProxy.Password = built.Password;
            vm.EditingProxy.ObfsPassword = built.ObfsPassword;
            vm.EditingProxy.ServerPorts = built.ServerPorts;
            vm.EditingProxy.Insecure = built.Insecure;
            vm.EditingProxy.CongestionControl = built.CongestionControl;
            vm.EditingProxy.UdpRelayMode = built.UdpRelayMode;

            // Whatever the last check found was about the old settings
            vm.EditingProxy.Status = ProxyStatus.Unknown;
            vm.EditingProxy.PingMs = -1;
            vm.EditingProxy.WorkingAddress = null;

            vm.SelectProxy(vm.EditingProxy);
            vm.SaveConfig();
        }
        else
        {
            // Add new proxy
            vm.AddProxy(built);
        }

        // Auto resolve country asynchronously
        var targetProxy = vm.EditingProxy ?? built;
        _ = Task.Run(async () =>
        {
            string resolved = await GeoIpService.ResolveCountryForHostAsync(targetProxy.CleanHost);
            if (!string.IsNullOrWhiteSpace(resolved))
            {
                targetProxy.Country = resolved;
                Application.Current?.Dispatcher?.Invoke(vm.SaveConfig);
            }
        });

        vm.CurrentScreen = AppScreen.Dashboard;
    }
}
