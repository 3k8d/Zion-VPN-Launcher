using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Zion.Models;
using Zion.Services;

namespace Zion.ViewModels;

public class DnsOptionItem : INotifyPropertyChanged
{
    public DnsProvider Provider { get; }
    public string Name { get; }

    private bool _isSelected;

    public DnsOptionItem(DnsProvider provider, string name)
    {
        Provider = provider;
        Name = name;
    }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetField(ref _isSelected, value);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}

public class MainViewModel : INotifyPropertyChanged
{
    private readonly ConnectionController _controller = new();
    private ObservableCollection<ProxyItem> _proxies = new();
    private ProxyItem? _selectedProxy;
    private PropertyChangedEventHandler? _selectedProxyPropChanged;
    private bool _isConnected;
    private bool _isConnecting;

    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(1) };
    // Hourly check whether the daily subscription refresh is due (see AutoUpdateSubscriptionIfDueAsync)
    private readonly DispatcherTimer _subscriptionTimer = new() { Interval = TimeSpan.FromHours(1) };
    private DateTime _connectedStartTime;
    private long _totalTrafficBytes = 0;

    private readonly List<string> _logEntries = new();

    private string _sessionTimerText = "00:00:00";
    private string _totalTrafficText = "0.00 GB";
    private string _downSpeedText = "0.0 KB/s";
    private string _upSpeedText = "0.0 KB/s";

    private bool _isDnsModalOpen;

    public ObservableCollection<ProxyItem> Proxies
    {
        get => _proxies;
        set => SetField(ref _proxies, value);
    }

    public ProxyItem? SelectedProxy
    {
        get => _selectedProxy;
        set
        {
            if (_selectedProxy != null && _selectedProxyPropChanged != null)
            {
                _selectedProxy.PropertyChanged -= _selectedProxyPropChanged;
            }

            if (SetField(ref _selectedProxy, value))
            {
                if (_selectedProxy != null)
                {
                    _selectedProxyPropChanged = (s, e) =>
                    {
                        if (e.PropertyName == nameof(ProxyItem.Country))
                        {
                            NotifyUiProperties();
                        }
                    };
                    _selectedProxy.PropertyChanged += _selectedProxyPropChanged;
                }
                NotifyUiProperties();
                SaveConfig();
            }
        }
    }

    public bool IsConnected
    {
        get => _isConnected;
        set
        {
            if (SetField(ref _isConnected, value))
            {
                NotifyUiProperties();
            }
        }
    }

    public bool IsConnecting
    {
        get => _isConnecting;
        set
        {
            if (SetField(ref _isConnecting, value))
            {
                NotifyUiProperties();
            }
        }
    }

    public string SessionTimerText
    {
        get => _sessionTimerText;
        set => SetField(ref _sessionTimerText, value);
    }

    public string TotalTrafficText
    {
        get => _totalTrafficText;
        set => SetField(ref _totalTrafficText, value);
    }

    public string DownSpeedText
    {
        get => _downSpeedText;
        set => SetField(ref _downSpeedText, value);
    }

    public string UpSpeedText
    {
        get => _upSpeedText;
        set => SetField(ref _upSpeedText, value);
    }

    // State palette: mint = connected, amber = connecting, violet = idle
    public string StatusDotColor => IsConnected ? "#34E0A1" : (IsConnecting ? "#FBBF24" : "#8B7DFF");

    public string OuterHaloBg => IsConnected ? "#0E3B2C" : (IsConnecting ? "#3A2A08" : "#1D1A45");
    public string OuterHaloBorder => IsConnected ? "#34E0A1" : (IsConnecting ? "#FBBF24" : "#8B7DFF");
    private string PowerBtnTopFill => IsConnected ? "#4BEBB0" : (IsConnecting ? "#FCD34D" : "#9D8FFF");
    private string PowerBtnBottomFill => IsConnected ? "#0C9B6B" : (IsConnecting ? "#D97706" : "#5B4BE8");
    public string PowerBtnRingStroke => IsConnected ? "#8AF7D0" : (IsConnecting ? "#FDE68A" : "#B9B0FF");

    public Brush PowerBtnBrush
    {
        get
        {
            var topColor = (Color)ColorConverter.ConvertFromString(PowerBtnTopFill);
            var bottomColor = (Color)ColorConverter.ConvertFromString(PowerBtnBottomFill);
            var brush = new RadialGradientBrush
            {
                Center = new Point(0.5, 0.45),
                GradientOrigin = new Point(0.5, 0.4),
                RadiusX = 0.65,
                RadiusY = 0.65
            };
            brush.GradientStops.Add(new GradientStop(topColor, 0.0));
            brush.GradientStops.Add(new GradientStop(bottomColor, 1.0));
            brush.Freeze();
            return brush;
        }
    }

    public string PowerStatusTextColor
    {
        get
        {
            if (_controller.State == ConnectionState.Connected && IsLinkDown) return "#FB7185";

            return _controller.State switch
            {
                ConnectionState.Failed => "#FB7185",
                ConnectionState.Starting or ConnectionState.Validating or ConnectionState.Reconnecting => "#FBBF24",
                _ => "#A3ACC2"
            };
        }
    }

    public string PowerPromptText
    {
        get
        {
            if (_controller.State == ConnectionState.Connected && IsLinkDown)
                return _controller.IsInternetDown ? "Нет интернета" : "Нет связи с сервером";
            if (_controller.State == ConnectionState.Failed && KillSwitchFirewall.IsArmed)
                return "Kill Switch: интернет заблокирован";

            return _controller.State switch
            {
                ConnectionState.Starting => "Инициализация...",
                ConnectionState.Validating => "Проверка конфигурации...",
                ConnectionState.Reconnecting => "Переподключение...",
                ConnectionState.Connected => "Нажмите для отключения",
                ConnectionState.Stopping => "Отключение...",
                ConnectionState.Failed => "Ошибка подключения",
                _ => "Нажмите для подключения"
            };
        }
    }

    public string ProtocolBadge => SelectedProxy?.ProtocolBadge ?? "VLESS";

    // Server card on the dashboard
    public string ServerCardSubtitle => SelectedProxy?.DisplayName ?? "Выберите сервер";
    public string ServerCardBadge => ProtocolBadge;
    public string ServerCardCountry => SelectedProxy?.Country ?? "";

    public AppConfig Config => ConfigStore.Current;

    private bool _autoConnectOnStartup;
    public bool AutoConnectOnStartup
    {
        get => _autoConnectOnStartup;
        set
        {
            if (SetField(ref _autoConnectOnStartup, value))
            {
                SaveConfig();
            }
        }
    }

    private bool _bypassTorrents;
    public bool BypassTorrents
    {
        get => _bypassTorrents;
        set
        {
            if (SetField(ref _bypassTorrents, value))
            {
                SaveConfig();
                if (IsConnected)
                {
                    _ = ReconnectWithCurrentConfigAsync();
                }
            }
        }
    }

    private bool _bypassDomesticRu;
    public bool BypassDomesticRu
    {
        get => _bypassDomesticRu;
        set
        {
            if (SetField(ref _bypassDomesticRu, value))
            {
                SaveConfig();
                if (IsConnected)
                {
                    _ = ReconnectWithCurrentConfigAsync();
                }
            }
        }
    }

    private DnsProvider _selectedDns = DnsProvider.Auto;
    public DnsProvider SelectedDns
    {
        get => _selectedDns;
        set
        {
            if (SetField(ref _selectedDns, value))
            {
                SaveConfig();
                OnPropertyChanged(nameof(DnsBadgeText));
                OnPropertyChanged(nameof(DnsSubtitleText));
                OnPropertyChanged(nameof(DnsSubtitleColor));
                UpdateDnsOptionsSelection();
                if (IsConnected)
                {
                    _ = ReconnectWithCurrentConfigAsync();
                }
            }
        }
    }

    public string DnsBadgeText => SelectedDns switch
    {
        DnsProvider.Cloudflare => "Cloudflare",
        DnsProvider.Google => "Google",
        DnsProvider.ControlD => "Control D",
        DnsProvider.NextDns => "NextDNS",
        DnsProvider.AdGuard => "AdGuard",
        DnsProvider.OpenDNS => "OpenDNS",
        DnsProvider.CleanBrowsing => "CleanBrowsing",
        _ => "Авто"
    };

    public string DnsSubtitleText
    {
        get
        {
            if (SelectedDns == DnsProvider.Auto)
            {
                // The DNS server the tunnel actually picked when it started (fastest one)
                string active = _controller.ActiveDnsName;
                return IsConnected && active.Length > 0 ? $"Работает через: {active}" : "Автоматический выбор";
            }
            return "Прямой выбор";
        }
    }

    public string DnsSubtitleColor => (SelectedDns == DnsProvider.Auto && IsConnected) ? "#B3A9FF" : "#E6E9F2";

    public ObservableCollection<DnsOptionItem> DnsOptions { get; }

    public bool IsDnsModalOpen
    {
        get => _isDnsModalOpen;
        set => SetField(ref _isDnsModalOpen, value);
    }

    private bool _autoServerFailover;
    public bool AutoServerFailover
    {
        get => _autoServerFailover;
        set
        {
            if (SetField(ref _autoServerFailover, value))
            {
                SaveConfig();
            }
        }
    }

    private bool _killSwitch;
    public bool KillSwitch
    {
        get => _killSwitch;
        set
        {
            if (SetField(ref _killSwitch, value))
            {
                SaveConfig();
                _controller.KillSwitchEnabled = value;

                if (!value)
                {
                    // Turning it off is the user's way back to direct internet after a failure.
                    _controller.DisarmKillSwitch();
                }
                else if (_userWantsConnection)
                {
                    if (!_controller.ArmKillSwitchIfEnabled())
                    {
                        ShowToast($"Kill Switch не включился. {KillSwitchFirewall.LastError}");
                    }
                }

                NotifyUiProperties();
            }
        }
    }

    // True from the moment the user (or auto-connect) asks for a tunnel until they disconnect.
    private bool _userWantsConnection;
    private bool _failoverInProgress;
    private DateTime _lastFailoverFinishedUtc = DateTime.MinValue;

    private bool _isLinkDown;
    /// <summary>The tunnel is up but the server has stopped answering.</summary>
    public bool IsLinkDown
    {
        get => _isLinkDown;
        private set
        {
            if (SetField(ref _isLinkDown, value))
            {
                NotifyUiProperties();
            }
        }
    }

    private string _toastText = "";
    public string ToastText
    {
        get => _toastText;
        private set => SetField(ref _toastText, value);
    }

    private bool _isToastVisible;
    public bool IsToastVisible
    {
        get => _isToastVisible;
        private set => SetField(ref _isToastVisible, value);
    }

    public ICommand DismissToastCommand { get; }

    private readonly DispatcherTimer _toastTimer = new() { Interval = TimeSpan.FromSeconds(20) };

    private void ShowToast(string text)
    {
        ToastText = text;
        IsToastVisible = true;
        _toastTimer.Stop();
        _toastTimer.Start();
    }

    private string _copyLogsButtonText = "Скопировать";
    /// <summary>Label of the copy button: briefly confirms the result, then returns to normal.</summary>
    public string CopyLogsButtonText
    {
        get => _copyLogsButtonText;
        private set => SetField(ref _copyLogsButtonText, value);
    }

    private async void CopyLogs()
    {
        if (_logEntries.Count == 0)
        {
            CopyLogsButtonText = "Журнал пуст";
        }
        else
        {
            try
            {
                string header = $"Zion — журнал событий, {DateTime.Now:dd.MM.yyyy HH:mm}{Environment.NewLine}";
                Clipboard.SetText(header + string.Join(Environment.NewLine, _logEntries));
                CopyLogsButtonText = "Скопировано";
            }
            catch
            {
                CopyLogsButtonText = "Не удалось";
            }
        }

        await Task.Delay(1800);
        CopyLogsButtonText = "Скопировать";
    }

    private void AddLog(string line)
    {
        if (_logEntries.Count > 400) _logEntries.RemoveAt(0);
        _logEntries.Add($"[{DateTime.Now:HH:mm:ss}] {line}");
    }

    private bool _autoStartWithWindows;
    public bool AutoStartWithWindows
    {
        get => _autoStartWithWindows;
        set
        {
            if (SetField(ref _autoStartWithWindows, value))
            {
                AutoStartService.SetAutoStart(value);
            }
        }
    }

    public ICommand CopyLogsCommand { get; }

    private bool _autoUpdateSubscription;
    /// <summary>Refresh the subscription by itself once a day (checked at start-up and then every hour).</summary>
    public bool AutoUpdateSubscription
    {
        get => _autoUpdateSubscription;
        set
        {
            if (SetField(ref _autoUpdateSubscription, value))
            {
                SaveConfig();
                if (value) _ = AutoUpdateSubscriptionIfDueAsync();
            }
        }
    }

    private bool _blockQuic;
    public bool BlockQuic
    {
        get => _blockQuic;
        set
        {
            if (SetField(ref _blockQuic, value))
            {
                SaveConfig();
                if (IsConnected)
                {
                    _ = ReconnectWithCurrentConfigAsync();
                }
            }
        }
    }

    private bool _blockWebRtc;
    public bool BlockWebRtc
    {
        get => _blockWebRtc;
        set
        {
            if (SetField(ref _blockWebRtc, value))
            {
                SaveConfig();
                if (IsConnected)
                {
                    _ = ReconnectWithCurrentConfigAsync();
                }
            }
        }
    }

    private bool _blockTrackers;
    public bool BlockTrackers
    {
        get => _blockTrackers;
        set
        {
            if (SetField(ref _blockTrackers, value))
            {
                SaveConfig();
                if (IsConnected)
                {
                    _ = ReconnectWithCurrentConfigAsync();
                }
            }
        }
    }

    private AppScreen _currentScreen = AppScreen.Dashboard;
    public AppScreen CurrentScreen
    {
        get => _currentScreen;
        set
        {
            if (SetField(ref _currentScreen, value))
            {
                OnPropertyChanged(nameof(IsDashboardVisible));
                OnPropertyChanged(nameof(IsServerListVisible));
                OnPropertyChanged(nameof(IsServerEditVisible));
                OnPropertyChanged(nameof(IsSettingsVisible));
                OnPropertyChanged(nameof(IsSubscriptionsVisible));
                OnPropertyChanged(nameof(IsExclusionsVisible));
                OnPropertyChanged(nameof(IsExcludedSitesVisible));
                OnScreenChanged(value);
            }
        }
    }

    public bool IsDashboardVisible => CurrentScreen == AppScreen.Dashboard;
    public bool IsServerListVisible => CurrentScreen == AppScreen.ServerList;
    public bool IsServerEditVisible => CurrentScreen == AppScreen.ServerEdit;
    public bool IsSettingsVisible => CurrentScreen == AppScreen.Settings;
    public bool IsSubscriptionsVisible => CurrentScreen == AppScreen.Subscriptions;
    public bool IsExclusionsVisible => CurrentScreen == AppScreen.Exclusions;
    public bool IsExcludedSitesVisible => CurrentScreen == AppScreen.ExcludedSites;

    public ServerListViewModel ServerListVm { get; }
    public SubscriptionsViewModel SubscriptionsVm { get; }
    public ExcludedAppsViewModel ExcludedAppsVm { get; }
    public ExcludedSitesViewModel ExcludedSitesVm { get; }

    // Several programs or sites are often added one after another: restart the tunnel once, after a short pause
    private readonly DispatcherTimer _routingReconnectTimer = new() { Interval = TimeSpan.FromSeconds(2) };

    /// <summary>Hands the excluded programs and sites to the core and restarts a running tunnel to apply them.</summary>
    public void ApplyRoutingExceptions()
    {
        SaveConfig();
        _controller.DirectApps = TunRoutingEngine.SanitizeDirectApps(Config.DirectApps.Select(a => a.ProcessName));
        _controller.DirectSites = DirectSites.Sanitize(Config.DirectSites);
        if (IsConnected)
        {
            _routingReconnectTimer.Stop();
            _routingReconnectTimer.Start();
        }
    }

    private ProxyItem? _editingProxy;
    public ProxyItem? EditingProxy
    {
        get => _editingProxy;
        set => SetField(ref _editingProxy, value);
    }

    private readonly DispatcherTimer _livePingTimer = new() { Interval = TimeSpan.FromSeconds(10.0) };

    private void OnScreenChanged(AppScreen screen)
    {
        if (screen == AppScreen.ServerList)
        {
            _ = RunLivePingOnceAsync();
            if (!_livePingTimer.IsEnabled)
            {
                _livePingTimer.Start();
            }
        }
        else
        {
            if (_livePingTimer.IsEnabled)
            {
                _livePingTimer.Stop();
            }
        }
    }

    private async Task RunLivePingOnceAsync()
    {
        if (Proxies.Count == 0) return;
        var targets = Proxies.ToList();
        var tasks = targets.Select(p => ProxyCheckerService.FastPingProxyAsync(p));
        await Task.WhenAll(tasks);
    }

    public string EditFormTitle => EditingProxy != null ? "РЕДАКТИРОВАНИЕ СЕРВЕРА" : "ДОБАВЛЕНИЕ СЕРВЕРА";

    public ICommand ToggleConnectionCommand { get; }
    public ICommand OpenServerListCommand { get; }
    public ICommand NavigateToSettingsCommand { get; }
    public ICommand OpenSubscriptionsCommand { get; }
    public ICommand OpenExclusionsCommand { get; }
    public ICommand OpenExcludedSitesCommand { get; }
    public ICommand OpenDnsModalCommand { get; }
    public ICommand CloseDnsModalCommand { get; }
    public ICommand SelectDnsCommand { get; }

    public MainViewModel()
    {
        var config = ConfigStore.Current;
        Proxies = new ObservableCollection<ProxyItem>(config.Proxies);

        ServerListVm = new ServerListViewModel(this);
        SubscriptionsVm = new SubscriptionsViewModel(this);
        ExcludedAppsVm = new ExcludedAppsViewModel(this);
        ExcludedSitesVm = new ExcludedSitesViewModel(this);
        _controller.DirectApps = TunRoutingEngine.SanitizeDirectApps(config.DirectApps.Select(a => a.ProcessName));
        _controller.DirectSites = DirectSites.Sanitize(config.DirectSites);
        _routingReconnectTimer.Tick += async (_, _) =>
        {
            _routingReconnectTimer.Stop();
            await ReconnectWithCurrentConfigAsync();
        };

        if (Proxies.Count > 0)
        {
            if (config.SelectedProxyId.HasValue)
                _selectedProxy = Proxies.FirstOrDefault(p => p.Id == config.SelectedProxyId.Value);
            _selectedProxy ??= Proxies.FirstOrDefault();
        }
        else
        {
            _selectedProxy = null;
        }

        if (_selectedProxy != null)
        {
            _selectedProxyPropChanged = (s, e) =>
            {
                if (e.PropertyName == nameof(ProxyItem.Country))
                {
                    NotifyUiProperties();
                }
            };
            _selectedProxy.PropertyChanged += _selectedProxyPropChanged;
        }

        _autoConnectOnStartup = config.AutoConnectOnStartup;
        _autoServerFailover = config.AutoServerFailover;
        _bypassTorrents = config.BypassTorrents;
        _bypassDomesticRu = config.BypassDomesticRu;
        _selectedDns = config.SelectedDns;
        _autoUpdateSubscription = config.AutoUpdateSubscription;
        _blockQuic = config.BlockQuic;
        _blockWebRtc = config.BlockWebRtc;
        _blockTrackers = config.BlockTrackers;
        _killSwitch = config.KillSwitch;
        _controller.KillSwitchEnabled = _killSwitch;
        _autoStartWithWindows = AutoStartService.IsAutoStartEnabled();

        DismissToastCommand = new RelayCommand(_ => IsToastVisible = false);
        _toastTimer.Tick += (_, _) => { _toastTimer.Stop(); IsToastVisible = false; };

        DnsOptions = new ObservableCollection<DnsOptionItem>
        {
            new(DnsProvider.Auto, "Авто"),
            new(DnsProvider.Cloudflare, "Cloudflare"),
            new(DnsProvider.Google, "Google"),
            new(DnsProvider.ControlD, "Control D"),
            new(DnsProvider.NextDns, "NextDNS"),
            new(DnsProvider.AdGuard, "AdGuard"),
            new(DnsProvider.OpenDNS, "OpenDNS"),
            new(DnsProvider.CleanBrowsing, "CleanBrowsing")
        };

        UpdateDnsOptionsSelection();

        ToggleConnectionCommand = new RelayCommand(async _ => await ToggleConnectionAsync(), _ => !IsConnecting);
        OpenServerListCommand = new RelayCommand(_ => CurrentScreen = AppScreen.ServerList);
        NavigateToSettingsCommand = new RelayCommand(_ => CurrentScreen = AppScreen.Settings);
        OpenSubscriptionsCommand = new RelayCommand(_ => CurrentScreen = AppScreen.Subscriptions);
        OpenExclusionsCommand = new RelayCommand(_ => CurrentScreen = AppScreen.Exclusions);
        OpenExcludedSitesCommand = new RelayCommand(_ => CurrentScreen = AppScreen.ExcludedSites);

        CopyLogsCommand = new RelayCommand(_ => CopyLogs());

        OpenDnsModalCommand = new RelayCommand(_ => IsDnsModalOpen = true);
        CloseDnsModalCommand = new RelayCommand(_ => IsDnsModalOpen = false);
        SelectDnsCommand = new RelayCommand(p =>
        {
            if (p is DnsProvider provider)
            {
                SelectedDns = provider;
                IsDnsModalOpen = false;
            }
        });

        _timer.Tick += Timer_Tick;
        _livePingTimer.Tick += async (_, _) =>
        {
            if (CurrentScreen == AppScreen.ServerList)
            {
                await RunLivePingOnceAsync();
            }
        };

        // Wire ConnectionController State Machine
        _controller.StateChanged += (state, err) =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                IsConnected = (state == ConnectionState.Connected);
                IsConnecting = (state == ConnectionState.Starting || state == ConnectionState.Validating ||
                                state == ConnectionState.Reconnecting || state == ConnectionState.Stopping);

                if (state == ConnectionState.Connected)
                {
                    _connectedStartTime = _controller.ConnectedStartTime ?? DateTime.Now;
                    _totalTrafficBytes = 0;
                    TotalTrafficText = "0.00 GB";
                    SessionTimerText = "00:00:00";
                    _timer.Start();

                    // Never let the toggle promise protection that is not actually in place
                    if (KillSwitch && !KillSwitchFirewall.IsArmed)
                    {
                        ShowToast($"Kill Switch не включился. {KillSwitchFirewall.LastError}");
                    }
                }
                else if (state == ConnectionState.Disconnected || state == ConnectionState.Failed)
                {
                    _timer.Stop();
                    DownSpeedText = "0.0 KB/s";
                    UpSpeedText = "0.0 KB/s";
                }

                if (state != ConnectionState.Connected)
                {
                    IsLinkDown = false;
                }

                if (state == ConnectionState.Failed)
                {
                    if (CanAutoFailover())
                    {
                        _ = RunFailoverAsync(err);
                    }
                    else if (!_failoverInProgress && !string.IsNullOrEmpty(err))
                    {
                        MessageBox.Show(WithKillSwitchHint(err), "Ошибка соединения", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }

                NotifyUiProperties();
            });
        };

        // DNS stopped answering through the VPN: the controller moves to a working one by itself
        _controller.DnsSwitched += (from, to) =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
                ShowToast(from == to
                    ? $"DNS {from} не отвечал. Переключено на его запасной адрес."
                    : $"DNS {from} не отвечал. Переключено на {to}."));
        };
        _controller.DnsUnavailable += name =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
                ShowToast($"DNS {name} не отвечает. Выберите «Авто» в настройках DNS."));
        };

        // Server stopped answering (or came back) while the tunnel itself is still up
        _controller.LinkHealthChanged += healthy =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                if (!IsConnected) return;
                IsLinkDown = !healthy;
                NotifyUiProperties(); // the prompt also depends on why the link is down

                // No switching while the network itself is down: the tunnel comes back on its own
                if (!healthy && !_controller.IsInternetDown && CanAutoFailover())
                {
                    _ = RunFailoverAsync();
                }
            });
        };

        // Live Clash API Traffic Stream
        _controller.TrafficUpdated += (up, down) =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                if (IsConnected)
                {
                    DownSpeedText = FormatSpeed(down);
                    UpSpeedText = FormatSpeed(up);
                }
            });
        };

        // Session traffic: the single source is the core's per-connection accounting,
        // and only what went through the VPN server is counted.
        _controller.ProxiedTotalUpdated += bytes =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() =>
            {
                if (IsConnected)
                {
                    _totalTrafficBytes = bytes;
                    TotalTrafficText = FormatTraffic(_totalTrafficBytes);
                }
            });
        };

        _controller.LogReceived += line =>
        {
            Application.Current?.Dispatcher?.InvokeAsync(() => AddLog(line));
        };

        // Startup country resolution
        _ = Task.Run(async () =>
        {
            await Task.Delay(2000);
            AutoResolveMissingCountries();
        });

        // Automatic subscription refresh: once shortly after start-up (auto-connect goes first,
        // so the download can use the tunnel), then an hourly check whether a day has passed.
        _subscriptionTimer.Tick += async (_, _) => await AutoUpdateSubscriptionIfDueAsync();
        _subscriptionTimer.Start();
        _ = Task.Run(async () =>
        {
            await Task.Delay(TimeSpan.FromSeconds(15));
            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher != null) await dispatcher.InvokeAsync(AutoUpdateSubscriptionIfDueAsync);
        });

        // Auto-connect on startup if configured
        if (AutoConnectOnStartup && SelectedProxy != null)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(800);
                await Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    if (!IsConnected && !IsConnecting)
                    {
                        await ConnectAsync();
                    }
                });
            });
        }
    }

    private void UpdateDnsOptionsSelection()
    {
        foreach (var opt in DnsOptions)
        {
            opt.IsSelected = (opt.Provider == SelectedDns);
        }
    }

    private void NotifyUiProperties()
    {
        OnPropertyChanged(nameof(StatusDotColor));
        OnPropertyChanged(nameof(OuterHaloBg));
        OnPropertyChanged(nameof(OuterHaloBorder));
        OnPropertyChanged(nameof(PowerBtnRingStroke));
        OnPropertyChanged(nameof(PowerBtnBrush));
        OnPropertyChanged(nameof(PowerStatusTextColor));
        OnPropertyChanged(nameof(PowerPromptText));
        OnPropertyChanged(nameof(ProtocolBadge));
        OnPropertyChanged(nameof(ServerCardSubtitle));
        OnPropertyChanged(nameof(ServerCardBadge));
        OnPropertyChanged(nameof(ServerCardCountry));
        OnPropertyChanged(nameof(DnsBadgeText));
        OnPropertyChanged(nameof(DnsSubtitleText));
        OnPropertyChanged(nameof(DnsSubtitleColor));
    }

    public static string FormatCountryAndCity(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";

        string cleaned = raw.Trim();
        if (cleaned.StartsWith("Flag_", StringComparison.OrdinalIgnoreCase))
        {
            cleaned = cleaned.Substring(5).Trim();
            int spaceIdx = cleaned.IndexOf(' ');
            if (spaceIdx > 0 && spaceIdx <= 3)
            {
                cleaned = cleaned.Substring(spaceIdx + 1).Trim();
            }
        }

        var parts = cleaned.Split(new[] { ',', '-' }, StringSplitOptions.RemoveEmptyEntries)
                           .Select(p => p.Trim())
                           .Where(p => !string.IsNullOrEmpty(p))
                           .ToList();

        if (parts.Count >= 2)
        {
            return $"{parts[0]}, {parts[1]}";
        }
        else if (parts.Count == 1)
        {
            return parts[0];
        }

        return cleaned;
    }

    public void AutoResolveMissingCountries()
    {
        var unresolved = Proxies.Where(p => string.IsNullOrEmpty(p.Country) || p.Country == p.CleanHost).ToList();
        if (unresolved.Count == 0) return;

        _ = Task.Run(async () =>
        {
            foreach (var proxy in unresolved)
            {
                string country = await GeoIpService.ResolveCountryForHostAsync(proxy.CleanHost);
                if (!string.IsNullOrEmpty(country))
                {
                    Application.Current?.Dispatcher?.Invoke(() =>
                    {
                        proxy.Country = country;
                        if (proxy == SelectedProxy)
                        {
                            NotifyUiProperties();
                        }
                    });
                }
                await Task.Delay(200);
            }
            Application.Current?.Dispatcher?.Invoke(SaveConfig);
        });
    }

    public void SelectProxy(ProxyItem proxy)
    {
        bool wasConnected = IsConnected;
        SelectedProxy = proxy;
        SaveConfig();
        NotifyUiProperties();

        if (wasConnected)
        {
            _ = _controller.ReconnectAsync(proxy, BypassTorrents, BypassDomesticRu, SelectedDns, BlockQuic, BlockWebRtc, BlockTrackers);
        }
    }

    public void AddProxy(ProxyItem proxy)
    {
        Proxies.Add(proxy);
        SelectProxy(proxy);
    }

    public void DeleteProxy(ProxyItem proxy)
    {
        if (Proxies.Count <= 1) return;

        bool isCurrent = SelectedProxy?.Id == proxy.Id;
        Proxies.Remove(proxy);

        if (isCurrent)
        {
            var next = Proxies.FirstOrDefault();
            if (next != null)
            {
                SelectProxy(next);
            }
        }
        else
        {
            SaveConfig();
        }
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        if (!IsConnected) return;

        var elapsed = DateTime.Now - _connectedStartTime;
        SessionTimerText = elapsed.ToString(@"hh\:mm\:ss");
    }

    public static string FormatTraffic(long bytes)
    {
        double gb = bytes / (1024.0 * 1024.0 * 1024.0);
        return gb.ToString("F2", System.Globalization.CultureInfo.InvariantCulture) + " GB";
    }

    private static string FormatSpeed(long bytesPerSec)
    {
        if (bytesPerSec < 1024 * 1024)
            return (bytesPerSec / 1024.0).ToString("F1", System.Globalization.CultureInfo.InvariantCulture) + " KB/s";
        return (bytesPerSec / (1024.0 * 1024.0)).ToString("F2", System.Globalization.CultureInfo.InvariantCulture) + " MB/s";
    }

    private async Task ToggleConnectionAsync()
    {
        if (IsConnected)
            Disconnect();
        else
            await ConnectAsync();
    }

    private async Task ConnectAsync()
    {
        if (SelectedProxy == null)
        {
            // Nothing to connect to (e.g. the list was emptied): show where servers are added
            CurrentScreen = AppScreen.ServerList;
            return;
        }
        _userWantsConnection = true;
        await _controller.ConnectAsync(SelectedProxy, BypassTorrents, BypassDomesticRu, SelectedDns, BlockQuic, BlockWebRtc, BlockTrackers);
    }

    public void Disconnect()
    {
        _userWantsConnection = false;
        IsLinkDown = false;
        _ = _controller.DisconnectAsync();
    }

    // =========================================================================
    // AUTOMATIC SERVER FAILOVER
    // =========================================================================

    private bool CanAutoFailover() =>
        AutoServerFailover
        && _userWantsConnection
        && !_failoverInProgress
        && Proxies.Count > 1
        && (DateTime.UtcNow - _lastFailoverFinishedUtc) > TimeSpan.FromSeconds(3);

    private string WithKillSwitchHint(string message) =>
        KillSwitchFirewall.IsArmed
            ? message + "\n\nKill Switch активен: интернет заблокирован, пока вы не подключитесь снова или не выключите Kill Switch."
            : message;

    /// <summary>
    /// Walks the fallback list (same country first) until one server connects.
    /// The Kill Switch, if enabled, stays armed the whole time, so nothing leaks between attempts.
    /// </summary>
    private async Task RunFailoverAsync(string? originalError = null)
    {
        if (_failoverInProgress) return;
        _failoverInProgress = true;

        try
        {
            var failed = SelectedProxy;
            string failedName = failed?.DisplayName ?? "Сервер";

            // Another server cannot help when the network itself is down
            if (await InternetProbe.IsInternetReachableAsync() == false)
            {
                AddLog("Автопереключение отменено: нет интернета.");
                if (_userWantsConnection && !IsConnected)
                {
                    MessageBox.Show(
                        WithKillSwitchHint("Нет подключения к интернету. Сервер не менялся: подключитесь снова, когда сеть вернётся."),
                        "Ошибка соединения", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                return;
            }

            var candidates = FailoverPlanner.OrderCandidates(failed, Proxies);
            AddLog($"Автопереключение: «{failedName}» недоступен, кандидатов: {candidates.Count}.");

            foreach (var next in candidates)
            {
                if (!_userWantsConnection) return;

                AddLog($"Автопереключение: пробуем «{next.DisplayName}».");
                SelectedProxy = next;

                bool ok = await _controller.ReconnectAsync(next, BypassTorrents, BypassDomesticRu, SelectedDns, BlockQuic, BlockWebRtc, BlockTrackers);
                if (ok)
                {
                    ShowToast($"«{failedName}» не отвечает. Переключено на «{next.DisplayName}».");
                    return;
                }
            }

            if (_userWantsConnection)
            {
                // Nothing worked: leave the user's own choice selected rather than the last thing we tried
                if (failed != null && Proxies.Contains(failed)) SelectedProxy = failed;

                string details = string.IsNullOrWhiteSpace(originalError) ? "" : $"\n\nПервая ошибка: {originalError}";
                MessageBox.Show(
                    WithKillSwitchHint("Не удалось подключиться ни к одному из серверов. Проверьте интернет или обновите подписку." + details),
                    "Ошибка соединения", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        finally
        {
            _failoverInProgress = false;
            _lastFailoverFinishedUtc = DateTime.UtcNow;
            NotifyUiProperties();
        }
    }

    private async Task ReconnectWithCurrentConfigAsync()
    {
        if (!IsConnected || SelectedProxy == null) return;
        await _controller.ReconnectAsync(SelectedProxy, BypassTorrents, BypassDomesticRu, SelectedDns, BlockQuic, BlockWebRtc, BlockTrackers);
    }

    // =========================================================================
    // SUBSCRIPTION UPDATES (manual button, import, automatic daily refresh)
    // =========================================================================

    // Links being downloaded right now (one download per link at a time)
    private readonly HashSet<string> _subscriptionsUpdating = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Raised after anything about subscriptions changed (added, updated, failed, removed, started).</summary>
    public event Action? SubscriptionsChanged;

    public bool IsSubscriptionUpdating(string url) => _subscriptionsUpdating.Contains(url.Trim());

    /// <summary>
    /// Downloads one subscription (adding it if the link is new) and merges it into the list.
    /// Every path goes through here, so the selected server always stays valid. Never throws.
    /// </summary>
    public async Task<SubscriptionUpdateResult> UpdateSubscriptionAsync(string url, bool automatic = false)
    {
        url = ProxyParser.ExtractActualSubscriptionUrl(url ?? "").Trim();
        if (string.IsNullOrWhiteSpace(url)) return SubscriptionUpdateResult.Failed("Пустая ссылка");
        if (!_subscriptionsUpdating.Add(url)) return SubscriptionUpdateResult.Failed("Уже обновляется");
        SubscriptionsChanged?.Invoke();

        string name = SubscriptionDisplayName(SubscriptionService.Find(Config, url)?.Title, url);
        try
        {
            var result = await SubscriptionService.UpdateAsync(url, Proxies, Config);
            if (result.Ok)
            {
                EnsureValidSelection();
                AutoResolveMissingCountries();
                SaveConfig();
                AddLog($"{(automatic ? "Автообновление" : "Обновление")} подписки «{name}»: серверов {result.Total} (+{result.Added}, −{result.Removed}).");
            }
            else
            {
                AddLog($"Подписка «{name}» не обновилась: {result.Error}.{(automatic ? " Повторим через час." : "")}");
            }
            return result;
        }
        catch (Exception ex)
        {
            AddLog($"Ошибка обновления подписки «{name}»: {ex.Message}");
            return SubscriptionUpdateResult.Failed(ex.Message);
        }
        finally
        {
            _subscriptionsUpdating.Remove(url);
            SubscriptionsChanged?.Invoke();
        }
    }

    /// <summary>
    /// Old entry point kept for the "add server" form and the list button:
    /// with a link it adds/updates that subscription, without one it refreshes all of them.
    /// </summary>
    public async Task<bool> RefreshSubscriptionAsync(string? url = null, bool automatic = false)
    {
        if (!string.IsNullOrWhiteSpace(url)) return (await UpdateSubscriptionAsync(url, automatic)).Ok;
        return await RefreshAllSubscriptionsAsync(automatic, onlyDue: false) > 0;
    }

    /// <summary>Refreshes every subscription (or only those due for the daily update). Returns how many succeeded.</summary>
    public async Task<int> RefreshAllSubscriptionsAsync(bool automatic = false, bool onlyDue = false)
    {
        int ok = 0;
        foreach (var entry in Config.Subscriptions.ToList())
        {
            if (onlyDue && !SubscriptionService.IsAutoUpdateDue(Config, entry, DateTime.Now)) continue;
            if ((await UpdateSubscriptionAsync(entry.Url, automatic)).Ok) ok++;
        }
        return ok;
    }

    private Task AutoUpdateSubscriptionIfDueAsync() => RefreshAllSubscriptionsAsync(automatic: true, onlyDue: true);

    /// <summary>
    /// Forgets a subscription and its servers. The server the VPN is using stays (as a manual one),
    /// so the connection is not cut. Returns how many servers were removed.
    /// </summary>
    public sealed record RemovedSubscription(SubscriptionEntry Entry, ServerListSnapshot Servers, List<Guid> MemberIds, int RemovedCount);

    public RemovedSubscription RemoveSubscription(SubscriptionEntry entry)
    {
        string name = SubscriptionDisplayName(entry.Title, entry.Url);
        var memberIds = Proxies.Where(p => p.IsFromSubscription && SubscriptionService.SameUrl(p.SubscriptionUrl, entry.Url)).Select(p => p.Id).ToList();
        var snapshot = new ServerListSnapshot(Proxies.ToList(), memberIds.Count, SelectedProxy?.Id);

        int removed = SubscriptionService.RemoveSubscription(entry, Proxies, Config, ServerInUse);
        EnsureValidSelection();
        SaveConfig();
        AddLog($"Подписка «{name}» удалена вместе с серверами ({removed}).");
        SubscriptionsChanged?.Invoke();
        return new RemovedSubscription(entry, snapshot with { RemovedCount = removed }, memberIds, removed);
    }

    /// <summary>Undo for <see cref="RemoveSubscription"/>: the link and its servers come back where they were.</summary>
    public void RestoreSubscription(RemovedSubscription removed)
    {
        if (SubscriptionService.Find(Config, removed.Entry.Url) == null)
            Config.Subscriptions.Add(removed.Entry);

        RestoreProxies(removed.Servers);

        var members = removed.MemberIds.ToHashSet();
        foreach (var p in Proxies.Where(p => members.Contains(p.Id)))
        {
            p.IsFromSubscription = true;
            p.SubscriptionUrl = removed.Entry.Url;
        }

        SaveConfig();
        SubscriptionsChanged?.Invoke();
    }

    /// <summary>Provider's title if known, otherwise the host of the link.</summary>
    public static string SubscriptionDisplayName(string? title, string url)
    {
        if (!string.IsNullOrWhiteSpace(title)) return title.Trim();
        return Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : url;
    }

    /// <summary>
    /// After the list changed under us (subscription update, deletion): if the selected server is gone,
    /// pick the closest replacement, same country first. A running tunnel is moved over to it.
    /// </summary>
    private void EnsureValidSelection()
    {
        var current = SelectedProxy;
        if (current != null && Proxies.Contains(current)) return;

        var next = FailoverPlanner.OrderCandidates(current, Proxies, max: 1).FirstOrDefault();
        if (next == null)
        {
            SelectedProxy = null;
            return;
        }

        if (current != null && IsConnected)
        {
            ShowToast($"«{current.DisplayName}» больше нет в подписке. Переключено на «{next.DisplayName}».");
            SelectProxy(next); // reconnects
        }
        else
        {
            SelectedProxy = next;
        }
    }

    // =========================================================================
    // DELETE ALL SERVERS (with undo)
    // =========================================================================

    public sealed record ServerListSnapshot(List<ProxyItem> OriginalOrder, int RemovedCount, Guid? SelectedId);

    /// <summary>The server the tunnel is using right now, or null when the VPN is off.</summary>
    public ProxyItem? ServerInUse =>
        IsConnected || IsConnecting || _userWantsConnection ? SelectedProxy : null;

    /// <summary>Servers "delete all" would remove: everything except the one in use.</summary>
    public int DeletableProxyCount => Proxies.Count(p => p != ServerInUse);

    /// <summary>
    /// Removes every server except the one the VPN is using right now, so the connection keeps running.
    /// The subscription link stays: the refresh button (or the daily update) can fill the list again.
    /// Returns what is needed to undo it.
    /// </summary>
    public ServerListSnapshot DeleteAllProxies()
    {
        var keep = ServerInUse;
        var original = Proxies.ToList();
        var snapshot = new ServerListSnapshot(original, original.Count(p => p != keep), SelectedProxy?.Id);

        foreach (var p in original)
        {
            if (p != keep) Proxies.Remove(p);
        }

        SelectedProxy = keep;
        SaveConfig();

        AddLog(keep == null
            ? $"Удалены все серверы ({snapshot.RemovedCount})."
            : $"Удалены все серверы ({snapshot.RemovedCount}), кроме текущего «{keep.DisplayName}».");
        return snapshot;
    }

    /// <summary>Puts back what <see cref="DeleteAllProxies"/> removed in the original order; anything added since stays at the end.</summary>
    public void RestoreProxies(ServerListSnapshot snapshot)
    {
        var originalIds = snapshot.OriginalOrder.Select(p => p.Id).ToHashSet();
        var addedSince = Proxies.Where(p => !originalIds.Contains(p.Id)).ToList();
        var stillPresent = Proxies.GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First()); // ids are not guaranteed unique

        Proxies.Clear();
        foreach (var item in snapshot.OriginalOrder)
        {
            // Keep the live object for servers that never left the list (e.g. the one in use)
            Proxies.Add(stillPresent.TryGetValue(item.Id, out var live) ? live : item);
        }
        foreach (var item in addedSince) Proxies.Add(item);

        if (SelectedProxy == null || !Proxies.Contains(SelectedProxy))
        {
            SelectedProxy = Proxies.FirstOrDefault(p => p.Id == snapshot.SelectedId) ?? Proxies.FirstOrDefault();
        }

        SaveConfig();
        AddLog($"Удаление отменено: возвращено серверов {snapshot.RemovedCount}.");
    }

    public void SaveConfig()
    {
        var config = ConfigStore.Current;
        config.Proxies = Proxies.ToList();
        config.SelectedProxyId = SelectedProxy?.Id;
        config.AutoConnectOnStartup = AutoConnectOnStartup;
        config.AutoServerFailover = AutoServerFailover;
        config.BypassTorrents = BypassTorrents;
        config.BypassDomesticRu = BypassDomesticRu;
        config.SelectedDns = SelectedDns;
        config.AutoUpdateSubscription = AutoUpdateSubscription;
        config.BlockQuic = BlockQuic;
        config.BlockWebRtc = BlockWebRtc;
        config.BlockTrackers = BlockTrackers;
        config.KillSwitch = KillSwitch;
        ConfigStore.Save(config);
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
}
