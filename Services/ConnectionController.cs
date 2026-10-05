using Zion.Models;

namespace Zion.Services;

public enum ConnectionState
{
    Disconnected,
    Starting,
    Validating,
    Connected,
    Reconnecting,
    Stopping,
    Failed
}

public class ConnectionController : IDisposable
{
    private readonly SemaphoreSlim _processLock = new(1, 1);
    private readonly TunRoutingEngine _tun = new();
    private readonly ClashApiClient _clashApi = new();

    private readonly object _sessionSync = new();
    private CancellationTokenSource? _activeSessionCts;
    private Guid _currentSessionId = Guid.Empty;

    public ConnectionState State { get; private set; } = ConnectionState.Disconnected;
    public ProxyItem? ActiveProxy { get; private set; }
    public string LastError { get; private set; } = "";
    /// <summary>DNS server the running tunnel uses, for the dashboard.</summary>
    public string ActiveDnsName => _tun.ActiveDnsName;
    public DateTime? ConnectedStartTime { get; private set; }

    public event Action<ConnectionState, string?>? StateChanged;
    public event Action<long, long>? TrafficUpdated;

    /// <summary>Bytes (up + down) that went through the VPN server in the current session.</summary>
    public event Action<long>? ProxiedTotalUpdated;
    public event Action<string>? LogReceived;

    /// <summary>Raised when the server stops answering (false) or comes back (true) while the tunnel is up.</summary>
    public event Action<bool>? LinkHealthChanged;

    /// <summary>When true, traffic outside the tunnel is blocked from the moment a connection is requested.</summary>
    public bool KillSwitchEnabled { get; set; }

    /// <summary>Exe names whose traffic bypasses the VPN; applied on the next (re)connect.</summary>
    public IReadOnlyCollection<string> DirectApps { get; set; } = Array.Empty<string>();

    /// <summary>Sites (with subdomains) that bypass the VPN; applied on the next (re)connect.</summary>
    public IReadOnlyCollection<string> DirectSites { get; set; } = Array.Empty<string>();

    public bool IsLinkHealthy { get; private set; } = true;

    /// <summary>Set together with an unhealthy link when the cause is the network itself, not the server.</summary>
    public bool IsInternetDown { get; private set; }

    // How often the link is checked, and how many failed checks in a row mean "server is gone".
    private static readonly TimeSpan HealthInterval = TimeSpan.FromSeconds(15);
    private const int HealthFailuresBeforeDown = 2;
    private static readonly string[] HealthProbeUrls =
    {
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204"
    };

    private CancellationTokenSource? _healthCts;
    private long _lastDownloadTicksUtc;

    // DNS: checked through the VPN with a real question shortly after connecting and then every round.
    private static readonly TimeSpan FirstDnsCheckDelay = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan DnsRecheckDelay = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan DnsQuietAfterNoAlternative = TimeSpan.FromSeconds(60);

    /// <summary>What the current tunnel was started with, so a DNS switch can restart it identically.</summary>
    private sealed record ConnectArgs(ProxyItem Proxy, bool BypassTorrents, bool BypassDomesticRu, DnsProvider Dns, bool BlockQuic, bool BlockWebRtc, bool BlockTrackers);
    private ConnectArgs? _lastArgs;

    /// <summary>DNS server proven to work through the VPN; used first on the next (re)start.</summary>
    private DohTarget? _preferredDns;

    /// <summary>The DNS server stopped answering and the tunnel is moving to another one (from, to).</summary>
    public event Action<string, string>? DnsSwitched;

    /// <summary>The chosen DNS provider does not answer through the VPN and has no working address left.</summary>
    public event Action<string>? DnsUnavailable;

    public ConnectionController()
    {
        _tun.OnLog += msg => LogReceived?.Invoke(msg);
        _tun.OnUnexpectedExit += HandleUnexpectedExit;
        _clashApi.OnTraffic += (up, down) =>
        {
            if (down > 0) Interlocked.Exchange(ref _lastDownloadTicksUtc, DateTime.UtcNow.Ticks);

            if (State == ConnectionState.Connected && _currentSessionId != Guid.Empty)
            {
                TrafficUpdated?.Invoke(up, down);
            }
        };
        _clashApi.OnProxiedTotal += bytes =>
        {
            if (State == ConnectionState.Connected && _currentSessionId != Guid.Empty)
            {
                ProxiedTotalUpdated?.Invoke(bytes);
            }
        };
    }

    /// <summary>
    /// Arms the Kill Switch if the user enabled it. Called before anything touches the network,
    /// so the checks and the (re)start of the tunnel already happen behind the block.
    /// </summary>
    public bool ArmKillSwitchIfEnabled()
    {
        if (!KillSwitchEnabled) return false;
        if (KillSwitchFirewall.IsArmed) return true;

        bool ok = KillSwitchFirewall.Arm();
        LogReceived?.Invoke(ok
            ? "Kill Switch включён: трафик мимо туннеля заблокирован."
            : $"Kill Switch не удалось включить: {KillSwitchFirewall.LastError}");
        return ok;
    }

    public void DisarmKillSwitch()
    {
        if (!KillSwitchFirewall.IsArmed) return;
        KillSwitchFirewall.Disarm();
        LogReceived?.Invoke("Kill Switch снят: прямой доступ в интернет восстановлен.");
    }

    private void StartHealthMonitor(Guid sessionId)
    {
        StopHealthMonitor();
        IsLinkHealthy = true;
        IsInternetDown = false;
        Interlocked.Exchange(ref _lastDownloadTicksUtc, DateTime.UtcNow.Ticks);
        var cts = new CancellationTokenSource();
        _healthCts = cts;
        _ = Task.Run(() => HealthLoopAsync(sessionId, cts.Token));
    }

    private void StopHealthMonitor()
    {
        var cts = Interlocked.Exchange(ref _healthCts, null);
        if (cts == null) return;
        try { cts.Cancel(); } catch { }
        cts.Dispose();
    }

    private async Task HealthLoopAsync(Guid sessionId, CancellationToken ct)
    {
        int failures = 0;
        bool firstRound = true;
        DateTime dnsQuietUntil = DateTime.MinValue;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                // The first round comes quickly: a DNS server that does not work through the VPN
                // should be replaced before the user notices that sites do not open.
                await Task.Delay(firstRound ? FirstDnsCheckDelay : HealthInterval, ct).ConfigureAwait(false);
                if (sessionId != _currentSessionId || State != ConnectionState.Connected) return;

                // Data is flowing in, so the link is obviously alive: no probe needed.
                var sinceDownload = DateTime.UtcNow - new DateTime(Interlocked.Read(ref _lastDownloadTicksUtc), DateTimeKind.Utc);
                bool alive = firstRound || sinceDownload < HealthInterval || await ProbeLinkAsync(ct).ConfigureAwait(false);
                firstRound = false;

                if (ct.IsCancellationRequested || sessionId != _currentSessionId) return;

                if (alive)
                {
                    failures = 0;
                    SetLinkHealth(true, internetDown: false);

                    // The server answers; now make sure names still resolve. (The link probe above does not
                    // need DNS, so a dead DNS server would otherwise go unnoticed while no site opens.)
                    if (DateTime.UtcNow >= dnsQuietUntil && !await IsDnsWorkingAsync(ct).ConfigureAwait(false))
                    {
                        if (ct.IsCancellationRequested || sessionId != _currentSessionId) return;
                        bool switching = await TryDnsFailoverAsync(sessionId, ct).ConfigureAwait(false);
                        if (switching) return; // the tunnel restarts; a new monitor takes over
                        dnsQuietUntil = DateTime.UtcNow + DnsQuietAfterNoAlternative;
                    }
                }
                else if (++failures >= HealthFailuresBeforeDown)
                {
                    // Do not blame the server when the whole network is gone (Wi-Fi drop, sleep/wake):
                    // another server would not help, and the tunnel recovers by itself once the network is back.
                    bool? internet = await InternetProbe.IsInternetReachableAsync(2500, ct).ConfigureAwait(false);
                    if (ct.IsCancellationRequested || sessionId != _currentSessionId) return;

                    SetLinkHealth(false, internetDown: internet == false);
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            LogReceived?.Invoke($"Проверка соединения остановлена: {ex.Message}");
        }
    }

    private async Task<bool> ProbeLinkAsync(CancellationToken ct)
    {
        foreach (string url in HealthProbeUrls)
        {
            if (ct.IsCancellationRequested) return true;
            var result = await _clashApi.GetDelayDetailedAsync("proxy-out", url, 4000).ConfigureAwait(false);
            if (result.Success && result.DelayMs > 0) return true;
        }
        return false;
    }

    /// <summary>Asks the tunnel's DNS server a real question through the VPN; one quick retry before calling it dead.</summary>
    private async Task<bool> IsDnsWorkingAsync(CancellationToken ct)
    {
        var target = _tun.ActiveDnsTarget;
        if (target == null || string.IsNullOrEmpty(target.Host)) return true; // nothing we know how to check

        if (await DohProbe.ProbeAsync(target, ct: ct).ConfigureAwait(false) != null) return true;
        await Task.Delay(DnsRecheckDelay, ct).ConfigureAwait(false);
        return await DohProbe.ProbeAsync(target, ct: ct).ConfigureAwait(false) != null;
    }

    /// <summary>
    /// Finds a DNS server that answers through the VPN and restarts the tunnel with it.
    /// Auto mode may pick any provider; a provider chosen by the user only falls back to its own backup address.
    /// Returns true when a restart was started.
    /// </summary>
    private async Task<bool> TryDnsFailoverAsync(Guid sessionId, CancellationToken ct)
    {
        var current = _tun.ActiveDnsTarget;
        var args = _lastArgs;
        if (current == null || args == null) return false;

        var candidates = DohProbe.FailoverCandidates(args.Dns, current);

        LogReceived?.Invoke($"DNS {current.Name} ({current.Ip}) не отвечает через VPN. Ищем замену…");
        var ranked = await DohProbe.RankAsync(candidates, ct: ct).ConfigureAwait(false);
        if (ct.IsCancellationRequested || sessionId != _currentSessionId) return false;

        if (ranked.Count == 0)
        {
            if (args.Dns == DnsProvider.Auto)
            {
                LogReceived?.Invoke("Ни один DNS-сервер не ответил через VPN. Повторим через минуту.");
            }
            else
            {
                LogReceived?.Invoke($"DNS {current.Name} не отвечает через VPN, запасного адреса тоже нет.");
                DnsUnavailable?.Invoke(current.Name);
            }
            return false;
        }

        var (best, ms) = ranked[0];
        _preferredDns = best;
        LogReceived?.Invoke($"DNS переключён: {current.Name} ({current.Ip}) → {best.Name} ({best.Ip}, {ms} ms).");
        DnsSwitched?.Invoke(current.Name, best.Name);

        _ = Task.Run(() => ReconnectAsync(args.Proxy, args.BypassTorrents, args.BypassDomesticRu, args.Dns, args.BlockQuic, args.BlockWebRtc, args.BlockTrackers));
        return true;
    }

    private void SetLinkHealth(bool healthy, bool internetDown)
    {
        if (IsLinkHealthy == healthy && IsInternetDown == internetDown) return;
        IsLinkHealthy = healthy;
        IsInternetDown = internetDown;

        LogReceived?.Invoke(
            healthy ? "Связь с сервером восстановлена."
            : internetDown ? "Нет интернета: ждём, пока сеть вернётся. Сервер не меняем."
            : "Сервер не отвечает на контрольные запросы, хотя интернет есть.");
        LinkHealthChanged?.Invoke(healthy);
    }

    private void SetSessionState(ConnectionState newState, Guid sessionId, string? error = null)
    {
        // STRICT INVARIANT: Session-bound mutations MUST strictly match active _currentSessionId
        lock (_sessionSync)
        {
            if (sessionId == Guid.Empty || sessionId != _currentSessionId)
            {
                return; // Stale session callback -> completely ignored!
            }

            State = newState;
            if (!string.IsNullOrEmpty(error)) LastError = error;
        }

        StateChanged?.Invoke(newState, error);
    }

    private void ResetControllerState(ConnectionState newState, string? error = null)
    {
        // Explicit controller-level reset operations (e.g. DisconnectAsync)
        lock (_sessionSync)
        {
            State = newState;
            if (!string.IsNullOrEmpty(error)) LastError = error;
        }

        StateChanged?.Invoke(newState, error);
    }

    public async Task<bool> ConnectAsync(ProxyItem proxy, bool bypassTorrents, bool bypassDomesticRu, DnsProvider dns, bool blockQuic = false, bool blockWebRtc = false, bool blockTrackers = false)
    {
        if (State == ConnectionState.Connected && ActiveProxy?.Id == proxy.Id)
        {
            return true;
        }

        Guid sessionId;
        CancellationTokenSource newCts;

        // 1. INSTANT CANCELLATION of any prior session (Zero lock contention)
        lock (_sessionSync)
        {
            _activeSessionCts?.Cancel();
            _activeSessionCts?.Dispose();

            sessionId = Guid.NewGuid();
            newCts = new CancellationTokenSource();
            _activeSessionCts = newCts;
            _currentSessionId = sessionId;
        }

        var ct = newCts.Token;
        StopHealthMonitor();
        _preferredDns = null; // a fresh connection starts with a fresh DNS choice
        _lastArgs = new ConnectArgs(proxy, bypassTorrents, bypassDomesticRu, dns, blockQuic, blockWebRtc, blockTrackers);
        ArmKillSwitchIfEnabled();
        SetSessionState(ConnectionState.Starting, sessionId);

        try
        {
            // Acquire process execution lock with instant cancellation support
            await _processLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (sessionId != _currentSessionId || ct.IsCancellationRequested)
                {
                    return false;
                }

                // Step 1: Pre-validation of Proxy Reachability & Protocol Handshake
                SetSessionState(ConnectionState.Validating, sessionId);
                bool isProxyReachable = await ProxyCheckerService.CheckProxyAsync(proxy, ct).ConfigureAwait(false);

                if (sessionId != _currentSessionId || ct.IsCancellationRequested)
                {
                    return false;
                }

                if (!isProxyReachable && proxy.Status == ProxyStatus.AuthError)
                {
                    _tun.Stop();
                    ActiveProxy = null;
                    ConnectedStartTime = null;
                    SetSessionState(ConnectionState.Failed, sessionId, "Ошибка аутентификации прокси (неверный логин/пароль или UUID).");
                    return false;
                }

                // Step 2: Start TUN Core with Native Validation & Clash Delay Ready-Check
                var (success, error) = await _tun.StartAsync(proxy, bypassTorrents, bypassDomesticRu, dns, blockQuic, blockWebRtc, blockTrackers, sessionId, ct, DirectApps, _preferredDns, DirectSites).ConfigureAwait(false);

                if (sessionId != _currentSessionId || ct.IsCancellationRequested)
                {
                    _tun.Stop();
                    return false;
                }

                if (success)
                {
                    ActiveProxy = proxy;
                    ConnectedStartTime = DateTime.Now;
                    _clashApi.SetSecret(_tun.CurrentClashSecret);
                    _clashApi.StartTrafficStream();

                    SetSessionState(ConnectionState.Connected, sessionId);
                    StartHealthMonitor(sessionId);
                    return true;
                }
                else
                {
                    _tun.Stop();
                    ActiveProxy = null;
                    ConnectedStartTime = null;
                    SetSessionState(ConnectionState.Failed, sessionId, error);
                    return false;
                }
            }
            finally
            {
                _processLock.Release();
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _tun.Stop();
            ActiveProxy = null;
            ConnectedStartTime = null;
            SetSessionState(ConnectionState.Failed, sessionId, ex.Message);
            return false;
        }
    }

    public async Task<bool> ReconnectAsync(ProxyItem newProxy, bool bypassTorrents, bool bypassDomesticRu, DnsProvider dns, bool blockQuic = false, bool blockWebRtc = false, bool blockTrackers = false)
    {
        Guid sessionId;
        CancellationTokenSource newCts;

        // 1. INSTANT CANCELLATION of any prior session
        lock (_sessionSync)
        {
            _activeSessionCts?.Cancel();
            _activeSessionCts?.Dispose();

            sessionId = Guid.NewGuid();
            newCts = new CancellationTokenSource();
            _activeSessionCts = newCts;
            _currentSessionId = sessionId;
        }

        var ct = newCts.Token;
        StopHealthMonitor();
        if (_lastArgs == null || _lastArgs.Dns != dns) _preferredDns = null; // the user picked another DNS
        _lastArgs = new ConnectArgs(newProxy, bypassTorrents, bypassDomesticRu, dns, blockQuic, blockWebRtc, blockTrackers);
        // Armed before the old tunnel is torn down, so the switch-over never runs in the clear.
        ArmKillSwitchIfEnabled();
        SetSessionState(ConnectionState.Reconnecting, sessionId);

        try
        {
            await _processLock.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (sessionId != _currentSessionId || ct.IsCancellationRequested)
                {
                    return false;
                }

                // Stop current data flow before switching
                _clashApi.StopTrafficStream();
                _tun.Stop();

                // Step 1: Pre-validate new proxy
                SetSessionState(ConnectionState.Validating, sessionId);
                bool isProxyReachable = await ProxyCheckerService.CheckProxyAsync(newProxy, ct).ConfigureAwait(false);

                if (sessionId != _currentSessionId || ct.IsCancellationRequested)
                {
                    return false;
                }

                if (!isProxyReachable && newProxy.Status == ProxyStatus.AuthError)
                {
                    _tun.Stop();
                    ActiveProxy = null;
                    ConnectedStartTime = null;
                    SetSessionState(ConnectionState.Failed, sessionId, "Ошибка аутентификации прокси.");
                    return false;
                }

                // Step 2: Start new session tunnel
                var (success, error) = await _tun.StartAsync(newProxy, bypassTorrents, bypassDomesticRu, dns, blockQuic, blockWebRtc, blockTrackers, sessionId, ct, DirectApps, _preferredDns, DirectSites).ConfigureAwait(false);

                if (sessionId != _currentSessionId || ct.IsCancellationRequested)
                {
                    _tun.Stop();
                    return false;
                }

                if (success)
                {
                    ActiveProxy = newProxy;
                    ConnectedStartTime = DateTime.Now;
                    _clashApi.SetSecret(_tun.CurrentClashSecret);
                    _clashApi.StartTrafficStream();

                    SetSessionState(ConnectionState.Connected, sessionId);
                    StartHealthMonitor(sessionId);
                    return true;
                }
                else
                {
                    _tun.Stop();
                    ActiveProxy = null;
                    ConnectedStartTime = null;
                    SetSessionState(ConnectionState.Failed, sessionId, error);
                    return false;
                }
            }
            finally
            {
                _processLock.Release();
            }
        }
        catch (OperationCanceledException)
        {
            return false;
        }
        catch (Exception ex)
        {
            _tun.Stop();
            ActiveProxy = null;
            ConnectedStartTime = null;
            SetSessionState(ConnectionState.Failed, sessionId, ex.Message);
            return false;
        }
    }

    public async Task DisconnectAsync()
    {
        lock (_sessionSync)
        {
            _activeSessionCts?.Cancel();
            _activeSessionCts?.Dispose();
            _activeSessionCts = null;
            _currentSessionId = Guid.Empty;
        }

        StopHealthMonitor();
        _preferredDns = null;
        ResetControllerState(ConnectionState.Stopping);

        try
        {
            await _processLock.WaitAsync().ConfigureAwait(false);
            try
            {
                _clashApi.StopTrafficStream();
                _tun.Stop();
                ActiveProxy = null;
                ConnectedStartTime = null;

                // The user asked to disconnect, so direct access is what they want now.
                DisarmKillSwitch();
                ResetControllerState(ConnectionState.Disconnected);
            }
            finally
            {
                _processLock.Release();
            }
        }
        catch
        {
            DisarmKillSwitch();
            ResetControllerState(ConnectionState.Disconnected);
        }
    }

    private void HandleUnexpectedExit(Guid exitingSessionId)
    {
        lock (_sessionSync)
        {
            // INVARIANT: Stale/Old sessions MUST NEVER mutate active session!
            if (exitingSessionId == Guid.Empty || exitingSessionId != _currentSessionId)
            {
                return;
            }
        }

        if (State == ConnectionState.Connected || State == ConnectionState.Validating || State == ConnectionState.Starting)
        {
            // The Kill Switch, if armed, stays armed here: that is the whole point of it.
            StopHealthMonitor();
            _clashApi.StopTrafficStream();
            _tun.Stop();
            ActiveProxy = null;
            ConnectedStartTime = null;

            SetSessionState(ConnectionState.Failed, exitingSessionId, "Ядро sing-box неожиданно завершило работу.");
        }
    }

    public void Dispose()
    {
        lock (_sessionSync)
        {
            _activeSessionCts?.Cancel();
            _activeSessionCts?.Dispose();
        }
        StopHealthMonitor();
        _clashApi.Dispose();
        _tun.Stop();
        KillSwitchFirewall.Disarm();
        _processLock.Dispose();
    }
}

