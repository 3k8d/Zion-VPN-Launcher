using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Zion.Models;

namespace Zion.Services;

public record DnsBenchmarkResult(string Name, string ServerIp, string Path, int LatencyMs, bool Success);


public class TunRoutingEngine
{
    public bool IsActive { get; private set; } = false;
    public string CurrentClashSecret { get; private set; } = "";

    /// <summary>Name of the DNS server the running tunnel uses (e.g. "Cloudflare").</summary>
    public string ActiveDnsName { get; private set; } = "";

    /// <summary>The DNS server the running tunnel sends its questions to first.</summary>
    public DohTarget? ActiveDnsTarget { get; private set; }

    /// <summary>What GenerateSingBoxConfig will put first for these inputs.</summary>
    public static DohTarget ResolvePrimaryDns(DnsProvider dnsProvider, IReadOnlyList<DnsBenchmarkResult>? autoDnsOrder)
    {
        if (dnsProvider == DnsProvider.Auto && autoDnsOrder is { Count: > 0 })
        {
            var first = autoDnsOrder[0];
            var entry = DnsConstants.FindByIp(first.ServerIp);
            return new DohTarget(entry?.DisplayName ?? first.Name, first.ServerIp, entry?.DohHost ?? "", entry?.DohPath ?? first.Path);
        }

        // A fixed choice uses its primary address; Auto without a measurement falls back to the providers' order (Cloudflare first)
        var e = DnsConstants.GetEntry(dnsProvider == DnsProvider.Auto ? DnsProvider.Cloudflare : dnsProvider);
        return new DohTarget(e.DisplayName, e.PrimaryIp, e.DohHost, e.DohPath);
    }
    private Process? _singBoxProcess;
    private Guid _activeSessionId = Guid.Empty;
    private readonly SemaphoreSlim _syncLock = new(1, 1);

    private static bool _coreFilesVerified = false;
    private static string? _resolvedCoreDir;

    public static string CoreDir
    {
        get
        {
            if (_resolvedCoreDir != null) return _resolvedCoreDir;
            string primary = @"C:\Program Files\Zion\Core";
            try
            {
                if (!Directory.Exists(primary)) Directory.CreateDirectory(primary);
                string testFile = Path.Combine(primary, $".write_test_{Guid.NewGuid():N}");
                File.WriteAllText(testFile, "test");
                File.Delete(testFile);
                _resolvedCoreDir = primary;
                return _resolvedCoreDir;
            }
            catch
            {
                string fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Zion", "Core");
                try { if (!Directory.Exists(fallback)) Directory.CreateDirectory(fallback); } catch { }
                _resolvedCoreDir = fallback;
                return _resolvedCoreDir;
            }
        }
    }

    public static string SingBoxExePath => Path.Combine(CoreDir, "sing-box.exe");
    public static string WintunDllPath => Path.Combine(CoreDir, "wintun.dll");
    
    // Secure dedicated runtime directory for ephemeral active configuration
    public static readonly string RuntimeDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Zion",
        "Runtime"
    );
    public static readonly string ConfigPath = Path.Combine(RuntimeDir, "active_tun_config.json");

    public event Action<string>? OnLog;
    public event Action<Guid>? OnUnexpectedExit;

    public static void EnsureRuntimeDirectorySecurity()
    {
        try
        {
            var dirInfo = Directory.Exists(RuntimeDir)
                ? new DirectoryInfo(RuntimeDir)
                : Directory.CreateDirectory(RuntimeDir);

            try
            {
                var dSecurity = new System.Security.AccessControl.DirectorySecurity();
                dSecurity.SetAccessRuleProtection(true, false); // Disable inheritance

                // Grant SYSTEM FullControl
                dSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                // Grant Builtin Administrators FullControl
                dSecurity.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None,
                    System.Security.AccessControl.AccessControlType.Allow));

                // Apply on EVERY launch
                dirInfo.SetAccessControl(dSecurity);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[TunRoutingEngine] Runtime ACL notice: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[TunRoutingEngine] EnsureRuntimeDirectorySecurity error: {ex.Message}");
        }
    }

    public static (bool Success, string Error) EnsureCoreFiles(bool forceRecheck = false)
    {
        if (_coreFilesVerified && !forceRecheck && File.Exists(SingBoxExePath) && File.Exists(WintunDllPath))
        {
            return (true, "");
        }

        try
        {
            if (!Directory.Exists(CoreDir))
            {
                Directory.CreateDirectory(CoreDir);
            }

            var assembly = typeof(TunRoutingEngine).Assembly;
            var resources = assembly.GetManifestResourceNames();

            bool foundSingBox = false;
            bool foundWintun = false;

            foreach (var r in resources)
            {
                string fileName = "";
                bool isGz = false;

                if (r.EndsWith("sing-box.gz", StringComparison.OrdinalIgnoreCase))
                {
                    fileName = "sing-box.exe";
                    isGz = true;
                    foundSingBox = true;
                }
                else if (r.EndsWith("sing-box.exe", StringComparison.OrdinalIgnoreCase))
                {
                    fileName = "sing-box.exe";
                    foundSingBox = true;
                }
                else if (r.EndsWith("wintun.dll", StringComparison.OrdinalIgnoreCase))
                {
                    fileName = "wintun.dll";
                    foundWintun = true;
                }

                if (!string.IsNullOrEmpty(fileName))
                {
                    string dest = Path.Combine(CoreDir, fileName);
                    bool needsExtraction = !File.Exists(dest) || new FileInfo(dest).Length < 1000;

                    if (!needsExtraction)
                    {
                        needsExtraction = !IsFileIntegrityValid(assembly, r, dest, isGz);
                    }

                    if (needsExtraction)
                    {
                        bool extracted = ExtractResourceSafely(assembly, r, dest, isGz);
                        if (!extracted)
                        {
                            return (false, $"Не удалось безопасно извлечь компонент {fileName} в каталог {CoreDir}");
                        }
                    }
                }
            }

            // Files earlier versions shipped and nothing uses any more
            foreach (string obsolete in new[] { "ciadpi.exe" })
            {
                try { File.Delete(Path.Combine(CoreDir, obsolete)); } catch { }
            }

            if (!foundSingBox || !File.Exists(SingBoxExePath))
                return (false, $"Файл ядра {SingBoxExePath} отсутствует на диске.");

            if (!foundWintun || !File.Exists(WintunDllPath))
                return (false, $"Файл драйвера {WintunDllPath} отсутствует на диске.");

            _coreFilesVerified = true;
            return (true, "");
        }
        catch (UnauthorizedAccessException uex)
        {
            return (false, $"Отказано в доступе к каталогу {CoreDir}. Требуются права Администратора: {uex.Message}");
        }
        catch (Exception ex)
        {
            return (false, $"Сбой инициализации бинарных компонентов ядра: {ex.Message}");
        }
    }

    private static bool IsFileIntegrityValid(System.Reflection.Assembly assembly, string resourceName, string filePath, bool isGz)
    {
        try
        {
            if (!File.Exists(filePath)) return false;

            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) return false;

            byte[] expectedHash;
            using (var ms = new MemoryStream())
            {
                if (isGz)
                {
                    using var gz = new GZipStream(stream, CompressionMode.Decompress);
                    gz.CopyTo(ms);
                }
                else
                {
                    stream.CopyTo(ms);
                }
                expectedHash = SHA256.HashData(ms.ToArray());
            }

            byte[] diskHash = SHA256.HashData(File.ReadAllBytes(filePath));
            return CryptographicOperations.FixedTimeEquals(expectedHash, diskHash);
        }
        catch
        {
            return false;
        }
    }

    private static bool ExtractResourceSafely(System.Reflection.Assembly assembly, string resourceName, string destPath, bool isGz)
    {
        string tempDest = destPath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) return false;

            byte[] expectedHash;
            using (var ms = new MemoryStream())
            {
                if (isGz)
                {
                    using var gz = new GZipStream(stream, CompressionMode.Decompress);
                    gz.CopyTo(ms);
                }
                else
                {
                    stream.CopyTo(ms);
                }

                byte[] decompressedBytes = ms.ToArray();
                expectedHash = SHA256.HashData(decompressedBytes);

                using (var fs = new FileStream(tempDest, FileMode.Create, FileAccess.Write, FileShare.None, 8192, FileOptions.WriteThrough))
                {
                    fs.Write(decompressedBytes, 0, decompressedBytes.Length);
                    fs.Flush(true);
                }
            }

            // Verify SHA-256 on disk before atomic replacement
            byte[] diskHash = SHA256.HashData(File.ReadAllBytes(tempDest));
            if (CryptographicOperations.FixedTimeEquals(expectedHash, diskHash))
            {
                if (File.Exists(destPath)) File.Delete(destPath);
                File.Move(tempDest, destPath, overwrite: true);
                return true;
            }
            else
            {
                try { if (File.Exists(tempDest)) File.Delete(tempDest); } catch { }
                return false;
            }
        }
        catch
        {
            try { if (File.Exists(tempDest)) File.Delete(tempDest); } catch { }
            return false;
        }
    }

    public static async Task<(bool valid, string error)> ValidateConfigFileWithNativeSingBoxAsync(string configFilePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(SingBoxExePath))
        {
            return (false, $"Файл ядра sing-box.exe не найден в {SingBoxExePath}");
        }

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = SingBoxExePath,
                Arguments = $"check -c \"{configFilePath}\"",
                WorkingDirectory = CoreDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            string stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

            if (process.ExitCode == 0)
            {
                return (true, "");
            }
            else
            {
                string rawErr = !string.IsNullOrWhiteSpace(stderr) ? stderr.Trim() : stdout.Trim();
                return (false, $"Ошибка валидации sing-box (ExitCode {process.ExitCode}): {rawErr}");
            }
        }
        catch (Exception ex)
        {
            return (false, $"Сбой при проверке конфигурации: {ex.Message}");
        }
    }

    public async Task<(bool success, string error)> StartAsync(
        ProxyItem proxy,
        bool bypassTorrents = false,
        bool bypassDomesticRu = false,
        DnsProvider dnsProvider = DnsProvider.Auto,
        bool blockQuic = false,
        bool blockWebRtc = false,
        bool blockTrackers = false,
        Guid sessionId = default,
        CancellationToken cancellationToken = default,
        IReadOnlyCollection<string>? directApps = null,
        DohTarget? preferredDns = null)
    {
        await _syncLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            StopInternal();
            _activeSessionId = sessionId != Guid.Empty ? sessionId : Guid.NewGuid();

            var (coreOk, coreErr) = EnsureCoreFiles();
            if (!coreOk)
            {
                return (false, coreErr);
            }
            EnsureRuntimeDirectorySecurity();

            // 1. Generate unique session secret for Clash API protection
            CurrentClashSecret = Guid.NewGuid().ToString("N");

            // 2. Which DNS server goes first
            List<DnsBenchmarkResult>? autoDnsOrder = null;
            if (preferredDns != null)
            {
                // A server already proven to answer through the VPN (DNS failover): use it as is
                autoDnsOrder = new List<DnsBenchmarkResult> { new(preferredDns.Name, preferredDns.Ip, preferredDns.Path, 0, true) };
                dnsProvider = DnsProvider.Auto; // same config shape: one explicit server first
                OnLog?.Invoke($"DNS: используем {preferredDns.Name} ({preferredDns.Ip}), он отвечает через VPN.");
            }
            else if (dnsProvider == DnsProvider.Auto)
            {
                // First guess only; after the tunnel is up the controller checks it through the VPN
                try
                {
                    autoDnsOrder = await MeasureDnsLatencyAsync(cancellationToken).ConfigureAwait(false);
                    var fastest = autoDnsOrder.FirstOrDefault(d => d.Success);
                    if (fastest != null)
                    {
                        OnLog?.Invoke($"⚡ DNS Auto: Выбран самый быстрый DoH сервер — {fastest.Name} ({fastest.LatencyMs} ms)");
                    }
                }
                catch { }
            }

            // Remember the server the config below puts first: shown as "Работает через" and checked by the controller
            ActiveDnsTarget = ResolvePrimaryDns(dnsProvider, autoDnsOrder);
            ActiveDnsName = ActiveDnsTarget.Name;

            // 3. Generate configuration with optimized DNS provider order and security flags
            var config = GenerateSingBoxConfig(proxy, bypassTorrents, bypassDomesticRu, CurrentClashSecret, dnsProvider, autoDnsOrder, blockQuic, blockWebRtc, blockTrackers, directApps);
            if (directApps is { Count: > 0 })
            {
                OnLog?.Invoke($"Мимо VPN идут программы: {string.Join(", ", directApps)}");
            }
            string configJson = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });

            // Step A: Syntax validation
            try
            {
                using var _ = JsonDocument.Parse(configJson);
            }
            catch (Exception ex)
            {
                return (false, $"Ошибка синтаксиса JSON конфигурации: {ex.Message}");
            }

            // Step B: TOCTOU-Free Atomic Validation Gate: write staging file -> validate -> atomic replace -> execute exact same file
            string stagingConfigPath = Path.Combine(RuntimeDir, $"staging_{_activeSessionId:N}.json");
            try
            {
                byte[] configBytes = Encoding.UTF8.GetBytes(configJson);
                using (var fs = new FileStream(stagingConfigPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    fs.Write(configBytes, 0, configBytes.Length);
                    fs.Flush(true);
                }

                var (isNativeValid, nativeError) = await ValidateConfigFileWithNativeSingBoxAsync(stagingConfigPath, cancellationToken).ConfigureAwait(false);
                if (!isNativeValid)
                {
                    try { if (File.Exists(stagingConfigPath)) File.Delete(stagingConfigPath); } catch { }
                    return (false, nativeError);
                }

                // True Windows Atomic Replacement: MoveFileEx(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
                File.Move(stagingConfigPath, ConfigPath, overwrite: true);
            }
            catch (Exception ex)
            {
                try { if (File.Exists(stagingConfigPath)) File.Delete(stagingConfigPath); } catch { }
                return (false, $"Ошибка подготовки конфигурационного файла: {ex.Message}");
            }

            // 3. Launch sing-box.exe with Windows Job Object and non-blocking I/O
            string lastError = "";

            var startInfo = new ProcessStartInfo
            {
                FileName = SingBoxExePath,
                Arguments = $"run -c \"{ConfigPath}\"",
                WorkingDirectory = CoreDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            _singBoxProcess = new Process { StartInfo = startInfo, EnableRaisingEvents = true };

            _singBoxProcess.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data)) OnLog?.Invoke(e.Data);
            };

            _singBoxProcess.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                {
                    lastError = e.Data;
                    OnLog?.Invoke(e.Data);
                }
            };

            var thisSessionId = _activeSessionId;
            _singBoxProcess.Exited += (_, _) =>
            {
                if (IsActive && _activeSessionId == thisSessionId)
                {
                    IsActive = false;
                    OnUnexpectedExit?.Invoke(thisSessionId);
                }
            };

            _singBoxProcess.Start();

            // Always begin reading immediately to prevent pipe deadlock
            _singBoxProcess.BeginOutputReadLine();
            _singBoxProcess.BeginErrorReadLine();

            // Track with Windows Job Object (Auto-kill when Zion closes)
                        var (jobOk, jobErr) = ProcessJobTracker.TrackProcess(_singBoxProcess);
            if (!jobOk)
            {
                OnLog?.Invoke($"⚠️ Process Supervisor: {jobErr}");
            }

            // 4. Multi-Level Ready-Check Pipeline with Exponential Backoff
            using var clashClient = new ClashApiClient(9090);
            clashClient.SetSecret(CurrentClashSecret);

            bool isCoreReady = false;
            int[] backoffDelays = { 50, 100, 150, 250, 350, 500, 500, 750, 1000 };

            foreach (int delay in backoffDelays)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    StopInternal();
                    return (false, "Запуск отменён пользователем.");
                }

                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);

                if (_singBoxProcess.HasExited)
                {
                    string msg = !string.IsNullOrEmpty(lastError)
                        ? $"sing-box завершил работу: {lastError}"
                        : "Ядро sing-box неожиданно остановилось.";
                    StopInternal();
                    return (false, msg);
                }

                // Check 1: Clash API alive
                bool apiAlive = await clashClient.IsAliveAsync(400);

                // Check 2: Wintun interface UP in network stack
                bool wintunUp = IsWintunInterfaceUp();

                if (apiAlive && wintunUp)
                {
                    isCoreReady = true;
                    break;
                }
            }

            if (!isCoreReady)
            {
                string msg = !string.IsNullOrEmpty(lastError)
                    ? $"sing-box: {lastError}"
                    : "Таймаут инициализации сетевого адаптера Wintun. Убедитесь в наличии прав Администратора.";
                StopInternal();
                return (false, msg);
            }

            // 5. Authoritative Outbound Connectivity Verification via sing-box Clash API (Multi-URL Fallback)
            string[] testEndpoints =
            {
                "https://www.gstatic.com/generate_204",
                "https://cp.cloudflare.com/generate_204",
                "https://www.google.com/generate_204"
            };

            int outboundDelay = -1;
            ClashDelayResult? lastDelayResult = null;

            foreach (var testUrl in testEndpoints)
            {
                if (cancellationToken.IsCancellationRequested) break;

                var delayRes = await clashClient.GetDelayDetailedAsync("proxy-out", testUrl, 3000).ConfigureAwait(false);
                lastDelayResult = delayRes;

                if (delayRes.Success && delayRes.DelayMs > 0)
                {
                    outboundDelay = delayRes.DelayMs;
                    break;
                }

                OnLog?.Invoke($"⚠️ Тест через {testUrl} не прошёл: {delayRes.ErrorMessage}. Пробуем альтернативный эндпоинт...");
            }

            if (outboundDelay < 0)
            {
                StopInternal();
                string errorMsg = "Туннель запущен, но прокси-сервер не отвечает на контрольные сетевые запросы.";
                if (lastDelayResult != null)
                {
                    if (lastDelayResult.StatusCode == 407 || lastDelayResult.ErrorMessage.Contains("407") || lastDelayResult.ErrorMessage.Contains("auth", StringComparison.OrdinalIgnoreCase))
                    {
                        errorMsg = "Ошибка аутентификации прокси-сервера (проверьте логин/пароль или UUID).";
                    }
                    else if (lastDelayResult.StatusCode == 400 || lastDelayResult.StatusCode == 404)
                    {
                        errorMsg = $"Сбой Clash API: {lastDelayResult.ErrorMessage} (HTTP {lastDelayResult.StatusCode})";
                    }
                    else if (!string.IsNullOrWhiteSpace(lastDelayResult.ErrorMessage))
                    {
                        errorMsg = $"Сбой проверки соединения: {lastDelayResult.ErrorMessage}";
                    }
                }
                return (false, errorMsg);
            }

            IsActive = true;
            OnLog?.Invoke($"⚡ Wintun туннель активен! ({outboundDelay} ms) Весь трафик → {proxy.DisplayAddress}");
            return (true, "");
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            StopInternal();
            return (false, "Запрос прав Администратора был отклонён. Для работы сетевого адаптера Wintun требуются права.");
        }
        catch (Exception ex)
        {
            StopInternal();
            return (false, $"Ошибка запуска: {ex.Message}");
        }
        finally
        {
            _syncLock.Release();
        }
    }

    private static bool IsWintunInterfaceUp()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces().Any(ni =>
                (ni.Description.Contains("wintun", StringComparison.OrdinalIgnoreCase) ||
                 ni.Name.Contains("wintun", StringComparison.OrdinalIgnoreCase)) &&
                ni.OperationalStatus == OperationalStatus.Up);
        }
        catch
        {
            return false;
        }
    }

    public void Stop()
    {
        _syncLock.Wait();
        try
        {
            StopInternal();
        }
        finally
        {
            _syncLock.Release();
        }
    }

    private void StopInternal()
    {
        if (!IsActive && _singBoxProcess == null) return;
        IsActive = false;

        try
        {
            if (_singBoxProcess != null && !_singBoxProcess.HasExited)
            {
                _singBoxProcess.Kill(true);
                _singBoxProcess.Dispose();
            }
        }
        catch { }
        _singBoxProcess = null;

        try { if (File.Exists(ConfigPath)) File.Delete(ConfigPath); } catch { }
        OnLog?.Invoke(KillSwitchFirewall.IsArmed
            ? "Туннель остановлен. Kill Switch держит интернет заблокированным."
            : "Туннель остановлен. Прямой интернет восстановлен.");
    }

    public static async Task<List<DnsBenchmarkResult>> MeasureDnsLatencyAsync(CancellationToken cancellationToken = default)
    {
        var candidates = DnsConstants.GetAllRealEntries();

        var tasks = candidates.Select(async c =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp) { NoDelay = true };
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(450); // 450ms fast timeout
                await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(c.PrimaryIp), 443), cts.Token).ConfigureAwait(false);
                sw.Stop();
                return new DnsBenchmarkResult(c.DisplayName, c.PrimaryIp, c.DohPath, (int)sw.ElapsedMilliseconds, true);
            }
            catch
            {
                return new DnsBenchmarkResult(c.DisplayName, c.PrimaryIp, c.DohPath, 9999, false);
            }
        });

        var results = await Task.WhenAll(tasks).ConfigureAwait(false);
        return results.OrderBy(r => r.LatencyMs).ToList();
    }

    public static JsonObject GenerateSingBoxConfig(ProxyItem proxy, bool bypassTorrents = false, bool bypassDomesticRu = false, string clashSecret = "", DnsProvider dnsProvider = DnsProvider.Auto, List<DnsBenchmarkResult>? autoDnsOrder = null, bool blockQuic = false, bool blockWebRtc = false, bool blockTrackers = false, IReadOnlyCollection<string>? directApps = null)
    {
        string host = proxy.CleanHost;
        int port = proxy.Port;

        var routeRules = new JsonArray
        {
            new JsonObject { ["action"] = "sniff" },
            new JsonObject { ["protocol"] = "dns", ["action"] = "hijack-dns" },
            new JsonObject { ["ip_is_private"] = true, ["outbound"] = "direct-out" },
            // Complete IPv6 Leak Protection: reject any IPv6 traffic inside TUN
            new JsonObject { ["ip_version"] = 6, ["action"] = "reject" }
        };

        var dnsRules = new JsonArray
        {
            // Reject ECH DNS Queries (HTTPS RR 65 & SVCB RR 64) to prevent TSPU hardware reset on Cloudflare
            new JsonObject
            {
                ["query_type"] = new JsonArray { "HTTPS", "SVCB" },
                ["action"] = "reject",
                ["method"] = "default"
            }
        };

        // 1. Torrent rules (Strictly by process name and DPI protocol, ZERO keyword collisions with Rutracker!)
        if (bypassTorrents)
        {
            routeRules.Add(new JsonObject
            {
                ["protocol"] = new JsonArray { "bittorrent" },
                ["outbound"] = "direct-out"
            });

            // Matched by a case-insensitive pattern: the core compares process_name exactly,
            // and real files are named e.g. "uTorrent.exe", not "utorrent.exe".
            string torrentPattern = BuildProcessPattern(CreateTorrentClientsArray().Select(n => n!.GetValue<string>()));

            routeRules.Add(new JsonObject
            {
                ["process_path_regex"] = new JsonArray { torrentPattern },
                ["outbound"] = "direct-out"
            });

            dnsRules.Add(new JsonObject
            {
                ["process_path_regex"] = new JsonArray { torrentPattern },
                ["server"] = "direct-dns"
            });
        }

        // 1b. Programs the user excluded from the VPN: everything they open goes out directly.
        //     Placed before the QUIC/WebRTC blocks, which are meant for tunnelled traffic only.
        //     Case-insensitive, like Windows itself ("Steam.exe" and "steam.exe" are the same program).
        var excluded = SanitizeDirectApps(directApps);
        if (excluded.Count > 0)
        {
            string pattern = BuildProcessPattern(excluded);

            routeRules.Add(new JsonObject
            {
                ["process_path_regex"] = new JsonArray { pattern },
                ["outbound"] = "direct-out"
            });

            dnsRules.Add(new JsonObject
            {
                ["process_path_regex"] = new JsonArray { pattern },
                ["server"] = "direct-dns"
            });
        }

        // 2. Comprehensive Domestic Domain Whitelist (Instant local routing for Russian resources)
        if (bypassDomesticRu)
        {
            routeRules.Add(new JsonObject
            {
                ["domain_suffix"] = CreateDomesticDomainsArray(),
                ["outbound"] = "direct-out"
            });

            dnsRules.Add(new JsonObject
            {
                ["domain_suffix"] = CreateDomesticDomainsArray(),
                ["server"] = "direct-dns"
            });
        }

        // 3. Reject QUIC (UDP 443/80) and WebRTC STUN (UDP 19302/3478) for foreign traffic
        if (blockQuic)
        {
            routeRules.Add(new JsonObject
            {
                ["network"] = "udp",
                ["port"] = new JsonArray { 443, 80 },
                ["action"] = "reject"
            });
        }
        if (blockWebRtc)
        {
            routeRules.Add(new JsonObject
            {
                ["network"] = "udp",
                ["port"] = new JsonArray { 19302, 3478, 5349 },
                ["action"] = "reject"
            });
        }

        if (blockTrackers)
        {
            var trackerDomains = new JsonArray
            {
                "google-analytics.com",
                "analytics.google.com",
                "googletagmanager.com",
                "doubleclick.net",
                "adservice.google.com",
                "facebook.net",
                "connect.facebook.net",
                "mc.yandex.ru",
                "top-fwz1.mail.ru",
                "app-measurement.com",
                "crashlytics.com",
                "adjust.com",
                "appsflyer.com"
            };

            routeRules.Add(new JsonObject
            {
                ["domain_suffix"] = trackerDomains,
                ["action"] = "reject"
            });

            dnsRules.Add(new JsonObject
            {
                ["domain_suffix"] = trackerDomains.DeepClone(),
                ["action"] = "reject"
            });
        }

        // 4. Direct Outbound for Proxy Endpoints (Zero DNS deadlocks & Real Direct Physical Latency)
        if (!string.IsNullOrEmpty(host))
        {
            if (IPAddress.TryParse(host, out _))
            {
                routeRules.Add(new JsonObject
                {
                    ["ip_cidr"] = new JsonArray { host.Contains('/') ? host : $"{host}/32" },
                    ["outbound"] = "direct-out"
                });
            }
            else
            {
                dnsRules.Add(new JsonObject
                {
                    ["domain"] = new JsonArray { host },
                    ["server"] = "direct-dns"
                });
                routeRules.Add(new JsonObject
                {
                    ["domain"] = new JsonArray { host },
                    ["outbound"] = "direct-out"
                });
            }
        }

        // 5. Construct DNS servers based on selected DnsProvider
        var dnsServersArray = new JsonArray();
        if (dnsProvider == DnsProvider.Auto)
        {
            if (autoDnsOrder != null && autoDnsOrder.Count > 0)
            {
                int idx = 0;
                foreach (var dns in autoDnsOrder)
                {
                    var matchEntry = DnsConstants.FindByIp(dns.ServerIp); // primary or backup address
                    string tag = idx == 0 ? "remote-dns" : (matchEntry != null ? matchEntry.SingBoxTag : $"remote-dns-{dns.Name.ToLowerInvariant().Replace(" ", "")}");
                    var serverObj = new JsonObject
                    {
                        ["tag"] = tag,
                        ["type"] = "https",
                        ["server"] = dns.ServerIp,
                        ["path"] = dns.Path,
                        ["detour"] = "proxy-out"
                    };
                    if (matchEntry != null)
                    {
                        serverObj["tls"] = new JsonObject
                        {
                            ["enabled"] = true,
                            ["server_name"] = matchEntry.DohHost
                        };
                    }
                    dnsServersArray.Add(serverObj);
                    idx++;
                }
            }
            else
            {
                foreach (var entry in DnsConstants.GetAllRealEntries())
                {
                    dnsServersArray.Add(new JsonObject
                    {
                        ["tag"] = entry.Provider == DnsProvider.Cloudflare ? "remote-dns" : entry.SingBoxTag,
                        ["type"] = "https",
                        ["server"] = entry.PrimaryIp,
                        ["path"] = entry.DohPath,
                        ["tls"] = new JsonObject
                        {
                            ["enabled"] = true,
                            ["server_name"] = entry.DohHost
                        },
                        ["detour"] = "proxy-out"
                    });
                }
            }
        }
        else
        {
            var entry = DnsConstants.GetEntry(dnsProvider);
            dnsServersArray.Add(new JsonObject
            {
                ["tag"] = "remote-dns",
                ["type"] = "https",
                ["server"] = entry.PrimaryIp,
                ["path"] = entry.DohPath,
                ["tls"] = new JsonObject
                {
                    ["enabled"] = true,
                    ["server_name"] = entry.DohHost
                },
                ["detour"] = "proxy-out"
            });

            if (!string.IsNullOrWhiteSpace(entry.SecondaryIp))
            {
                dnsServersArray.Add(new JsonObject
                {
                    ["tag"] = "remote-dns-backup",
                    ["type"] = "https",
                    ["server"] = entry.SecondaryIp,
                    ["path"] = entry.DohPath,
                    ["tls"] = new JsonObject
                    {
                        ["enabled"] = true,
                        ["server_name"] = entry.DohHost
                    },
                    ["detour"] = "proxy-out"
                });
            }
        }

        dnsServersArray.Add(new JsonObject
        {
            ["tag"] = "direct-dns",
            ["type"] = "local"
        });

        var config = new JsonObject
        {
            ["log"] = new JsonObject
            {
                ["level"] = "warn",
                ["timestamp"] = true
            },
            ["experimental"] = new JsonObject
            {
                ["clash_api"] = new JsonObject
                {
                    ["external_controller"] = "127.0.0.1:9090",
                    ["secret"] = clashSecret
                }
            },
            ["dns"] = new JsonObject
            {
                ["servers"] = dnsServersArray,
                ["rules"] = dnsRules,
                ["strategy"] = "ipv4_only"
            },
            // ==============================================================================
            // ARCHITECTURE: IPv6 STRICT SINKHOLE ISOLATION (ZERO-LEAK LEAK-PROOF MODEL)
            // ------------------------------------------------------------------------------
            // 1. Wintun binds a dummy IPv6 ULA address "fdfe:dcba:9876::1/126" with strict_route: true.
            //    This forces Windows OS to claim the default IPv6 route (::/0) into the Wintun adapter.
            // 2. DNS strategy is strictly "ipv4_only" (blocking AAAA lookups at the resolver level).
            // 3. Any rogue/hardcoded IPv6 packets entering Wintun are destroyed by rule:
            //    { "ip_version": 6, "action": "reject" }.
            // 4. External proxy outbounds operate strictly over IPv4 endpoints.
            // 5. This ensures 0% ISP IPv6 leaks while completely isolating user traffic.
            // ==============================================================================
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "tun",
                    ["tag"] = "tun-in",
                    ["interface_name"] = "wintun",
                    ["address"] = new JsonArray { "172.19.0.1/30", "fdfe:dcba:9876::1/126" },
                    ["auto_route"] = true,
                    ["strict_route"] = true,
                    ["stack"] = "mixed",
                    ["endpoint_independent_nat"] = true
                },
                new JsonObject
                {
                    ["type"] = "mixed",
                    ["tag"] = "mixed-in",
                    ["listen"] = "127.0.0.1",
                    ["listen_port"] = 9050
                }
            },
            ["route"] = new JsonObject
            {
                ["auto_detect_interface"] = true,
                ["default_domain_resolver"] = "direct-dns",
                ["rules"] = routeRules,
                ["final"] = "proxy-out"
            }
        };

        JsonObject proxyOutbound;

        if (proxy.Protocol == ProxyProtocol.Vless)
        {
            proxyOutbound = new JsonObject
            {
                ["type"] = "vless",
                ["tag"] = "proxy-out",
                ["server"] = host,
                ["server_port"] = port,
                ["uuid"] = proxy.Uuid
            };

            if (!string.IsNullOrEmpty(proxy.Flow))
            {
                proxyOutbound["flow"] = proxy.Flow;
            }

            var alpnArray = new JsonArray();
            if (!string.IsNullOrEmpty(proxy.Alpn))
            {
                // Links carry a comma list ("h2,http/1.1"); TLS needs each protocol as a separate entry
                foreach (var a in proxy.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    alpnArray.Add(a);
            }
            else if (proxy.TransportType == "ws")
            {
                alpnArray.Add("http/1.1");
            }
            else if (proxy.TransportType == "h2" || proxy.TransportType == "http")
            {
                alpnArray.Add("h2");
            }
            else if (proxy.Security == "reality")
            {
                alpnArray.Add("h2");
                alpnArray.Add("http/1.1");
            }

            if (proxy.Security == "reality")
            {
                var realityTls = new JsonObject
                {
                    ["enabled"] = true,
                    ["server_name"] = !string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host,
                    ["reality"] = new JsonObject
                    {
                        ["enabled"] = true,
                        ["public_key"] = proxy.PublicKey ?? "",
                        ["short_id"] = proxy.ShortId ?? ""
                    },
                    ["utls"] = new JsonObject
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = !string.IsNullOrEmpty(proxy.Fingerprint) ? proxy.Fingerprint : "chrome"
                    }
                };

                if (alpnArray.Count > 0)
                {
                    realityTls["alpn"] = alpnArray;
                }

                proxyOutbound["tls"] = realityTls;
            }
            else if (proxy.Security == "tls")
            {
                var standardTls = new JsonObject
                {
                    ["enabled"] = true,
                    ["server_name"] = !string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host,
                    ["insecure"] = false,
                    // Look like a browser, not a Go program: the plain Go TLS handshake is a known DPI signal.
                    // Same as Reality/Trojan/VMess; the fingerprint from the link wins.
                    ["utls"] = new JsonObject
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = !string.IsNullOrEmpty(proxy.Fingerprint) ? proxy.Fingerprint : "chrome"
                    }
                };

                if (alpnArray.Count > 0)
                {
                    standardTls["alpn"] = alpnArray;
                }

                proxyOutbound["tls"] = standardTls;
            }

            if (proxy.TransportType == "ws")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "ws",
                    ["path"] = !string.IsNullOrEmpty(proxy.WsPath) ? proxy.WsPath : "/",
                    ["headers"] = new JsonObject
                    {
                        ["Host"] = !string.IsNullOrEmpty(proxy.WsHost) ? proxy.WsHost : (!string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host)
                    }
                };
            }
            else if (proxy.TransportType == "grpc")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "grpc",
                    ["service_name"] = !string.IsNullOrEmpty(proxy.GrpcServiceName) ? proxy.GrpcServiceName : ""
                };
            }
            else if (proxy.TransportType == "httpupgrade")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "httpupgrade",
                    ["path"] = !string.IsNullOrEmpty(proxy.WsPath) ? proxy.WsPath : "/",
                    ["host"] = !string.IsNullOrEmpty(proxy.WsHost) ? proxy.WsHost : host
                };
            }
            else if (proxy.TransportType == "h2" || proxy.TransportType == "http")
            {
                var hosts = new JsonArray();
                if (!string.IsNullOrEmpty(proxy.WsHost)) hosts.Add(proxy.WsHost);
                else if (!string.IsNullOrEmpty(proxy.Sni)) hosts.Add(proxy.Sni);
                else hosts.Add(host);

                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "http",
                    ["path"] = !string.IsNullOrEmpty(proxy.WsPath) ? proxy.WsPath : "/",
                    ["host"] = hosts
                };
            }
        }
        else if (proxy.Protocol == ProxyProtocol.Trojan)
        {
            proxyOutbound = new JsonObject
            {
                ["type"] = "trojan",
                ["tag"] = "proxy-out",
                ["server"] = host,
                ["server_port"] = port,
                ["password"] = !string.IsNullOrEmpty(proxy.Password) ? proxy.Password : proxy.Uuid
            };

            var trojanTls = new JsonObject
            {
                ["enabled"] = true,
                ["server_name"] = !string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host,
                ["insecure"] = false,
                ["utls"] = new JsonObject
                {
                    ["enabled"] = true,
                    ["fingerprint"] = !string.IsNullOrEmpty(proxy.Fingerprint) ? proxy.Fingerprint : "chrome"
                }
            };

            var alpnArray = new JsonArray();
            if (!string.IsNullOrEmpty(proxy.Alpn))
            {
                foreach (var a in proxy.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    alpnArray.Add(a);
            }
            else
            {
                alpnArray.Add("h2");
                alpnArray.Add("http/1.1");
            }
            trojanTls["alpn"] = alpnArray;
            proxyOutbound["tls"] = trojanTls;

            if (proxy.TransportType == "ws")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "ws",
                    ["path"] = !string.IsNullOrEmpty(proxy.WsPath) ? proxy.WsPath : "/",
                    ["headers"] = new JsonObject
                    {
                        ["Host"] = !string.IsNullOrEmpty(proxy.WsHost) ? proxy.WsHost : (!string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host)
                    }
                };
            }
            else if (proxy.TransportType == "grpc")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "grpc",
                    ["service_name"] = !string.IsNullOrEmpty(proxy.GrpcServiceName) ? proxy.GrpcServiceName : ""
                };
            }
        }
        else if (proxy.Protocol == ProxyProtocol.Shadowsocks)
        {
            string method = !string.IsNullOrEmpty(proxy.Security) && proxy.Security != "none" ? proxy.Security : "aes-256-gcm";
            string pass = !string.IsNullOrEmpty(proxy.Password) ? proxy.Password : proxy.Uuid;
            proxyOutbound = new JsonObject
            {
                ["type"] = "shadowsocks",
                ["tag"] = "proxy-out",
                ["server"] = host,
                ["server_port"] = port,
                ["method"] = method,
                ["password"] = pass
            };
        }
        else if (proxy.Protocol == ProxyProtocol.Vmess)
        {
            string security = !string.IsNullOrEmpty(proxy.Security) && proxy.Security != "tls" ? proxy.Security : "auto";
            proxyOutbound = new JsonObject
            {
                ["type"] = "vmess",
                ["tag"] = "proxy-out",
                ["server"] = host,
                ["server_port"] = port,
                ["uuid"] = proxy.Uuid,
                ["alter_id"] = 0,
                ["security"] = security
            };

            if (proxy.Security == "tls" || !string.IsNullOrEmpty(proxy.Sni))
            {
                var vmessTls = new JsonObject
                {
                    ["enabled"] = true,
                    ["server_name"] = !string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host,
                    ["insecure"] = false,
                    ["utls"] = new JsonObject
                    {
                        ["enabled"] = true,
                        ["fingerprint"] = !string.IsNullOrEmpty(proxy.Fingerprint) ? proxy.Fingerprint : "chrome"
                    }
                };
                if (!string.IsNullOrEmpty(proxy.Alpn))
                {
                    var alpnArray = new JsonArray();
                    foreach (var a in proxy.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        alpnArray.Add(a);
                    vmessTls["alpn"] = alpnArray;
                }
                proxyOutbound["tls"] = vmessTls;
            }

            if (proxy.TransportType == "ws")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "ws",
                    ["path"] = !string.IsNullOrEmpty(proxy.WsPath) ? proxy.WsPath : "/",
                    ["headers"] = new JsonObject
                    {
                        ["Host"] = !string.IsNullOrEmpty(proxy.WsHost) ? proxy.WsHost : (!string.IsNullOrEmpty(proxy.Sni) ? proxy.Sni : host)
                    }
                };
            }
            else if (proxy.TransportType == "grpc")
            {
                proxyOutbound["transport"] = new JsonObject
                {
                    ["type"] = "grpc",
                    ["service_name"] = !string.IsNullOrEmpty(proxy.GrpcServiceName) ? proxy.GrpcServiceName : ""
                };
            }
        }
        else if (proxy.Protocol == ProxyProtocol.Socks5)
        {
            proxyOutbound = new JsonObject
            {
                ["type"] = "socks",
                ["tag"] = "proxy-out",
                ["server"] = host,
                ["server_port"] = port
            };
            if (proxy.HasAuth)
            {
                proxyOutbound["username"] = proxy.Username;
                proxyOutbound["password"] = proxy.Password;
            }
        }
        else
        {
            proxyOutbound = new JsonObject
            {
                ["type"] = "http",
                ["tag"] = "proxy-out",
                ["server"] = host,
                ["server_port"] = port
            };
            if (proxy.HasAuth)
            {
                proxyOutbound["username"] = proxy.Username;
                proxyOutbound["password"] = proxy.Password;
            }
        }

        proxyOutbound["tcp_keep_alive"] = "15s";
        proxyOutbound["tcp_keep_alive_interval"] = "15s";

        config["outbounds"] = new JsonArray
        {
            proxyOutbound,
            new JsonObject { ["type"] = "direct", ["tag"] = "direct-out" }
        };

        return config;
    }

    /// <summary>
    /// Clean list of exe names for the bypass rule: no blanks, no duplicates, and never Zion or the core
    /// itself (excluding those would make no sense and could break the tunnel).
    /// </summary>
    public static List<string> SanitizeDirectApps(IEnumerable<string>? names)
    {
        var result = new List<string>();
        if (names == null) return result;

        string self = Path.GetFileName(Environment.ProcessPath ?? "") ?? "";
        foreach (string raw in names)
        {
            string n = Path.GetFileName((raw ?? "").Trim());
            if (n.Length == 0 || !n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (n.Equals("sing-box.exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (n.Equals(self, StringComparison.OrdinalIgnoreCase) ||
                System.Text.RegularExpressions.Regex.IsMatch(n, @"^Zion(_v\d+)?\.exe$", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) continue;
            if (result.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
            result.Add(n);
        }
        return result;
    }

    /// <summary>
    /// One case-insensitive pattern matching any of the given file names at the end of a process path,
    /// e.g. (?i)(^|[\\/])(steam\.exe|cs2\.exe)$. Written for the core's RE2 regex engine.
    /// </summary>
    public static string BuildProcessPattern(IEnumerable<string> fileNames)
    {
        static string Escape(string s)
        {
            var sb = new System.Text.StringBuilder(s.Length + 8);
            foreach (char c in s)
            {
                if (@"\.+*?()|[]{}^$".IndexOf(c) >= 0) sb.Append('\\');
                sb.Append(c);
            }
            return sb.ToString();
        }

        var parts = fileNames.Where(n => !string.IsNullOrWhiteSpace(n))
                             .Select(n => Escape(n.Trim()))
                             .Distinct(StringComparer.OrdinalIgnoreCase);
        return $@"(?i)(^|[\\/])({string.Join("|", parts)})$";
    }

    private static JsonArray CreateTorrentClientsArray() => new()
    {
        "qbittorrent.exe", "qbittorrent",
        "utorrent.exe", "utorrent", "utorrentie.exe",
        "bittorrent.exe", "bittorrent",
        "transmission-qt.exe", "transmission-daemon.exe",
        "deluge.exe", "tixati.exe", "biglybt.exe",
        "picotorrent.exe", "webtorrent.exe", "motrix.exe",
        "fdm.exe", "aria2c.exe"
    };

    private static JsonArray CreateDomesticDomainsArray() => new()
    {
        ".ru", "ru", ".xn--p1ai", "xn--p1ai", ".рф", "рф", ".su", "su",
        "osnova.io", "soccer365.me", "s365.me", "soccer365.ru",
        "pep.link", "pepper.com", "pepper.ru",
        "habr.com", "habrastorage.org", "4pda.to", "4pda.ws",
        "championat.com", "sports.ru", "s5o.ru",
        "userapi.com", "vk.me", "vkuser.net", "vks.im", "vk.com", "vk.ru",
        "yastatic.net", "yastat.net", "yandex.ru", "yandex.net", "ya.ru", "dzen.ru",
        "kinopoisk.ru", "kinopoisk.com",
        "ozon.ru", "ozonusercontent.com", "wildberries.ru", "wb.ru", "wbstatic.net",
        "avito.ru", "avito.st", "pikabu.ru", "rutube.ru", "rutubelist.ru",
        "mail.ru", "rambler.ru", "2gis.ru", "2gis.com", "rzd.ru",
        "gosuslugi.ru", "nalog.gov.ru",
        "sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "vtb.ru", "alfabank.ru",
        "auto.ru", "cian.ru", "domclick.ru", "megamarket.ru", "dns-shop.ru", "citilink.ru"
    };
}

