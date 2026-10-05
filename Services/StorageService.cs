using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Zion.Models;

namespace Zion.Services;

public class AppConfig
{
    public int SchemaVersion { get; set; } = 3;
    public List<ProxyItem> Proxies { get; set; } = new();
    public Guid? SelectedProxyId { get; set; }
    public bool AutoConnectOnStartup { get; set; } = false;
    public bool BypassTorrents { get; set; } = false;
    public bool BypassDomesticRu { get; set; } = false;

    /// <summary>All subscription links. Any number; each owns the servers that carry its URL.</summary>
    public List<SubscriptionEntry> Subscriptions { get; set; } = new();

    /// <summary>Up to schema 2 only one link was kept here. Read once by the migration, then left empty.</summary>
    public string SubscriptionUrl { get; set; } = "";
    public DateTime? LastSubscriptionUpdate { get; set; }

    public bool AutoUpdateSubscription { get; set; } = false;

    /// <summary>Programs whose traffic always bypasses the VPN.</summary>
    public List<ExcludedApp> DirectApps { get; set; } = new();

    /// <summary>Sites (with their subdomains) that always bypass the VPN, e.g. "kinopoisk.ru".</summary>
    public List<string> DirectSites { get; set; } = new();
    public DnsProvider SelectedDns { get; set; } = DnsProvider.Auto;
    public bool AutoFailover { get; set; } = false;
    public bool AutoServerFailover { get => AutoFailover; set => AutoFailover = value; }
    public bool BlockQuic { get; set; } = false;
    public bool BlockWebRtc { get; set; } = false;
    public bool BlockTrackers { get; set; } = false;
    public bool KillSwitch { get; set; } = false;
}


public static class ConfigStore
{
    private static readonly object _lock = new();
    private static AppConfig? _current;

    public static bool IsTestMode { get; set; } = false;

    private static readonly string ConfigDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "Zion"
    );
    private static readonly string ConfigPath = Path.Combine(ConfigDir, "config.dat");
    private static readonly string TempConfigPath = Path.Combine(ConfigDir, "config.dat.tmp");
    private static readonly string LegacyJsonPath = Path.Combine(ConfigDir, "config.json");

    private static readonly byte[] LegacyAesKey = SHA256.HashData(Encoding.UTF8.GetBytes("Zion_ProxyMasterLauncher_MasterKey_2026"));

    public static AppConfig Current
    {
        get
        {
            if (_current == null)
            {
                lock (_lock)
                {
                    _current ??= LoadInternal();
                }
            }
            return _current;
        }
    }

    private static AppConfig LoadInternal()
    {
        try
        {
            EnsureDirectories();

            AppConfig? config = null;
            if (File.Exists(ConfigPath))
            {
                config = TryReadEncryptedFile(ConfigPath);
            }
            else if (File.Exists(LegacyJsonPath))
            {
                config = TryReadJsonFile(LegacyJsonPath);
                if (config != null)
                {
                    SaveAtomicInternal(config);
                    try { File.Delete(LegacyJsonPath); } catch { }
                }
            }

            if (config != null)
            {
                bool modified = false;
                foreach (var p in config.Proxies)
                {
                    string prevCountry = p.Country;
                    p.AutoEnrichCountryIfMissing();
                    if (p.Country != prevCountry)
                        modified = true;
                }
                if (modified)
                {
                    SaveAtomicInternal(config);
                }
                return config;
            }
        }
        catch { }

        return new AppConfig();
    }

    public static void Save(AppConfig? config = null)
    {
        lock (_lock)
        {
            var target = config ?? Current;
            _current = target;
            SaveAtomicInternal(target);
        }
    }

    private static void SaveAtomicInternal(AppConfig config)
    {
        if (IsTestMode) return;

        try
        {
            EnsureDirectories();

            string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
            byte[] plainBytes = Encoding.UTF8.GetBytes(json);

            // Windows DPAPI Protection (CurrentUser scope)
            byte[] encryptedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.CurrentUser);

            // 1. Write to temporary file with explicit write-through flush
            using (var fs = new FileStream(TempConfigPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                fs.Write(encryptedBytes, 0, encryptedBytes.Length);
                fs.Flush(true);
            }

            // 2. Atomic replacement of main config file
            if (File.Exists(TempConfigPath))
            {
                File.Move(TempConfigPath, ConfigPath, overwrite: true);
            }

            try { if (File.Exists(LegacyJsonPath)) File.Delete(LegacyJsonPath); } catch { }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ConfigStore] Error saving config: {ex.Message}");
        }
    }

    public static void EnsureDirectories()
    {
        try
        {
            if (!Directory.Exists(ConfigDir))
            {
                Directory.CreateDirectory(ConfigDir);
            }
        }
        catch { }
    }

    private static AppConfig? TryReadEncryptedFile(string path)
    {
        try
        {
            byte[] fileBytes = File.ReadAllBytes(path);
            if (fileBytes.Length == 0) return null;

            string json = "";
            bool needsReEncrypt = false;

            // 1. Primary: Windows DPAPI (CurrentUser)
            try
            {
                byte[] decrypted = ProtectedData.Unprotect(fileBytes, null, DataProtectionScope.CurrentUser);
                json = Encoding.UTF8.GetString(decrypted);
            }
            catch
            {
                // 2. Controlled Legacy AES migration only
                try
                {
                    byte[] decrypted = DecryptLegacyAes(fileBytes);
                    json = Encoding.UTF8.GetString(decrypted);
                    needsReEncrypt = true;
                }
                catch
                {
                    // Fail-Closed: DO NOT fall back to plaintext!
                    // Backup corrupted file for safety
                    try
                    {
                        string backupPath = Path.Combine(ConfigDir, $"config.dat.corrupted_{DateTime.UtcNow:yyyyMMdd_HHmmss}.bak");
                        File.Copy(path, backupPath, true);
                        System.Diagnostics.Debug.WriteLine($"[ConfigStore] Corrupted config preserved at {backupPath}");
                    }
                    catch { }

                    return null;
                }
            }

            if (!string.IsNullOrWhiteSpace(json))
            {
                var config = JsonSerializer.Deserialize<AppConfig>(json);
                if (config != null)
                {
                    var migrated = MigrateIfNeeded(config);
                    if (needsReEncrypt)
                    {
                        SaveAtomicInternal(migrated);
                    }
                    return migrated;
                }
            }
        }
        catch { }

        return null;
    }

    private static AppConfig? TryReadJsonFile(string path)
    {
        try
        {
            string json = File.ReadAllText(path);
            var config = JsonSerializer.Deserialize<AppConfig>(json);
            if (config != null)
            {
                return MigrateIfNeeded(config);
            }
        }
        catch { }

        return null;
    }

    private static AppConfig MigrateIfNeeded(AppConfig config)
    {
        bool wasMigrated = false;

        // Schema 1 (or unversioned legacy) -> Schema 2
        if (config.SchemaVersion < 2)
        {
            foreach (var p in config.Proxies)
            {
                if (!string.IsNullOrWhiteSpace(p.Country))
                    p.Country = GeoIpService.NormalizeLocation(p.Country);

                if (p.IsFromSubscription)
                    p.EnsureDeterministicId();
            }

            if (config.SelectedProxyId == null && config.Proxies.Count > 0)
            {
                config.SelectedProxyId = config.Proxies[0].Id;
            }

            config.SchemaVersion = 2;
            wasMigrated = true;
        }

        // Schema 2 -> 3: a single subscription link becomes the first entry of a list
        if (config.SchemaVersion < 3 || !string.IsNullOrWhiteSpace(config.SubscriptionUrl))
        {
            MigrateSingleSubscription(config);
            config.SchemaVersion = 3;
            wasMigrated = true;
        }

        if (wasMigrated)
        {
            SaveAtomicInternal(config);
        }

        return config;
    }

    /// <summary>
    /// Moves the old single SubscriptionUrl into the Subscriptions list and gives subscription servers
    /// that were saved without a link to that subscription. Safe to run more than once.
    /// </summary>
    public static void MigrateSingleSubscription(AppConfig config)
    {
        string legacyUrl = config.SubscriptionUrl?.Trim() ?? "";
        if (legacyUrl.Length > 0 && !config.Subscriptions.Any(s => SubscriptionService.SameUrl(s.Url, legacyUrl)))
        {
            config.Subscriptions.Add(new SubscriptionEntry
            {
                Url = legacyUrl,
                LastUpdate = config.LastSubscriptionUpdate,
                LastAttempt = config.LastSubscriptionUpdate,
                AddedAt = config.LastSubscriptionUpdate ?? DateTime.Now
            });
        }

        if (legacyUrl.Length > 0)
        {
            foreach (var p in config.Proxies)
            {
                if (p.IsFromSubscription && string.IsNullOrWhiteSpace(p.SubscriptionUrl))
                    p.SubscriptionUrl = legacyUrl;
            }
        }

        config.SubscriptionUrl = "";
        config.LastSubscriptionUpdate = null;
    }

    private static byte[] DecryptLegacyAes(byte[] encryptedBytes)
    {
        if (encryptedBytes.Length < 16) throw new InvalidOperationException("Encrypted data is too short.");

        using var aes = Aes.Create();
        aes.Key = LegacyAesKey;

        byte[] iv = new byte[16];
        Buffer.BlockCopy(encryptedBytes, 0, iv, 0, 16);
        aes.IV = iv;

        using var ms = new MemoryStream();
        using (var cs = new CryptoStream(new MemoryStream(encryptedBytes, 16, encryptedBytes.Length - 16), aes.CreateDecryptor(), CryptoStreamMode.Read))
        {
            cs.CopyTo(ms);
        }

        return ms.ToArray();
    }
}
