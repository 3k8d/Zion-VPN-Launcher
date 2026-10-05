using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Zion.Models;
using Zion.Services;
using Zion.ViewModels;

namespace Zion.Tests;

class Program
{
    static int _passed = 0;
    static int _failed = 0;

    static void Assert(bool condition, string testName, string errorMsg = "")
    {
        if (condition)
        {
            Console.WriteLine($"[PASS] {testName}");
            _passed++;
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[FAIL] {testName} - {errorMsg}");
            Console.ResetColor();
            _failed++;
        }
    }

    static void Main(string[] args)
    {
        ConfigStore.IsTestMode = true;
        Console.WriteLine("=== ZION WINDOWS PORTABLE PARITY VERIFICATION SUITE ===");

        TestHwidGeneration();
        TestProxyParsing();
        TestShareableUrlRoundtrip();
        TestFingerprintDeterministic();
        TestSubscriptionDetection();
        TestThreeTierCascadeMerge();
        TestSingBoxConfigGenerationAndNativeValidation();
        TestBypassRoutingTogglesAndKeepAlive();
        TestWsHostAndAlterIdPreservation();
        TestDnsConstantsAndProviders();
        TestSecurityTogglesInConfig();
        TestAutoStartAndFailover();
        TestFormatTrafficAndViewModel();
        TestCountryResolutionAndEmojiFlags();
        TestFailoverPlanner();
        TestKillSwitchInterop();
        TestDirectDns();
        TestProxiedTrafficCounter();
        TestMultipleSubscriptions();
        TestExcludedPrograms();
        TestVlessTlsHandshake();
        TestDnsFailover();
        TestDirectSites();
        TestFavorites();
        TestServerListSections();
        TestQuicProtocols();
        TestLocalEndpoints();
        TestServerChecker();

        Console.WriteLine("\n=======================================================");
        Console.WriteLine($"RESULTS: {_passed} Passed, {_failed} Failed");
        if (_failed > 0)
        {
            Environment.Exit(1);
        }
        Console.WriteLine("ALL END-TO-END PARITY CHECKS PASSED SUCCESSFULLY!");
    }

    static void TestHwidGeneration()
    {
        Console.WriteLine("\n--- 1. HWID Generation & Formatting ---");
        string hwid1 = ProxyParser.GetOrGenerateDeviceHwid();
        string hwid2 = ProxyParser.GetOrGenerateDeviceHwid();

        Assert(!string.IsNullOrWhiteSpace(hwid1), "HWID is non-empty");
        Assert(hwid1.Length == 32, $"HWID is 32-char MD5 hex (length: {hwid1.Length})");
        Assert(hwid1.All(c => "0123456789abcdefABCDEF".Contains(c)), "HWID is valid hex string");
        Assert(hwid1 == hwid2, "HWID is deterministic and stable across calls");
    }

    static void TestProxyParsing()
    {
        Console.WriteLine("\n--- 2. Multi-Protocol Proxy Parsing ---");

        // 2.1 VLESS Reality
        string vlessUrl = "vless://11111111-2222-3333-4444-555555555555@95.163.22.10:443?security=reality&sni=google.com&fp=chrome&pbk=1234567890abcdef1234567890abcdef1234567890a&sid=abcd1234&type=tcp#VLESS-Reality";
        var vless = ProxyParser.ParseSingle(vlessUrl);
        Assert(vless != null, "Parse VLESS Reality");
        Assert(vless?.Protocol == ProxyProtocol.Vless, "VLESS Protocol Type");
        Assert(vless?.Host == "95.163.22.10" && vless?.Port == 443, "VLESS Host & Port");
        Assert(vless?.Security == "reality", "VLESS Security reality");
        Assert(vless?.PublicKey == "1234567890abcdef1234567890abcdef1234567890a", "VLESS PublicKey");
        Assert(vless?.ShortId == "abcd1234", "VLESS ShortId");
        Assert(vless?.Name == "VLESS-Reality", "VLESS Name");

        // 2.2 Trojan
        string trojanUrl = "trojan://secretpassword@95.163.22.11:443?sni=trojan.example.com&type=ws&path=%2Fws#Trojan-WS";
        var trojan = ProxyParser.ParseSingle(trojanUrl);
        Assert(trojan != null, "Parse Trojan");
        Assert(trojan?.Protocol == ProxyProtocol.Trojan, "Trojan Protocol Type");
        Assert(trojan?.Password == "secretpassword", "Trojan Password");
        Assert(trojan?.Sni == "trojan.example.com", "Trojan SNI");
        Assert(trojan?.TransportType == "ws", "Trojan WS Transport");
        Assert(trojan?.WsPath == "/ws", "Trojan WS Path");

        // 2.3 Shadowsocks SIP002
        string ssSipUrl = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@95.163.22.12:8388#SS-SIP002";
        var ss = ProxyParser.ParseSingle(ssSipUrl);
        Assert(ss != null, "Parse Shadowsocks SIP002");
        Assert(ss?.Protocol == ProxyProtocol.Shadowsocks, "SS Protocol Type");
        Assert(ss?.Host == "95.163.22.12" && ss?.Port == 8388, "SS Host & Port");
        Assert(ss?.Security == "aes-256-gcm", "SS Encryption Method");
        Assert(ss?.Password == "password", "SS Password");

        // 2.4 Shadowsocks Legacy Base64
        string ssLegacyUrl = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTguMTU2LjIwLjEwOjgzODg=#SS-Legacy";
        var ssLeg = ProxyParser.ParseSingle(ssLegacyUrl);
        Assert(ssLeg != null, "Parse Shadowsocks Legacy Base64");
        Assert(ssLeg?.Host == "18.156.20.10" && ssLeg?.Port == 8388, "SS Legacy Host & Port");
        Assert(ssLeg?.Security == "aes-256-gcm" && ssLeg?.Password == "password", "SS Legacy Method & Pass");

        // 2.5 VMess Base64 JSON
        string vmessJson = "{\"v\":\"2\",\"ps\":\"VMess-WS\",\"add\":\"95.163.22.13\",\"port\":443,\"id\":\"11111111-2222-3333-4444-555555555555\",\"aid\":0,\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"vmess.example.com\",\"path\":\"/vmess\",\"tls\":\"tls\",\"sni\":\"vmess.example.com\",\"alpn\":\"h2,http/1.1\"}";
        string vmessBase64 = "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessJson));
        var vmess = ProxyParser.ParseSingle(vmessBase64);
        Assert(vmess != null, "Parse VMess Base64 JSON");
        Assert(vmess?.Protocol == ProxyProtocol.Vmess, "VMess Protocol Type");
        Assert(vmess?.Host == "95.163.22.13" && vmess?.Port == 443, "VMess Host & Port");
        Assert(vmess?.Uuid == "11111111-2222-3333-4444-555555555555", "VMess UUID");
        Assert(vmess?.Security == "tls", "VMess Security TLS");
        Assert(vmess?.TransportType == "ws" && vmess?.WsPath == "/vmess", "VMess WS Transport & Path");
        Assert(vmess?.Sni == "vmess.example.com", "VMess SNI");

        // 2.6 SOCKS5 & HTTP
        var socks = ProxyParser.ParseSingle("socks5://testuser:testpass@95.163.22.14:1080#MySocks");
        Assert(socks != null && socks.Protocol == ProxyProtocol.Socks5 && socks.Username == "testuser" && socks.Password == "testpass", "Parse SOCKS5");

        var http = ProxyParser.ParseSingle("http://httpuser:httppass@95.163.22.15:8080#MyHttp");
        Assert(http != null && http.Protocol == ProxyProtocol.Http && http.Username == "httpuser" && http.Password == "httppass", "Parse HTTP");
    }

    static void TestShareableUrlRoundtrip()
    {
        Console.WriteLine("\n--- 3. ToShareableUrl Round-Trip Validation ---");

        var p1 = new ProxyItem
        {
            Protocol = ProxyProtocol.Vless,
            Name = "Server-Vless",
            Host = "1.2.3.4",
            Port = 443,
            Uuid = "11111111-2222-3333-4444-555555555555",
            Security = "reality",
            Fingerprint = "chrome",
            PublicKey = "abcdef123456",
            ShortId = "1234",
            Sni = "yahoo.com"
        };
        string url1 = p1.ToShareableUrl();
        var re1 = ProxyParser.ParseSingle(url1);
        Assert(re1 != null && re1.Host == p1.Host && re1.Port == p1.Port && re1.Uuid == p1.Uuid && re1.PublicKey == p1.PublicKey, "VLESS ToShareableUrl Roundtrip");

        var p2 = new ProxyItem
        {
            Protocol = ProxyProtocol.Trojan,
            Name = "Server-Trojan",
            Host = "2.3.4.5",
            Port = 8443,
            Password = "trojanpassword",
            Sni = "trojan.test",
            TransportType = "ws",
            WsPath = "/path"
        };
        string url2 = p2.ToShareableUrl();
        var re2 = ProxyParser.ParseSingle(url2);
        Assert(re2 != null && re2.Host == p2.Host && re2.Port == p2.Port && re2.Password == p2.Password && re2.Sni == p2.Sni, "Trojan ToShareableUrl Roundtrip");

        var p3 = new ProxyItem
        {
            Protocol = ProxyProtocol.Shadowsocks,
            Name = "Server-SS",
            Host = "3.4.5.6",
            Port = 8388,
            Password = "sspassword",
            Security = "aes-256-gcm"
        };
        string url3 = p3.ToShareableUrl();
        var re3 = ProxyParser.ParseSingle(url3);
        Assert(re3 != null && re3.Host == p3.Host && re3.Port == p3.Port && re3.Password == p3.Password && re3.Security == p3.Security, "Shadowsocks ToShareableUrl Roundtrip");

        var p4 = new ProxyItem
        {
            Protocol = ProxyProtocol.Vmess,
            Name = "Server-VMess",
            Host = "4.5.6.7",
            Port = 443,
            Uuid = "11111111-2222-3333-4444-555555555555",
            Security = "auto",
            TransportType = "ws",
            WsPath = "/vmessws",
            Sni = "vmess.sni"
        };
        string url4 = p4.ToShareableUrl();
        var re4 = ProxyParser.ParseSingle(url4);
        Assert(re4 != null && re4.Host == p4.Host && re4.Port == p4.Port && re4.Uuid == p4.Uuid && re4.WsPath == p4.WsPath, "VMess ToShareableUrl Roundtrip");
    }

    static void TestFingerprintDeterministic()
    {
        Console.WriteLine("\n--- 4. Deterministic Fingerprint Generation ---");
        var a = new ProxyItem { Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Vless, Uuid = "u1" };
        var b = new ProxyItem { Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Vless, Uuid = "u1" };
        var c = new ProxyItem { Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Vless, Uuid = "u2" };

        Assert(a.GetFingerprint() == b.GetFingerprint(), "Identical configs produce identical fingerprint");
        Assert(a.GetFingerprint() != c.GetFingerprint(), "Different configs produce distinct fingerprints");
    }

    static void TestSubscriptionDetection()
    {
        Console.WriteLine("\n--- 5. Subscription URL Detection & Deep-Link Extraction ---");
        Assert(ProxyParser.IsSubscriptionUrl("https://my-proxy-provider.com/sub/token123"), "HTTPS URL is recognized as subscription");
        Assert(ProxyParser.IsSubscriptionUrl("http://my-proxy-provider.com/sub/token123"), "HTTP URL is recognized as subscription");
        Assert(!ProxyParser.IsSubscriptionUrl("vless://user@host:443?security=reality"), "VLESS URL is NOT subscription");
        Assert(!ProxyParser.IsSubscriptionUrl("trojan://pass@host:443"), "Trojan URL is NOT subscription");
        Assert(!ProxyParser.IsSubscriptionUrl("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@host:8388"), "SS URL is NOT subscription");
        Assert(!ProxyParser.IsSubscriptionUrl("vmess://eyJhZGQiOiIxLjIuMy40In0="), "VMess URL is NOT subscription");
        Assert(!ProxyParser.IsSubscriptionUrl("http://user:pass@1.2.3.4:8080"), "Single HTTP proxy with credentials is NOT subscription");

        // 5.1 Deep-link extraction tests
        string happRaw = "happ://add/https://sub.example.net/TestToken123";
        string happExpected = "https://sub.example.net/TestToken123";
        Assert(ProxyParser.ExtractActualSubscriptionUrl(happRaw) == happExpected, "Extract from happ://add/ deep link");
        Assert(ProxyParser.IsSubscriptionUrl(happRaw), "happ://add/ is recognized as subscription");

        string happEncoded = "happ://add/https%3A%2F%2Fsub.example.net%2FTestToken123";
        Assert(ProxyParser.ExtractActualSubscriptionUrl(happEncoded) == happExpected, "Extract from URL-encoded happ:// link");
        Assert(ProxyParser.IsSubscriptionUrl(happEncoded), "URL-encoded happ link is recognized as subscription");

        string v2rayngLink = "v2rayng://install-sub?url=https%3A%2F%2Fsub.example.net%2FTestToken123&name=Example";
        Assert(ProxyParser.ExtractActualSubscriptionUrl(v2rayngLink) == happExpected, "Extract from v2rayng://install-sub?url= parameter");
        Assert(ProxyParser.IsSubscriptionUrl(v2rayngLink), "v2rayng:// link is recognized as subscription");

        string subB64Link = "sub://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(happExpected));
        Assert(ProxyParser.ExtractActualSubscriptionUrl(subB64Link) == happExpected, "Extract from sub:// base64 link");
        Assert(ProxyParser.IsSubscriptionUrl(subB64Link), "sub:// link is recognized as subscription");

        Assert(ProxyParser.ExtractActualSubscriptionUrl(happExpected) == happExpected, "Direct HTTPS subscription link preserved");
        Assert(ProxyParser.IsSubscriptionUrl(happExpected), "Direct HTTPS subscription link recognized as subscription");

        // 5.2 Sing-box JSON subscription parsing test
        string singboxJson = """
        {
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "Happ-Node-1",
                    "server": "95.163.22.10",
                    "server_port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "tls": {
                        "enabled": true,
                        "server_name": "gateway.icloud.com",
                        "reality": {
                            "enabled": true,
                            "public_key": "pbk12345",
                            "short_id": "sid12345"
                        }
                    }
                }
            ]
        }
        """;
        var parsedJsonProxies = ProxyParser.ParseBulk(singboxJson);
        Assert(parsedJsonProxies.Count == 1, "SingBox JSON subscription parsed 1 outbound");
        Assert(parsedJsonProxies[0].Protocol == ProxyProtocol.Vless, "Parsed outbound protocol is Vless");
        Assert(parsedJsonProxies[0].Host == "95.163.22.10", "Parsed outbound host matches");
        Assert(parsedJsonProxies[0].Security == "reality", "Parsed outbound security is reality");
        Assert(parsedJsonProxies[0].PublicKey == "pbk12345", "Parsed outbound public key matches");
        Assert(parsedJsonProxies[0].Name == "Happ-Node-1", "Parsed outbound name tag matches");

        // 5.3 Cloudflare Relay & AutoUpdateSubscription checks
        Assert(!string.IsNullOrEmpty(ProxyParser.CloudflareRelayUrl) && ProxyParser.CloudflareRelayUrl.StartsWith("https://") && ProxyParser.CloudflareRelayUrl.Contains("workers.dev/?url="), "CloudflareRelayUrl is configured with valid HTTPS endpoint");
        Assert(!new AppConfig().AutoUpdateSubscription, "AutoUpdateSubscription default is FALSE on Windows (no background sync)");

        // 5.4 When the automatic daily refresh is due (per subscription)
        var now = new DateTime(2026, 10, 1, 12, 0, 0);
        var sub = new AppConfig { AutoUpdateSubscription = true };
        var entry = new SubscriptionEntry { Url = "https://sub.example.com/abc" };
        sub.Subscriptions.Add(entry);
        Assert(SubscriptionService.IsAutoUpdateDue(sub, entry, now), "Auto-update: never updated -> due");
        entry.LastUpdate = now.AddHours(-3);
        Assert(!SubscriptionService.IsAutoUpdateDue(sub, entry, now), "Auto-update: updated 3 h ago -> not due");
        entry.LastUpdate = now.AddHours(-24);
        Assert(SubscriptionService.IsAutoUpdateDue(sub, entry, now), "Auto-update: updated a day ago -> due");
        entry.LastUpdate = now.AddDays(3);
        Assert(SubscriptionService.IsAutoUpdateDue(sub, entry, now), "Auto-update: date in the future (clock moved back) -> due");
        entry.LastUpdate = null;
        sub.AutoUpdateSubscription = false;
        Assert(!SubscriptionService.IsAutoUpdateDue(sub, entry, now), "Auto-update: switched off -> never due");

        // Settings written by older versions still load (removed options are simply ignored)
        var legacy = JsonSerializer.Deserialize<AppConfig>("{\"LocalBridgePort\":9050,\"StealthModeEnabled\":true,\"KillSwitch\":true}");
        Assert(legacy != null && legacy.KillSwitch, "Old settings with removed options still load");
    }

    static void TestThreeTierCascadeMerge()
    {
        Console.WriteLine("\n--- 6. 3-Tier Cascade Smart Merge ---");

        var existing1 = new ProxyItem
        {
            Id = Guid.NewGuid(),
            Name = "Germany #1",
            Host = "1.2.3.4",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            Uuid = "same-uuid",
            PingMs = 45,
            Status = ProxyStatus.Online,
            IsFromSubscription = true,
            SubscriptionUrl = "https://example.com/sub"
        };

        var existing2 = new ProxyItem
        {
            Id = Guid.NewGuid(),
            Name = "Finland #2",
            Host = "5.6.7.8",
            Port = 8443,
            Protocol = ProxyProtocol.Trojan,
            Password = "oldpass",
            PingMs = 70,
            Status = ProxyStatus.Online,
            WorkingAddress = "5.6.7.8",
            IsFromSubscription = true,
            SubscriptionUrl = "https://example.com/sub"
        };

        var currentList = new System.Collections.ObjectModel.ObservableCollection<ProxyItem> { existing1, existing2 };

        var incoming1 = new ProxyItem
        {
            Id = Guid.NewGuid(),
            Name = "Germany Fast 1",
            Host = "1.2.3.4",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            Uuid = "same-uuid"
        };

        var incoming2 = new ProxyItem
        {
            Id = Guid.NewGuid(),
            Name = "Finland #2",
            Host = "5.6.7.9",
            Port = 8443,
            Protocol = ProxyProtocol.Trojan,
            Password = "newpass"
        };

        var incoming3 = new ProxyItem
        {
            Id = Guid.NewGuid(),
            Name = "Netherlands #3",
            Host = "9.9.9.9",
            Port = 443,
            Protocol = ProxyProtocol.Vless,
            Uuid = "uuid-nl"
        };

        var incomingList = new List<ProxyItem> { incoming1, incoming2, incoming3 };

        var config = new AppConfig { SelectedProxyId = existing1.Id };
        SubscriptionService.MergeSubscriptionItems(currentList, incomingList, config, "https://example.com/sub");

        Assert(currentList.Count == 3, "Merged list has 3 items");

        var m1 = currentList.FirstOrDefault(p => p.Host == "1.2.3.4");
        Assert(m1 != null && m1.Id == existing1.Id, "Tier 1: Preserved existing ID by fingerprint");
        Assert(m1 != null && m1.PingMs == 45, "Tier 1: Preserved measured PingMs");

        var m2 = currentList.FirstOrDefault(p => p.Name == "Finland #2");
        Assert(m2 != null && m2.Id == existing2.Id, "Tier 2: Preserved ID by Name");
        Assert(m2 != null && m2.Password == "newpass", "Tier 2: Updated credentials from subscription");
        // Its address changed (5.6.7.8 -> 5.6.7.9): the old check result and pinned address described the old server
        Assert(m2 != null && m2.PingMs == -1 && m2.Status == ProxyStatus.Unknown && m2.WorkingAddress == null,
            "Tier 2: A server that moved loses the old check result and pinned address");

        var m3 = currentList.FirstOrDefault(p => p.Name == "Netherlands #3");
        Assert(m3 != null && m3.Host == "9.9.9.9", "New server correctly added");
    }

    static void TestSingBoxConfigGenerationAndNativeValidation()
    {
        Console.WriteLine("\n--- 8. Sing-Box Config Generation & Native sing-box.exe Validation ---");

        string singBoxPath = TunRoutingEngine.SingBoxExePath;
        bool hasSingBox = File.Exists(singBoxPath);
        Assert(hasSingBox, $"Native sing-box.exe located at {singBoxPath}");

        // The integrity check streams the files instead of loading them: it must still accept the real core
        long before = GC.GetAllocatedBytesForCurrentThread();
        var (coreOk, coreError) = TunRoutingEngine.EnsureCoreFiles(forceRecheck: true);
        long allocatedMb = (GC.GetAllocatedBytesForCurrentThread() - before) / 1048576;
        Assert(coreOk, "Core files pass the integrity check", coreError);
        Assert(allocatedMb < 16, $"The integrity check does not copy the 43 MB core into memory (allocated {allocatedMb} MB)");

        var testProtocols = new List<(string Name, ProxyItem Proxy)>
        {
            ("VLESS Reality", new ProxyItem
            {
                Protocol = ProxyProtocol.Vless,
                Name = "Test-Vless",
                Host = "95.163.22.10",
                Port = 443,
                Uuid = Guid.NewGuid().ToString(),
                Security = "reality",
                PublicKey = "1234567890abcdef1234567890abcdef1234567890a",
                ShortId = "1234",
                Sni = "google.com",
                Fingerprint = "chrome"
            }),
            ("Trojan TLS", new ProxyItem
            {
                Protocol = ProxyProtocol.Trojan,
                Name = "Test-Trojan",
                Host = "95.163.22.11",
                Port = 443,
                Password = "trojanpassword",
                Sni = "trojan.test",
                Security = "tls",
                Fingerprint = "chrome"
            }),
            ("Shadowsocks", new ProxyItem
            {
                Protocol = ProxyProtocol.Shadowsocks,
                Name = "Test-SS",
                Host = "95.163.22.12",
                Port = 8388,
                Password = "sspassword",
                Security = "aes-256-gcm"
            }),
            ("VMess WS", new ProxyItem
            {
                Protocol = ProxyProtocol.Vmess,
                Name = "Test-VMess",
                Host = "95.163.22.13",
                Port = 443,
                Uuid = Guid.NewGuid().ToString(),
                Security = "auto",
                TransportType = "ws",
                WsPath = "/vmess",
                Sni = "vmess.example.com"
            })
        };

        foreach (var (name, proxy) in testProtocols)
        {
            var config = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: true, bypassDomesticRu: true, dnsProvider: DnsProvider.Auto);
            string json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });

            Assert(config["route"]?["rules"] is JsonArray, $"{name}: Route rules present");
            Assert(config["dns"]?["servers"] is JsonArray, $"{name}: DNS servers present");
            Assert(config["inbounds"] is JsonArray, $"{name}: Inbounds present");

            string routeRulesStr = config["route"]?["rules"]?.ToJsonString() ?? "";
            Assert(routeRulesStr.Contains(".ru") && routeRulesStr.Contains("gosuslugi.ru") && routeRulesStr.Contains("sberbank.ru"), $"{name}: Domestic RU bypass rules present");
            Assert(routeRulesStr.Contains("bittorrent") && routeRulesStr.Contains("qbittorrent") && routeRulesStr.Contains("process_path_regex"), $"{name}: Torrent bypass rules present");
            Assert(routeRulesStr.Contains("\"ip_version\":6") && routeRulesStr.Contains("\"action\":\"reject\""), $"{name}: IPv6 strict reject rule present");

            string dnsRulesStr = config["dns"]?["rules"]?.ToJsonString() ?? "";
            Assert(dnsRulesStr.Contains("HTTPS") && dnsRulesStr.Contains("SVCB") && dnsRulesStr.Contains("\"action\":\"reject\""), $"{name}: ECH rejection rule present");

            if (hasSingBox)
            {
                string tempConfigFile = Path.Combine(Path.GetTempPath(), $"singbox_test_{Guid.NewGuid():N}.json");
                try
                {
                    File.WriteAllText(tempConfigFile, json);
                    var psi = new ProcessStartInfo
                    {
                        FileName = singBoxPath,
                        Arguments = $"check -c \"{tempConfigFile}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        string stdErr = proc.StandardError.ReadToEnd();
                        string stdOut = proc.StandardOutput.ReadToEnd();
                        proc.WaitForExit();

                        Assert(proc.ExitCode == 0, $"{name}: Native sing-box.exe check passed", $"ExitCode: {proc.ExitCode}, Err: {stdErr} {stdOut}");
                    }
                }
                finally
                {
                    try { if (File.Exists(tempConfigFile)) File.Delete(tempConfigFile); } catch { }
                }
            }
        }
    }

    static void TestBypassRoutingTogglesAndKeepAlive()
    {
        Console.WriteLine("\n--- 9. Bypass Toggles & TCP KeepAlive Verification ---");

        var proxy = new ProxyItem
        {
            Protocol = ProxyProtocol.Vless,
            Name = "Test-Bypass",
            Host = "95.163.22.10",
            Port = 443,
            Uuid = Guid.NewGuid().ToString(),
            Security = "reality",
            PublicKey = "1234567890abcdef1234567890abcdef1234567890a",
            ShortId = "1234",
            Sni = "google.com",
            Fingerprint = "chrome"
        };

        // 9.1 BypassDomesticRu = true
        var configWithRu = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: true, bypassDomesticRu: true);
        string routeRuStr = configWithRu["route"]?["rules"]?.ToJsonString() ?? "";
        string dnsRuStr = configWithRu["dns"]?["rules"]?.ToJsonString() ?? "";
        Assert(routeRuStr.Contains(".ru") && routeRuStr.Contains("gosuslugi.ru"), "BypassDomesticRu TRUE includes domestic route rules");
        Assert(dnsRuStr.Contains(".ru") && dnsRuStr.Contains("gosuslugi.ru"), "BypassDomesticRu TRUE includes domestic DNS rules");

        // 9.2 BypassDomesticRu = false
        var configWithoutRu = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: true, bypassDomesticRu: false);
        string routeNoRuStr = configWithoutRu["route"]?["rules"]?.ToJsonString() ?? "";
        string dnsNoRuStr = configWithoutRu["dns"]?["rules"]?.ToJsonString() ?? "";
        Assert(!routeNoRuStr.Contains(".ru") && !routeNoRuStr.Contains("gosuslugi.ru"), "BypassDomesticRu FALSE excludes domestic route rules");
        Assert(!dnsNoRuStr.Contains(".ru") && !dnsNoRuStr.Contains("gosuslugi.ru"), "BypassDomesticRu FALSE excludes domestic DNS rules");

        // 9.3 BypassTorrents = false
        var configNoTorrents = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: false, bypassDomesticRu: true);
        string routeNoTorrentsStr = configNoTorrents["route"]?["rules"]?.ToJsonString() ?? "";
        Assert(!routeNoTorrentsStr.Contains("bittorrent") && !routeNoTorrentsStr.Contains("qbittorrent"), "BypassTorrents FALSE excludes torrent rules");

        // 9.4 TCP KeepAlive in Outbound (TSPU survival)
        var outbounds = configWithRu["outbounds"] as JsonArray;
        var proxyOutbound = outbounds?.FirstOrDefault(o => o?["tag"]?.ToString() == "proxy-out");
        Assert(proxyOutbound != null, "proxy-out outbound exists");
        Assert(proxyOutbound?["tcp_keep_alive"]?.ToString() == "15s", "proxy-out has tcp_keep_alive = 15s");
        Assert(proxyOutbound?["tcp_keep_alive_interval"]?.ToString() == "15s", "proxy-out has tcp_keep_alive_interval = 15s");
    }

    static void TestWsHostAndAlterIdPreservation()
    {
        Console.WriteLine("\n--- 10. Extended Properties (WsHost, AlterId) Roundtrip & Parsing ---");

        string vmessJson = "{\"v\":\"2\",\"ps\":\"VMess-Test\",\"add\":\"vmess.example.com\",\"port\":443,\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"aid\":64,\"net\":\"ws\",\"path\":\"/ws\",\"host\":\"custom-vhost.com\",\"tls\":\"tls\",\"sni\":\"sni.example.com\"}";
        string base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessJson));
        string vmessUri = "vmess://" + base64;

        var parsed = ProxyParser.ParseSingle(vmessUri);
        Assert(parsed != null, "Parse VMess with WsHost and AlterId");
        Assert(parsed?.AlterId == 64, $"Parsed AlterId == 64 (got {parsed?.AlterId})");
        Assert(parsed?.WsHost == "custom-vhost.com", $"Parsed WsHost == 'custom-vhost.com' (got '{parsed?.WsHost}')");

        string shareUrl = parsed!.ToShareableUrl();
        var reParsed = ProxyParser.ParseSingle(shareUrl);
        Assert(reParsed?.AlterId == 64, $"Roundtrip AlterId == 64 (got {reParsed?.AlterId})");
        Assert(reParsed?.WsHost == "custom-vhost.com", $"Roundtrip WsHost == 'custom-vhost.com' (got '{reParsed?.WsHost}')");
    }

    static void TestDnsConstantsAndProviders()
    {
        Console.WriteLine("\n--- 11. DNS Constants & 8 Providers Mapping ---");

        var enumValues = Enum.GetValues<DnsProvider>();
        Assert(enumValues.Length == 8, $"DnsProvider has exactly 8 values (got {enumValues.Length})");
        Assert(enumValues.Contains(DnsProvider.Auto), "DnsProvider contains Auto");
        Assert(enumValues.Contains(DnsProvider.Cloudflare), "DnsProvider contains Cloudflare");
        Assert(enumValues.Contains(DnsProvider.Google), "DnsProvider contains Google");
        Assert(enumValues.Contains(DnsProvider.ControlD), "DnsProvider contains ControlD");
        Assert(enumValues.Contains(DnsProvider.NextDns), "DnsProvider contains NextDns");
        Assert(enumValues.Contains(DnsProvider.AdGuard), "DnsProvider contains AdGuard");
        Assert(enumValues.Contains(DnsProvider.OpenDNS), "DnsProvider contains OpenDNS");
        Assert(enumValues.Contains(DnsProvider.CleanBrowsing), "DnsProvider contains CleanBrowsing");

        Assert(DnsConstants.Entries.Count == 7, $"DnsConstants defines 7 DoH providers (got {DnsConstants.Entries.Count})");

        foreach (var p in DnsConstants.Entries.Values)
        {
            Assert(p.DohUrl.StartsWith("https://"), $"{p.DisplayName}: DoH URL starts with https:// ({p.DohUrl})");
            Assert(!string.IsNullOrWhiteSpace(p.DohHost), $"{p.DisplayName}: Host is non-empty ({p.DohHost})");
            Assert(p.DohPath.StartsWith("/"), $"{p.DisplayName}: Path starts with / ({p.DohPath})");
            Assert(!string.IsNullOrWhiteSpace(p.PrimaryIp), $"{p.DisplayName}: Has primary IP ({p.PrimaryIp})");
            Assert(!string.IsNullOrWhiteSpace(p.SecondaryIp), $"{p.DisplayName}: Has secondary backup IP ({p.SecondaryIp})");
        }

        var cf = DnsConstants.Entries[DnsProvider.Cloudflare];
        Assert(cf.PrimaryIp == "1.1.1.1", "Cloudflare has 1.1.1.1 bootstrap");
        Assert(cf.SecondaryIp == "1.0.0.1", "Cloudflare has 1.0.0.1 backup");

        var goog = DnsConstants.Entries[DnsProvider.Google];
        Assert(goog.PrimaryIp == "8.8.8.8", "Google has 8.8.8.8 bootstrap");
        Assert(goog.SecondaryIp == "8.8.4.4", "Google has 8.8.4.4 backup");

        var adg = DnsConstants.Entries[DnsProvider.AdGuard];
        Assert(adg.PrimaryIp == "94.140.14.14", "AdGuard has 94.140.14.14 bootstrap");
        Assert(adg.SecondaryIp == "94.140.15.15", "AdGuard has 94.140.15.15 backup");

        var opendns = DnsConstants.Entries[DnsProvider.OpenDNS];
        Assert(opendns.PrimaryIp == "208.67.222.222", "OpenDNS has 208.67.222.222 bootstrap");
        Assert(opendns.SecondaryIp == "208.67.220.220", "OpenDNS has 208.67.220.220 backup");

        var cb = DnsConstants.Entries[DnsProvider.CleanBrowsing];
        Assert(cb.PrimaryIp == "185.228.168.9", "CleanBrowsing has 185.228.168.9 bootstrap");
        Assert(cb.SecondaryIp == "185.228.169.9", "CleanBrowsing has 185.228.169.9 backup");

        var cd = DnsConstants.Entries[DnsProvider.ControlD];
        Assert(cd.PrimaryIp == "76.76.2.0", "ControlD has 76.76.2.0 bootstrap");
        Assert(cd.SecondaryIp == "76.76.10.0", "ControlD has 76.76.10.0 backup");

        var nd = DnsConstants.Entries[DnsProvider.NextDns];
        Assert(nd.PrimaryIp == "45.90.28.0", "NextDNS has 45.90.28.0 bootstrap");
        Assert(nd.SecondaryIp == "45.90.30.0", "NextDNS has 45.90.30.0 backup");

        var testProxy = new ProxyItem { Protocol = ProxyProtocol.Vless, Name = "DnsTest", Host = "1.2.3.4", Port = 443, Uuid = Guid.NewGuid().ToString() };
        var singBoxConfigCf = TunRoutingEngine.GenerateSingBoxConfig(testProxy, dnsProvider: DnsProvider.Cloudflare);
        var serversArray = singBoxConfigCf["dns"]?["servers"] as JsonArray;
        Assert(serversArray != null && serversArray.Any(s => s?["tag"]?.ToString() == "remote-dns-backup"), "SingBox config for Cloudflare contains remote-dns-backup");
    }

    static void TestSecurityTogglesInConfig()
    {
        Console.WriteLine("\n--- 14. Security & Privacy Toggles Verification ---");

        var proxy = new ProxyItem
        {
            Protocol = ProxyProtocol.Vless,
            Name = "Test-Security",
            Host = "95.163.22.10",
            Port = 443,
            Uuid = Guid.NewGuid().ToString(),
            Security = "reality",
            PublicKey = "1234567890abcdef1234567890abcdef1234567890a",
            ShortId = "1234",
            Sni = "google.com"
        };

        // 14.1 Block QUIC
        var configQuicOn = TunRoutingEngine.GenerateSingBoxConfig(proxy, blockQuic: true);
        string routeQuicOnStr = configQuicOn["route"]?["rules"]?.ToJsonString() ?? "";
        Assert(routeQuicOnStr.Contains("\"network\":\"udp\"") && routeQuicOnStr.Contains("443") && routeQuicOnStr.Contains("\"action\":\"reject\""), "Block QUIC ON generates UDP 443 reject rule");

        var configQuicOff = TunRoutingEngine.GenerateSingBoxConfig(proxy, blockQuic: false);
        string routeQuicOffStr = configQuicOff["route"]?["rules"]?.ToJsonString() ?? "";
        Assert(!routeQuicOffStr.Contains("\"network\":\"udp\",\"port\":[443]"), "Block QUIC OFF does NOT reject UDP 443");

        // 14.2 Block WebRTC / STUN
        var configStunOn = TunRoutingEngine.GenerateSingBoxConfig(proxy, blockWebRtc: true);
        string routeStunOnStr = configStunOn["route"]?["rules"]?.ToJsonString() ?? "";
        Assert(routeStunOnStr.Contains("3478") && routeStunOnStr.Contains("5349") && routeStunOnStr.Contains("\"action\":\"reject\""), "Block WebRTC ON generates STUN 3478,5349 reject rule");

        // 14.3 Block Trackers
        var configTrackersOn = TunRoutingEngine.GenerateSingBoxConfig(proxy, blockTrackers: true);
        string routeTrackersOnStr = configTrackersOn["route"]?["rules"]?.ToJsonString() ?? "";
        Assert(routeTrackersOnStr.Contains("google-analytics.com") && routeTrackersOnStr.Contains("\"action\":\"reject\""), "Block Trackers ON generates tracker domain reject rule");

        // 14.4 Together with the RU bypass the tracker block must come first, or ".ru" would let mc.yandex.ru through
        var both = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassDomesticRu: true, blockTrackers: true);
        foreach (string section in new[] { "route", "dns" })
        {
            var rules = both[section]!["rules"]!.AsArray().Select(r => r!.ToJsonString()).ToList();
            int tracker = rules.FindIndex(r => r.Contains("mc.yandex.ru"));
            int ru = rules.FindIndex(r => r.Contains("gosuslugi.ru"));
            Assert(tracker >= 0 && ru >= 0 && tracker < ru, $"{section}: trackers are blocked before the RU bypass (tracker rule {tracker}, RU rule {ru})");
        }
    }

    static void TestAutoStartAndFailover()
    {
        Console.WriteLine("\n--- 13. Default settings ---");

        var config = new AppConfig();
        Assert(!config.AutoServerFailover && !config.BypassTorrents && !config.BypassDomesticRu && !config.BlockQuic && !config.BlockWebRtc && !config.BlockTrackers && !config.KillSwitch && !config.AutoUpdateSubscription,
            "Every switch is OFF by default and only works once turned on");
        Assert(config.AutoConnectOnStartup == false, "AutoConnectOnStartup is false by default");

    }

    static void TestFormatTrafficAndViewModel()
    {
        Console.WriteLine("\n--- 14. Format Traffic & Formatting Parity ---");

        Assert(MainViewModel.FormatTraffic(0) == "0.00 GB", "FormatTraffic(0) == 0.00 GB");
        Assert(MainViewModel.FormatTraffic(500) == "0.00 GB", "FormatTraffic(500) == 0.00 GB");
        Assert(MainViewModel.FormatTraffic(104857600) == "0.10 GB", "FormatTraffic(100 MB) == 0.10 GB");
        Assert(MainViewModel.FormatTraffic(1024L * 1024 * 1024) == "1.00 GB", "FormatTraffic(1 GB) == 1.00 GB");
        Assert(MainViewModel.FormatTraffic(2500L * 1024 * 1024) == "2.44 GB", "FormatTraffic(2500 MB) == 2.44 GB");

        Assert(MainViewModel.FormatCountryAndCity("flag_de Germany, Frankfurt") == "Germany, Frankfurt", "FormatCountryAndCity parses country and city");
        Assert(MainViewModel.FormatCountryAndCity("Netherlands") == "Netherlands", "FormatCountryAndCity single string");
    }

    static void TestCountryResolutionAndEmojiFlags()
    {
        Console.WriteLine("\n--- 15. Country Resolution, Emoji Flags & Russian Naming ---");

        // 1. Emoji Flag decoding
        Assert(ProxyItem.ExtractEmojiFlag("🇵🇹 Португалия N1") == "pt", "Extract emoji flag PT from '🇵🇹 Португалия N1'");
        Assert(ProxyItem.ExtractEmojiFlag("🇦🇱 Албания N1 (YouTube без рекл)") == "al", "Extract emoji flag AL from '🇦🇱 Албания N1'");
        Assert(ProxyItem.ExtractEmojiFlag("🇷🇴 Румыния N1 (Торренты)") == "ro", "Extract emoji flag RO from '🇷🇴 Румыния N1'");
        Assert(ProxyItem.ExtractEmojiFlag("🇮🇳 Индия N1") == "in", "Extract emoji flag IN from '🇮🇳 Индия N1'");
        Assert(ProxyItem.ExtractEmojiFlag("🇬🇧 Великобритания N1") == "gb", "Extract emoji flag GB from '🇬🇧 Великобритания N1'");
        Assert(ProxyItem.ExtractEmojiFlag("🚀 Авто выбор") == null, "Extract emoji flag returns null for rocket/auto");

        // 2. ResolveIsoCode multi-tier
        Assert(ProxyItem.ResolveIsoCode("🇵🇹 Португалия N1", null, "pt-n1.example.net") == "pt", "ResolveIsoCode for Portugal");
        Assert(ProxyItem.ResolveIsoCode("🇦🇱 Албания N1", null, "al-n1.example.net") == "al", "ResolveIsoCode for Albania");
        Assert(ProxyItem.ResolveIsoCode("🇷🇴 Румыния N1", null, "rm-n1.example.net") == "ro", "ResolveIsoCode for Romania");
        Assert(ProxyItem.ResolveIsoCode("🇮🇳 Индия N1", null, "id.example.net") == "in", "ResolveIsoCode for India");
        Assert(ProxyItem.ResolveIsoCode("🚀 Авто выбор", null, "auto.example.net") == "auto", "ResolveIsoCode for Auto выбор is auto");
        Assert(ProxyItem.ResolveIsoCode("en-n1.example.net", "GB", "en-n1.example.net") == "gb", "ResolveIsoCode for GB");

        // 3. GetCountryNameRu mapping
        Assert(ProxyItem.GetCountryNameRu("pt") == "Португалия", "GetCountryNameRu(pt) == Португалия");
        Assert(ProxyItem.GetCountryNameRu("al") == "Албания", "GetCountryNameRu(al) == Албания");
        Assert(ProxyItem.GetCountryNameRu("ro") == "Румыния", "GetCountryNameRu(ro) == Румыния");
        Assert(ProxyItem.GetCountryNameRu("in") == "Индия", "GetCountryNameRu(in) == Индия");
        Assert(ProxyItem.GetCountryNameRu("gb") == "Великобритания", "GetCountryNameRu(gb) == Великобритания");
        Assert(ProxyItem.GetCountryNameRu("nl") == "Нидерланды", "GetCountryNameRu(nl) == Нидерланды");
        Assert(ProxyItem.GetCountryNameRu("de") == "Германия", "GetCountryNameRu(de) == Германия");

        // 4. CleanCountryName property
        var ptProxy = new ProxyItem { Name = "🇵🇹 Португалия N1", Host = "pt-n1.example.net" };
        Assert(ptProxy.CleanCountryName == "Португалия", "CleanCountryName for Portugal is 'Португалия'");
        Assert(ptProxy.CountryCode == "pt", "CountryCode for Portugal is 'pt'");

        var autoProxy = new ProxyItem { Name = "🚀 Авто выбор", Host = "auto.example.net" };
        Assert(autoProxy.CleanCountryName == "Автоматический выбор", "CleanCountryName for auto is 'Автоматический выбор'");
        Assert(autoProxy.CountryCode == "auto", "CountryCode for auto is 'auto'");

        var roProxy = new ProxyItem { Name = "🇷🇴 Румыния N1 (Торренты)", Host = "rm-n1.example.net" };
        Assert(roProxy.CleanCountryName == "Румыния", "CleanCountryName for Romania is 'Румыния'");
        Assert(roProxy.CountryCode == "ro", "CountryCode for Romania is 'ro'");

        var inProxy = new ProxyItem { Name = "🇮🇳 Индия N1", Host = "id.example.net" };
        Assert(inProxy.CleanCountryName == "Индия", "CleanCountryName for India is 'Индия'");
        Assert(inProxy.CountryCode == "in", "CountryCode for India is 'in'");

        var gbProxy = new ProxyItem { Name = "🇬🇧 Великобритания N1", Host = "en-n1.example.net", Country = "GB" };
        Assert(gbProxy.CleanCountryName == "Великобритания", "CleanCountryName for GB is 'Великобритания'");
        Assert(gbProxy.CountryCode == "gb", "CountryCode for GB is 'gb'");

        // 5. AutoEnrichCountryIfMissing
        ptProxy.AutoEnrichCountryIfMissing();
        Assert(ptProxy.Country == "Португалия", "AutoEnrichCountryIfMissing sets Country to 'Португалия'");

        autoProxy.AutoEnrichCountryIfMissing();
        Assert(autoProxy.Country == "Автоматический выбор", "AutoEnrichCountryIfMissing sets Country to 'Автоматический выбор'");

        gbProxy.AutoEnrichCountryIfMissing();
        Assert(gbProxy.Country == "Великобритания", "AutoEnrichCountryIfMissing upgrades 'GB' to 'Великобритания'");

        // 6. Test Host Prefix Country Detection
        var hostPt = new ProxyItem { Host = "pt-nl.example.net", Port = 443 };
        hostPt.AutoEnrichCountryIfMissing();
        Assert(hostPt.Country == "Португалия", "pt-nl.example.net resolves to 'Португалия'");

        var hostRo = new ProxyItem { Host = "ro-nl.example.net", Port = 443 };
        hostRo.AutoEnrichCountryIfMissing();
        Assert(hostRo.Country == "Румыния", "ro-nl.example.net resolves to 'Румыния'");

        var hostAu = new ProxyItem { Host = "au-nl.example.net", Port = 443 };
        hostAu.AutoEnrichCountryIfMissing();
        Assert(hostAu.Country == "Австрия", "au-nl.example.net resolves to 'Австрия'");

        var hostFi = new ProxyItem { Host = "fi-hel1.example.com", Port = 443 };
        hostFi.AutoEnrichCountryIfMissing();
        Assert(hostFi.Country == "Финляндия", "fi-hel1.example.com resolves to 'Финляндия'");

        TestSubscriptionMergeSafety();
    }

    static void TestFailoverPlanner()
    {
        Console.WriteLine("\n--- 17. Failover candidate ordering ---");
        // Country codes are derived from the emoji flag in the name
        var current = new ProxyItem { Name = "🇩🇪 one", Host = "1.1.1.1", Port = 443, PingMs = 40 };
        var deSlow = new ProxyItem { Name = "🇩🇪 two", Host = "1.1.1.2", Port = 443, PingMs = 180 };
        var deFast = new ProxyItem { Name = "🇩🇪 three", Host = "1.1.1.3", Port = 443, PingMs = 60 };
        var deDead = new ProxyItem { Name = "🇩🇪 four", Host = "1.1.1.4", Port = 443, PingMs = -1, Status = ProxyStatus.Offline };
        var nlFast = new ProxyItem { Name = "🇳🇱 five", Host = "1.1.1.5", Port = 443, PingMs = 20 };
        var usUnknown = new ProxyItem { Name = "🇺🇸 six", Host = "1.1.1.6", Port = 443, PingMs = 0 };
        var all = new List<ProxyItem> { nlFast, usUnknown, deDead, current, deSlow, deFast };
        Assert(current.CountryCode == "de" && deDead.CountryCode == "de" && nlFast.CountryCode == "nl" && usUnknown.CountryCode == "us", "Test servers resolve to the intended countries");

        var order = FailoverPlanner.OrderCandidates(current, all);
        Assert(!order.Contains(current), "Failed server is never offered as its own replacement");
        Assert(order.Count == 5, $"All other servers are offered (got {order.Count})");
        Assert(order[0] == deFast && order[1] == deSlow, "Same country first, fastest first");
        Assert(order[2] == deDead, "Same-country server known to be offline still comes before other countries");
        Assert(order[3] == nlFast, "Other countries follow, fastest first");
        Assert(order[4] == usUnknown, "Servers without a measured ping go last");

        var limited = FailoverPlanner.OrderCandidates(current, all, max: 2);
        Assert(limited.Count == 2 && limited[0] == deFast && limited[1] == deSlow, "Attempt limit is respected");

        var auto = new ProxyItem { Name = "Auto", Host = "1.1.1.9", Port = 443 };
        var fromAuto = FailoverPlanner.OrderCandidates(auto, all);
        Assert(fromAuto[0] == nlFast, "Unknown country of the failed server: plain fastest-first order");

        Assert(FailoverPlanner.OrderCandidates(current, new List<ProxyItem> { current }).Count == 0, "Single-server list yields no candidates");
        Assert(FailoverPlanner.OrderCandidates(null, all).Count == 5, "No current server: list is still ordered and limited");
    }

    static void TestKillSwitchInterop()
    {
        Console.WriteLine("\n--- 18. Kill Switch: native structure layout ---");
        // These sizes come from the Windows SDK headers (x64). A mismatch would corrupt the firewall calls.
        Assert(System.Runtime.InteropServices.Marshal.SizeOf<KillSwitchFirewall.Native.Value>() == 16, "FWP_VALUE0 is 16 bytes");
        Assert(System.Runtime.InteropServices.Marshal.SizeOf<KillSwitchFirewall.Native.Condition>() == 40, "FWPM_FILTER_CONDITION0 is 40 bytes");
        Assert(System.Runtime.InteropServices.Marshal.SizeOf<KillSwitchFirewall.Native.Filter>() == 200, "FWPM_FILTER0 is 200 bytes");
        Assert(System.Runtime.InteropServices.Marshal.SizeOf<KillSwitchFirewall.Native.Session>() == 72, "FWPM_SESSION0 is 72 bytes");
        Assert(System.Runtime.InteropServices.Marshal.SizeOf<KillSwitchFirewall.Native.SubLayer>() == 72, "FWPM_SUBLAYER0 is 72 bytes");
        Assert(System.Runtime.InteropServices.Marshal.SizeOf<KillSwitchFirewall.Native.Action>() == 20, "FWPM_ACTION0 is 20 bytes");

        var (v4, p4) = KillSwitchFirewall.ParseCidr("172.19.0.0/30");
        Assert(v4.ToString() == "172.19.0.0" && p4 == 30, "IPv4 range is parsed");
        var (v6, p6) = KillSwitchFirewall.ParseCidr("fdfe:dcba:9876::/126");
        Assert(v6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && p6 == 126, "IPv6 range is parsed");

        var apps = KillSwitchFirewall.DefaultPermittedApps();
        Assert(apps.Any(a => a.EndsWith("sing-box.exe", StringComparison.OrdinalIgnoreCase)), "sing-box is on the permit list");
        Assert(apps.Count >= 2, "Zion itself is on the permit list");
        Assert(!KillSwitchFirewall.IsArmed, "Kill Switch is not armed by default");
        KillSwitchFirewall.Disarm();
        Assert(!KillSwitchFirewall.IsArmed, "Disarm without Arm is harmless");
    }

    static void TestDirectDns()
    {
        Console.WriteLine("\n--- 19. Built-in DNS query (used while Kill Switch is armed) ---");
        byte[] q = DirectDns.BuildQuery("vpn.example.com", 0xBEEF);
        byte[] expected =
        {
            0xBE, 0xEF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            3, (byte)'v', (byte)'p', (byte)'n', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 3, (byte)'c', (byte)'o', (byte)'m', 0,
            0x00, 0x01, 0x00, 0x01
        };
        Assert(q.SequenceEqual(expected), "Query packet is a standard recursive A question");

        // Reply: the question, then CNAME vpn.example.com -> edge.example.com, then two A records (names compressed)
        var reply = new List<byte>(expected);
        reply[2] = 0x81; reply[3] = 0x80;   // response, recursion available, no error
        reply[7] = 3;                       // three answers
        reply.AddRange(new byte[] { 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x07, 4, (byte)'e', (byte)'d', (byte)'g', (byte)'e', 0xC0, 0x10 });
        reply.AddRange(new byte[] { 0xC0, 0x2D, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 203, 0, 113, 10 });
        reply.AddRange(new byte[] { 0xC0, 0x2D, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0x00, 0x04, 203, 0, 113, 11 });
        byte[] replyBytes = reply.ToArray();

        var parsed = DirectDns.ParseAddresses(replyBytes, 0xBEEF);
        Assert(parsed.Length == 2 && parsed[0].ToString() == "203.0.113.10" && parsed[1].ToString() == "203.0.113.11", "A records are read past a CNAME and compressed names");
        Assert(DirectDns.ParseAddresses(replyBytes, 0x1234).Length == 0, "Reply with a foreign ID is ignored");

        byte[] nx = (byte[])replyBytes.Clone();
        nx[3] = 0x83;
        Assert(DirectDns.ParseAddresses(nx, 0xBEEF).Length == 0, "NXDOMAIN yields no addresses");
        Assert(DirectDns.ParseAddresses(replyBytes.AsSpan(0, replyBytes.Length - 3), 0xBEEF).Length == 1, "Truncated packet does not crash and keeps complete records");
        Assert(DirectDns.ParseAddresses(new byte[5], 0xBEEF).Length == 0, "Garbage is rejected");

        bool threw = false;
        try { DirectDns.BuildQuery("bad..name", 1); } catch (ArgumentException) { threw = true; }
        Assert(threw, "Malformed host name is refused");

        var literal = DirectDns.ResolveAsync("10.20.30.40").GetAwaiter().GetResult();
        Assert(literal.Length == 1 && literal[0].ToString() == "10.20.30.40", "IP literal is returned as is, without any query");

        // Reachability helper, exercised on loopback only (no traffic leaves the machine)
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var openPort = (System.Net.IPEndPoint)listener.LocalEndpoint;
        bool open = InternetProbe.TryConnectAsync(openPort, System.Net.IPAddress.Loopback, default).GetAwaiter().GetResult();
        listener.Stop();
        bool closed = InternetProbe.TryConnectAsync(openPort, null, new System.Threading.CancellationTokenSource(1500).Token).GetAwaiter().GetResult();
        Assert(open, "Reachability check succeeds against a listening port (bound to a chosen local address)");
        Assert(!closed, "Reachability check reports a closed port as unreachable instead of throwing");
    }

    static void TestProxiedTrafficCounter()
    {
        Console.WriteLine("\n--- 20. Session traffic: VPN-only accounting ---");

        static string Snap(long upTotal, long downTotal, params (string id, string chain, long up, long down)[] conns) =>
            "{\"downloadTotal\":" + downTotal + ",\"uploadTotal\":" + upTotal + ",\"connections\":[" +
            string.Join(",", conns.Select(c => "{\"id\":\"" + c.id + "\",\"chains\":[\"" + c.chain + "\"],\"upload\":" + c.up + ",\"download\":" + c.down + "}")) +
            "],\"memory\":1}";

        var c = new ProxiedTrafficCounter("proxy-out");
        Assert(c.Apply(Snap(0, 0)) && c.ProxiedBytes == 0 && c.DirectBytes == 0, "Empty core: nothing counted");

        // One VPN download and one direct (bypass) download running side by side
        c.Apply(Snap(100, 1900, ("a", "proxy-out", 50, 950), ("b", "direct-out", 50, 950)));
        Assert(c.ProxiedBytes == 1000 && c.DirectBytes == 1000, "VPN and direct traffic are kept apart");

        c.Apply(Snap(150, 4850, ("a", "proxy-out", 100, 3900), ("b", "direct-out", 50, 950)));
        Assert(c.ProxiedBytes == 4000, $"Only the growth of VPN connections is added (got {c.ProxiedBytes})");
        Assert(c.DirectBytes == 1000, "Direct traffic does not leak into the VPN figure");

        // Same snapshot again: nothing new
        c.Apply(Snap(150, 4850, ("a", "proxy-out", 100, 3900), ("b", "direct-out", 50, 950)));
        Assert(c.ProxiedBytes == 4000 && c.DirectBytes == 1000, "Repeated snapshot adds nothing");

        // VPN connection "a" closed after 500 more bytes that no snapshot saw; direct "b" is still listed and idle
        c.Apply(Snap(150, 5350, ("b", "direct-out", 50, 950)));
        Assert(c.ProxiedBytes == 4500 && c.DirectBytes == 1000, $"Last bytes of a closed VPN connection are credited to the VPN (got {c.ProxiedBytes})");

        // Direct "b" closed after 300 unseen bytes while a new VPN connection "d" is running
        c.Apply(Snap(150, 5850, ("d", "proxy-out", 0, 200)));
        Assert(c.ProxiedBytes == 4700 && c.DirectBytes == 1300, $"Last bytes of a closed direct connection stay out of the VPN figure (got {c.ProxiedBytes}/{c.DirectBytes})");

        // 600 bytes from connections that opened and closed between two snapshots: split like the visible traffic (3:1)
        c.Apply(Snap(150, 6850, ("d", "proxy-out", 0, 500), ("e", "direct-out", 0, 100)));
        Assert(c.ProxiedBytes == 5450 && c.DirectBytes == 1550, $"Unseen short connections are shared by the visible proportion (got {c.ProxiedBytes}/{c.DirectBytes})");
        Assert(c.ProxiedBytes + c.DirectBytes == 7000, "VPN + direct always equals the core's own total");

        // Everything closed, fresh counter: with nothing to go by, the default route (VPN) gets it
        var fresh = new ProxiedTrafficCounter("proxy-out");
        fresh.Apply("{\"connections\":[],\"downloadTotal\":3016121,\"memory\":3997696,\"uploadTotal\":1356}");
        Assert(fresh.ProxiedBytes == 3017477, "Real sing-box reply with no live connections is understood");

        // Core restarted (new session): totals start over and so does the counter
        c.Apply(Snap(10, 90, ("z", "proxy-out", 10, 90)));
        Assert(c.ProxiedBytes == 100 && c.DirectBytes == 0, "Core restart resets the figure instead of going negative");

        long beforeBad = c.ProxiedBytes;
        Assert(!c.Apply("not json") && !c.Apply("[]") && c.ProxiedBytes == beforeBad, "Malformed reply is ignored");
        Assert(c.Apply("{\"connections\":null,\"downloadTotal\":90,\"uploadTotal\":10}") && c.ProxiedBytes == 100, "Reply without a connection list is accepted");

        c.Reset();
        Assert(c.ProxiedBytes == 0 && c.DirectBytes == 0, "Reset clears the counter");
    }

    static void TestMultipleSubscriptions()
    {
        Console.WriteLine("\n--- 21. Several subscriptions side by side ---");
        const string urlA = "https://a.example.com/sub/aaa";
        const string urlB = "https://b.example.net/sub/bbb";

        var list = new System.Collections.ObjectModel.ObservableCollection<ProxyItem>();
        var config = new AppConfig();
        var manual = new ProxyItem { Name = "My own", Host = "7.7.7.7", Port = 443, Protocol = ProxyProtocol.Vless, Uuid = "mine" };
        list.Add(manual);

        ProxyItem Srv(string name, string host, string uuid) => new() { Name = name, Host = host, Port = 443, Protocol = ProxyProtocol.Vless, Uuid = uuid };

        var (addedA, _) = SubscriptionService.MergeSubscriptionItems(list, new List<ProxyItem> { Srv("A1", "1.0.0.1", "a1"), Srv("A2", "1.0.0.2", "a2") }, config, urlA);
        var (addedB, _) = SubscriptionService.MergeSubscriptionItems(list, new List<ProxyItem> { Srv("B1", "2.0.0.1", "b1"), Srv("B2", "2.0.0.2", "b2"), Srv("B3", "2.0.0.3", "b3") }, config, urlB);
        Assert(addedA == 2 && addedB == 3 && list.Count == 6, $"Second subscription is added next to the first, not instead of it (got {list.Count})");
        Assert(list.Contains(manual), "Manual server survives both imports");

        // A shrinks: only its own vanished server goes; B and the manual one stay
        var (_, removedA) = SubscriptionService.MergeSubscriptionItems(list, new List<ProxyItem> { Srv("A1", "1.0.0.1", "a1") }, config, urlA);
        Assert(removedA == 1 && list.Count == 5, "Updating one subscription removes only its own vanished servers");
        Assert(list.Count(p => SubscriptionService.BelongsTo(p, urlB)) == 3, "Other subscription's servers are untouched");

        // B now also lists A1 and a copy of the manual server: no duplicates appear
        SubscriptionService.MergeSubscriptionItems(list, new List<ProxyItem> { Srv("B1", "2.0.0.1", "b1"), Srv("B2", "2.0.0.2", "b2"), Srv("B3", "2.0.0.3", "b3"), Srv("A1 copy", "1.0.0.1", "a1"), Srv("Mine copy", "7.7.7.7", "mine") }, config, urlB);
        Assert(list.Count == 5, $"A server already in the list is not added twice (got {list.Count})");
        Assert(!manual.IsFromSubscription, "A subscription never takes over a manual server");

        // Links differing only in case or a trailing slash are the same subscription
        Assert(SubscriptionService.SameUrl("https://A.example.com/sub/aaa/", urlA), "Link comparison ignores case and trailing slash");

        // Removing a subscription keeps the server in use (as a manual one)
        var entryB = new SubscriptionEntry { Url = urlB };
        config.Subscriptions.Add(entryB);
        var inUse = list.First(p => p.Name == "B2");
        int removed = SubscriptionService.RemoveSubscription(entryB, list, config, inUse);
        Assert(removed == 2 && list.Contains(inUse), "Removing a subscription keeps the server the VPN is using");
        Assert(!inUse.IsFromSubscription && inUse.SubscriptionUrl == "", "That server becomes a manual one");
        Assert(config.Subscriptions.Count == 0, "The link itself is forgotten");

        // Migration from the old single-link settings
        var legacy = new AppConfig { SubscriptionUrl = urlA, LastSubscriptionUpdate = new DateTime(2026, 9, 1) };
        legacy.Proxies.Add(new ProxyItem { Name = "old", Host = "3.3.3.3", Port = 443, IsFromSubscription = true });
        ConfigStore.MigrateSingleSubscription(legacy);
        Assert(legacy.Subscriptions.Count == 1 && legacy.Subscriptions[0].Url == urlA && legacy.Subscriptions[0].LastUpdate == new DateTime(2026, 9, 1), "Old single link becomes the first subscription");
        Assert(legacy.Proxies[0].SubscriptionUrl == urlA, "Its servers are linked to it");
        Assert(legacy.SubscriptionUrl == "", "The old field is emptied");
        ConfigStore.MigrateSingleSubscription(legacy);
        Assert(legacy.Subscriptions.Count == 1, "Migration is safe to run twice");

        // Provider's plan header
        var info = ProxyParser.ParseSubscriptionUserInfo("upload=1073741824; download=9663676416; total=107374182400; expire=1792022400");
        Assert(info.Upload == 1073741824 && info.Download == 9663676416 && info.Total == 107374182400, "subscription-userinfo traffic numbers are read");
        Assert(info.Expire.HasValue && info.Expire.Value.ToUniversalTime() == new DateTime(2026, 10, 15, 0, 0, 0, DateTimeKind.Utc), "subscription-userinfo expiry is read");
        var noLimit = ProxyParser.ParseSubscriptionUserInfo("upload=0;download=5;total=0;expire=0;junk;x=y");
        Assert(noLimit.Total == 0 && noLimit.Expire == null && noLimit.Download == 5, "Zero means no limit / no end date; junk is skipped");
        Assert(ProxyParser.ParseSubscriptionUserInfo(null).Total == 0, "Missing header is fine");
        Assert(ProxyParser.DecodeProfileTitle("base64:" + Convert.ToBase64String(Encoding.UTF8.GetBytes("Мой VPN"))) == "Мой VPN", "profile-title in base64 is decoded");
        Assert(ProxyParser.DecodeProfileTitle(" Plain Name ") == "Plain Name", "Plain profile-title is kept");

        // What the card says
        var day = new DateTime(2026, 10, 1, 12, 0, 0);
        var plan = SubscriptionsViewModel.Plan(new SubscriptionEntry { Upload = 1L << 30, Download = 12L << 30, Total = 100L << 30, Expire = new DateTime(2026, 11, 15) }, day);
        Assert(plan.Text == "Осталось 87 ГБ из 100 ГБ · до 15 ноября", $"Plan line (got '{plan.Text}')");
        Assert(Math.Abs(plan.UsedFraction - 0.13) < 0.001 && !plan.IsWarning, "Used share for the bar");
        var ending = SubscriptionsViewModel.Plan(new SubscriptionEntry { Expire = day.AddDays(2) }, day);
        Assert(ending.Text == "ещё 2 дня" && ending.IsWarning, $"Ending soon is highlighted (got '{ending.Text}')");
        var expired = SubscriptionsViewModel.Plan(new SubscriptionEntry { Expire = day.AddDays(-1) }, day);
        Assert(expired.Text.StartsWith("истекла") && expired.IsWarning, "Expired subscription is highlighted");
        Assert(SubscriptionsViewModel.Servers(1) == "1 сервер" && SubscriptionsViewModel.Servers(3) == "3 сервера" && SubscriptionsViewModel.Servers(11) == "11 серверов" && SubscriptionsViewModel.Servers(24) == "24 сервера", "Russian plural forms");
        Assert(SubscriptionsViewModel.When(day.AddHours(-2), day) == "сегодня в 10:00" && SubscriptionsViewModel.When(day.AddDays(-1), day) == "вчера в 12:00", "Update time wording");
    }

    static void TestServerListSections()
    {
        Console.WriteLine("\n--- 27. Server list: provider names, sections, dividers ---");

        var named = new ProxyItem { Name = "🇬🇧 Великобритания N1 (YouTube без рек)", Country = "Великобритания" };
        Assert(named.CleanName == "Великобритания N1 (YouTube без рек)", $"Flag emoji is dropped from the name (got '{named.CleanName}')");
        Assert(new ProxyItem { Name = "Кипр 🇨🇾 2" }.CleanName == "Кипр 2", "A flag in the middle is dropped too");
        Assert(new ProxyItem { Name = "user@203.0.113.7" }.CleanName == "user@203.0.113.7", "A name without flags stays as it is");
        Assert(new ProxyItem { Name = "🇳🇱", Country = "Нидерланды" }.CleanName == "Нидерланды", "A name that is only a flag falls back to the country");

        var divider = new ProxyItem { Name = "❗️Белые списки ниже" };
        Assert(divider.IsDivider, "«❗️Белые списки ниже» is recognised as a divider");
        Assert(divider.DividerTitle == "Белые списки ниже", $"Divider title has no marks (got '{divider.DividerTitle}')");
        Assert(!new ProxyItem { Name = "🇨🇾 Белый список N3 (X5)" }.IsDivider, "A real server is not a divider");
        Assert(!new ProxyItem { Name = "❗ Германия N1" }.IsDivider, "A mark alone does not make a divider");
        Assert(!new ProxyItem { Name = "Сервер ниже" }.IsDivider, "A word alone does not make a divider");

        const string subA = "https://a.example.net/sub/TestToken123";
        const string subB = "https://b.example.net/sub/TestToken123";
        var subs = new List<SubscriptionEntry>
        {
            new() { Url = subA, Title = "Provider A" },
            new() { Url = subB, Title = "" }
        };
        ProxyItem S(string name, string sub = "", bool fav = false) => new()
        {
            Name = name, Host = "203.0.113.1", Port = 443, Protocol = ProxyProtocol.Vless,
            IsFromSubscription = sub.Length > 0, SubscriptionUrl = sub, IsFavorite = fav
        };
        var manual = S("Мой сервер");
        var a1 = S("🇩🇪 Германия N1", subA);
        var a2 = S("🇵🇱 Польша N1", subA, fav: true);
        var aDiv = S("❗️Белые списки ниже", subA);
        var a3 = S("🇨🇾 Белый список N3", subA);
        var b1 = S("🇫🇮 Финляндия", subB);
        var list = new List<ProxyItem> { manual, a1, a2, aDiv, a3, b1 };

        var sections = ServerListViewModel.BuildSections(list, subs);
        Assert(sections.Select(s => s.Key).SequenceEqual(new[] { "fav", "sub:" + subs[0].Id, "sub:" + subs[1].Id, "manual" }),
            $"Sections: favourites, each subscription in order, manual (got {string.Join(",", sections.Select(s => s.Title))})");
        Assert(sections[0].Members.SequenceEqual(new[] { a2 }), "A favourite is shown only under «Избранное»");
        Assert(sections[1].Title == "Provider A", "A subscription section is titled with the provider's name");
        Assert(sections[1].Members.SequenceEqual(new[] { a1, aDiv, a3 }), "Inside a subscription the saved order is kept, divider included");
        Assert(sections[2].Title == MainViewModel.SubscriptionDisplayName("", subB), "Without a title the subscription's usual display name is used");
        Assert(sections[3].Title == "Добавлены вручную" && sections[3].Members.SequenceEqual(new[] { manual }), "Manual servers come last");

        var onlyManual = ServerListViewModel.BuildSections(new[] { manual }, subs);
        Assert(onlyManual.Count == 1, "Empty sections are dropped");

        var onlyDivider = ServerListViewModel.BuildSections(new[] { manual, aDiv }, subs);
        Assert(onlyDivider.All(s => s.Key != "sub:" + subs[0].Id), "A section holding only a divider is dropped");

        var orphan = S("🇺🇸 США", "https://gone.example.net/sub/TestToken123");
        var withOrphan = ServerListViewModel.BuildSections(new[] { orphan, manual }, subs);
        Assert(withOrphan.Any(s => s.Key == "orphan" && s.Members.Contains(orphan)), "Servers of a removed subscription are still listed");

        var candidates = FailoverPlanner.OrderCandidates(a1, list, 10);
        Assert(!candidates.Contains(aDiv), "Failover never picks a divider");
    }

    static void TestQuicProtocols()
    {
        Console.WriteLine("\n--- 28. Hysteria2 and TUIC ---");

        var hy = ProxyParser.ParseSingle("hysteria2://p%40ss@hy.example.net:8443/?sni=cdn.example.net&obfs=salamander&obfs-password=ObfsPass&insecure=1&mport=20000-30000#%F0%9F%87%A9%F0%9F%87%AA%20Hy2");
        Assert(hy?.Protocol == ProxyProtocol.Hysteria2, "Parse hysteria2://");
        Assert(hy?.Password == "p@ss" && hy.Host == "hy.example.net" && hy.Port == 8443, "Hysteria2 password, host and port");
        Assert(hy?.Sni == "cdn.example.net" && hy.ObfsPassword == "ObfsPass" && hy.Insecure, "Hysteria2 SNI, obfuscation, insecure");
        Assert(hy?.ServerPorts == "8443,20000-30000", $"Hysteria2 port hopping kept (got '{hy?.ServerPorts}')");
        Assert(hy?.CleanName == "Hy2", "Hysteria2 name from the link");
        Assert(hy?.ProtocolBadge == "Hysteria2", "Hysteria2 badge");

        var hy2 = ProxyParser.ParseSingle("hy2://secret@[2001:db8::1]:443,5000-6000?sni=a.example.net#Short");
        Assert(hy2?.Protocol == ProxyProtocol.Hysteria2 && hy2.Host == "2001:db8::1" && hy2.Port == 443, "hy2:// with IPv6 and a port list");
        Assert(hy2?.ServerPorts == "443,5000-6000", "Port list from the address part");
        var hyPlain = ProxyParser.ParseSingle("hy2://secret@hy.example.net#Plain");
        Assert(hyPlain?.Port == 443 && hyPlain.ServerPorts == "" && !hyPlain.Insecure, "No port -> 443, no hopping, certificate checked");

        var tuic = ProxyParser.ParseSingle("tuic://11111111-2222-3333-4444-555555555555:tu%3Apass@tuic.example.net:10443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.net&allow_insecure=0#TUIC%201");
        Assert(tuic?.Protocol == ProxyProtocol.Tuic, "Parse tuic://");
        Assert(tuic?.Uuid == "11111111-2222-3333-4444-555555555555" && tuic.Password == "tu:pass", "TUIC UUID and password");
        Assert(tuic?.Port == 10443 && tuic.CongestionControl == "bbr" && tuic.UdpRelayMode == "native" && !tuic.Insecure, "TUIC options");
        Assert(tuic?.ProtocolBadge == "TUIC", "TUIC badge");
        Assert(ProxyParser.ParseSingle("tuic://only-uuid@tuic.example.net:443") == null, "TUIC without a password is rejected");

        // Share links survive a round trip
        var hyBack = ProxyParser.ParseSingle(hy!.ToShareableUrl());
        Assert(hyBack != null && hyBack.Password == hy.Password && hyBack.ObfsPassword == hy.ObfsPassword &&
               hyBack.ServerPorts == hy.ServerPorts && hyBack.Insecure && hyBack.Sni == hy.Sni && hyBack.Port == hy.Port,
               $"Hysteria2 share link round trip ({hy.ToShareableUrl()})");
        var tuicBack = ProxyParser.ParseSingle(tuic!.ToShareableUrl());
        Assert(tuicBack != null && tuicBack.Uuid == tuic.Uuid && tuicBack.Password == tuic.Password &&
               tuicBack.CongestionControl == "bbr" && tuicBack.Sni == tuic.Sni, $"TUIC share link round trip ({tuic.ToShareableUrl()})");

        // Subscriptions in sing-box JSON
        string json = """
        {"outbounds":[
          {"type":"hysteria2","tag":"HY","server":"hy.example.net","server_port":443,"password":"pw",
           "server_ports":["20000:30000"],"obfs":{"type":"salamander","password":"ob"},"tls":{"enabled":true,"insecure":true,"server_name":"s.example.net"}},
          {"type":"tuic","tag":"TU","server":"tu.example.net","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","password":"pw2",
           "congestion_control":"cubic","tls":{"enabled":true,"alpn":["h3"]}}
        ]}
        """;
        var fromJson = ProxyParser.ParseJsonSubscription(json);
        Assert(fromJson.Count == 2, "Both QUIC servers read from a sing-box subscription");
        Assert(fromJson[0].Protocol == ProxyProtocol.Hysteria2 && fromJson[0].Password == "pw" && fromJson[0].ObfsPassword == "ob" &&
               fromJson[0].ServerPorts == "20000-30000" && fromJson[0].Insecure, "Hysteria2 from JSON");
        Assert(fromJson[1].Protocol == ProxyProtocol.Tuic && fromJson[1].Uuid.StartsWith("11111111") && fromJson[1].Password == "pw2" &&
               fromJson[1].CongestionControl == "cubic" && fromJson[1].Alpn == "h3", "TUIC from JSON");

        // Core config
        var hyOut = TunRoutingEngine.GenerateSingBoxConfig(hy)["outbounds"]!.AsArray().First(o => o!["tag"]!.GetValue<string>() == "proxy-out")!;
        Assert(hyOut["type"]!.GetValue<string>() == "hysteria2", "Hysteria2 outbound type");
        Assert(hyOut["obfs"]?["type"]?.GetValue<string>() == "salamander" && hyOut["obfs"]?["password"]?.GetValue<string>() == "ObfsPass", "Salamander obfuscation");
        Assert(hyOut["server_ports"]!.AsArray().Select(x => x!.GetValue<string>()).SequenceEqual(new[] { "8443:8443", "20000:30000" }), "Port hopping in sing-box form");
        Assert(hyOut["server_port"] == null, "With port hopping the single port is left out");
        var plainOut = TunRoutingEngine.GenerateSingBoxConfig(hyPlain!)["outbounds"]!.AsArray().First(o => o!["tag"]!.GetValue<string>() == "proxy-out")!;
        Assert(plainOut["server_port"]?.GetValue<int>() == 443 && plainOut["server_ports"] == null, "Without hopping: one port");
        Assert(hyOut["tls"]?["insecure"]?.GetValue<bool>() == true && hyOut["tls"]?["alpn"]?[0]?.GetValue<string>() == "h3", "TLS: insecure from the link, ALPN h3");
        Assert(hyOut["tls"]?["utls"] == null && hyOut["tcp_keep_alive"] == null, "No uTLS and no TCP keep-alive on QUIC");

        var tuicOut = TunRoutingEngine.GenerateSingBoxConfig(tuic)["outbounds"]!.AsArray().First(o => o!["tag"]!.GetValue<string>() == "proxy-out")!;
        Assert(tuicOut["type"]!.GetValue<string>() == "tuic" && tuicOut["uuid"]!.GetValue<string>() == tuic.Uuid, "TUIC outbound");
        Assert(tuicOut["congestion_control"]?.GetValue<string>() == "bbr" && tuicOut["udp_relay_mode"]?.GetValue<string>() == "native", "TUIC options in config");
        Assert(tuicOut["tls"]?["insecure"]?.GetValue<bool>() == false, "TUIC checks the certificate unless the link says otherwise");

        Assert(TunRoutingEngine.HysteriaPortRanges("443, 20000-30000, bad, 70000, 5-1").SequenceEqual(new[] { "443:443", "20000:30000" }),
            "Invalid ports and ranges are dropped");

        foreach (var (label, p) in new[] { ("Hysteria2", hy), ("Hysteria2 without extras", hyPlain!), ("TUIC", tuic) })
        {
            if (!File.Exists(TunRoutingEngine.SingBoxExePath)) break;
            string tmp = Path.Combine(Path.GetTempPath(), $"singbox_quic_{Guid.NewGuid():N}.json");
            try
            {
                File.WriteAllText(tmp, TunRoutingEngine.GenerateSingBoxConfig(p, blockQuic: true).ToJsonString());
                var psi = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, $"check -c \"{tmp}\"")
                {
                    RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi)!;
                string err = proc.StandardError.ReadToEnd() + proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                Assert(proc.ExitCode == 0, $"Native sing-box check passes for {label}", err);
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
    }

    // ---- helpers for tests that run the real core (no TUN, no admin rights needed) ----

    /// <summary>Starts sing-box with a config passed through stdin (as Zion's server check does).</summary>
    static Process StartCore(JsonObject config)
    {
        var psi = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, "run -c stdin")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            StandardInputEncoding = new UTF8Encoding(false)
        };
        var process = Process.Start(psi)!;
        process.StandardInput.Write(config.ToJsonString());
        process.StandardInput.Close();
        return process;
    }

    static bool WaitForPort(int port, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            try { using var c = new TcpClient(); c.Connect(IPAddress.Loopback, port); return true; }
            catch { Thread.Sleep(50); }
        }
        return false;
    }

    /// <summary>A proxy setting that never skips the proxy (the stock WebProxy always bypasses loopback).</summary>
    sealed class AlwaysProxy : IWebProxy
    {
        public AlwaysProxy(Uri proxy) => Proxy = proxy;
        public Uri Proxy { get; }
        public ICredentials? Credentials { get; set; }
        public Uri GetProxy(Uri destination) => Proxy;
        public bool IsBypassed(Uri host) => false;
    }

    static void TestLocalEndpoints()
    {
        Console.WriteLine("\n--- 29. Local ports and the locked SOCKS entry ---");

        var a = LocalEndpoints.Create();
        var b = LocalEndpoints.Create();
        Assert(a.ControlPort > 0 && a.SocksPort > 0 && a.ControlPort != a.SocksPort, "Control API and SOCKS get two different free ports");
        Assert(a.ControlSecret != b.ControlSecret && a.SocksPassword != b.SocksPassword && a.SocksPassword.Length == 32, "Every session gets fresh random secrets");
        Assert(!a.ToString().Contains(a.SocksPassword) && !a.ToString().Contains(a.ControlSecret), "Credentials never show up in logs");
        Assert(LocalEndpoints.IsPortConflict("start service: listen tcp 127.0.0.1:9090: bind: Only one usage of each socket address") &&
               !LocalEndpoints.IsPortConflict("create service: initialize outbound[1]: unknown method"), "A port taken by another program is recognised");

        var cfg = TunRoutingEngine.GenerateSingBoxConfig(new ProxyItem { Protocol = ProxyProtocol.Trojan, Host = "203.0.113.9", Port = 443, Password = "p", Sni = "example.com" }, local: a);
        var inbounds = cfg["inbounds"]!.AsArray();
        var socks = inbounds.First(i => i!["tag"]!.GetValue<string>() == "socks-in")!;
        Assert(socks["type"]!.GetValue<string>() == "socks" && socks["listen"]!.GetValue<string>() == "127.0.0.1" && socks["listen_port"]!.GetValue<int>() == a.SocksPort,
            "SOCKS entry: loopback only, on the session's port");
        Assert(socks["users"]![0]!["username"]!.GetValue<string>() == a.SocksUser && socks["users"]![0]!["password"]!.GetValue<string>() == a.SocksPassword,
            "SOCKS entry requires the session's login");
        Assert(inbounds.All(i => i!["type"]!.GetValue<string>() is "tun" or "socks"), "No open HTTP/SOCKS entry is left");
        var api = cfg["experimental"]!["clash_api"]!;
        Assert(api["external_controller"]!.GetValue<string>() == $"127.0.0.1:{a.ControlPort}" && api["secret"]!.GetValue<string>() == a.ControlSecret,
            "Control API: loopback, the session's port and secret");

        byte[] login = DohProbe.BuildSocksLogin("user", "pässword");
        Assert(login[0] == 1 && login[1] == 4 && login[6] == Encoding.UTF8.GetByteCount("pässword"), "Login request follows RFC 1929");

        if (!File.Exists(TunRoutingEngine.SingBoxExePath)) return;

        // The real core with a locked SOCKS entry in front of two local servers: no internet needed
        var echo = new TcpListener(IPAddress.Loopback, 0);
        echo.Start();
        int echoPort = ((IPEndPoint)echo.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await echo.AcceptTcpClientAsync(); } catch { return; }
                _ = Task.Run(async () =>
                {
                    using (c)
                    {
                        var st = c.GetStream();
                        var buf = new byte[1024];
                        int n;
                        try { while ((n = await st.ReadAsync(buf)) > 0) await st.WriteAsync(buf.AsMemory(0, n)); } catch { }
                    }
                });
            }
        });

        var web = new TcpListener(IPAddress.Loopback, 0);
        web.Start();
        int webPort = ((IPEndPoint)web.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (true)
            {
                TcpClient c;
                try { c = await web.AcceptTcpClientAsync(); } catch { return; }
                using (c)
                {
                    var st = c.GetStream();
                    var buf = new byte[4096];
                    try
                    {
                        await st.ReadAsync(buf);
                        await st.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nzion"));
                    }
                    catch { }
                }
            }
        });

        var local = LocalEndpoints.Create();
        var core = StartCore(new JsonObject
        {
            ["log"] = new JsonObject { ["disabled"] = true },
            ["inbounds"] = new JsonArray
            {
                new JsonObject
                {
                    ["type"] = "socks", ["tag"] = "socks-in", ["listen"] = "127.0.0.1", ["listen_port"] = local.SocksPort,
                    ["users"] = new JsonArray { new JsonObject { ["username"] = local.SocksUser, ["password"] = local.SocksPassword } }
                }
            },
            ["outbounds"] = new JsonArray { new JsonObject { ["type"] = "direct", ["tag"] = "direct" } },
            ["route"] = new JsonObject { ["final"] = "direct" }
        });
        try
        {
            Assert(WaitForPort(local.SocksPort, 5000), "The core opened the SOCKS entry");

            string echoed = "";
            try
            {
                using var tcp = new TcpClient();
                tcp.Connect(IPAddress.Loopback, local.SocksPort);
                var st = tcp.GetStream();
                DohProbe.Socks5ConnectAsync(st, IPAddress.Loopback, echoPort, local.SocksUser, local.SocksPassword, CancellationToken.None).GetAwaiter().GetResult();
                st.Write(Encoding.ASCII.GetBytes("ping"));
                var buf = new byte[4];
                int got = 0;
                while (got < 4) got += st.Read(buf, got, 4 - got);
                echoed = Encoding.ASCII.GetString(buf);
            }
            catch (Exception ex) { echoed = ex.Message; }
            Assert(echoed == "ping", $"With the session login the entry passes traffic (got '{echoed}')");

            bool wrongRefused = false;
            try
            {
                using var tcp = new TcpClient();
                tcp.Connect(IPAddress.Loopback, local.SocksPort);
                DohProbe.Socks5ConnectAsync(tcp.GetStream(), IPAddress.Loopback, echoPort, local.SocksUser, "wrong-password", CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception) { wrongRefused = true; }
            Assert(wrongRefused, "A wrong password is refused");

            byte[] reply = new byte[2];
            try
            {
                using var tcp = new TcpClient();
                tcp.Connect(IPAddress.Loopback, local.SocksPort);
                var st = tcp.GetStream();
                st.Write(new byte[] { 5, 1, 0 }); // what any other program would try: no login
                int got = 0;
                while (got < 2) { int n = st.Read(reply, got, 2 - got); if (n == 0) break; got += n; }
            }
            catch { }
            Assert(reply[1] == 0xFF, $"Without a login the entry accepts no one (method answer {reply[1]:X2})");

            // The subscription download path: .NET's own SOCKS client with the session login
            string body;
            using (var withLogin = new HttpClient(new SocketsHttpHandler { Proxy = new AlwaysProxy(new Uri($"socks5://127.0.0.1:{local.SocksPort}")) { Credentials = local.SocksCredential } }) { Timeout = TimeSpan.FromSeconds(5) })
            {
                try { body = withLogin.GetStringAsync($"http://127.0.0.1:{webPort}/").GetAwaiter().GetResult(); }
                catch (Exception ex) { body = ex.Message; }
            }
            Assert(body == "zion", $"Subscription downloads log in to the entry (got '{body}')");

            bool anonymousRefused;
            using (var noLogin = new HttpClient(new SocketsHttpHandler { Proxy = new AlwaysProxy(new Uri($"socks5://127.0.0.1:{local.SocksPort}")) }) { Timeout = TimeSpan.FromSeconds(5) })
            {
                try { noLogin.GetStringAsync($"http://127.0.0.1:{webPort}/").GetAwaiter().GetResult(); anonymousRefused = false; }
                catch { anonymousRefused = true; }
            }
            Assert(anonymousRefused, "Another program without the login cannot use the entry");
        }
        finally
        {
            try { core.Kill(true); } catch { }
            echo.Stop();
            web.Stop();
        }
    }

    static void TestServerChecker()
    {
        Console.WriteLine("\n--- 30. Real server check ---");

        // An outbound can dial one exact address while the name still goes into TLS
        var named = new ProxyItem { Protocol = ProxyProtocol.Vless, Host = "vpn.example.net", Port = 443, Uuid = Guid.NewGuid().ToString(), Security = "tls", Fingerprint = "chrome" };
        var pinned = TunRoutingEngine.BuildProxyOutbound(named, "x", "203.0.113.7");
        Assert(pinned["server"]!.GetValue<string>() == "203.0.113.7" && pinned["tls"]!["server_name"]!.GetValue<string>() == "vpn.example.net",
            "Pinned address is dialled, the server name still goes into TLS");
        Assert(TunRoutingEngine.BuildProxyOutbound(named, "x")["server"]!.GetValue<string>() == "vpn.example.net", "Without a pin the name is resolved as usual");
        var hyPinned = TunRoutingEngine.BuildProxyOutbound(new ProxyItem { Protocol = ProxyProtocol.Hysteria2, Host = "hy.example.net", Port = 443, Password = "p" }, "h", "203.0.113.8");
        Assert(hyPinned["server"]!.GetValue<string>() == "203.0.113.8" && hyPinned["tls"]!["server_name"]!.GetValue<string>() == "hy.example.net", "The same for Hysteria2");

        var tunnel = TunRoutingEngine.GenerateSingBoxConfig(named, serverAddress: "203.0.113.7");
        Assert(tunnel["outbounds"]![0]!["server"]!.GetValue<string>() == "203.0.113.7", "The tunnel connects to the address the check found working");
        Assert(tunnel["route"]!["rules"]!.ToJsonString().Contains("203.0.113.7/32"), "Traffic to that address itself never loops into the tunnel");

        // The check's own config
        var socks = new ProxyItem { Protocol = ProxyProtocol.Socks5, Host = "198.51.100.1", Port = 1080 };
        var targets = new List<ServerChecker.Target> { new(named, "203.0.113.7"), new(named, "203.0.113.8"), new(socks, null) };
        var bound = ServerChecker.BuildConfig(targets, 40000, "sec", "Ethernet", new[] { IPAddress.Parse("192.168.0.1") });
        var outbounds = bound["outbounds"]!.AsArray();
        Assert(outbounds.Count == 4 && outbounds[0]!["tag"]!.GetValue<string>() == "s0" && outbounds[2]!["tag"]!.GetValue<string>() == "s2" &&
               outbounds[3]!["type"]!.GetValue<string>() == "direct", "One outbound per address, tagged by position");
        Assert(outbounds[1]!["server"]!.GetValue<string>() == "203.0.113.8", "Each address of a name is checked on its own");
        Assert(bound["route"]!["default_interface"]!.GetValue<string>() == "Ethernet", "While the tunnel is up the check goes around it");
        var dns = bound["dns"]!["servers"]![0]!;
        Assert(dns["type"]!.GetValue<string>() == "udp" && dns["server"]!.GetValue<string>() == "192.168.0.1", "Names are asked at the real adapter's DNS server");
        Assert(bound["inbounds"] == null, "The check opens no entry points");
        var unbound = ServerChecker.BuildConfig(targets, 40000, "sec", null, Array.Empty<IPAddress>());
        Assert(unbound["route"]!["default_interface"] == null && unbound["dns"]!["servers"]![0]!["type"]!.GetValue<string>() == "local",
            "Without a tunnel: no binding, the system's DNS");

        // What the core says
        Assert(ServerChecker.ParseBadOutbound("create service: initialize outbound[2]: invalid public_key") == 2, "The core names the server it refuses");
        Assert(ServerChecker.ParseBadOutbound("start service: something else") == null, "No index when the core names none");
        Assert(ServerChecker.CleanCoreError("\u001b[31mFATAL\u001b[0m[0000] create service: initialize outbound[1]: unknown method: bogus") ==
               "create service: initialize outbound[1]: unknown method: bogus", "Core errors lose colour codes and the level prefix");
        var (status, addresses) = ClashApiClient.ParseDnsAnswer(
            "{\"Answer\":[{\"TTL\":60,\"data\":\"203.0.113.1\",\"name\":\"a.\",\"type\":1},{\"TTL\":60,\"data\":\"b.\",\"name\":\"a.\",\"type\":5}," +
            "{\"TTL\":60,\"data\":\"203.0.113.2\",\"name\":\"a.\",\"type\":1}],\"Status\":0}");
        Assert(status == 0 && addresses.Count == 2 && addresses[1].ToString() == "203.0.113.2", "DNS answers: only IPv4 addresses are taken");
        Assert(ClashApiClient.ParseDnsAnswer("{\"Status\":3}").Status == 3, "\"No such name\" is recognised");

        if (!File.Exists(TunRoutingEngine.SingBoxExePath)) return;

        string tmp = Path.Combine(Path.GetTempPath(), $"singbox_check_{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(tmp, bound.ToJsonString());
            var psi = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, $"check -c \"{tmp}\"")
            {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            };
            using var proc = Process.Start(psi)!;
            string err = proc.StandardError.ReadToEnd() + proc.StandardOutput.ReadToEnd();
            proc.WaitForExit();
            Assert(proc.ExitCode == 0, "Native sing-box check passes for the server check config", err);
        }
        finally { try { File.Delete(tmp); } catch { } }

        // End to end without internet: a server the core refuses, one that refuses connections, a divider
        var refusedByCore = new ProxyItem { Name = "bad", Protocol = ProxyProtocol.Vless, Host = "203.0.113.20", Port = 443, Uuid = Guid.NewGuid().ToString(), Security = "reality", PublicKey = "", Sni = "example.com" };
        var closedPort = new ProxyItem { Name = "closed", Protocol = ProxyProtocol.Socks5, Host = "127.0.0.1", Port = LocalEndpoints.FreeLoopbackPort() };
        var divider = new ProxyItem { Name = "❗️Белые списки ниже", Host = "127.0.0.1", Port = 1 };
        var reported = new List<ServerCheckResult>();
        var results = ServerChecker.CheckAsync(new[] { refusedByCore, closedPort, divider }, r => { lock (reported) reported.Add(r); }).GetAwaiter().GetResult();
        Assert(results.Count == 2 && results.All(r => r.Server != divider), "Dividers are not checked");
        Assert(reported.Count == results.Count, "Every result is reported as soon as it is known");
        var bad = results.First(r => r.Server == refusedByCore);
        Assert(bad.Outcome == ServerCheckOutcome.NotWorking && bad.Detail.Contains("public_key"), $"A server the core refuses is named, the rest are still checked ({bad.Detail})");
        Assert(results.First(r => r.Server == closedPort).Outcome == ServerCheckOutcome.NotWorking, "A server that refuses connections is not working");
        Assert(ServerChecker.CheckAsync(Array.Empty<ProxyItem>()).GetAwaiter().GetResult().Count == 0, "Nothing to check, nothing started");
    }

    static void TestFavorites()
    {
        Console.WriteLine("\n--- 26. Favourite servers ---");
        ProxyItem S(string name, bool fav = false, int ping = 50) => new() { Name = name, Host = $"{name}.example.net", Port = 443, IsFavorite = fav, PingMs = ping };

        // List order: favourites first, the saved order kept inside each group
        var a = S("🇩🇪 a"); var b = S("🇳🇱 b", fav: true); var c = S("🇫🇮 c"); var d = S("🇺🇸 d", fav: true);
        var shown = ServerListViewModel.BuildSections(new[] { a, b, c, d }, new List<SubscriptionEntry>()).SelectMany(s => s.Members).ToList();
        Assert(shown.SequenceEqual(new[] { b, d, a, c }), "Favourites come first, saved order kept inside each group");
        var noFavourites = ServerListViewModel.BuildSections(new[] { a, c }, new List<SubscriptionEntry>()).SelectMany(s => s.Members);
        Assert(noFavourites.SequenceEqual(new[] { a, c }), "Without favourites the order is unchanged");

        // Failover: same country still wins, then favourites, then ping
        var cur = S("🇩🇪 current");
        var deFast = S("🇩🇪 fast", ping: 20); var deFav = S("🇩🇪 starred", fav: true, ping: 300); var nlFav = S("🇳🇱 starred", fav: true, ping: 10);
        var order = FailoverPlanner.OrderCandidates(cur, new[] { deFast, nlFav, deFav, cur });
        Assert(order[0] == deFav && order[1] == deFast && order[2] == nlFav, "Failover: same country first, a favourite before a faster non-favourite");

        // Kept when the subscription is refreshed, and saved with the settings
        var list = new System.Collections.ObjectModel.ObservableCollection<ProxyItem>
        {
            new() { Name = "A1", Host = "1.0.0.1", Port = 443, Protocol = ProxyProtocol.Vless, Uuid = "a1", IsFromSubscription = true, SubscriptionUrl = "https://s.example.net/x", IsFavorite = true }
        };
        SubscriptionService.MergeSubscriptionItems(list, new List<ProxyItem> { new() { Name = "A1 renamed", Host = "1.0.0.1", Port = 443, Protocol = ProxyProtocol.Vless, Uuid = "a1" } }, new AppConfig(), "https://s.example.net/x");
        Assert(list.Count == 1 && list[0].IsFavorite && list[0].Name == "A1 renamed", "Star survives a subscription update");
        var json = JsonSerializer.Serialize(new AppConfig { Proxies = list.ToList() });
        Assert(JsonSerializer.Deserialize<AppConfig>(json)!.Proxies[0].IsFavorite, "Star is saved with the settings");
        Assert(!new ProxyItem().IsFavorite, "New servers are not favourites");
    }

    static void TestDirectSites()
    {
        Console.WriteLine("\n--- 25. Sites that bypass the VPN ---");

        // Whatever the user pastes becomes a bare site name
        string? N(string s) => DirectSites.Normalize(s, out _);
        Assert(N("kinopoisk.ru") == "kinopoisk.ru", "Plain site name is kept");
        Assert(N("https://www.kinopoisk.ru/film/123?x=1#top") == "kinopoisk.ru", "Full link -> site name, www. dropped");
        Assert(N("  WWW.Sberbank.RU/ ") == "sberbank.ru", "Spaces, capitals and trailing slash are cleaned");
        Assert(N("*.vk.com") == "vk.com" && N(".vk.com") == "vk.com", "Wildcard notation is understood");
        Assert(N("music.yandex.ru:443") == "music.yandex.ru", "Port is dropped, subdomain kept as typed");
        Assert(N("кинопоиск.рф") == "xn--h1aaecngahu.xn--p1ai", "Cyrillic domain is converted for the core");
        Assert(DirectSites.Display("xn--h1aaecngahu.xn--p1ai") == "кинопоиск.рф", "...and shown back in Cyrillic");
        Assert(N("") == null && N("hello") == null && N("1.2.3.4") == null && N("-bad-.com") == null && N("a..b") == null, "Garbage, single words and IPs are refused");
        DirectSites.Normalize("8.8.8.8", out string ipError);
        Assert(ipError.Contains("IP"), "Refusing an IP says why");
        Assert(DirectSites.Sanitize(new[] { "vk.com", "https://vk.com/feed", "bad", "ok.ru" }).SequenceEqual(new[] { "vk.com", "ok.ru" }), "List is de-duplicated and cleaned");

        // In the core config: before everything that could override it
        var proxy = new ProxyItem { Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Trojan, Password = "p", Sni = "example.com" };
        var cfg = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: true, bypassDomesticRu: true, blockQuic: true, blockTrackers: true,
            directSites: new[] { "kinopoisk.ru", "https://www.example.org/x" });
        var rules = cfg["route"]?["rules"]?.AsArray() ?? new JsonArray();
        int siteIdx = -1, ruIdx = -1, quicIdx = -1, trackersIdx = -1;
        for (int i = 0; i < rules.Count; i++)
        {
            string r = rules[i]!.ToJsonString();
            if (r.Contains("kinopoisk.ru") && r.Contains("direct-out") && siteIdx < 0) siteIdx = i;
            if (r.Contains("\"ru\"") && ruIdx < 0) ruIdx = i;
            if (r.Contains("\"udp\"") && r.Contains("443") && r.Contains("reject") && quicIdx < 0) quicIdx = i;
            if (r.Contains("google-analytics.com") && trackersIdx < 0) trackersIdx = i;
        }
        Assert(siteIdx >= 0 && rules[siteIdx]!.ToJsonString().Contains("example.org"), "User sites get one direct rule (links cleaned)");
        Assert(siteIdx < ruIdx && siteIdx < quicIdx && siteIdx < trackersIdx, "That rule comes before 'Обход РФ', the QUIC block and tracker blocking");
        Assert((cfg["dns"]?["rules"]?.ToJsonString() ?? "").Contains("kinopoisk.ru"), "Their names are resolved by the local resolver");
        Assert(!(TunRoutingEngine.GenerateSingBoxConfig(proxy)["route"]?["rules"]?.ToJsonString() ?? "").Contains("example.org"), "No sites -> no extra rule");
        Assert(new AppConfig().DirectSites.Count == 0, "The list starts empty");

        if (File.Exists(TunRoutingEngine.SingBoxExePath))
        {
            string tmp = Path.Combine(Path.GetTempPath(), $"singbox_sites_{Guid.NewGuid():N}.json");
            try
            {
                File.WriteAllText(tmp, cfg.ToJsonString());
                var psi = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, $"check -c \"{tmp}\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi)!;
                string err = proc.StandardError.ReadToEnd() + proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                Assert(proc.ExitCode == 0, "Native sing-box check passes with user sites", err);
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
    }

    static void TestDnsFailover()
    {
        Console.WriteLine("\n--- 24. DNS checked through the VPN, with failover ---");

        // Which server the tunnel starts with
        var order = new List<DnsBenchmarkResult> { new("Google", "8.8.4.4", "/dns-query", 30, true), new("Cloudflare", "1.1.1.1", "/dns-query", 40, true) };
        var first = TunRoutingEngine.ResolvePrimaryDns(DnsProvider.Auto, order);
        Assert(first.Name == "Google" && first.Ip == "8.8.4.4" && first.Host == "dns.google", "Auto: the measured fastest server is the one in use, backup address included");
        var fixedOne = TunRoutingEngine.ResolvePrimaryDns(DnsProvider.AdGuard, null);
        Assert(fixedOne.Name == "AdGuard" && fixedOne.Ip == "94.140.14.14", "Chosen provider starts on its main address");
        Assert(TunRoutingEngine.ResolvePrimaryDns(DnsProvider.Auto, null).Name == "Cloudflare", "Auto without a measurement: Cloudflare, as in the config");

        // A backup address now gets proper TLS settings when it is put first
        var proxy = new ProxyItem { Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Trojan, Password = "p", Sni = "example.com" };
        var cfg = TunRoutingEngine.GenerateSingBoxConfig(proxy, dnsProvider: DnsProvider.Auto, autoDnsOrder: order);
        var primary = cfg["dns"]!["servers"]!.AsArray().First(s => s!["tag"]!.GetValue<string>() == "remote-dns")!;
        Assert(primary["server"]!.GetValue<string>() == "8.8.4.4" && primary["tls"]?["server_name"]?.GetValue<string>() == "dns.google",
            "Backup address of a provider is used with its TLS name (was sent without TLS before)");

        // Where failover looks
        var current = new DohTarget("Cloudflare", "1.1.1.1", "cloudflare-dns.com", "/dns-query");
        var auto = DohProbe.FailoverCandidates(DnsProvider.Auto, current);
        Assert(!auto.Any(t => t.Ip == "1.1.1.1") && auto.Any(t => t.Name == "Google") && auto.Any(t => t.Ip == "1.0.0.1"), "Auto: every other server, including Cloudflare's backup address");
        var adguard = DohProbe.FailoverCandidates(DnsProvider.AdGuard, new DohTarget("AdGuard", "94.140.14.14", "dns.adguard-dns.com", "/dns-query"));
        Assert(adguard.Count == 1 && adguard[0].Ip == "94.140.15.15", "Chosen provider: only its own backup address (the user's choice is kept)");

        // Raw HTTP answers from DoH servers
        var dnsAnswer = new byte[] { 1, 2, 3 };
        var plain = System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\n").Concat(dnsAnswer).ToArray();
        var (st1, body1) = DohProbe.ParseHttpResponse(plain);
        Assert(st1 == 200 && body1.SequenceEqual(dnsAnswer) && DohProbe.IsComplete(plain), "Content-Length answer is read");
        var chunked = System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n\u0001\u0002\r\n1\r\n\u0003\r\n0\r\n\r\n");
        var (st2, body2) = DohProbe.ParseHttpResponse(chunked);
        Assert(st2 == 200 && body2.SequenceEqual(dnsAnswer) && DohProbe.IsComplete(chunked), "Chunked answer is read");
        Assert(DohProbe.ParseHttpResponse(System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")).Status == 403, "Error status is recognised");
        Assert(!DohProbe.IsComplete(System.Text.Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nabc")), "Incomplete answer is not taken for a whole one");
        Assert(DohProbe.Base64Url(new byte[] { 0xFB, 0xFF, 0xFE }) == "-__-", "DNS question is encoded URL-safe, without padding");
        Assert(DohProbe.SocksReplyTail(1) == 6 && DohProbe.SocksReplyTail(4) == 18 && DohProbe.SocksReplyTail(3) == -1, "SOCKS replies of every address type are understood");

        // The real core accepts a config that starts with a backup address
        if (File.Exists(TunRoutingEngine.SingBoxExePath))
        {
            string tmp = Path.Combine(Path.GetTempPath(), $"singbox_dns_{Guid.NewGuid():N}.json");
            try
            {
                File.WriteAllText(tmp, cfg.ToJsonString());
                var psi = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, $"check -c \"{tmp}\"")
                { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
                using var proc = Process.Start(psi)!;
                string err = proc.StandardError.ReadToEnd() + proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                Assert(proc.ExitCode == 0, "Native sing-box check passes with a backup DNS address first", err);
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
    }

    static void TestVlessTlsHandshake()
    {
        Console.WriteLine("\n--- 23. VLESS over plain TLS: browser fingerprint and ALPN list ---");
        var tlsProxy = new ProxyItem
        {
            Protocol = ProxyProtocol.Vless, Host = "203.0.113.5", Port = 443, Uuid = Guid.NewGuid().ToString(),
            Security = "tls", Sni = "cdn.example.com", TransportType = "ws", WsPath = "/ws",
            Fingerprint = "firefox", Alpn = "h2, http/1.1"
        };
        var tls = TunRoutingEngine.GenerateSingBoxConfig(tlsProxy)["outbounds"]!.AsArray()
            .First(o => o!["tag"]!.GetValue<string>() == "proxy-out")!["tls"]!;

        Assert(tls["utls"]?["enabled"]?.GetValue<bool>() == true, "VLESS+TLS now masks itself as a browser (uTLS on)");
        Assert(tls["utls"]?["fingerprint"]?.GetValue<string>() == "firefox", "The fingerprint from the link is used");
        var alpn = tls["alpn"]!.AsArray().Select(a => a!.GetValue<string>()).ToList();
        Assert(alpn.SequenceEqual(new[] { "h2", "http/1.1" }), $"ALPN list is split into separate protocols (got {string.Join("|", alpn)})");

        tlsProxy.Fingerprint = "";
        var tlsDefault = TunRoutingEngine.GenerateSingBoxConfig(tlsProxy)["outbounds"]!.AsArray()
            .First(o => o!["tag"]!.GetValue<string>() == "proxy-out")!["tls"]!;
        Assert(tlsDefault["utls"]?["fingerprint"]?.GetValue<string>() == "chrome", "No fingerprint in the link -> Chrome");

        // The real core accepts it
        tlsProxy.Fingerprint = "firefox";
        string json = TunRoutingEngine.GenerateSingBoxConfig(tlsProxy).ToJsonString();
        if (File.Exists(TunRoutingEngine.SingBoxExePath))
        {
            string tmp = Path.Combine(Path.GetTempPath(), $"singbox_vlesstls_{Guid.NewGuid():N}.json");
            try
            {
                File.WriteAllText(tmp, json);
                var psi = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, $"check -c \"{tmp}\"")
                {
                    RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var proc = Process.Start(psi)!;
                string err = proc.StandardError.ReadToEnd() + proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                Assert(proc.ExitCode == 0, "Native sing-box check passes for VLESS+TLS with uTLS and ALPN list", err);
            }
            finally { try { File.Delete(tmp); } catch { } }
        }
    }

    static void TestExcludedPrograms()
    {
        Console.WriteLine("\n--- 22. Programs that bypass the VPN ---");
        var clean = TunRoutingEngine.SanitizeDirectApps(new[] { "steam.exe", "Steam.exe", @"C:\Games\cs2.exe", "  ", "readme.txt", "sing-box.exe", "Zion.exe", "Zion_v13.exe", "ZionGame.exe" });
        Assert(clean.SequenceEqual(new[] { "steam.exe", "cs2.exe", "ZionGame.exe" }), $"Exe names are cleaned, de-duplicated, and Zion/core are refused (got {string.Join(",", clean)})");
        Assert(TunRoutingEngine.SanitizeDirectApps(null).Count == 0, "No list is fine");

        var proxy = new ProxyItem { Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Trojan, Password = "p", Sni = "example.com" };
        var cfg = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: true, bypassDomesticRu: true, blockQuic: true, directApps: new[] { "steam.exe", "Discord.exe" });
        var rules = cfg["route"]?["rules"]?.AsArray() ?? new JsonArray();
        int bypassIdx = -1, quicIdx = -1;
        for (int i = 0; i < rules.Count; i++)
        {
            var r = rules[i]!;
            if (r["process_path_regex"] is JsonArray pn && pn.Any(x => x!.GetValue<string>().Contains("steam\\.exe")) && r["outbound"]?.GetValue<string>() == "direct-out") bypassIdx = i;
            if (r["network"]?.GetValue<string>() == "udp" && r["action"]?.GetValue<string>() == "reject" && r["port"]?.ToJsonString().Contains("443") == true) quicIdx = i;
        }
        Assert(bypassIdx >= 0, "Excluded programs get a direct route rule");
        Assert(quicIdx > bypassIdx, "That rule comes before the QUIC block, so their QUIC is not cut");
        var dnsRules = cfg["dns"]?["rules"]?.ToJsonString() ?? "";
        Assert(dnsRules.Contains("Discord") && dnsRules.Contains("process_path_regex") && dnsRules.Contains("direct-dns"), "Their own DNS lookups go to the local resolver");

        // The real core accepts the config with the new rules
        if (File.Exists(TunRoutingEngine.SingBoxExePath))
        {
            string tmp = Path.Combine(Path.GetTempPath(), $"singbox_excl_{Guid.NewGuid():N}.json");
            try
            {
                File.WriteAllText(tmp, cfg.ToJsonString());
                var psi = new ProcessStartInfo
                {
                    FileName = TunRoutingEngine.SingBoxExePath,
                    Arguments = $"check -c \"{tmp}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = Process.Start(psi)!;
                string err = proc.StandardError.ReadToEnd() + proc.StandardOutput.ReadToEnd();
                proc.WaitForExit();
                Assert(proc.ExitCode == 0, "Native sing-box check passes with excluded programs", err);
            }
            finally
            {
                try { File.Delete(tmp); } catch { }
            }
        }

        var none = TunRoutingEngine.GenerateSingBoxConfig(proxy, bypassTorrents: false, bypassDomesticRu: false);
        Assert(!(none["route"]?["rules"]?.ToJsonString() ?? "").Contains("process_path_regex"), "No exclusions -> no extra rule");

        // Case does not matter, like in Windows; special characters in file names are escaped
        string pattern = TunRoutingEngine.BuildProcessPattern(new[] { "uTorrent.exe", "Some Game (x64).exe" });
        var re = new System.Text.RegularExpressions.Regex(pattern.Replace("(?i)", ""), System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        Assert(re.IsMatch(@"C:\Users\me\AppData\Roaming\uTorrent\UTORRENT.EXE"), "Pattern matches regardless of letter case");
        Assert(re.IsMatch(@"D:\Games\Some Game (x64).exe") && !re.IsMatch(@"D:\Games\Some Game x64.exe"), "Brackets and dots in names are taken literally");
        Assert(!re.IsMatch(@"C:\Tools\notutorrent.exe"), "Only the whole file name matches, not a part of it");

        var legacy = JsonSerializer.Deserialize<AppConfig>("{\"KillSwitch\":true}");
        Assert(legacy != null && legacy.DirectApps.Count == 0, "Older settings load with an empty exclusion list");
    }

    static void TestSubscriptionMergeSafety()
    {
        Console.WriteLine("\n--- 16. Subscription Merge Safety & Duplicate Resilience ---");
        var existingList = new System.Collections.ObjectModel.ObservableCollection<ProxyItem>();

        var duplicateId = Guid.NewGuid();
        // Add two proxies with identical ID and identical Host:Port to test duplicate key collision resilience
        existingList.Add(new ProxyItem { Id = duplicateId, Name = "Server 1", Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Vless, IsFromSubscription = true });
        existingList.Add(new ProxyItem { Id = duplicateId, Name = "Server 1 Dup", Host = "1.2.3.4", Port = 443, Protocol = ProxyProtocol.Vless, IsFromSubscription = true });
        existingList.Add(new ProxyItem { Id = Guid.NewGuid(), Name = "Server 2", Host = "5.6.7.8", Port = 443, Protocol = ProxyProtocol.Trojan, PingMs = 45, IsFromSubscription = true });

        var freshList = new List<ProxyItem>
        {
            new ProxyItem { Name = "Server 2 Updated", Host = "5.6.7.8", Port = 443, Protocol = ProxyProtocol.Trojan },
            new ProxyItem { Name = "Server 3 New", Host = "pt-nl.example.net", Port = 443, Protocol = ProxyProtocol.Vless }
        };

        var config = new AppConfig();
        // This MUST NOT throw ArgumentException!
        SubscriptionService.MergeSubscriptionItems(existingList, freshList, config, "https://sub.example.com/test");

        Assert(existingList.Count == 2, $"Merge trimmed obsolete and updated list to 2 items (got {existingList.Count})");
        var updatedServer2 = existingList.FirstOrDefault(p => p.Host == "5.6.7.8");
        Assert(updatedServer2 != null, "Server 2 exists after merge");
        Assert(updatedServer2!.PingMs == 45, "Server 2 preserved PingMs");

        var newServer3 = existingList.FirstOrDefault(p => p.Host == "pt-nl.example.net");
        Assert(newServer3 != null, "Server 3 added from subscription");
        Assert(newServer3!.Country == "Португалия", "Server 3 country auto-enriched to 'Португалия'");
        Assert(newServer3.IsFromSubscription == true, "Server 3 marked as IsFromSubscription");
    }
}

