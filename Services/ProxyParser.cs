using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Zion.Models;

namespace Zion.Services;

public static class ProxyParser
{
    private static string? _cachedDeviceHwid;

    public static string GetOrGenerateDeviceHwid()
    {
        if (!string.IsNullOrEmpty(_cachedDeviceHwid))
            return _cachedDeviceHwid;

        try
        {
            // 1. Try reading native Windows MachineGuid
            using var rk = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            if (rk != null)
            {
                object? val = rk.GetValue("MachineGuid");
                if (val is string guidStr && !string.IsNullOrWhiteSpace(guidStr))
                {
                    byte[] md5 = MD5.HashData(Encoding.UTF8.GetBytes(guidStr.Trim()));
                    _cachedDeviceHwid = Convert.ToHexString(md5).ToLowerInvariant();
                    return _cachedDeviceHwid;
                }
            }
        }
        catch { }

        // 2. Fallback: Stable machine fingerprint hash
        try
        {
            string raw = $"{Environment.MachineName}|{Environment.UserName}|{Environment.ProcessorCount}|Windows";
            byte[] md5 = MD5.HashData(Encoding.UTF8.GetBytes(raw));
            _cachedDeviceHwid = Convert.ToHexString(md5).ToLowerInvariant();
            return _cachedDeviceHwid;
        }
        catch
        {
            _cachedDeviceHwid = Guid.NewGuid().ToString("N");
            return _cachedDeviceHwid;
        }
    }

    public static ProxyItem? ParseSingle(string input, string defaultName = "Импортированный прокси")
    {
        var item = ParseSingleInternal(input, defaultName);
        if (item != null)
        {
            item.EnsureDeterministicId();
            item.AutoEnrichCountryIfMissing();
        }
        return item;
    }

    private static ProxyItem? ParseSingleInternal(string input, string defaultName = "Импортированный прокси")
    {
        if (string.IsNullOrWhiteSpace(input)) return null;

        input = input.Trim().Trim('"', '\'', '`');

        // 0. Detect VLESS link
        if (input.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseVless(input);
        }

        // 1. Detect Trojan link
        if (input.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseTrojan(input);
        }

        // 2. Detect Shadowsocks link
        if (input.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseShadowsocks(input);
        }

        // 3. Detect VMess link
        if (input.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseVmess(input);
        }

        // 3a. Hysteria2 / TUIC (QUIC-based)
        if (input.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) || input.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseHysteria2(input);
        }
        if (input.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase))
        {
            return ParseTuic(input);
        }

        string name = defaultName;
        int hashIdx = input.IndexOf('#');
        if (hashIdx != -1)
        {
            name = Uri.UnescapeDataString(input[(hashIdx + 1)..].Trim());
            input = input[..hashIdx].Trim();
        }

        var protocol = ProxyProtocol.Http;

        // 4. Detect protocol scheme
        if (input.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase) || input.StartsWith("socks://", StringComparison.OrdinalIgnoreCase))
        {
            protocol = ProxyProtocol.Socks5;
            input = input.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase) ? input[9..] : input[8..];
        }
        else if (input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            protocol = ProxyProtocol.Http;
            input = input[8..];
        }
        else if (input.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            protocol = ProxyProtocol.Http;
            input = input[7..];
        }

        string host = "";
        int port = 8080;
        string user = "";
        string pass = "";

        // Format A: user:pass@host:port
        if (input.Contains('@'))
        {
            var parts = input.Split('@', 2);
            var authPart = parts[0];
            var hostPart = parts[1].Split('?', '/')[0].Trim();

            if (authPart.Contains(':'))
            {
                var authTokens = authPart.Split(':', 2);
                user = Uri.UnescapeDataString(authTokens[0]);
                pass = Uri.UnescapeDataString(authTokens[1]);
            }
            else
            {
                user = Uri.UnescapeDataString(authPart);
            }

            if (hostPart.Contains(':'))
            {
                var hostTokens = hostPart.Split(':', 2);
                host = hostTokens[0];
                int.TryParse(hostTokens[1].TrimEnd('/'), out port);
            }
            else
            {
                host = hostPart.TrimEnd('/');
            }
        }
        else
        {
            // Strip any trailing path or query
            var cleanInput = input.Split('?', '/')[0].Trim();

            // Split by ':' or ';' or tab
            var tokens = cleanInput.Split(new[] { ':', ';', '\t', ' ' }, StringSplitOptions.RemoveEmptyEntries);

            if (tokens.Length >= 4)
            {
                // Format B: host:port:user:pass
                host = tokens[0];
                int.TryParse(tokens[1], out port);
                user = tokens[2];
                pass = tokens[3];
            }
            else if (tokens.Length == 2)
            {
                // Format C: host:port
                host = tokens[0];
                int.TryParse(tokens[1], out port);
            }
            else if (tokens.Length == 3)
            {
                // Format D: host:port:user
                host = tokens[0];
                int.TryParse(tokens[1], out port);
                user = tokens[2];
            }
        }

        if (string.IsNullOrWhiteSpace(host) || port <= 0 || port > 65535)
            return null;

        return new ProxyItem
        {
            Name = !string.IsNullOrWhiteSpace(name) && name != defaultName ? name : (string.IsNullOrEmpty(user) ? $"{host}:{port}" : $"{user}@{host}"),
            Host = host,
            Port = port,
            Protocol = protocol,
            Username = user,
            Password = pass,
            Status = ProxyStatus.Unknown
        };
    }

    public static List<ProxyItem> ParseBulk(string text)
    {
        var result = new List<ProxyItem>();
        if (string.IsNullOrWhiteSpace(text)) return result;

        string workingText = text.Trim();

        // 1. If text is JSON, try parsing JSON outbounds/proxies directly
        if (workingText.StartsWith('{') || workingText.StartsWith('['))
        {
            var jsonItems = ParseJsonSubscription(workingText);
            if (jsonItems.Count > 0) return jsonItems;
        }

        // 2. Try Base64 decode if whole text is base64
        if (!workingText.Contains('\n') && !workingText.Contains("://") && workingText.Length > 20)
        {
            byte[]? decodedBytes = TryDecodeBase64Safe(workingText);
            if (decodedBytes != null)
            {
                string decodedString = Encoding.UTF8.GetString(decodedBytes).Trim();
                if (decodedString.StartsWith('{') || decodedString.StartsWith('['))
                {
                    var jsonItems = ParseJsonSubscription(decodedString);
                    if (jsonItems.Count > 0) return jsonItems;
                }
                else if (decodedString.Contains("://") || decodedString.Contains('\n'))
                {
                    workingText = decodedString;
                }
            }
        }

        var lines = workingText.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        int index = 1;

        foreach (var rawLine in lines)
        {
            string line = rawLine.Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith("//"))
                continue;

            var item = ParseSingle(line, $"Прокси #{index}");
            if (item != null)
            {
                result.Add(item);
                index++;
            }
        }

        return result;
    }

    public static List<ProxyItem> ParseJsonSubscription(string jsonText)
    {
        var proxies = new List<ProxyItem>();
        if (string.IsNullOrWhiteSpace(jsonText)) return proxies;

        try
        {
            using var doc = JsonDocument.Parse(jsonText);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array)
            {
                foreach (var elem in root.EnumerateArray())
                {
                    if (elem.TryGetProperty("outbounds", out var outboundsElem) && outboundsElem.ValueKind == JsonValueKind.Array)
                    {
                        string remarks = elem.TryGetProperty("remarks", out var rem) ? rem.GetString() ?? "" : "";
                        foreach (var ob in outboundsElem.EnumerateArray())
                        {
                            var item = ParseSingBoxOutbound(ob, remarks);
                            if (item != null) proxies.Add(item);
                        }
                    }
                    else
                    {
                        var item = ParseSingBoxOutbound(elem, "");
                        if (item != null) proxies.Add(item);
                    }
                }
            }
            else if (root.ValueKind == JsonValueKind.Object)
            {
                JsonElement outboundsElem = default;
                if (root.TryGetProperty("outbounds", out var ob1) && ob1.ValueKind == JsonValueKind.Array)
                    outboundsElem = ob1;
                else if (root.TryGetProperty("proxies", out var ob2) && ob2.ValueKind == JsonValueKind.Array)
                    outboundsElem = ob2;

                if (outboundsElem.ValueKind == JsonValueKind.Array)
                {
                    foreach (var ob in outboundsElem.EnumerateArray())
                    {
                        var item = ParseSingBoxOutbound(ob, "");
                        if (item != null) proxies.Add(item);
                    }
                }
            }
        }
        catch { }

        return proxies;
    }

    private static ProxyItem? ParseSingBoxOutbound(JsonElement ob, string defaultName)
    {
        if (ob.ValueKind != JsonValueKind.Object) return null;

        string type = ob.TryGetProperty("type", out var typeProp) ? typeProp.GetString()?.ToLowerInvariant() ?? "" :
                      ob.TryGetProperty("protocol", out var protoProp) ? protoProp.GetString()?.ToLowerInvariant() ?? "" : "";

        if (type == "direct" || type == "block" || type == "dns") return null;

        string server = ob.TryGetProperty("server", out var sProp) ? sProp.GetString() ?? "" :
                        ob.TryGetProperty("address", out var aProp) ? aProp.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(server)) return null;

        int port = 443;
        if (ob.TryGetProperty("server_port", out var spProp) && spProp.TryGetInt32(out int p1)) port = p1;
        else if (ob.TryGetProperty("port", out var pProp) && pProp.TryGetInt32(out int p2)) port = p2;

        string tag = ob.TryGetProperty("tag", out var tagProp) ? tagProp.GetString() ?? "" :
                     ob.TryGetProperty("name", out var nProp) ? nProp.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(tag)) tag = !string.IsNullOrWhiteSpace(defaultName) ? defaultName : $"{server}:{port}";

        ProxyProtocol proto;
        if (type == "vless") proto = ProxyProtocol.Vless;
        else if (type == "trojan") proto = ProxyProtocol.Trojan;
        else if (type == "shadowsocks") proto = ProxyProtocol.Shadowsocks;
        else if (type == "vmess") proto = ProxyProtocol.Vmess;
        else if (type == "socks" || type == "socks5") proto = ProxyProtocol.Socks5;
        else if (type == "hysteria2") proto = ProxyProtocol.Hysteria2;
        else if (type == "tuic") proto = ProxyProtocol.Tuic;
        else return null;

        string uuid = ob.TryGetProperty("uuid", out var uProp) ? uProp.GetString() ?? "" :
                      ob.TryGetProperty("password", out var pwProp) ? pwProp.GetString() ?? "" : "";
        string flow = ob.TryGetProperty("flow", out var flowProp) ? flowProp.GetString() ?? "" : "";

        string security = "none";
        string sni = "";
        string pbk = "";
        string sid = "";
        string fp = "chrome";

        if (ob.TryGetProperty("tls", out var tlsElem) && tlsElem.ValueKind == JsonValueKind.Object)
        {
            security = "tls";
            if (tlsElem.TryGetProperty("server_name", out var snProp)) sni = snProp.GetString() ?? "";
            if (tlsElem.TryGetProperty("utls", out var utlsElem) && utlsElem.TryGetProperty("fingerprint", out var fpProp))
                fp = fpProp.GetString() ?? "chrome";

            if (tlsElem.TryGetProperty("reality", out var realityElem) && realityElem.ValueKind == JsonValueKind.Object)
            {
                security = "reality";
                if (realityElem.TryGetProperty("public_key", out var pbkProp)) pbk = pbkProp.GetString() ?? "";
                if (realityElem.TryGetProperty("short_id", out var sidProp)) sid = sidProp.GetString() ?? "";
            }
        }

        string transportType = "tcp";
        string wsPath = "/";
        string grpcServiceName = "";

        if (ob.TryGetProperty("transport", out var trElem) && trElem.ValueKind == JsonValueKind.Object)
        {
            if (trElem.TryGetProperty("type", out var trTypeProp)) transportType = trTypeProp.GetString()?.ToLowerInvariant() ?? "tcp";
            if (trElem.TryGetProperty("path", out var trPathProp)) wsPath = trPathProp.GetString() ?? "/";
            if (trElem.TryGetProperty("service_name", out var trSnProp)) grpcServiceName = trSnProp.GetString() ?? "";
        }

        var item = new ProxyItem
        {
            Name = tag,
            Host = server,
            Port = port,
            Protocol = proto,
            Uuid = uuid,
            Password = uuid,
            Security = security,
            Sni = sni,
            Flow = flow,
            PublicKey = pbk,
            ShortId = sid,
            Fingerprint = fp,
            TransportType = transportType,
            WsPath = wsPath,
            GrpcServiceName = grpcServiceName,
            Status = ProxyStatus.Unknown
        };

        if (proto is ProxyProtocol.Hysteria2 or ProxyProtocol.Tuic)
        {
            item.TransportType = "";
            item.Fingerprint = "";
            item.Password = Str(ob, "password");
            item.Uuid = proto == ProxyProtocol.Tuic ? Str(ob, "uuid") : "";
            item.CongestionControl = Str(ob, "congestion_control");
            item.UdpRelayMode = Str(ob, "udp_relay_mode");
            if (ob.TryGetProperty("obfs", out var obfsElem) && obfsElem.ValueKind == JsonValueKind.Object)
                item.ObfsPassword = Str(obfsElem, "password");
            if (ob.TryGetProperty("server_ports", out var portsElem))
            {
                // sing-box writes ranges as "20000:30000", links as "20000-30000"
                var ranges = portsElem.ValueKind == JsonValueKind.Array
                    ? portsElem.EnumerateArray().Select(e => e.GetString() ?? "")
                    : new[] { portsElem.GetString() ?? "" };
                item.ServerPorts = string.Join(",", ranges.Where(r => r.Length > 0).Select(r => r.Replace(':', '-')));
            }
            if (ob.TryGetProperty("tls", out var qTls) && qTls.ValueKind == JsonValueKind.Object)
            {
                item.Insecure = qTls.TryGetProperty("insecure", out var insElem) && insElem.ValueKind == JsonValueKind.True;
                if (qTls.TryGetProperty("alpn", out var alpnElem))
                {
                    item.Alpn = alpnElem.ValueKind == JsonValueKind.Array
                        ? string.Join(",", alpnElem.EnumerateArray().Select(e => e.GetString() ?? "").Where(s => s.Length > 0))
                        : alpnElem.GetString() ?? "";
                }
            }
        }

        item.EnsureDeterministicId();
        item.AutoEnrichCountryIfMissing();
        return item;
    }

    public static ProxyItem? ParseVless(string link)
    {
        if (string.IsNullOrWhiteSpace(link) || !link.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            string raw = link[8..];
            string name = "VLESS Сервер";

            int hashIdx = raw.IndexOf('#');
            if (hashIdx != -1)
            {
                name = Uri.UnescapeDataString(raw[(hashIdx + 1)..].Trim());
                raw = raw[..hashIdx];
            }

            int atIdx = raw.IndexOf('@');
            if (atIdx == -1) return null;

            string uuid = raw[..atIdx].Trim();
            string rest = raw[(atIdx + 1)..];

            int qIdx = rest.IndexOf('?');
            string hostPortPart = qIdx != -1 ? rest[..qIdx] : rest;
            string queryString = qIdx != -1 ? rest[(qIdx + 1)..] : "";

            string host;
            int port = 443;

            if (hostPortPart.StartsWith('['))
            {
                int closeBracket = hostPortPart.IndexOf(']');
                if (closeBracket == -1) return null;
                host = hostPortPart[1..closeBracket];
                string afterBracket = hostPortPart[(closeBracket + 1)..];
                if (afterBracket.StartsWith(':'))
                {
                    int.TryParse(afterBracket[1..].TrimEnd('/'), out port);
                }
            }
            else if (hostPortPart.Contains(':'))
            {
                var hpTokens = hostPortPart.Split(':', 2);
                host = hpTokens[0];
                int.TryParse(hpTokens[1].TrimEnd('/'), out port);
            }
            else
            {
                host = hostPortPart.TrimEnd('/');
            }

            if (string.IsNullOrWhiteSpace(host) || port <= 0 || port > 65535) return null;

            var queryParams = ParseQueryString(queryString);

            string security = queryParams.GetValueOrDefault("security", "none").ToLowerInvariant();
            string sni = queryParams.GetValueOrDefault("sni", queryParams.GetValueOrDefault("peer", ""));
            string fp = queryParams.GetValueOrDefault("fp", queryParams.GetValueOrDefault("fingerprint", "chrome"));
            string pbk = queryParams.GetValueOrDefault("pbk", queryParams.GetValueOrDefault("publicKey", queryParams.GetValueOrDefault("public_key", "")));
            string sid = queryParams.GetValueOrDefault("sid", queryParams.GetValueOrDefault("shortId", queryParams.GetValueOrDefault("short_id", "")));
            string spx = queryParams.GetValueOrDefault("spx", "");
            string type = queryParams.GetValueOrDefault("type", queryParams.GetValueOrDefault("net", "tcp")).ToLowerInvariant();
            string path = queryParams.GetValueOrDefault("path", "");
            string wsHost = queryParams.GetValueOrDefault("host", "");
            string serviceName = queryParams.GetValueOrDefault("serviceName", queryParams.GetValueOrDefault("service_name", ""));
            string flow = queryParams.GetValueOrDefault("flow", "");
            string alpn = queryParams.GetValueOrDefault("alpn", "");

            if (string.IsNullOrEmpty(serviceName) && type == "grpc" && !string.IsNullOrEmpty(path))
            {
                serviceName = path;
            }

            return new ProxyItem
            {
                Name = !string.IsNullOrWhiteSpace(name) ? name : $"{host}:{port}",
                Host = host,
                Port = port > 0 ? port : 443,
                Protocol = ProxyProtocol.Vless,
                Uuid = uuid,
                Flow = flow,
                Security = security,
                Sni = sni,
                Fingerprint = fp,
                PublicKey = pbk,
                ShortId = sid,
                SpiderX = spx,
                TransportType = type,
                WsPath = path,
                WsHost = wsHost,
                GrpcServiceName = serviceName,
                Alpn = alpn,
                RawLink = link,
                Status = ProxyStatus.Unknown
            };
        }
        catch
        {
            return null;
        }
    }

    public static ProxyItem? ParseTrojan(string link)
    {
        if (string.IsNullOrWhiteSpace(link) || !link.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            string raw = link[9..];
            string name = "Trojan Сервер";

            int hashIdx = raw.IndexOf('#');
            if (hashIdx != -1)
            {
                name = Uri.UnescapeDataString(raw[(hashIdx + 1)..].Trim());
                raw = raw[..hashIdx];
            }

            int atIdx = raw.IndexOf('@');
            if (atIdx == -1) return null;

            string password = Uri.UnescapeDataString(raw[..atIdx].Trim());
            string rest = raw[(atIdx + 1)..];

            int qIdx = rest.IndexOf('?');
            string hostPortPart = qIdx != -1 ? rest[..qIdx] : rest;
            string queryString = qIdx != -1 ? rest[(qIdx + 1)..] : "";

            string host;
            int port = 443;

            if (hostPortPart.StartsWith('['))
            {
                int closeBracket = hostPortPart.IndexOf(']');
                if (closeBracket == -1) return null;
                host = hostPortPart[1..closeBracket];
                string afterBracket = hostPortPart[(closeBracket + 1)..];
                if (afterBracket.StartsWith(':'))
                    int.TryParse(afterBracket[1..].TrimEnd('/'), out port);
            }
            else if (hostPortPart.Contains(':'))
            {
                var hpTokens = hostPortPart.Split(':', 2);
                host = hpTokens[0];
                int.TryParse(hpTokens[1].TrimEnd('/'), out port);
            }
            else
            {
                host = hostPortPart.TrimEnd('/');
            }

            if (string.IsNullOrWhiteSpace(host) || port <= 0 || port > 65535) return null;

            var queryParams = ParseQueryString(queryString);

            string sni = queryParams.GetValueOrDefault("sni", queryParams.GetValueOrDefault("peer", ""));
            string type = queryParams.GetValueOrDefault("type", queryParams.GetValueOrDefault("net", "tcp")).ToLowerInvariant();
            string path = queryParams.GetValueOrDefault("path", "");
            string wsHost = queryParams.GetValueOrDefault("host", "");
            string serviceName = queryParams.GetValueOrDefault("serviceName", queryParams.GetValueOrDefault("service_name", ""));
            string alpn = queryParams.GetValueOrDefault("alpn", "");
            string fp = queryParams.GetValueOrDefault("fp", queryParams.GetValueOrDefault("fingerprint", "chrome"));

            if (string.IsNullOrEmpty(serviceName) && type == "grpc" && !string.IsNullOrEmpty(path))
            {
                serviceName = path;
            }

            return new ProxyItem
            {
                Name = !string.IsNullOrWhiteSpace(name) ? name : $"{host}:{port}",
                Host = host,
                Port = port > 0 ? port : 443,
                Protocol = ProxyProtocol.Trojan,
                Password = password,
                Uuid = password,
                Security = "tls",
                Sni = sni,
                Fingerprint = fp,
                TransportType = type,
                WsPath = path,
                WsHost = wsHost,
                GrpcServiceName = serviceName,
                Alpn = alpn,
                RawLink = link,
                Status = ProxyStatus.Unknown
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// hysteria2://password@host:port/?sni=..&amp;obfs=salamander&amp;obfs-password=..&amp;insecure=1#name (also hy2://).
    /// The port part may list several ports and ranges ("443,20000-30000") for port hopping; so may mport=.
    /// </summary>
    public static ProxyItem? ParseHysteria2(string link)
    {
        if (string.IsNullOrWhiteSpace(link)) return null;
        string scheme = link.StartsWith("hy2://", StringComparison.OrdinalIgnoreCase) ? "hy2://" :
                        link.StartsWith("hysteria2://", StringComparison.OrdinalIgnoreCase) ? "hysteria2://" : "";
        if (scheme.Length == 0) return null;

        try
        {
            if (!SplitQuicLink(link[scheme.Length..], out string auth, out string host, out string portSpec, out var query, out string name))
                return null;

            var ports = portSpec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            string mport = query.GetValueOrDefault("mport", "");
            ports.AddRange(mport.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            ports = ports.Distinct().ToList();

            int port = 443;
            string? single = ports.FirstOrDefault(p => !p.Contains('-'));
            string? first = single ?? ports.FirstOrDefault();
            if (first != null && !int.TryParse(first.Split('-')[0], out port)) return null;
            if (port <= 0 || port > 65535) return null;
            bool hopping = ports.Count > 1 || ports.Any(p => p.Contains('-'));

            string obfs = query.GetValueOrDefault("obfs", "");
            string obfsPassword = query.GetValueOrDefault("obfs-password", query.GetValueOrDefault("obfs_password", ""));

            return new ProxyItem
            {
                Name = !string.IsNullOrWhiteSpace(name) ? name : $"{host}:{port}",
                Host = host,
                Port = port,
                Protocol = ProxyProtocol.Hysteria2,
                Password = auth,
                Security = "tls",
                Sni = query.GetValueOrDefault("sni", query.GetValueOrDefault("peer", "")),
                ObfsPassword = obfs.Length == 0 || obfs.Equals("salamander", StringComparison.OrdinalIgnoreCase) ? obfsPassword : "",
                ServerPorts = hopping ? string.Join(",", ports) : "",
                Insecure = IsTrue(query.GetValueOrDefault("insecure", query.GetValueOrDefault("allowInsecure", ""))),
                Alpn = query.GetValueOrDefault("alpn", ""),
                TransportType = "",
                Fingerprint = "",
                RawLink = link,
                Status = ProxyStatus.Unknown
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>tuic://uuid:password@host:port?congestion_control=bbr&amp;udp_relay_mode=native&amp;alpn=h3&amp;sni=..#name</summary>
    public static ProxyItem? ParseTuic(string link)
    {
        if (string.IsNullOrWhiteSpace(link) || !link.StartsWith("tuic://", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            if (!SplitQuicLink(link[7..], out string auth, out string host, out string portSpec, out var query, out string name))
                return null;

            int colon = auth.IndexOf(':');
            if (colon <= 0) return null; // TUIC v5 needs both the UUID and the password
            string uuid = auth[..colon].Trim();
            string password = auth[(colon + 1)..];

            int port = 443;
            if (portSpec.Length > 0 && !int.TryParse(portSpec, out port)) return null;
            if (port <= 0 || port > 65535) return null;

            return new ProxyItem
            {
                Name = !string.IsNullOrWhiteSpace(name) ? name : $"{host}:{port}",
                Host = host,
                Port = port,
                Protocol = ProxyProtocol.Tuic,
                Uuid = uuid,
                Password = password,
                Security = "tls",
                Sni = query.GetValueOrDefault("sni", query.GetValueOrDefault("peer", "")),
                CongestionControl = query.GetValueOrDefault("congestion_control", query.GetValueOrDefault("congestion-control", "")).ToLowerInvariant(),
                UdpRelayMode = query.GetValueOrDefault("udp_relay_mode", query.GetValueOrDefault("udp-relay-mode", "")).ToLowerInvariant(),
                Insecure = IsTrue(query.GetValueOrDefault("allow_insecure", query.GetValueOrDefault("insecure", query.GetValueOrDefault("allowInsecure", "")))),
                Alpn = query.GetValueOrDefault("alpn", ""),
                TransportType = "",
                Fingerprint = "",
                RawLink = link,
                Status = ProxyStatus.Unknown
            };
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Splits "auth@host:ports/?query#name" (the part after the scheme) of a Hysteria2/TUIC link.</summary>
    private static bool SplitQuicLink(string raw, out string auth, out string host, out string portSpec,
                                      out Dictionary<string, string> query, out string name)
    {
        auth = host = portSpec = name = "";
        query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        int hashIdx = raw.IndexOf('#');
        if (hashIdx != -1)
        {
            name = Uri.UnescapeDataString(raw[(hashIdx + 1)..].Trim());
            raw = raw[..hashIdx];
        }

        int qIdx = raw.IndexOf('?');
        string main = qIdx != -1 ? raw[..qIdx] : raw;
        if (qIdx != -1)
        {
            foreach (var kv in ParseQueryString(raw[(qIdx + 1)..])) query[kv.Key] = kv.Value;
        }

        int atIdx = main.LastIndexOf('@');
        if (atIdx <= 0) return false;
        auth = Uri.UnescapeDataString(main[..atIdx]);
        string hostPort = main[(atIdx + 1)..].TrimEnd('/');

        if (hostPort.StartsWith('['))
        {
            int close = hostPort.IndexOf(']');
            if (close == -1) return false;
            host = hostPort[1..close];
            string after = hostPort[(close + 1)..];
            if (after.StartsWith(':')) portSpec = after[1..];
        }
        else
        {
            int colon = hostPort.IndexOf(':');
            host = colon != -1 ? hostPort[..colon] : hostPort;
            if (colon != -1) portSpec = hostPort[(colon + 1)..];
        }

        return !string.IsNullOrWhiteSpace(host) && auth.Length > 0;
    }

    private static bool IsTrue(string value) =>
        value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase);

    public static ProxyItem? ParseShadowsocks(string link)
    {
        if (string.IsNullOrWhiteSpace(link) || !link.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            string raw = link[5..];
            string name = "Shadowsocks";

            int hashIdx = raw.IndexOf('#');
            if (hashIdx != -1)
            {
                name = Uri.UnescapeDataString(raw[(hashIdx + 1)..].Trim());
                raw = raw[..hashIdx];
            }

            string method = "aes-256-gcm";
            string password = "";
            string host = "";
            int port = 8388;

            if (raw.Contains('@'))
            {
                // Format: ss://BASE64(method:password)@host:port or ss://method:password@host:port
                var atParts = raw.Split('@', 2);
                string authPart = atParts[0];
                string hostPart = atParts[1].Split('?', '/')[0].Trim();

                // Decode userInfo if base64
                string authDecoded = authPart;
                byte[]? decodedBytes = TryDecodeBase64Safe(authPart);
                if (decodedBytes != null)
                {
                    authDecoded = Encoding.UTF8.GetString(decodedBytes);
                }

                if (authDecoded.Contains(':'))
                {
                    var authParts = authDecoded.Split(':', 2);
                    method = authParts[0];
                    password = authParts[1];
                }
                else
                {
                    password = authDecoded;
                }

                if (hostPart.StartsWith('['))
                {
                    int closeBracket = hostPart.IndexOf(']');
                    host = hostPart[1..closeBracket];
                    if (hostPart.Length > closeBracket + 1 && hostPart[closeBracket + 1] == ':')
                        int.TryParse(hostPart[(closeBracket + 2)..], out port);
                }
                else if (hostPart.Contains(':'))
                {
                    var hParts = hostPart.Split(':', 2);
                    host = hParts[0];
                    int.TryParse(hParts[1], out port);
                }
                else
                {
                    host = hostPart;
                }
            }
            else
            {
                // Format: ss://BASE64(method:password@host:port)
                byte[]? decodedBytes = TryDecodeBase64Safe(raw);
                if (decodedBytes == null) return null;

                string decoded = Encoding.UTF8.GetString(decodedBytes);
                return ParseShadowsocks($"ss://{decoded}" + (!string.IsNullOrEmpty(name) ? $"#{Uri.EscapeDataString(name)}" : ""));
            }

            if (string.IsNullOrWhiteSpace(host) || port <= 0 || port > 65535)
                return null;

            return new ProxyItem
            {
                Name = !string.IsNullOrWhiteSpace(name) ? name : $"{host}:{port}",
                Host = host,
                Port = port,
                Protocol = ProxyProtocol.Shadowsocks,
                Password = password,
                Security = method,
                RawLink = link,
                Status = ProxyStatus.Unknown
            };
        }
        catch
        {
            return null;
        }
    }

    public static ProxyItem? ParseVmess(string link)
    {
        if (string.IsNullOrWhiteSpace(link) || !link.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            string raw = link[8..].Trim();
            byte[]? decodedBytes = TryDecodeBase64Safe(raw);
            if (decodedBytes == null) return null;

            string jsonString = Encoding.UTF8.GetString(decodedBytes);
            using var doc = JsonDocument.Parse(jsonString);
            var root = doc.RootElement;

            string name = root.TryGetProperty("ps", out var psProp) ? psProp.GetString() ?? "" : "";
            string host = root.TryGetProperty("add", out var addProp) ? addProp.GetString() ?? "" : "";

            int port = 443;
            if (root.TryGetProperty("port", out var portProp))
            {
                if (portProp.ValueKind == JsonValueKind.Number)
                    port = portProp.GetInt32();
                else if (portProp.ValueKind == JsonValueKind.String && int.TryParse(portProp.GetString(), out int p))
                    port = p;
            }

            string uuid = root.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
            int aid = 0;
            if (root.TryGetProperty("aid", out var aidProp))
            {
                if (aidProp.ValueKind == JsonValueKind.Number) aid = aidProp.GetInt32();
                else if (aidProp.ValueKind == JsonValueKind.String && int.TryParse(aidProp.GetString(), out int a)) aid = a;
            }

            string net = root.TryGetProperty("net", out var netProp) ? netProp.GetString() ?? "tcp" : "tcp";
            string scy = root.TryGetProperty("scy", out var scyProp) ? scyProp.GetString() ?? "auto" : "auto";
            string tls = root.TryGetProperty("tls", out var tlsProp) ? tlsProp.GetString() ?? "none" : "none";
            string sni = root.TryGetProperty("sni", out var sniProp) ? sniProp.GetString() ?? "" : "";
            string wsHost = root.TryGetProperty("host", out var hostProp) ? hostProp.GetString() ?? "" : "";
            string path = root.TryGetProperty("path", out var pathProp) ? pathProp.GetString() ?? "" : "";
            string alpn = root.TryGetProperty("alpn", out var alpnProp) ? alpnProp.GetString() ?? "" : "";
            string fp = root.TryGetProperty("fp", out var fpProp) ? fpProp.GetString() ?? "chrome" : "chrome";

            if (string.IsNullOrWhiteSpace(host) || port <= 0 || port > 65535)
                return null;

            return new ProxyItem
            {
                Name = !string.IsNullOrWhiteSpace(name) ? name : $"{host}:{port}",
                Host = host,
                Port = port,
                Protocol = ProxyProtocol.Vmess,
                Uuid = uuid,
                AlterId = aid,
                Security = tls.Equals("tls", StringComparison.OrdinalIgnoreCase) ? "tls" : scy,
                TransportType = net.ToLowerInvariant(),
                Sni = !string.IsNullOrEmpty(sni) ? sni : wsHost,
                WsHost = wsHost,
                WsPath = path,
                GrpcServiceName = net.Equals("grpc", StringComparison.OrdinalIgnoreCase) ? path : "",
                Alpn = alpn,
                Fingerprint = fp,
                RawLink = link,
                Status = ProxyStatus.Unknown
            };
        }
        catch
        {
            return null;
        }
    }

    public static string ExtractActualSubscriptionUrl(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "";

        string clean = input.Trim().Trim('"', '\'', '`', '<', '>');

        // 1. Check for sub:// base64 scheme
        if (clean.StartsWith("sub://", StringComparison.OrdinalIgnoreCase))
        {
            string b64 = clean[6..].Trim();
            byte[]? decoded = TryDecodeBase64Safe(b64);
            if (decoded != null)
            {
                string decodedStr = Encoding.UTF8.GetString(decoded).Trim();
                if (decodedStr.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                    decodedStr.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    return decodedStr;
                }
            }
        }

        // 2. Unescape if contains URL-encoded slashes/colons
        if (clean.Contains("%3A", StringComparison.OrdinalIgnoreCase) || clean.Contains("%2F", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                clean = Uri.UnescapeDataString(clean);
            }
            catch { }
        }

        // 3. Check for parameter ?url= or &url= (e.g., v2rayng://install-sub?url=...)
        int urlParamIdx = clean.IndexOf("url=", StringComparison.OrdinalIgnoreCase);
        if (urlParamIdx != -1)
        {
            string subParam = clean[(urlParamIdx + 4)..];
            int ampIdx = subParam.IndexOf('&');
            if (ampIdx != -1) subParam = subParam[..ampIdx];
            int hashIdx = subParam.IndexOf('#');
            if (hashIdx != -1) subParam = subParam[..hashIdx];
            subParam = subParam.Trim();
            if (subParam.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                subParam.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return subParam;
            }
        }

        // 4. Locate direct embedded http:// or https:// (handles happ://add/https://..., etc.)
        int httpIdx = clean.IndexOf("https://", StringComparison.OrdinalIgnoreCase);
        if (httpIdx == -1)
            httpIdx = clean.IndexOf("http://", StringComparison.OrdinalIgnoreCase);

        if (httpIdx != -1)
        {
            string candidate = clean[httpIdx..].Trim();
            int spaceIdx = candidate.IndexOf(' ');
            if (spaceIdx != -1) candidate = candidate[..spaceIdx];
            return candidate;
        }

        return clean;
    }

    public static bool IsSubscriptionUrl(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        string normalized = ExtractActualSubscriptionUrl(input);
        if (string.IsNullOrWhiteSpace(normalized)) return false;

        if (!normalized.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
            !normalized.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return false;

        // If it contains @, it's user:pass@host:port (single proxy)
        if (normalized.Contains('@')) return false;

        string lower = normalized.ToLowerInvariant();
        if (lower.Contains("/sub") ||
            lower.Contains("sub.") ||
            lower.Contains("subscription") ||
            lower.Contains("token=") ||
            lower.Contains("key=") ||
            lower.Contains("/api/v1/client/subscribe") ||
            lower.Contains("/api/v1/client/") ||
            lower.Contains("/subscribe") ||
            lower.Contains("/download") ||
            lower.Contains("/clash") ||
            lower.Contains("/sing-box") ||
            lower.Contains("/v2ray") ||
            lower.Contains("/xray"))
        {
            return true;
        }

        if (Uri.TryCreate(normalized, UriKind.Absolute, out var uri))
        {
            string host = uri.Host.ToLowerInvariant();
            if (host.Contains("sub") || host.Contains("subscribe") || host.Contains("feed"))
                return true;

            if (uri.PathAndQuery.Length > 1 || uri.Query.Length > 1)
                return true;
        }
        return false;
    }

    public const string CloudflareRelayUrl = "https://dark-moon-b211.airtoneaokirazer94.workers.dev/?url=";

    private static readonly string[] UserAgentsToTry = new[]
    {
        "Happ/3.0.0",
        "sing-box/1.10.0",
        "v2rayNG/1.8.19",
        "ClashMeta/1.18.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"
    };

    /// <summary>Downloads a subscription: its servers plus what the provider says about the plan.</summary>
    public static async Task<SubscriptionFetchResult> FetchSubscriptionDetailedAsync(string url, CancellationToken ct = default)
    {
        var empty = new SubscriptionFetchResult();
        if (string.IsNullOrWhiteSpace(url)) return empty with { Error = "Пустая ссылка" };

        url = ExtractActualSubscriptionUrl(url);
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return empty with { Error = "Это не ссылка" };

        if (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp)
            return empty with { Error = "Ссылка должна начинаться с http:// или https://" };

        // SSRF Protection: Disallow localhost, private ranges, link-local, cloud metadata
        string host = uri.DnsSafeHost.ToLowerInvariant();
        var blockedLocal = empty with { Error = "Локальные адреса не поддерживаются" };
        if (host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "169.254.169.254" ||
            host.EndsWith(".internal") || host.EndsWith(".local") || host.EndsWith(".localhost"))
        {
            return blockedLocal;
        }

        if (IPAddress.TryParse(host, out var ip))
        {
            byte[] bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (bytes[0] == 127 || bytes[0] == 10 ||
                   (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                   (bytes[0] == 192 && bytes[1] == 168) ||
                   (bytes[0] == 169 && bytes[1] == 254) ||
                    bytes[0] == 0)
                {
                    return blockedLocal;
                }
            }
            else if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal)
            {
                return blockedLocal;
            }
        }

        string deviceHwid = GetOrGenerateDeviceHwid();

        // 1. Check if Zion VPN tunnel is currently active (local SOCKS5 bridge on 127.0.0.1:9050)
        bool isTunnelActive = await IsLocalTunnelActiveAsync(9050, 100);

        // 2. Primary attempt: Direct connection (or active SOCKS5 VPN tunnel if running)
        var result = await ExecuteFetchAsync(uri, url, deviceHwid, isRelay: false, isTunnelActive: isTunnelActive, ct: ct);
        if (result.Items.Count > 0 || result.IsFinal)
        {
            return result;
        }

        // 3. Fallback attempt: If direct request was blocked by TSPU/ISP (timeout, reset, 502, network fail),
        // route through Cloudflare Worker relay out-of-region
        bool shouldTryRelay = !url.Contains("workers.dev/?url=");
        if (shouldTryRelay)
        {
            string encodedTarget = Uri.EscapeDataString(url);
            string relayUrl = $"{CloudflareRelayUrl}{encodedTarget}";
            if (Uri.TryCreate(relayUrl, UriKind.Absolute, out var relayUri))
            {
                System.Diagnostics.Debug.WriteLine($"[ProxyParser] Direct fetch failed. Attempting fallback via Cloudflare Relay: {relayUrl}");
                var relayed = await ExecuteFetchAsync(relayUri, url, deviceHwid, isRelay: true, isTunnelActive: false, ct: ct);
                if (relayed.Items.Count > 0)
                {
                    System.Diagnostics.Debug.WriteLine($"[ProxyParser] Cloudflare Relay SUCCESS: Loaded {relayed.Items.Count} proxies!");
                    return relayed;
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Reads the de-facto standard header "subscription-userinfo: upload=1; download=2; total=3; expire=1700000000".
    /// Unknown or broken parts are skipped; expire=0 means "no end date".
    /// </summary>
    public static (long Upload, long Download, long Total, DateTime? Expire) ParseSubscriptionUserInfo(string? header)
    {
        long up = 0, down = 0, total = 0;
        DateTime? expire = null;
        if (string.IsNullOrWhiteSpace(header)) return (up, down, total, expire);

        foreach (string part in header.Split(';', ',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0) continue;
            string key = part[..eq].Trim().ToLowerInvariant();
            if (!long.TryParse(part[(eq + 1)..].Trim(), out long value) || value < 0) continue;

            switch (key)
            {
                case "upload": up = value; break;
                case "download": down = value; break;
                case "total": total = value; break;
                case "expire":
                    if (value > 0 && value < 253402300800) // before year 10000
                        expire = DateTimeOffset.FromUnixTimeSeconds(value).LocalDateTime;
                    break;
            }
        }
        return (up, down, total, expire);
    }

    /// <summary>"profile-title" is plain text or "base64:..." (that is how non-Latin names are sent).</summary>
    public static string DecodeProfileTitle(string? header)
    {
        if (string.IsNullOrWhiteSpace(header)) return "";
        string value = header.Trim();
        if (value.StartsWith("base64:", StringComparison.OrdinalIgnoreCase))
        {
            byte[]? bytes = TryDecodeBase64Safe(value[7..].Trim());
            value = bytes != null ? Encoding.UTF8.GetString(bytes) : "";
        }
        value = value.Trim();
        return value.Length > 60 ? value[..60] : value;
    }

    private static async Task<bool> IsLocalTunnelActiveAsync(int port = 9050, int timeoutMs = 80)
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var cts = new CancellationTokenSource(timeoutMs);
            await socket.ConnectAsync(new IPEndPoint(IPAddress.Loopback, port), cts.Token);
            return socket.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<SubscriptionFetchResult> ExecuteFetchAsync(
        Uri targetUri,
        string originalUrl,
        string deviceHwid,
        bool isRelay,
        bool isTunnelActive,
        CancellationToken ct)
    {
        var items = new List<ProxyItem>();
        string error = "Сервер подписки не отвечает";
        TimeSpan timeout = isRelay
            ? TimeSpan.FromSeconds(8)
            : (isTunnelActive ? TimeSpan.FromSeconds(5) : TimeSpan.FromMilliseconds(1500));

        foreach (var ua in UserAgentsToTry)
        {
            try
            {
                using var handler = new SocketsHttpHandler
                {
                    AllowAutoRedirect = true,
                    MaxAutomaticRedirections = 5,
                    ConnectTimeout = timeout
                };

                if (isTunnelActive)
                {
                    handler.Proxy = new WebProxy("socks5://127.0.0.1:9050");
                }
                else if (KillSwitchFirewall.IsArmed)
                {
                    // Tunnel is down and the Kill Switch blocks the system resolver:
                    // Zion is permitted, so it looks the host up itself.
                    handler.ConnectCallback = DirectDns.ConnectAsync;
                }

                using var client = new HttpClient(handler) { Timeout = timeout };
                client.DefaultRequestHeaders.UserAgent.ParseAdd(ua);
                client.DefaultRequestHeaders.Add("X-Hwid", deviceHwid);
                client.DefaultRequestHeaders.Add("Accept", "*/*");

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(timeout);

                using var response = await client.GetAsync(targetUri, cts.Token);
                if (response.StatusCode == HttpStatusCode.NotFound)
                {
                    // Endpoint doesn't exist; do not keep retrying with other UAs or relay
                    return new SubscriptionFetchResult { Error = "Подписка не найдена (ошибка 404): возможно, ссылка устарела", IsFinal = true };
                }

                if (response.StatusCode == HttpStatusCode.BadGateway && !isRelay)
                {
                    // 502 from direct connection -> TSPPU / server issue, break UA loop to try relay
                    error = "Сервер подписки недоступен (ошибка 502)";
                    break;
                }

                if (!response.IsSuccessStatusCode)
                {
                    error = response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                        ? $"Доступ к подписке закрыт (ошибка {(int)response.StatusCode}): возможно, она истекла"
                        : $"Сервер подписки ответил ошибкой {(int)response.StatusCode}";
                    continue;
                }

                // 10 MB maximum limit protection
                long? contentLength = response.Content.Headers.ContentLength;
                if (contentLength.HasValue && contentLength.Value > 10 * 1024 * 1024)
                    return new SubscriptionFetchResult { Error = "Ответ подписки слишком большой", IsFinal = true };

                string content = (await response.Content.ReadAsStringAsync(cts.Token)).Trim();
                if (string.IsNullOrWhiteSpace(content))
                {
                    error = "Подписка пустая: в ней нет серверов";
                    continue;
                }

                // Try Base64 decode
                byte[]? decodedBytes = TryDecodeBase64Safe(content);
                string decoded = decodedBytes != null ? Encoding.UTF8.GetString(decodedBytes) : content;

                items = ParseBulk(decoded);
                if (items.Count > 0)
                {
                    foreach (var item in items)
                    {
                        item.IsFromSubscription = true;
                        item.SubscriptionUrl = originalUrl;
                        item.EnsureDeterministicId();
                        item.AutoEnrichCountryIfMissing();
                    }

                    var info = ParseSubscriptionUserInfo(HeaderValue(response, "subscription-userinfo"));
                    string title = DecodeProfileTitle(HeaderValue(response, "profile-title"));
                    if (string.IsNullOrWhiteSpace(title))
                        title = response.Content.Headers.ContentDisposition?.FileNameStar?.Trim('"')
                                ?? response.Content.Headers.ContentDisposition?.FileName?.Trim('"') ?? "";

                    return new SubscriptionFetchResult
                    {
                        Items = items,
                        Title = title.Trim(),
                        Upload = info.Upload,
                        Download = info.Download,
                        Total = info.Total,
                        Expire = info.Expire
                    };
                }

                error = "В ответе не нашлось серверов: ссылка не похожа на подписку";
            }
            catch (Exception ex) when (ex is OperationCanceledException || ex is HttpRequestException || ex is SocketException)
            {
                error = ex is OperationCanceledException ? "Сервер подписки не ответил вовремя" : "Не удалось соединиться с сервером подписки";

                // Network drop / TSPPU reset / connection timeout on direct attempt:
                // Immediately abort the UA loop so we don't waste 5 * 1.5s waiting for nothing.
                if (!isRelay && !isTunnelActive)
                {
                    System.Diagnostics.Debug.WriteLine($"[ProxyParser] Direct connection failed ({ex.Message}). Aborting UA loop to try relay.");
                    break;
                }
            }
            catch
            {
                // Other transient error, try next UA
            }
        }

        return new SubscriptionFetchResult { Error = error };
    }

    private static string? HeaderValue(HttpResponseMessage response, string name)
    {
        if (response.Headers.TryGetValues(name, out var values)) return values.FirstOrDefault();
        if (response.Content.Headers.TryGetValues(name, out var contentValues)) return contentValues.FirstOrDefault();
        return null;
    }

    public static byte[]? TryDecodeBase64Safe(string text)
    {
        try
        {
            string clean = text.Replace("\r", "").Replace("\n", "").Replace(" ", "").Trim();
            if (string.IsNullOrEmpty(clean)) return null;

            // Handle URL encoded characters (e.g. %3D)
            if (clean.Contains('%'))
            {
                try { clean = Uri.UnescapeDataString(clean); } catch { }
            }

            clean = clean.Replace('-', '+').Replace('_', '/');
            int mod = clean.Length % 4;
            if (mod == 2) clean += "==";
            else if (mod == 3) clean += "=";
            else if (mod == 1) return null; // Invalid base64 length

            return Convert.FromBase64String(clean);
        }
        catch
        {
            return null;
        }
    }

    private static string Str(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query)) return result;

        if (query.StartsWith('?')) query = query[1..];

        var pairs = query.Split('&', StringSplitOptions.RemoveEmptyEntries);
        foreach (var pair in pairs)
        {
            int eqIdx = pair.IndexOf('=');
            if (eqIdx != -1)
            {
                string key = pair[..eqIdx].Trim();
                string val = Uri.UnescapeDataString(pair[(eqIdx + 1)..].Trim());
                result[key] = val;
            }
            else
            {
                result[pair.Trim()] = "";
            }
        }

        return result;
    }
}
