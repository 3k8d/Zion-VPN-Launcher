using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;

namespace Zion.Services;

public class ClashDelayResult
{
    public bool Success { get; set; }
    public int DelayMs { get; set; } = -1;
    public int StatusCode { get; set; }
    public string ErrorMessage { get; set; } = "";
}

public class ClashApiClient : IDisposable
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private ClientWebSocket? _ws;
    private CancellationTokenSource? _wsCts;
    private string _baseUrl = "";
    private string _wsUrl = "";
    private string _secret = "";

    public event Action<long, long>? OnTraffic;

    /// <summary>Total bytes (up + down) that went through the VPN server since the stream was started.</summary>
    public event Action<long>? OnProxiedTotal;

    /// <summary>Not usable until <see cref="Configure"/> names the session's port and secret.</summary>
    public ClashApiClient() { }

    public ClashApiClient(int port, string secret) => Configure(port, secret);

    /// <summary>Points the client at a core's control API (each session has its own port and secret).</summary>
    public void Configure(int port, string secret)
    {
        _baseUrl = $"http://127.0.0.1:{port}";
        _wsUrl = $"ws://127.0.0.1:{port}/traffic";
        _secret = secret;
    }

    public async Task<bool> IsAliveAsync(int timeoutMs = 500)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}/version");
            if (!string.IsNullOrEmpty(_secret))
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _secret);
            }
            using var resp = await _http.SendAsync(req, cts.Token);
            return resp.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    public void StartTrafficStream()
    {
        StopTrafficStream();
        _wsCts = new CancellationTokenSource();
        _ = TrafficLoopAsync(_wsCts.Token);
        _ = ProxiedTotalLoopAsync(_wsCts.Token);
    }

    public void StopTrafficStream()
    {
        _wsCts?.Cancel();
        try { _ws?.Dispose(); } catch { }
        _ws = null;
    }

    private async Task TrafficLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var ws = new ClientWebSocket();
                _ws = ws;

                if (!string.IsNullOrEmpty(_secret))
                {
                    ws.Options.SetRequestHeader("Authorization", $"Bearer {_secret}");
                }

                await ws.ConnectAsync(new Uri(_wsUrl), ct);

                var buffer = new byte[2048];
                while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct);
                    if (result.MessageType == WebSocketMessageType.Close) break;

                    if (result.Count > 0)
                    {
                        string json = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        using var doc = JsonDocument.Parse(json);
                        var root = doc.RootElement;
                        long up = root.TryGetProperty("up", out var u) ? u.GetInt64() : 0;
                        long down = root.TryGetProperty("down", out var d) ? d.GetInt64() : 0;
                        OnTraffic?.Invoke(up, down);
                    }
                }
            }
            catch
            {
                if (ct.IsCancellationRequested) break;
                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
        }
    }

    /// <summary>
    /// Once a second reads the core's connection list and reports how much has gone through the VPN
    /// outbound. Direct traffic (bypass rules, local network) is not included.
    /// </summary>
    private async Task ProxiedTotalLoopAsync(CancellationToken ct)
    {
        var counter = new ProxiedTrafficCounter("proxy-out");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}/connections");
                    if (!string.IsNullOrEmpty(_secret))
                    {
                        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _secret);
                    }

                    using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode)
                    {
                        string json = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                        if (counter.Apply(json)) OnProxiedTotal?.Invoke(counter.ProxiedBytes);
                    }
                }
                catch when (!ct.IsCancellationRequested) { }

                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { }
    }

    public async Task<ClashDelayResult> GetDelayDetailedAsync(string proxyName, string testUrl = "https://www.gstatic.com/generate_204", int timeoutMs = 3000)
    {
        var result = new ClashDelayResult();
        try
        {
            string encName = Uri.EscapeDataString(proxyName);
            string encUrl = Uri.EscapeDataString(testUrl);
            string url = $"{_baseUrl}/proxies/{encName}/delay?url={encUrl}&timeout={timeoutMs}";

            using var cts = new CancellationTokenSource(timeoutMs + 1500);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrEmpty(_secret))
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _secret);
            }

            using var resp = await _http.SendAsync(req, cts.Token);
            result.StatusCode = (int)resp.StatusCode;

            string content = await resp.Content.ReadAsStringAsync(cts.Token);

            if (resp.IsSuccessStatusCode)
            {
                using var doc = JsonDocument.Parse(content);
                if (doc.RootElement.TryGetProperty("delay", out var d))
                {
                    result.DelayMs = d.GetInt32();
                    result.Success = true;
                    return result;
                }
                result.ErrorMessage = "Ответ Clash API не содержит поля 'delay'.";
                return result;
            }

            try
            {
                using var errDoc = JsonDocument.Parse(content);
                if (errDoc.RootElement.TryGetProperty("message", out var m))
                {
                    result.ErrorMessage = m.GetString() ?? content;
                }
                else
                {
                    result.ErrorMessage = content;
                }
            }
            catch
            {
                result.ErrorMessage = content;
            }

        }
        catch (OperationCanceledException)
        {
            result.ErrorMessage = "Превышено время ожидания ответа от Clash API (таймаут).";
        }
        catch (Exception ex)
        {
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Asks the core's own DNS (the servers its config names) for the IPv4 addresses of a name.
    /// Status is the DNS response code (0 = fine, 3 = no such name); -1 = the core could not answer.
    /// </summary>
    public async Task<(int Status, List<IPAddress> Addresses)> QueryDnsAsync(string name, int timeoutMs = 4000)
    {
        try
        {
            using var cts = new CancellationTokenSource(timeoutMs);
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}/dns/query?name={Uri.EscapeDataString(name)}&type=A");
            if (!string.IsNullOrEmpty(_secret))
            {
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _secret);
            }

            using var resp = await _http.SendAsync(req, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return (-1, new List<IPAddress>());
            return ParseDnsAnswer(await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false));
        }
        catch
        {
            return (-1, new List<IPAddress>());
        }
    }

    /// <summary>Reads the core's /dns/query reply: {"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"},...]}.</summary>
    internal static (int Status, List<IPAddress> Addresses) ParseDnsAnswer(string json)
    {
        var addresses = new List<IPAddress>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            int status = root.TryGetProperty("Status", out var s) && s.TryGetInt32(out int code) ? code : -1;

            if (root.TryGetProperty("Answer", out var answers) && answers.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in answers.EnumerateArray())
                {
                    if (a.TryGetProperty("type", out var t) && t.TryGetInt32(out int type) && type == 1 &&
                        a.TryGetProperty("data", out var d) && IPAddress.TryParse(d.GetString(), out var ip) &&
                        ip.AddressFamily == AddressFamily.InterNetwork && !addresses.Contains(ip))
                    {
                        addresses.Add(ip);
                    }
                }
            }
            return (status, addresses);
        }
        catch
        {
            return (-1, addresses);
        }
    }

    public void Dispose()
    {
        StopTrafficStream();
        _http.Dispose();
    }
}

