using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Zion.Models;

namespace Zion.Services;

public static class ProxyCheckerService
{
    private static readonly SemaphoreSlim _pingThrottle = new(4, 4);

    public static async Task FastPingProxyAsync(ProxyItem proxy, CancellationToken ct = default)
    {
        await _pingThrottle.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            string host = proxy.CleanHost;
            int port = proxy.Port;

            using var pingCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            pingCts.CancelAfter(2500);

            IPAddress? targetIp = null;
            if (IPAddress.TryParse(host, out var parsed))
            {
                if (parsed.AddressFamily == AddressFamily.InterNetwork)
                    targetIp = parsed;
            }
            else
            {
                try
                {
                    // Falls back to Zion's own DNS query when the Kill Switch keeps the system resolver offline
                    var resolved = await DirectDns.ResolveAsync(host, pingCts.Token).ConfigureAwait(false);
                    targetIp = resolved.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                }
                catch { }
            }

            if (targetIp == null)
            {
                proxy.Status = ProxyStatus.Offline;
                proxy.PingMs = -1;
                return;
            }

            // Hysteria2 / TUIC listen on UDP only: a TCP connect would fail even on a healthy server,
            // and a QUIC handshake from here would be its own fingerprint. The name resolves - that's all we know.
            if (proxy.UsesUdpTransport)
            {
                proxy.Status = ProxyStatus.Unknown;
                proxy.PingMs = -1;
                proxy.LastChecked = DateTime.Now;
                return;
            }

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

            // While the tunnel is up an ordinary socket would be answered by the tunnel itself (a fake 0 ms).
            // Bound to the real adapter, the check goes straight to the server.
            IPAddress? bypass = InternetProbe.TunnelBypassAddressCached();
            if (bypass != null)
            {
                try { socket.Bind(new IPEndPoint(bypass, 0)); } catch { }
            }

            var sw = Stopwatch.StartNew();
            await socket.ConnectAsync(new IPEndPoint(targetIp, port), pingCts.Token).ConfigureAwait(false);

            // Measure true application-layer round-trip time across the internet
            if (proxy.Protocol == ProxyProtocol.Http || proxy.Protocol == ProxyProtocol.Https)
            {
                var req = Encoding.ASCII.GetBytes($"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n");
                await socket.SendAsync(req, SocketFlags.None, pingCts.Token).ConfigureAwait(false);
                
                byte[] buf = new byte[256];
                int read = await socket.ReceiveAsync(buf, SocketFlags.None, pingCts.Token).ConfigureAwait(false);
                sw.Stop();

                if (read > 0)
                {
                    proxy.PingMs = Math.Max(1, (int)sw.ElapsedMilliseconds);
                    proxy.Status = ProxyStatus.Online;
                }
                else
                {
                    proxy.Status = ProxyStatus.Offline;
                    proxy.PingMs = -1;
                }
            }
            else if (proxy.Protocol == ProxyProtocol.Socks5)
            {
                byte[] greeting = new byte[] { 0x05, 0x01, 0x00 };
                await socket.SendAsync(greeting, SocketFlags.None, pingCts.Token).ConfigureAwait(false);

                byte[] buf = new byte[2];
                int read = await socket.ReceiveAsync(buf, SocketFlags.None, pingCts.Token).ConfigureAwait(false);
                sw.Stop();

                if (read >= 2 && buf[0] == 0x05)
                {
                    proxy.PingMs = Math.Max(1, (int)sw.ElapsedMilliseconds);
                    proxy.Status = ProxyStatus.Online;
                }
                else
                {
                    proxy.Status = ProxyStatus.Offline;
                    proxy.PingMs = -1;
                }
            }
            else // Shadowsocks / VLESS / Reality / Trojan / VMess
            {
                // Port reachability only: the TCP connect time is the latency.
                // We deliberately do NOT start a TLS handshake here. A handshake from .NET carries a
                // non-browser fingerprint together with the masking SNI, which is exactly the kind of
                // anomaly DPI looks for right before the real (Chrome-fingerprinted) connection.
                sw.Stop();
                proxy.PingMs = Math.Max(1, (int)sw.ElapsedMilliseconds);
                proxy.Status = ProxyStatus.Online;
            }

            proxy.LastChecked = DateTime.Now;
        }
        catch
        {
            proxy.Status = ProxyStatus.Offline;
            proxy.PingMs = -1;
        }
        finally
        {
            _pingThrottle.Release();
        }
    }

    public static async Task<bool> CheckProxyAsync(ProxyItem proxy, CancellationToken cancellationToken = default)
    {
        await FastPingProxyAsync(proxy, cancellationToken).ConfigureAwait(false);

        // Resolve country in background if missing
        string host = proxy.CleanHost;
        if (string.IsNullOrEmpty(proxy.Country) || proxy.Country == proxy.CleanHost)
        {
            _ = Task.Run(async () =>
            {
                string country = await GeoIpService.ResolveCountryForHostAsync(host);
                if (!string.IsNullOrEmpty(country))
                {
                    proxy.Country = country;
                }
            });
        }

        return proxy.Status == ProxyStatus.Online;
    }
}
