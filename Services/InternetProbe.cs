using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Zion.Services;

/// <summary>
/// Checks that go around the tunnel on purpose: a socket bound to the address of the real network
/// adapter leaves through that adapter even while the VPN owns the default route.
/// Used to tell "the VPN server died" apart from "the internet itself is down".
/// </summary>
public static class InternetProbe
{
    // Well-known addresses that accept TCP on 443. One answer is enough.
    private static readonly IPEndPoint[] Landmarks =
    {
        new(IPAddress.Parse("1.1.1.1"), 443),
        new(IPAddress.Parse("8.8.8.8"), 443),
        new(IPAddress.Parse("77.88.8.8"), 443),
        new(IPAddress.Parse("9.9.9.9"), 443)
    };

    private static readonly object _cacheLock = new();
    private static IPAddress? _cachedAddress;
    private static long _cachedAtTicks;

    /// <summary>IPv4 address of the adapter that holds the default gateway (never the tunnel).</summary>
    public static IPAddress? FindPhysicalAddress()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                if (nic.Description.Contains("wintun", StringComparison.OrdinalIgnoreCase) || nic.Name.Contains("wintun", StringComparison.OrdinalIgnoreCase)) continue;

                var props = nic.GetIPProperties();
                if (!props.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any))) continue;

                var addr = props.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                if (addr != null) return addr.Address;
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Address to bind to when a measurement has to go around Zion's tunnel, or null when the tunnel
    /// is not up (then an ordinary socket already goes out directly).
    /// Remembered for a few seconds: adapter enumeration is not free and pings come in batches.
    /// </summary>
    public static IPAddress? TunnelBypassAddressCached()
    {
        lock (_cacheLock)
        {
            long now = Environment.TickCount64;
            if (_cachedAtTicks != 0 && now - _cachedAtTicks < 5000) return _cachedAddress;
            _cachedAddress = IsTunnelUp() ? FindPhysicalAddress() : null;
            _cachedAtTicks = now;
            return _cachedAddress;
        }
    }

    /// <summary>True while the sing-box tunnel adapter exists and is up.</summary>
    public static bool IsTunnelUp()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().UnicastAddresses)
                .Any(a => a.Address.ToString() == "172.19.0.1");
        }
        catch { return false; }
    }

    /// <summary>
    /// True when at least one landmark answers past the tunnel.
    /// Null when there is no real adapter to test through (nothing can be concluded).
    /// </summary>
    public static async Task<bool?> IsInternetReachableAsync(int timeoutMs = 2500, CancellationToken ct = default)
    {
        IPAddress? physical = FindPhysicalAddress();
        if (physical == null) return null;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);

        var attempts = Landmarks.Select(target => TryConnectAsync(target, physical, cts.Token)).ToList();
        while (attempts.Count > 0)
        {
            var finished = await Task.WhenAny(attempts).ConfigureAwait(false);
            if (finished.Result)
            {
                cts.Cancel(); // the rest are no longer needed
                return true;
            }
            attempts.Remove(finished);
        }
        return false;
    }

    /// <summary>TCP connect, optionally bound to a specific local address. Never throws.</summary>
    public static async Task<bool> TryConnectAsync(IPEndPoint target, IPAddress? bindTo, CancellationToken ct)
    {
        try
        {
            using var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            if (bindTo != null) socket.Bind(new IPEndPoint(bindTo, 0));
            await socket.ConnectAsync(target, ct).ConfigureAwait(false);
            return socket.Connected;
        }
        catch
        {
            return false;
        }
    }
}
