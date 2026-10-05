using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Zion.Services;

/// <summary>
/// The two loopback doors the core opens for Zion itself in one session: the control API
/// (status, traffic, checks) and a SOCKS entry used to test DNS and fetch subscriptions through the VPN.
///
/// Ports are not fixed numbers: each session takes ports Windows reports free, so another program
/// (Tor on 9050, a dashboard on 9090, Hyper-V reserved ranges) can never block the connection.
/// Both doors are locked with fresh random credentials, so no other program on the computer
/// can use the SOCKS entry to send traffic past the user's rules or read the API.
/// </summary>
public sealed record LocalEndpoints(int ControlPort, string ControlSecret, int SocksPort, string SocksUser, string SocksPassword)
{
    public static LocalEndpoints Create()
    {
        int control = FreeLoopbackPort();
        int socks = FreeLoopbackPort(exclude: control);
        return new LocalEndpoints(control, RandomSecret(16), socks, RandomSecret(8), RandomSecret(16));
    }

    public NetworkCredential SocksCredential => new(SocksUser, SocksPassword);

    /// <summary>A TCP port nobody listens on right now; Windows picks it, so reserved ranges are skipped.</summary>
    public static int FreeLoopbackPort(int exclude = 0)
    {
        for (int attempt = 0; attempt < 8; attempt++)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            if (port != exclude) return port;
        }
        throw new InvalidOperationException("No free loopback port");
    }

    /// <summary>Lowercase hex of cryptographically random bytes.</summary>
    public static string RandomSecret(int bytes) => Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();

    /// <summary>The core reports a port it could not take as "listen tcp ...: bind: ...".</summary>
    public static bool IsPortConflict(string? coreError) =>
        !string.IsNullOrEmpty(coreError) && coreError.Contains("bind:", StringComparison.OrdinalIgnoreCase);

    // Never print the credentials (logs, exceptions, debugger)
    public override string ToString() => $"control 127.0.0.1:{ControlPort}, socks 127.0.0.1:{SocksPort}";
}
