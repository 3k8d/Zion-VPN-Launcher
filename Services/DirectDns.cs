using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Zion.Services;

/// <summary>
/// Minimal DNS client that sends its queries from Zion's own process.
///
/// Why it exists: while the Kill Switch is armed, port 53 is closed for everything outside the
/// tunnel, including the Windows DNS service that normally resolves names for every program.
/// Zion still has to look up its own server and subscription hosts to bring the tunnel back,
/// and Zion.exe is on the permit list, so it asks the system DNS servers directly.
/// </summary>
public static class DirectDns
{
    private const int QueryTimeoutMs = 1200;

    /// <summary>
    /// Normal path first (Windows resolver), own query as a fallback when the Kill Switch is armed.
    /// Returns an empty array when the name cannot be resolved.
    /// </summary>
    public static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct = default)
    {
        if (IPAddress.TryParse(host, out var literal)) return new[] { literal };

        bool armed = KillSwitchFirewall.IsArmed;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (armed) cts.CancelAfter(900); // leave time for the fallback
            var viaSystem = await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            if (viaSystem.Length > 0) return viaSystem;
        }
        catch when (!ct.IsCancellationRequested) { }

        if (!armed) return Array.Empty<IPAddress>();
        return await QueryAsync(host, ct).ConfigureAwait(false);
    }

    /// <summary>Asks the system DNS servers for the IPv4 addresses of a name, bypassing the Windows resolver.</summary>
    public static async Task<IPAddress[]> QueryAsync(string host, CancellationToken ct = default)
    {
        foreach (IPAddress server in SystemDnsServers())
        {
            try
            {
                var found = await QueryServerAsync(server, host, ct).ConfigureAwait(false);
                if (found.Length > 0) return found;
            }
            catch when (!ct.IsCancellationRequested) { }
        }
        return Array.Empty<IPAddress>();
    }

    public static async Task<IPAddress[]> QueryServerAsync(IPAddress server, string host, CancellationToken ct = default)
    {
        ushort id = (ushort)RandomNumberGenerator.GetInt32(1, 0x10000);
        byte[] query = BuildQuery(host, id);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(QueryTimeoutMs);

        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(new IPEndPoint(server, 53), cts.Token).ConfigureAwait(false);
        await socket.SendAsync(query, SocketFlags.None, cts.Token).ConfigureAwait(false);

        byte[] buffer = new byte[1500];
        int read = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
        return ParseAddresses(buffer.AsSpan(0, read), id);
    }

    /// <summary>
    /// For SocketsHttpHandler.ConnectCallback: lets an HttpClient resolve through <see cref="ResolveAsync"/>.
    /// </summary>
    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var addresses = await ResolveAsync(context.DnsEndPoint.Host, ct).ConfigureAwait(false);
        IPAddress? target = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses.FirstOrDefault();
        if (target == null) throw new SocketException((int)SocketError.HostNotFound);

        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, context.DnsEndPoint.Port), ct).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>IPv4 DNS servers of the real adapters (the tunnel's own resolver is skipped).</summary>
    public static List<IPAddress> SystemDnsServers()
    {
        var servers = new List<IPAddress>();
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
                if (nic.Description.Contains("wintun", StringComparison.OrdinalIgnoreCase) || nic.Name.Contains("wintun", StringComparison.OrdinalIgnoreCase)) continue;

                var props = nic.GetIPProperties();
                if (props.UnicastAddresses.Any(a => a.Address.ToString().StartsWith("172.19.0."))) continue;

                foreach (IPAddress dns in props.DnsAddresses)
                {
                    if (dns.AddressFamily == AddressFamily.InterNetwork && !servers.Contains(dns))
                        servers.Add(dns);
                }
            }
        }
        catch { }
        return servers;
    }

    /// <summary>Standard recursive query for one A record.</summary>
    internal static byte[] BuildQuery(string host, ushort id)
    {
        using var ms = new MemoryStream();
        ms.WriteByte((byte)(id >> 8));
        ms.WriteByte((byte)id);
        ms.Write(new byte[] { 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // RD, 1 question

        foreach (string label in host.TrimEnd('.').Split('.'))
        {
            byte[] bytes = System.Text.Encoding.ASCII.GetBytes(label);
            if (bytes.Length == 0 || bytes.Length > 63) throw new ArgumentException("Invalid host name", nameof(host));
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes);
        }
        ms.WriteByte(0);
        ms.Write(new byte[] { 0x00, 0x01, 0x00, 0x01 }); // type A, class IN
        return ms.ToArray();
    }

    /// <summary>Collects the A records of a response. Returns nothing for a foreign, failed or malformed reply.</summary>
    internal static IPAddress[] ParseAddresses(ReadOnlySpan<byte> response, ushort expectedId)
    {
        var result = new List<IPAddress>();
        if (response.Length < 12) return result.ToArray();
        if (((response[0] << 8) | response[1]) != expectedId) return result.ToArray();
        if ((response[2] & 0x80) == 0) return result.ToArray();  // not a response
        if ((response[3] & 0x0F) != 0) return result.ToArray();  // error code (NXDOMAIN, SERVFAIL...)

        int questions = (response[4] << 8) | response[5];
        int answers = (response[6] << 8) | response[7];
        int pos = 12;

        for (int i = 0; i < questions; i++)
        {
            if (!SkipName(response, ref pos)) return result.ToArray();
            pos += 4;
        }

        for (int i = 0; i < answers; i++)
        {
            if (!SkipName(response, ref pos) || pos + 10 > response.Length) break;
            int type = (response[pos] << 8) | response[pos + 1];
            int length = (response[pos + 8] << 8) | response[pos + 9];
            pos += 10;
            if (pos + length > response.Length) break;
            if (type == 1 && length == 4) result.Add(new IPAddress(response.Slice(pos, 4)));
            pos += length;
        }
        return result.ToArray();
    }

    private static bool SkipName(ReadOnlySpan<byte> data, ref int pos)
    {
        while (pos < data.Length)
        {
            byte len = data[pos];
            if (len == 0) { pos += 1; return true; }
            if ((len & 0xC0) == 0xC0) { pos += 2; return pos <= data.Length; } // compression pointer ends the name
            pos += 1 + len;
        }
        return false;
    }
}
