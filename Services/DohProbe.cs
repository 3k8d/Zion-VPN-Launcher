using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using Zion.Models;

namespace Zion.Services;

/// <summary>One DNS-over-HTTPS server, addressed by IP (so checking it needs no DNS at all).</summary>
public sealed record DohTarget(string Name, string Ip, string Host, string Path);

/// <summary>
/// Checks DNS-over-HTTPS servers the way the tunnel actually uses them: through the VPN (via the
/// core's local SOCKS entry, which requires the session's login), over TLS to the provider's host
/// name, with a real DNS question. A server that only accepts a TCP connection but does not answer
/// DNS counts as failed.
/// </summary>
public static class DohProbe
{
    private const string TestName = "example.com";

    /// <summary>Every server Zion knows, primary and backup addresses, in the providers' order.</summary>
    public static List<DohTarget> AllTargets()
    {
        var list = new List<DohTarget>();
        foreach (var e in DnsConstants.GetAllRealEntries())
        {
            list.Add(new DohTarget(e.DisplayName, e.PrimaryIp, e.DohHost, e.DohPath));
            if (!string.IsNullOrWhiteSpace(e.SecondaryIp))
                list.Add(new DohTarget(e.DisplayName, e.SecondaryIp, e.DohHost, e.DohPath));
        }
        return list;
    }

    /// <summary>
    /// Where to look when the current DNS server stops answering: in Auto mode any other server,
    /// otherwise only the other address of the provider the user chose (their choice is respected).
    /// </summary>
    public static List<DohTarget> FailoverCandidates(DnsProvider mode, DohTarget current)
    {
        var all = AllTargets().Where(t => t.Ip != current.Ip);
        if (mode != DnsProvider.Auto)
        {
            string chosen = DnsConstants.GetEntry(mode).DisplayName;
            all = all.Where(t => t.Name == chosen);
        }
        return all.ToList();
    }

    /// <summary>Round-trip time in ms of a real DNS answer through the tunnel, or null if it failed.</summary>
    public static async Task<int?> ProbeAsync(DohTarget target, LocalEndpoints tunnel, int timeoutMs = 4000, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var sw = Stopwatch.StartNew();
        try
        {
            using var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(IPAddress.Loopback, tunnel.SocksPort, cts.Token).ConfigureAwait(false);
            var net = tcp.GetStream();

            await Socks5ConnectAsync(net, IPAddress.Parse(target.Ip), 443, tunnel.SocksUser, tunnel.SocksPassword, cts.Token).ConfigureAwait(false);

            using var tls = new SslStream(net, leaveInnerStreamOpen: false);
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = target.Host,
                ApplicationProtocols = new List<SslApplicationProtocol> { SslApplicationProtocol.Http11 }
            }, cts.Token).ConfigureAwait(false);

            ushort id = (ushort)Random.Shared.Next(1, 0x10000);
            string dns = Base64Url(DirectDns.BuildQuery(TestName, id));
            string sep = target.Path.Contains('?') ? "&" : "?";
            string request =
                $"GET {target.Path}{sep}dns={dns} HTTP/1.1\r\n" +
                $"Host: {target.Host}\r\n" +
                "Accept: application/dns-message\r\n" +
                "User-Agent: Mozilla/5.0\r\n" +
                "Connection: close\r\n\r\n";
            await tls.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token).ConfigureAwait(false);

            byte[] response = await ReadAllAsync(tls, 64 * 1024, cts.Token).ConfigureAwait(false);
            var (status, body) = ParseHttpResponse(response);
            if (status != 200 || body.Length == 0) return null;

            return DirectDns.ParseAddresses(body, id).Length > 0 ? Math.Max(1, (int)sw.ElapsedMilliseconds) : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Checks all targets at once; working ones come back fastest first.</summary>
    public static async Task<List<(DohTarget Target, int Ms)>> RankAsync(IEnumerable<DohTarget> targets, LocalEndpoints tunnel, CancellationToken ct = default)
    {
        var list = targets.ToList();
        var results = await Task.WhenAll(list.Select(t => ProbeAsync(t, tunnel, 4000, ct))).ConfigureAwait(false);
        return list.Zip(results)
                   .Where(p => p.Second.HasValue)
                   .Select(p => (p.First, p.Second!.Value))
                   .OrderBy(p => p.Item2)
                   .ToList();
    }

    // ------------------------------------------------------------------ plumbing (internal for tests)

    /// <summary>SOCKS5 CONNECT with login and password (RFC 1928 + RFC 1929).</summary>
    internal static async Task Socks5ConnectAsync(Stream s, IPAddress ip, int port, string user, string password, CancellationToken ct)
    {
        await s.WriteAsync(new byte[] { 5, 1, 2 }, ct).ConfigureAwait(false);          // version 5, one method: login/password
        byte[] hello = await ReadExactAsync(s, 2, ct).ConfigureAwait(false);
        if (hello[0] != 5 || hello[1] != 2) throw new IOException("SOCKS: login method refused");

        await s.WriteAsync(BuildSocksLogin(user, password), ct).ConfigureAwait(false);
        byte[] status = await ReadExactAsync(s, 2, ct).ConfigureAwait(false);
        if (status[1] != 0) throw new IOException("SOCKS: login rejected");

        byte[] addr = ip.GetAddressBytes();
        var req = new List<byte> { 5, 1, 0, (byte)(addr.Length == 4 ? 1 : 4) };
        req.AddRange(addr);
        req.Add((byte)(port >> 8));
        req.Add((byte)port);
        await s.WriteAsync(req.ToArray(), ct).ConfigureAwait(false);

        byte[] head = await ReadExactAsync(s, 4, ct).ConfigureAwait(false);
        if (head[1] != 0) throw new IOException($"SOCKS: connect failed ({head[1]})");
        int rest = SocksReplyTail(head[3]);
        if (rest < 0)
        {
            byte len = (await ReadExactAsync(s, 1, ct).ConfigureAwait(false))[0];
            rest = len + 2;
        }
        await ReadExactAsync(s, rest, ct).ConfigureAwait(false);
    }

    /// <summary>RFC 1929 request: version 1, then length-prefixed login and password (each 1..255 bytes).</summary>
    internal static byte[] BuildSocksLogin(string user, string password)
    {
        byte[] u = Encoding.UTF8.GetBytes(user);
        byte[] p = Encoding.UTF8.GetBytes(password);
        if (u.Length is 0 or > 255 || p.Length is 0 or > 255) throw new ArgumentException("SOCKS login must be 1..255 bytes");

        var req = new List<byte>(3 + u.Length + p.Length) { 1, (byte)u.Length };
        req.AddRange(u);
        req.Add((byte)p.Length);
        req.AddRange(p);
        return req.ToArray();
    }

    /// <summary>Bytes left in a SOCKS5 reply after its 4-byte head: address + port; -1 = length byte follows.</summary>
    internal static int SocksReplyTail(byte addressType) => addressType switch
    {
        1 => 4 + 2,     // IPv4
        4 => 16 + 2,    // IPv6
        3 => -1,        // domain: length byte, name, port
        _ => throw new IOException("SOCKS: unknown address type")
    };

    private static async Task<byte[]> ReadExactAsync(Stream s, int count, CancellationToken ct)
    {
        byte[] buf = new byte[count];
        int got = 0;
        while (got < count)
        {
            int n = await s.ReadAsync(buf.AsMemory(got, count - got), ct).ConfigureAwait(false);
            if (n == 0) throw new EndOfStreamException();
            got += n;
        }
        return buf;
    }

    private static async Task<byte[]> ReadAllAsync(Stream s, int limit, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        while (ms.Length < limit)
        {
            int n;
            try { n = await s.ReadAsync(buf, ct).ConfigureAwait(false); }
            catch (IOException) when (ms.Length > 0) { break; } // some servers reset after "Connection: close"
            if (n == 0) break;
            ms.Write(buf, 0, n);
            if (IsComplete(ms.GetBuffer().AsSpan(0, (int)ms.Length))) break;
        }
        return ms.ToArray();
    }

    /// <summary>True once the headers and the whole Content-Length body (or the last chunk) are in.</summary>
    internal static bool IsComplete(ReadOnlySpan<byte> data)
    {
        int headerEnd = IndexOf(data, "\r\n\r\n"u8);
        if (headerEnd < 0) return false;
        string headers = Encoding.ASCII.GetString(data[..headerEnd]).ToLowerInvariant();
        var body = data[(headerEnd + 4)..];

        int cl = headers.IndexOf("content-length:", StringComparison.Ordinal);
        if (cl >= 0)
        {
            int end = headers.IndexOf('\r', cl);
            string v = headers[(cl + 15)..(end < 0 ? headers.Length : end)].Trim();
            return int.TryParse(v, out int len) && body.Length >= len;
        }
        if (headers.Contains("transfer-encoding: chunked")) return IndexOf(body, "0\r\n\r\n"u8) >= 0;
        return false;
    }

    /// <summary>Status code and body of a raw HTTP/1.1 response (handles Content-Length and chunked bodies).</summary>
    internal static (int Status, byte[] Body) ParseHttpResponse(ReadOnlySpan<byte> data)
    {
        int headerEnd = IndexOf(data, "\r\n\r\n"u8);
        if (headerEnd < 0) return (0, Array.Empty<byte>());

        string headers = Encoding.ASCII.GetString(data[..headerEnd]);
        string[] statusLine = headers.Split("\r\n")[0].Split(' ');
        int status = statusLine.Length > 1 && int.TryParse(statusLine[1], out int s) ? s : 0;
        var body = data[(headerEnd + 4)..];

        string lower = headers.ToLowerInvariant();
        if (lower.Contains("transfer-encoding: chunked"))
        {
            using var ms = new MemoryStream();
            int pos = 0;
            while (pos < body.Length)
            {
                int lineEnd = IndexOf(body[pos..], "\r\n"u8);
                if (lineEnd < 0) break;
                string sizeText = Encoding.ASCII.GetString(body.Slice(pos, lineEnd)).Split(';')[0].Trim();
                if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out int size)) break;
                pos += lineEnd + 2;
                if (size == 0) break;
                if (pos + size > body.Length) break;
                ms.Write(body.Slice(pos, size));
                pos += size + 2;
            }
            return (status, ms.ToArray());
        }

        int cl = lower.IndexOf("content-length:", StringComparison.Ordinal);
        if (cl >= 0)
        {
            int end = lower.IndexOf('\r', cl);
            string v = lower[(cl + 15)..(end < 0 ? lower.Length : end)].Trim();
            if (int.TryParse(v, out int len)) return (status, body[..Math.Min(len, body.Length)].ToArray());
        }
        return (status, body.ToArray());
    }

    internal static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle) => haystack.IndexOf(needle);
}
