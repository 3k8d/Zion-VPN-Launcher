using System.Text.Json;

namespace Zion.Services;

/// <summary>
/// Counts only the bytes that went through the VPN server, from snapshots of the core's
/// /connections list (each connection reports its own byte count and the outbound it uses).
///
/// A snapshot shows live connections only, so the last bytes of a connection that closed since the
/// previous snapshot would be lost. The core's grand total does include them: whatever the live
/// connections do not explain goes to the kind of connection that just closed, or, when that is not
/// clear, is split in the same proportion as the explained part.
/// VPN + direct therefore always adds up to the core's own total.
/// </summary>
public sealed class ProxiedTrafficCounter
{
    private readonly string _proxyTag;
    private Dictionary<string, (long Bytes, bool Proxied)> _seen = new();
    private long _lastGlobal;

    public ProxiedTrafficCounter(string proxyTag = "proxy-out")
    {
        _proxyTag = proxyTag;
    }

    /// <summary>Upload + download that left through the VPN outbound.</summary>
    public long ProxiedBytes { get; private set; }

    /// <summary>Upload + download that went around the VPN (bypass rules, local network).</summary>
    public long DirectBytes { get; private set; }

    public void Reset()
    {
        _seen = new Dictionary<string, (long Bytes, bool Proxied)>();
        _lastGlobal = 0;
        ProxiedBytes = 0;
        DirectBytes = 0;
    }

    /// <summary>Feeds one /connections snapshot. Returns false (and changes nothing) if it cannot be read.</summary>
    public bool Apply(string connectionsJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(connectionsJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;

            long global = ReadLong(root, "uploadTotal") + ReadLong(root, "downloadTotal");
            if (global < _lastGlobal) Reset(); // the core was restarted: its totals started over

            long tickProxied = 0, tickDirect = 0;
            var seenNow = new Dictionary<string, (long Bytes, bool Proxied)>();

            if (root.TryGetProperty("connections", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var conn in list.EnumerateArray())
                {
                    if (!conn.TryGetProperty("id", out var idEl) || idEl.GetString() is not { Length: > 0 } id) continue;

                    long bytes = ReadLong(conn, "upload") + ReadLong(conn, "download");
                    bool proxied = UsesProxy(conn);
                    _seen.TryGetValue(id, out var before);
                    long grown = Math.Max(0, bytes - before.Bytes);
                    seenNow[id] = (bytes, proxied);

                    if (proxied) tickProxied += grown;
                    else tickDirect += grown;
                }
            }

            // Bytes the core counted that no live connection accounts for (connections already closed)
            long unexplained = Math.Max(0, global - (ProxiedBytes + DirectBytes + tickProxied + tickDirect));

            // Best evidence: which connections closed since the previous snapshot
            int closedProxied = 0, closedDirect = 0;
            foreach (var old in _seen)
            {
                if (seenNow.ContainsKey(old.Key)) continue;
                if (old.Value.Proxied) closedProxied++; else closedDirect++;
            }

            long unexplainedProxied = unexplained;
            if (closedProxied > 0 && closedDirect == 0)
                unexplainedProxied = unexplained;
            else if (closedDirect > 0 && closedProxied == 0)
                unexplainedProxied = 0;
            else if (tickProxied + tickDirect > 0)
                unexplainedProxied = (long)(unexplained * (double)tickProxied / (tickProxied + tickDirect));
            else if (ProxiedBytes + DirectBytes > 0)
                unexplainedProxied = (long)(unexplained * (double)ProxiedBytes / (ProxiedBytes + DirectBytes));
            // else: nothing to go by; the default route is the VPN, so it all counts as VPN

            ProxiedBytes += tickProxied + unexplainedProxied;
            DirectBytes += tickDirect + (unexplained - unexplainedProxied);
            _seen = seenNow;
            _lastGlobal = global;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private bool UsesProxy(JsonElement conn)
    {
        if (!conn.TryGetProperty("chains", out var chains) || chains.ValueKind != JsonValueKind.Array) return false;
        foreach (var hop in chains.EnumerateArray())
        {
            if (hop.ValueKind == JsonValueKind.String && hop.GetString() == _proxyTag) return true;
        }
        return false;
    }

    private static long ReadLong(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long n) ? n : 0;
}
