using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Zion.Models;

namespace Zion.Services;

public enum ServerCheckOutcome
{
    /// <summary>A real page loaded through the server.</summary>
    Working,

    /// <summary>The server passed no traffic on any of its addresses, or the core refused its settings.</summary>
    NotWorking,

    /// <summary>The check itself could not run; nothing new is known about the server.</summary>
    Unknown
}

/// <param name="Address">The fastest working address when the server is a name (null for IP servers).</param>
public sealed record ServerCheckResult(ProxyItem Server, ServerCheckOutcome Outcome, int DelayMs, string? Address, string Detail);

/// <summary>
/// The real server check. A separate, short-lived copy of the core loads a test page through every
/// server: the same test the tunnel passes before it reports "connected". So the result is honest for
/// every protocol, Hysteria2 and TUIC included, and a server that accepts connections but passes no
/// traffic counts as not working.
///
/// A server name often stands for several addresses, and some of them may be dead or blocked while
/// others work. Each address is therefore checked on its own: the server works if any address does,
/// and the fastest one is remembered so the tunnel can connect straight to it.
///
/// The running tunnel is never touched. While it is up, the copy is bound to the real network adapter
/// and asks that adapter's DNS server, so it measures the server itself and not the way through the
/// current VPN server. It is the same core executable, which the Kill Switch already lets through,
/// and its settings (with the servers' keys) go in through stdin, never to disk.
/// </summary>
public static class ServerChecker
{
    internal static readonly string[] TestUrls =
    {
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/generate_204"
    };

    private const int TestTimeoutMs = 5000;
    private const int Parallelism = 16;
    private const int MaxAddressesPerServer = 8;
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(5);

    /// <summary>One thing to measure: a server, on one specific address (null = the server's own IP).</summary>
    internal sealed record Target(ProxyItem Server, string? Address);

    /// <summary>
    /// Checks the servers (provider dividers are skipped) and reports each one as soon as it is known.
    /// Never throws. Cancelling stops the check; servers not finished by then are not reported.
    /// </summary>
    public static async Task<List<ServerCheckResult>> CheckAsync(IEnumerable<ProxyItem> servers, Action<ServerCheckResult>? onResult = null, CancellationToken ct = default)
    {
        var pending = servers.Where(s => !s.IsDivider).Distinct().ToList();
        var results = new List<ServerCheckResult>();

        void Report(ServerCheckResult r)
        {
            lock (results) results.Add(r);
            try { onResult?.Invoke(r); } catch { }
        }

        if (pending.Count == 0) return results;

        var (coreOk, coreError) = TunRoutingEngine.EnsureCoreFiles();
        if (!coreOk)
        {
            foreach (var s in pending) Report(new ServerCheckResult(s, ServerCheckOutcome.Unknown, -1, null, coreError));
            return results;
        }

        var adapter = InternetProbe.FindPhysicalAdapter();
        var network = new Network(InternetProbe.IsTunnelUp() ? adapter?.Name : null, adapter?.DnsServers ?? Array.Empty<IPAddress>());

        // 1. Every address of every server name, looked up by the core itself
        var targets = new List<Target>();
        var names = pending.Select(s => s.CleanHost).Where(h => !IPAddress.TryParse(h, out _))
                           .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var lookups = names.Count > 0
            ? await ResolveAsync(names, network, ct).ConfigureAwait(false)
            : new Dictionary<string, (int Status, List<IPAddress> Addresses)>(StringComparer.OrdinalIgnoreCase);
        if (ct.IsCancellationRequested) return results;

        foreach (var server in pending)
        {
            if (IPAddress.TryParse(server.CleanHost, out _))
            {
                targets.Add(new Target(server, null));
                continue;
            }

            var (status, addresses) = lookups.TryGetValue(server.CleanHost, out var found) ? found : (-1, new List<IPAddress>());
            if (addresses.Count > 0)
            {
                foreach (var ip in addresses.Take(MaxAddressesPerServer)) targets.Add(new Target(server, ip.ToString()));
            }
            else if (status == 3)
            {
                Report(new ServerCheckResult(server, ServerCheckOutcome.NotWorking, -1, null, "Адрес сервера не существует"));
            }
            else if (status == 0)
            {
                Report(new ServerCheckResult(server, ServerCheckOutcome.NotWorking, -1, null, "У адреса сервера нет IPv4-адресов"));
            }
            else
            {
                Report(new ServerCheckResult(server, ServerCheckOutcome.Unknown, -1, null, "Не удалось узнать адрес сервера"));
            }
        }

        // 2. A real page through every address
        await MeasureAsync(targets, network, Report, ct).ConfigureAwait(false);
        return results;
    }

    /// <summary>Where the check goes out: the adapter to bind to (while the tunnel is up) and its DNS servers.</summary>
    private sealed record Network(string? BindInterface, IReadOnlyList<IPAddress> DnsServers);

    private static async Task<Dictionary<string, (int Status, List<IPAddress> Addresses)>> ResolveAsync(List<string> names, Network network, CancellationToken ct)
    {
        var lookups = new ConcurrentDictionary<string, (int Status, List<IPAddress> Addresses)>(StringComparer.OrdinalIgnoreCase);
        var start = await Prober.StartAsync(Array.Empty<Target>(), network, ct).ConfigureAwait(false);
        if (start.Prober == null) return new(lookups, StringComparer.OrdinalIgnoreCase);

        using (var prober = start.Prober)
        {
            try
            {
                await Parallel.ForEachAsync(names, new ParallelOptions { MaxDegreeOfParallelism = Parallelism, CancellationToken = ct }, async (name, _) =>
                {
                    // Two questions: some name servers hand out only part of a pool per answer
                    var first = await prober.Api.QueryDnsAsync(name).ConfigureAwait(false);
                    var second = first.Status == 0 ? await prober.Api.QueryDnsAsync(name).ConfigureAwait(false) : first;
                    var all = first.Addresses.Concat(second.Addresses).Distinct().ToList();
                    lookups[name] = (first.Status == 0 || second.Status == 0 ? 0 : first.Status, all);
                }).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
        }
        return new(lookups, StringComparer.OrdinalIgnoreCase);
    }

    private static async Task MeasureAsync(List<Target> targets, Network network, Action<ServerCheckResult> report, CancellationToken ct)
    {
        int portRetries = 0;
        while (targets.Count > 0 && !ct.IsCancellationRequested)
        {
            var start = await Prober.StartAsync(targets, network, ct).ConfigureAwait(false);
            if (start.Prober == null)
            {
                // A server the core refuses to load would stop the whole check: report it and go on
                // without it. Every round removes one, so this always ends.
                if (start.BadIndex is int bad && bad >= 0 && bad < targets.Count)
                {
                    var server = targets[bad].Server;
                    report(new ServerCheckResult(server, ServerCheckOutcome.NotWorking, -1, null, "Ядро не принимает настройки сервера: " + start.Error));
                    targets = targets.Where(t => t.Server != server).ToList();
                    continue;
                }

                if (start.PortConflict && ++portRetries <= 2) continue;

                if (!ct.IsCancellationRequested)
                {
                    foreach (var server in targets.Select(t => t.Server).Distinct())
                        report(new ServerCheckResult(server, ServerCheckOutcome.Unknown, -1, null, start.Error));
                }
                return;
            }

            using var prober = start.Prober;
            var delays = new ConcurrentDictionary<int, int>();       // target index -> delay (working only)
            var errors = new ConcurrentDictionary<int, string>();
            var groups = targets.Select((t, i) => (t, i)).GroupBy(x => x.t.Server).ToDictionary(g => g.Key, g => g.ToList());

            ServerCheckResult Verdict(ProxyItem server)
            {
                var group = groups[server];
                var best = group.Where(x => delays.ContainsKey(x.i)).OrderBy(x => delays[x.i]).FirstOrDefault();
                if (best.t != null) return new ServerCheckResult(server, ServerCheckOutcome.Working, delays[best.i], best.t.Address, "");

                bool broken = ct.IsCancellationRequested || prober.HasExited; // a crashed check says nothing about the server
                string detail = group.Select(x => errors.GetValueOrDefault(x.i, "")).FirstOrDefault(e => e.Length > 0) ?? "";
                return new ServerCheckResult(server, broken ? ServerCheckOutcome.Unknown : ServerCheckOutcome.NotWorking, -1, null, detail);
            }

            // Measures the given servers' addresses with one test page. A server is finished (onServerDone)
            // the moment all of its addresses are measured, so results come in one by one.
            async Task RunAsync(IReadOnlyCollection<ProxyItem> servers, string url, Action<ProxyItem> onServerDone)
            {
                var remaining = new ConcurrentDictionary<ProxyItem, int>(servers.Select(s => KeyValuePair.Create(s, groups[s].Count)));
                try
                {
                    await Parallel.ForEachAsync(servers.SelectMany(s => groups[s]), new ParallelOptions { MaxDegreeOfParallelism = Parallelism, CancellationToken = ct }, async (x, _) =>
                    {
                        var r = await prober.Api.GetDelayDetailedAsync(Tag(x.i), url, TestTimeoutMs).ConfigureAwait(false);
                        if (r.Success && r.DelayMs > 0) delays[x.i] = r.DelayMs;
                        else errors[x.i] = r.ErrorMessage;

                        if (remaining.AddOrUpdate(x.t.Server, 0, (_, left) => left - 1) == 0) onServerDone(x.t.Server);
                    }).ConfigureAwait(false);
                }
                catch (OperationCanceledException) { }
            }

            // Pass 1: the main test page through every address; a server with a working address is done.
            // Pass 2: servers with no working address get a second chance with another test page.
            var silent = new ConcurrentBag<ProxyItem>();
            await RunAsync(groups.Keys, TestUrls[0], server =>
            {
                if (groups[server].Any(x => delays.ContainsKey(x.i))) report(Verdict(server));
                else silent.Add(server);
            }).ConfigureAwait(false);
            if (ct.IsCancellationRequested) return;

            if (!silent.IsEmpty)
            {
                await RunAsync(silent.ToList(), TestUrls[1], server => report(Verdict(server))).ConfigureAwait(false);
            }
            return;
        }
    }

    internal static string Tag(int index) => $"s{index}";

    /// <summary>
    /// The check's own config: one outbound per target (in the given order, so the core's
    /// "outbound[N]" errors point straight at it), a local control API, no inbounds at all.
    /// </summary>
    internal static JsonObject BuildConfig(IReadOnlyList<Target> targets, int controlPort, string secret, string? bindInterface, IReadOnlyList<IPAddress> dnsServers)
    {
        var outbounds = new JsonArray();
        for (int i = 0; i < targets.Count; i++)
        {
            outbounds.Add(TunRoutingEngine.BuildProxyOutbound(targets[i].Server, Tag(i), targets[i].Address));
        }
        outbounds.Add(new JsonObject { ["type"] = "direct", ["tag"] = "direct" });

        // The real adapter's DNS server, asked directly: while the tunnel is up the system resolver would
        // answer through the tunnel, and the core's "local" resolver may pick the tunnel's address.
        var dns = dnsServers.Count > 0
            ? new JsonObject { ["type"] = "udp", ["tag"] = "dns", ["server"] = dnsServers[0].ToString() }
            : new JsonObject { ["type"] = "local", ["tag"] = "dns" };

        var route = new JsonObject
        {
            ["default_domain_resolver"] = "dns",
            ["final"] = "direct"
        };
        if (!string.IsNullOrEmpty(bindInterface))
        {
            route["default_interface"] = bindInterface; // around the tunnel, straight to the server
        }

        return new JsonObject
        {
            ["log"] = new JsonObject { ["level"] = "error" },
            ["dns"] = new JsonObject
            {
                ["servers"] = new JsonArray { dns },
                ["strategy"] = "ipv4_only"
            },
            ["outbounds"] = outbounds,
            ["route"] = route,
            ["experimental"] = new JsonObject
            {
                ["clash_api"] = new JsonObject
                {
                    ["external_controller"] = $"127.0.0.1:{controlPort}",
                    ["secret"] = secret
                }
            }
        };
    }

    /// <summary>Index N from the core's "initialize outbound[N]: ..." error, or null.</summary>
    internal static int? ParseBadOutbound(string coreError)
    {
        var m = Regex.Match(coreError ?? "", @"outbound\[(\d+)\]");
        return m.Success && int.TryParse(m.Groups[1].Value, out int index) ? index : null;
    }

    /// <summary>The core's last fatal/error line, without colour codes and the "FATAL[0000]" prefix.</summary>
    internal static string CleanCoreError(string raw)
    {
        string text = Regex.Replace(raw ?? "", @"\x1B\[[0-9;]*m", "");
        string? line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                           .LastOrDefault(l => l.Contains("FATAL") || l.Contains("ERROR"));
        if (line == null) return text.Trim();
        int bracket = line.IndexOf("] ", StringComparison.Ordinal);
        return bracket >= 0 ? line[(bracket + 2)..].Trim() : line.Trim();
    }

    /// <summary>One running copy of the core with the targets loaded.</summary>
    private sealed class Prober : IDisposable
    {
        private readonly Process _process;

        public ClashApiClient Api { get; }
        public bool HasExited
        {
            get { try { return _process.HasExited; } catch { return true; } }
        }

        private Prober(Process process, ClashApiClient api)
        {
            _process = process;
            Api = api;
        }

        public sealed record StartResult(Prober? Prober, string Error, int? BadIndex, bool PortConflict);

        public static async Task<StartResult> StartAsync(IReadOnlyList<Target> targets, Network network, CancellationToken ct)
        {
            int port = LocalEndpoints.FreeLoopbackPort();
            string secret = LocalEndpoints.RandomSecret(16);
            string json = BuildConfig(targets, port, secret, network.BindInterface, network.DnsServers).ToJsonString();

            var process = new Process
            {
                StartInfo = new ProcessStartInfo(TunRoutingEngine.SingBoxExePath, "run -c stdin")
                {
                    WorkingDirectory = TunRoutingEngine.CoreDir,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardInputEncoding = new UTF8Encoding(false) // the core rejects a byte-order mark
                }
            };

            var stderr = new StringBuilder();
            process.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (stderr) stderr.AppendLine(e.Data); };
            process.OutputDataReceived += (_, _) => { };

            try
            {
                process.Start();
            }
            catch (Exception ex)
            {
                process.Dispose();
                return new StartResult(null, ex.Message, null, false);
            }

            ProcessJobTracker.TrackProcess(process); // goes away together with Zion, whatever happens
            process.BeginErrorReadLine();
            process.BeginOutputReadLine();

            try
            {
                await process.StandardInput.WriteAsync(json).ConfigureAwait(false);
                process.StandardInput.Close();
            }
            catch { }

            var api = new ClashApiClient(port, secret);
            var deadline = DateTime.UtcNow + StartTimeout;
            while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested && !process.HasExited)
            {
                if (await api.IsAliveAsync(300).ConfigureAwait(false))
                {
                    return new StartResult(new Prober(process, api), "", null, false);
                }
                await Task.Delay(100, CancellationToken.None).ConfigureAwait(false);
            }

            // It did not come up: find out why
            try { if (!process.HasExited) process.Kill(true); process.WaitForExit(1000); } catch { }
            string error;
            lock (stderr) error = CleanCoreError(stderr.ToString());
            api.Dispose();
            process.Dispose();

            if (ct.IsCancellationRequested) return new StartResult(null, "Проверка отменена", null, false);
            if (string.IsNullOrEmpty(error)) error = "Ядро не запустилось";
            return new StartResult(null, error, ParseBadOutbound(error), LocalEndpoints.IsPortConflict(error));
        }

        public void Dispose()
        {
            try { if (!_process.HasExited) _process.Kill(true); } catch { }
            _process.Dispose();
            Api.Dispose();
        }
    }
}
