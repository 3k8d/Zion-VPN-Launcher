using System.Collections.ObjectModel;
using System.Windows;
using Zion.Models;

namespace Zion.Services;

/// <summary>Outcome of one subscription download, for the status line and the log.</summary>
public sealed record SubscriptionUpdateResult(bool Ok, int Added, int Removed, int Total, string Error)
{
    public static SubscriptionUpdateResult Failed(string error) => new(false, 0, 0, 0, error);
}

public static class SubscriptionService
{
    public static readonly TimeSpan AutoUpdateInterval = TimeSpan.FromHours(24);

    /// <summary>Two links point to the same subscription (case, spaces and a trailing slash do not matter).</summary>
    public static bool SameUrl(string? a, string? b) =>
        string.Equals(Normalize(a), Normalize(b), StringComparison.OrdinalIgnoreCase);

    private static string Normalize(string? url) => (url ?? "").Trim().TrimEnd('/');

    public static SubscriptionEntry? Find(AppConfig config, string url) =>
        config.Subscriptions.FirstOrDefault(s => SameUrl(s.Url, url));

    /// <summary>
    /// A server belongs to a subscription when it carries its link. Subscription servers saved by very
    /// old versions have no link at all; they are adopted by whichever subscription is merged first.
    /// </summary>
    public static bool BelongsTo(ProxyItem p, string url) =>
        p.IsFromSubscription && (string.IsNullOrWhiteSpace(p.SubscriptionUrl) || SameUrl(p.SubscriptionUrl, url));

    /// <summary>
    /// True when automatic updates are on and this subscription's last successful download is a day old
    /// (or never happened). A failed attempt does not move that date, so it is retried on the next check.
    /// </summary>
    public static bool IsAutoUpdateDue(AppConfig config, SubscriptionEntry entry, DateTime now)
    {
        if (!config.AutoUpdateSubscription || string.IsNullOrWhiteSpace(entry.Url))
            return false;

        return !entry.LastUpdate.HasValue
               || now - entry.LastUpdate.Value >= AutoUpdateInterval
               || entry.LastUpdate.Value > now; // clock was moved back
    }

    /// <summary>
    /// Downloads one subscription and merges it into the list. A link that is not known yet is added
    /// as a new subscription; existing subscriptions and manual servers are left alone.
    /// </summary>
    public static async Task<SubscriptionUpdateResult> UpdateAsync(string url, ObservableCollection<ProxyItem> proxies, AppConfig config, CancellationToken ct = default)
    {
        url = ProxyParser.ExtractActualSubscriptionUrl(url ?? "");
        if (string.IsNullOrWhiteSpace(url)) return SubscriptionUpdateResult.Failed("Пустая ссылка");

        SubscriptionFetchResult fetched;
        try
        {
            fetched = await ProxyParser.FetchSubscriptionDetailedAsync(url, ct);
        }
        catch (Exception ex)
        {
            fetched = new SubscriptionFetchResult { Error = ex.Message };
        }

        SubscriptionUpdateResult result = null!;
        void Apply()
        {
            var entry = Find(config, url);
            bool isNew = entry == null;

            if (fetched.Items.Count == 0)
            {
                // A link that never worked is not added to the list
                if (entry != null)
                {
                    entry.LastAttempt = DateTime.Now;
                    entry.LastError = string.IsNullOrWhiteSpace(fetched.Error) ? "Не удалось загрузить" : fetched.Error;
                    ConfigStore.Save(config);
                }
                result = SubscriptionUpdateResult.Failed(string.IsNullOrWhiteSpace(fetched.Error) ? "Не удалось загрузить" : fetched.Error);
                return;
            }

            if (entry == null)
            {
                entry = new SubscriptionEntry { Url = url };
                config.Subscriptions.Add(entry);
            }

            entry.LastAttempt = DateTime.Now;
            entry.LastUpdate = DateTime.Now;
            entry.LastError = "";
            if (!string.IsNullOrWhiteSpace(fetched.Title)) entry.Title = fetched.Title;
            entry.Upload = fetched.Upload;
            entry.Download = fetched.Download;
            entry.Total = fetched.Total;
            entry.Expire = fetched.Expire;

            var (added, removed) = MergeSubscriptionItems(proxies, fetched.Items, config, entry.Url);
            int total = proxies.Count(p => BelongsTo(p, entry.Url));
            result = new SubscriptionUpdateResult(true, isNew ? total : added, removed, total, "");
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher != null && !dispatcher.CheckAccess()) dispatcher.Invoke(Apply);
        else Apply();

        return result;
    }

    /// <summary>
    /// Forgets a subscription and removes its servers. <paramref name="keep"/> (the server in use) stays
    /// and becomes an ordinary manual server, so a running connection is not cut.
    /// Returns how many servers were removed.
    /// </summary>
    public static int RemoveSubscription(SubscriptionEntry entry, ObservableCollection<ProxyItem> proxies, AppConfig config, ProxyItem? keep)
    {
        int removed = 0;
        foreach (var p in proxies.Where(p => p.IsFromSubscription && SameUrl(p.SubscriptionUrl, entry.Url)).ToList())
        {
            if (p == keep)
            {
                p.IsFromSubscription = false;
                p.SubscriptionUrl = "";
                continue;
            }
            proxies.Remove(p);
            removed++;
        }

        config.Subscriptions.RemoveAll(s => s.Id == entry.Id);
        config.Proxies = proxies.ToList();
        ConfigStore.Save(config);
        return removed;
    }

    /// <summary>
    /// Merges a fresh download of ONE subscription into the list. Only that subscription's servers are
    /// matched, updated or removed; manual servers and other subscriptions are never touched, and a fresh
    /// server that already exists elsewhere in the list is not added twice.
    /// Matching inside the subscription: same ID or connection, then same name (the provider changed
    /// address or keys), then same location and protocol.
    /// </summary>
    public static (int Added, int Removed) MergeSubscriptionItems(ObservableCollection<ProxyItem> proxies, List<ProxyItem> freshItems, AppConfig config, string url = "")
    {
        foreach (var fresh in freshItems)
        {
            fresh.IsFromSubscription = true;
            fresh.SubscriptionUrl = url;
            fresh.EnsureDeterministicId();
            fresh.AutoEnrichCountryIfMissing();
        }

        var own = proxies.Where(p => BelongsTo(p, url)).ToList();
        var foreign = proxies.Where(p => !BelongsTo(p, url)).ToList();

        var ownById = own.Where(p => p.Id != Guid.Empty).GroupBy(p => p.Id).ToDictionary(g => g.Key, g => g.First());
        var ownByFingerprint = own.Where(p => !string.IsNullOrEmpty(p.GetFingerprint()))
                                  .GroupBy(p => p.GetFingerprint()).ToDictionary(g => g.Key, g => g.First());
        var ownByName = own.Where(p => !string.IsNullOrWhiteSpace(p.Name))
                           .GroupBy(p => p.Name.Trim().ToLowerInvariant()).ToDictionary(g => g.Key, g => g.First());
        var ownByLocation = own.Where(p => !string.IsNullOrWhiteSpace(p.LocationShort) && p.LocationShort != "Локация не определена")
                               .GroupBy(p => $"{p.LocationShort.Trim().ToLowerInvariant()}|{p.Protocol}")
                               .ToDictionary(g => g.Key, g => g.First());

        var foreignIds = foreign.Select(p => p.Id).ToHashSet();
        var foreignFingerprints = foreign.Select(p => p.GetFingerprint()).Where(f => !string.IsNullOrEmpty(f)).ToHashSet();

        var claimed = new HashSet<ProxyItem>();     // an existing server can be matched only once
        var keptIds = new HashSet<Guid>();
        var updates = new List<(ProxyItem Existing, ProxyItem Fresh)>();
        var additions = new List<ProxyItem>();

        foreach (var fresh in freshItems)
        {
            ProxyItem? existing = null;
            if (ownById.TryGetValue(fresh.Id, out var byId) && !claimed.Contains(byId)) existing = byId;
            else if (ownByFingerprint.TryGetValue(fresh.GetFingerprint(), out var byFp) && !claimed.Contains(byFp)) existing = byFp;
            else if (!string.IsNullOrWhiteSpace(fresh.Name) && ownByName.TryGetValue(fresh.Name.Trim().ToLowerInvariant(), out var byName) && !claimed.Contains(byName)) existing = byName;
            else if (ownByLocation.TryGetValue($"{fresh.LocationShort.Trim().ToLowerInvariant()}|{fresh.Protocol}", out var byLoc) && !claimed.Contains(byLoc)) existing = byLoc;

            if (existing != null)
            {
                claimed.Add(existing);
                keptIds.Add(existing.Id);
                updates.Add((existing, fresh));
                continue;
            }

            // Already in the list through another subscription or added by hand: keep that one
            if (foreignIds.Contains(fresh.Id) || foreignFingerprints.Contains(fresh.GetFingerprint())) continue;
            if (!keptIds.Add(fresh.Id)) continue; // the same server twice in one download

            additions.Add(fresh);
        }

        // 1. Servers the provider no longer lists
        int removed = 0;
        foreach (var gone in own.Where(p => !claimed.Contains(p)).ToList())
        {
            proxies.Remove(gone);
            removed++;
        }

        // 2. Update matched servers in place (keeps favourites, ping, selection)
        foreach (var (existing, fresh) in updates)
        {
            // A server that moved: what the last check found (and the address it pinned) no longer applies
            if (!string.Equals(existing.CleanHost, fresh.CleanHost, StringComparison.OrdinalIgnoreCase) || existing.Port != fresh.Port)
            {
                existing.Status = ProxyStatus.Unknown;
                existing.PingMs = -1;
                existing.WorkingAddress = null;
            }

            existing.Name = fresh.Name;
            existing.Host = fresh.Host;
            existing.Port = fresh.Port;
            existing.Protocol = fresh.Protocol;
            existing.Uuid = fresh.Uuid;
            existing.TransportType = fresh.TransportType;
            existing.Security = fresh.Security;
            existing.Fingerprint = fresh.Fingerprint;
            existing.Sni = fresh.Sni;
            existing.PublicKey = fresh.PublicKey;
            existing.ShortId = fresh.ShortId;
            existing.GrpcServiceName = fresh.GrpcServiceName;
            existing.WsPath = fresh.WsPath;
            existing.WsHost = fresh.WsHost;
            existing.Username = fresh.Username;
            existing.Password = fresh.Password;
            existing.AlterId = fresh.AlterId;
            existing.Flow = fresh.Flow;
            existing.SpiderX = fresh.SpiderX;
            existing.Alpn = fresh.Alpn;
            existing.RawLink = fresh.RawLink;
            existing.ObfsPassword = fresh.ObfsPassword;
            existing.ServerPorts = fresh.ServerPorts;
            existing.Insecure = fresh.Insecure;
            existing.CongestionControl = fresh.CongestionControl;
            existing.UdpRelayMode = fresh.UdpRelayMode;
            existing.IsFromSubscription = true;
            existing.SubscriptionUrl = url;
            if (!string.IsNullOrWhiteSpace(fresh.Country))
                existing.Country = fresh.Country;
        }

        // 3. New servers
        foreach (var fresh in additions) proxies.Add(fresh);

        // 4. Keep the saved selection valid
        if (config.SelectedProxyId.HasValue && !proxies.Any(p => p.Id == config.SelectedProxyId.Value))
            config.SelectedProxyId = proxies.FirstOrDefault()?.Id;
        else if (!config.SelectedProxyId.HasValue && proxies.Count > 0)
            config.SelectedProxyId = proxies[0].Id;

        config.Proxies = proxies.ToList();
        ConfigStore.Save(config);
        return (additions.Count, removed);
    }
}
