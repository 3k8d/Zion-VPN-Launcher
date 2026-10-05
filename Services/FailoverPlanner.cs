using Zion.Models;

namespace Zion.Services;

/// <summary>Decides which servers to try, and in what order, when the current one stops responding.</summary>
public static class FailoverPlanner
{
    /// <summary>
    /// Same country as the failed server first (so the exit location changes as little as possible),
    /// then everything else. Inside each group: the user's favourites first, then servers not known
    /// to be offline, fastest ping first.
    /// </summary>
    public static List<ProxyItem> OrderCandidates(ProxyItem? current, IEnumerable<ProxyItem> all, int max = 5)
    {
        string code = current?.CountryCode ?? "";
        bool countryKnown = !string.IsNullOrEmpty(code) && code != "un" && code != "auto";

        return all
            .Where(p => current == null || p.Id != current.Id)
            .OrderBy(p => countryKnown && string.Equals(p.CountryCode, code, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(p => p.IsFavorite ? 0 : 1)
            .ThenBy(p => p.Status == ProxyStatus.Offline ? 1 : 0)
            .ThenBy(p => p.PingMs > 0 ? p.PingMs : int.MaxValue)
            .Take(max)
            .ToList();
    }
}
