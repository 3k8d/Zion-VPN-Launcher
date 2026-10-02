using Zion.Models;

namespace Zion.Services;

/// <summary>What one download of a subscription link produced.</summary>
public sealed record SubscriptionFetchResult
{
    public List<ProxyItem> Items { get; init; } = new();

    /// <summary>Provider's name for the subscription (profile-title or the file name), may be empty.</summary>
    public string Title { get; init; } = "";

    // From subscription-userinfo; bytes, 0 = unknown
    public long Upload { get; init; }
    public long Download { get; init; }
    public long Total { get; init; }
    public DateTime? Expire { get; init; }

    /// <summary>Human-readable reason when no servers came back.</summary>
    public string Error { get; init; } = "";

    /// <summary>The answer is definitive (e.g. 404): trying the relay would not change it.</summary>
    public bool IsFinal { get; init; }
}
