namespace Zion.Models;

/// <summary>One subscription link and what is known about it. Its servers carry the same URL in ProxyItem.SubscriptionUrl.</summary>
public class SubscriptionEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Url { get; set; } = "";

    /// <summary>Name sent by the provider (profile-title), empty if none.</summary>
    public string Title { get; set; } = "";

    public DateTime AddedAt { get; set; } = DateTime.Now;

    /// <summary>Last successful download.</summary>
    public DateTime? LastUpdate { get; set; }

    /// <summary>Last attempt, successful or not.</summary>
    public DateTime? LastAttempt { get; set; }

    /// <summary>Why the last attempt failed; empty when it succeeded.</summary>
    public string LastError { get; set; } = "";

    // Plan details from the provider's subscription-userinfo header (bytes; 0 = unknown/unlimited)
    public long Upload { get; set; }
    public long Download { get; set; }
    public long Total { get; set; }
    public DateTime? Expire { get; set; }
}
