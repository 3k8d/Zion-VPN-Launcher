using Zion.Models;

namespace Zion.Services;

public record DnsEntry(
    DnsProvider Provider,
    string DisplayName,
    string PrimaryIp,
    string SecondaryIp,
    string DohUrl,
    string DohHost,
    string DohPath = "/dns-query",
    string DotHost = "",
    int DotPort = 853,
    bool SupportsDoT = false
)
{
    public string SingBoxTag => $"remote-dns-{Provider.ToString().ToLowerInvariant()}";
}

public static class DnsConstants
{
    public static readonly IReadOnlyDictionary<DnsProvider, DnsEntry> Entries = new Dictionary<DnsProvider, DnsEntry>
    {
        [DnsProvider.Cloudflare] = new(
            DnsProvider.Cloudflare,
            "Cloudflare",
            "1.1.1.1",
            "1.0.0.1",
            "https://cloudflare-dns.com/dns-query",
            "cloudflare-dns.com",
            "/dns-query",
            "cloudflare-dns.com",
            853,
            true
        ),
        [DnsProvider.Google] = new(
            DnsProvider.Google,
            "Google",
            "8.8.8.8",
            "8.8.4.4",
            "https://dns.google/dns-query",
            "dns.google",
            "/dns-query",
            "dns.google",
            853,
            true
        ),
        [DnsProvider.ControlD] = new(
            DnsProvider.ControlD,
            "Control D",
            "76.76.2.0",
            "76.76.10.0",
            "https://freedns.controld.com/p0",
            "freedns.controld.com",
            "/p0",
            "freedns.controld.com",
            853,
            true
        ),
        [DnsProvider.NextDns] = new(
            DnsProvider.NextDns,
            "NextDNS",
            "45.90.28.0",
            "45.90.30.0",
            "https://dns.nextdns.io/dns-query",
            "dns.nextdns.io",
            "/dns-query",
            "dns.nextdns.io",
            853,
            true
        ),
        [DnsProvider.AdGuard] = new(
            DnsProvider.AdGuard,
            "AdGuard",
            "94.140.14.14",
            "94.140.15.15",
            "https://dns.adguard-dns.com/dns-query",
            "dns.adguard-dns.com",
            "/dns-query",
            "dns.adguard-dns.com",
            853,
            true
        ),
        [DnsProvider.OpenDNS] = new(
            DnsProvider.OpenDNS,
            "OpenDNS",
            "208.67.222.222",
            "208.67.220.220",
            "https://doh.opendns.com/dns-query",
            "doh.opendns.com",
            "/dns-query",
            "doh.opendns.com",
            853,
            true
        ),
        [DnsProvider.CleanBrowsing] = new(
            DnsProvider.CleanBrowsing,
            "CleanBrowsing",
            "185.228.168.9",
            "185.228.169.9",
            "https://doh.cleanbrowsing.org/doh/security-filter/",
            "doh.cleanbrowsing.org",
            "/doh/security-filter/",
            "security-filter-dns.cleanbrowsing.org",
            853,
            true
        )
    };

    public static DnsEntry GetEntry(DnsProvider provider)
    {
        if (Entries.TryGetValue(provider, out var entry))
            return entry;
        return Entries[DnsProvider.Cloudflare];
    }

    public static IReadOnlyList<DnsEntry> GetAllRealEntries() => Entries.Values.ToList();

    /// <summary>The provider that owns this address (primary or backup), or null.</summary>
    public static DnsEntry? FindByIp(string ip) =>
        Entries.Values.FirstOrDefault(e => e.PrimaryIp == ip || e.SecondaryIp == ip);
}
