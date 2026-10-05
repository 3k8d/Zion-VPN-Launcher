namespace Zion.Models;

public enum AppScreen
{
    Dashboard,
    ServerList,
    ServerEdit,
    Settings,
    Subscriptions,
    Exclusions,
    ExcludedSites
}

public enum DnsProvider
{
    Auto,
    Cloudflare,
    Google,
    ControlD,
    NextDns,
    AdGuard,
    OpenDNS,
    CleanBrowsing
}
