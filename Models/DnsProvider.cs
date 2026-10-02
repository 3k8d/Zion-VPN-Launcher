namespace Zion.Models;

public enum AppScreen
{
    Dashboard,
    ServerList,
    ServerEdit,
    Settings,
    Subscriptions,
    Exclusions
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
