namespace Zion.Models;

public enum ProxyProtocol
{
    Http,
    Https,
    Socks5,
    Vless,
    Trojan,
    Shadowsocks,
    Vmess,
    Hysteria2,
    Tuic
}

/// <summary>What the last server check found (not saved: it describes this run only).</summary>
public enum ProxyStatus
{
    /// <summary>Not checked yet, or the check could not run.</summary>
    Unknown,

    /// <summary>A real page loaded through the server.</summary>
    Online,

    /// <summary>The server passed no traffic.</summary>
    Offline
}
