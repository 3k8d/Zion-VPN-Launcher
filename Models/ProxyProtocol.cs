namespace Zion.Models;

public enum ProxyProtocol
{
    Http,
    Https,
    Socks5,
    Vless,
    Trojan,
    Shadowsocks,
    Vmess
}

public enum ProxyStatus
{
    Unknown,
    Testing,
    Online,
    Offline,
    AuthError
}
