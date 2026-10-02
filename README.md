# Zion

VPN client for Windows built on [sing-box](https://github.com/SagerNet/sing-box).

![Zion](docs/screenshots/dashboard.png)

## Features

- VLESS (Reality, TLS), Trojan, VMess, Shadowsocks, SOCKS5, HTTP
- Subscriptions: any number of links, daily auto-update, plan and expiry info from the provider
- System-wide tunnel (Wintun) with IPv6 leak protection
- Kill Switch on the Windows Filtering Platform
- Automatic server failover and DNS failover, checked through the tunnel
- Split tunnelling: Russian sites, torrents and chosen programs can bypass the VPN
- QUIC / WebRTC / tracker blocking

## Screenshots

| | | |
|---|---|---|
| ![Disconnected](docs/screenshots/disconnected.png) | ![Subscriptions](docs/screenshots/subscriptions.png) | ![Settings](docs/screenshots/settings.png) |
| ![Programs bypassing the VPN](docs/screenshots/exclusions.png) | ![DNS](docs/screenshots/dns.png) | ![Clear the server list](docs/screenshots/clear-list.png) |

## Download

Get `Zion.exe` from [Releases](../../releases). It is a single self-contained file and needs administrator rights (the tunnel adapter and the firewall require them).

## Build

Requirements: Windows 10/11 x64, .NET 10 SDK.

```
dotnet build Zion.csproj -c Release
dotnet run --project Tests/TestRunner/TestRunner.csproj -c Debug
dotnet publish Zion.csproj -c Release -o publish
```

## Third-party components

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
