<p align="center">
  <img src="docs/logo.png" width="128" alt="luci-app-netbird logo">
</p>

# luci-app-netbird

**English** | [简体中文](README.zh-cn.md)

LuCI app for the [NetBird](https://netbird.io) mesh-VPN client on OpenWrt / ImmortalWrt — manage NetBird on OpenWrt from the router, no command line needed.
Compatible with OpenWrt / ImmortalWrt 24.x (`opkg`) and 25.x (`apk`).

## Features

Surfaces the NetBird client's capabilities in the LuCI UI:

- Connect / reconnect / disconnect / deregister; self-hosted management
- Binary version management — official release, package feed, or custom URL
- Firewall automation — NetBird zone and LAN ↔ mesh forwarding
- Full `netbird up` settings — WireGuard, routes, DNS, SSH, IPv6, Rosenpass, log level
- Peer status and live logs

## Install

**One-click** — adds the signed package feed, then installs the app + Chinese language pack:

```sh
# with curl:
sh -c "$(curl -fsSL https://luci-app-netbird.okk.sh/install.sh)"
# routers without curl:
wget -O - https://luci-app-netbird.okk.sh/install.sh | sh
```

Afterwards manage it normally — `opkg`/`apk` on the command line, or **LuCI → System → Software**. The package is architecture-independent (`PKGARCH:=all`); open it at **Services → NetBird**.

<details><summary><b>Add the feed only, then install yourself</b></summary>

```sh
wget -O - https://luci-app-netbird.okk.sh/feed.sh | sh
opkg install luci-app-netbird luci-i18n-netbird-zh-cn
# or:  apk add luci-app-netbird luci-i18n-netbird-zh-cn
```
</details>

<details><summary><b>Install from package files</b></summary>

Runtime deps (usually present): `rpcd`, `rpcd-mod-ucode`, `luci-base`, `netbird`. Optional: `conntrack`.

```sh
# OpenWrt / ImmortalWrt 24.10 (opkg)
opkg install rpcd rpcd-mod-ucode luci-base netbird
opkg install luci-app-netbird_*.ipk luci-i18n-netbird-zh-cn_*.ipk
# OpenWrt / ImmortalWrt 25+ (apk)
apk add rpcd rpcd-mod-ucode luci-base netbird
apk add --allow-untrusted luci-app-netbird-*.apk luci-i18n-netbird-zh-cn-*.apk
```
</details>

<details><summary><b>Build from source</b></summary>

Add this repo to an OpenWrt / ImmortalWrt SDK or buildroot (under `package/` or a feed), then `make package/luci-app-netbird/compile V=s`.
</details>

**Uninstall:** `wget -O - https://luci-app-netbird.okk.sh/uninstall.sh | sh`

## Setup / Quick start

1. Create a **setup key** in the [NetBird dashboard](https://app.netbird.io) (or your self-hosted panel).
2. **Services → NetBird → Authentication** — for self-hosted, set the Management URL; turn on the master switch, paste the key, click **Connect**.
3. *(optional)* **Network** tab — create the firewall zone, then enable `LAN → NetBird` / `NetBird → LAN` forwarding as needed.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — design, data flow, module boundaries
- [Releasing](docs/RELEASING.md) — CI trigger rules, package-versioned releases
- [Changelog](CHANGELOG.md) — version history
- [GitHub](https://github.com/dont-touchme/luci-app-netbird) — source code, issues, releases

## Notes

- Verified on x86_64; other architectures (arm64 / 386 / armv6) are supported but less tested.
- SSH extensions (root login / SFTP / port forwarding) require netbird 0.72.x+.
- `/etc/config/netbird` is a conffile — settings are kept across upgrades.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
Architecture and some patterns are adapted from [luci-app-tailscale-community](https://github.com/Tokisaki-Galaxy/luci-app-tailscale-community) (Apache-2.0); UI ideas reference OPNsense [os-netbird](https://github.com/opnsense/plugins/tree/master/net/os-netbird) (BSD-2-Clause, © NetBird GmbH).

## Screenshots

### Authentication

![Authentication — connected](docs/screenshots/luci-app-netbird-menu-1-1.jpg)
![Authentication — login](docs/screenshots/luci-app-netbird-menu-1-2.jpg)

### Versions

![Versions](docs/screenshots/luci-app-netbird-menu-2.jpg)

### Settings

![Settings](docs/screenshots/luci-app-netbird-menu-3-1.jpg)
![Settings](docs/screenshots/luci-app-netbird-menu-3-2.jpg)
![Settings](docs/screenshots/luci-app-netbird-menu-3-3.jpg)
![Settings](docs/screenshots/luci-app-netbird-menu-3-4.jpg)
![Settings](docs/screenshots/luci-app-netbird-menu-3-5.jpg)
![Settings](docs/screenshots/luci-app-netbird-menu-3-6.jpg)

### Status

![Status](docs/screenshots/luci-app-netbird-menu-4.jpg)

### Network

![Network](docs/screenshots/luci-app-netbird-menu-5.jpg)

### Logs

![Logs](docs/screenshots/luci-app-netbird-menu-6.jpg)
