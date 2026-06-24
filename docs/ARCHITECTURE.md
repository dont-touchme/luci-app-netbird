# Architecture — luci-app-netbird

LuCI app to manage the [NetBird](https://netbird.io) mesh-VPN client on OpenWRT.
It has no daemon of its own — it drives the upstream `netbird` binary and its procd
service through UCI and a ucode RPC backend.

## Components

| Layer | Path | Role |
|---|---|---|
| Frontend (views) | `htdocs/luci-static/resources/view/netbird/*.js` | 6 tabs: overview / versions / settings / status / setup(network) / logs. All DOM via `E()` (no innerHTML). |
| Frontend helpers | `.../netbird/dom-helpers.js`, `netbird.css` | `pair / code / statusPill` builders. |
| Backend entry | `root/usr/share/rpcd/ucode/netbird.uc` | The `luci.netbird` rpcd object — 26 methods (12 read + 14 write). |
| Backend lib | `root/usr/share/rpcd/ucode/lib/*.uc` | `shell`(quote) · `paths`(binary probe) · `envelope`({ok,err,CODE}) · `netbird_cli`(CLI wrap) · `state`(5-state) · `sanitize`(validation). |
| ACL | `root/usr/share/rpcd/acl.d/luci-app-netbird.json` | read/write method whitelist + UCI scopes. Kept strictly 1:1 with the method table. |
| Settings pipeline | `root/etc/init.d/netbird-settings` | config-only procd service: renders UCI → `netbird up --flags`. |
| Config | `root/etc/config/netbird`, `root/etc/config/netbird_bin` | settings, and binary-source (kept separate so changing the download URL does not trigger a netbird reconnect). |
| First-install | `root/etc/uci-defaults/99-luci-app-netbird` | idempotent: seed config, chmod init.d 0755, append identity paths to `sysupgrade.conf`. |

## Single source of truth

**UCI is the only input source; `config.json` is read-only.** The apply chain:

```
write UCI  →  init.d reads UCI  →  netbird up --flag …  →  daemon persists config.json
```

The app never syncs or dual-writes `config.json`. Reads of `config.json` (e.g. to display
the management URL) are display-only.

## Settings application (`init.d/netbird-settings`)

- **Trigger**: LuCI "Save & Apply" commits `/etc/config/netbird`; procd fires a `config.change`
  reload trigger → `reload_service()` renders and applies. (No custom apply button; this also
  gives OpenWRT rollback semantics.)
- **Forward semantics + inversion are centralized here**: the UI is always positive ("Enable X");
  when off, the init.d emits the negative flag (`--disable-X` / `--block-X`). The frontend never
  inverts.
- **Capability gating**: at apply time the script reads `netbird up --help` and only emits flags
  the *running* binary supports; unsupported flags are silently skipped. So switching to an older
  binary never errors out on flags it lacks.
- **Injection-safe**: values are accumulated as `set -- "$@" --flag "$val"` positional parameters
  (no `eval`), equivalent to shell-quoting.
- **Interface-name sync**: renaming the WireGuard interface re-syncs the netbird fw4 zone's
  `list device` *before* netbird re-establishes (firewall reload must precede `netbird up`, or
  forwarding breaks). Only the firewall is reloaded — **never the network** — so even a rename
  never flushes the live device.
- **Pre-shared key is never logged**: it is not placed in `$@`; it is appended only at exec time,
  and logs/dry-run show a static `--preshared-key ***`.

## Versions tab

The tab manages two different update planes and keeps them separate:

1. **NetBird client binary source** — switched by repointing the `/usr/bin/netbird` symlink (the
   path the upstream procd service hard-codes).
2. **The LuCI app package itself** — checked and upgraded from this project's signed package feed.

### NetBird binary source management

Three sources:

| Source | Active form | Provenance & validation |
|---|---|---|
| **release** | symlink → `/usr/share/netbird/bin/netbird-release` | GitHub latest release; **SHA-256 + ELF e_machine arch** validated; backup/restore on failure. |
| **opkg** | real file at `/usr/bin/netbird` | OpenWRT package build; restored from a preserved copy, or fetched via `opkg download` + extract — **never** `opkg install --force-reinstall` (that would remove the daemon's `init.d`). |
| **custom** | symlink → `/usr/share/netbird/bin/netbird-v<ver>` | mirror/accelerator URL; **version-named** so multiple versions coexist (switch / roll back / delete); arch verified from the downloaded binary's ELF header. An **optional user-supplied checksum** (md5/sha1/sha256/sha512, auto-detected by length) is hard-verified before the binary is ever run; an `http://` URL with no checksum warns first (sha256+ recommended; md5/sha1 only guard corruption). |

Switching = stop daemon → poll until the process truly exits (avoid `ETXTBSY` when replacing a
running binary) → flip the symlink / restore the file → start. The identity in `config.json` is
preserved across switches.

**Package-manager dispatch (OpenWRT 24/25).** The "opkg" source is a *semantic* name for "the
distro feed". The four feed touchpoints (`_pkg_mgr`, `_opkg_feed_has_netbird`,
`_opkg_upgradable_netbird`, `_fetch_opkg_binary`, `get_opkg_versions`) dispatch at runtime by
`_pkg_mgr()` (`apk` if `/usr/bin/apk` exists, else `opkg`). On apk the C9-safe fetch is
`apk fetch` + `apk extract --allow-untrusted` (an OpenWRT `.apk` is apk-v3 ADB, unreadable by
`tar`); **never** `apk add/del/fix` (C9 — would delete the daemon's `init.d`). Downloads use
`_dl_cmd` (curl → uclient-fetch → BusyBox wget) so the release/custom paths work on minimal
images without curl.

**Multi-arch.** The package is `PKGARCH:=all` (pure ucode/JS/shell) → one artifact for every CPU;
no build matrix. Arch only matters at runtime for binary acquisition: the **feed path is
arch-agnostic** (the distro serves the right binary; validated against the host's own ELF
e_machine via `_native_emachine`, so it works on mips/riscv/etc.), while the **GitHub
auto-pick** stays at netbird's unambiguous release arches (amd64/arm64/386/armv6 — mips float ABI
can't be inferred from `uname -m`). Custom-URL is relaxed to any arch (host-ELF validated).

### luci-app-netbird package self-update

The current `luci-app-netbird` version row has its own "check for updates" action. It does **not**
touch the NetBird daemon or `/usr/bin/netbird`; it upgrades this LuCI package and its i18n package.

Backend methods:

- `check_luci_app_update` (read) — reads the package index and reports latest/local versions.
- `update_luci_app` (write) — re-checks, downloads the package files into `/tmp/nb-luci-update*`,
  installs them, and cleans the temporary directory on success or failure.

Feed selection is by OpenWrt release series:

| OpenWrt series | Package manager | Feed | Package filename |
|---|---|---|---|
| 24.10 | `opkg` | `https://luci-app-netbird.okk.sh/openwrt-24.10/all/netbird/` | `luci-app-netbird_<ver>_all.ipk` |
| 25.12 | `apk` | `https://luci-app-netbird.okk.sh/openwrt-25.12/all/netbird/` | `luci-app-netbird-<ver>.apk` |

Both the main package and `luci-i18n-netbird-zh-cn` are installed together. If either download fails
or is incomplete, the update is rejected and temporary files are removed; the UI keeps the user on
the current version and shows the error. When there is no newer version, `update_luci_app` returns
`invalid_input` and does not create an install workdir.

## State machine

Five runtime-first states (trust the daemon when reachable):
`not_installed` / `service_disabled` / `service_stopped` / `needs_login` / `running`.

## Network automation (network tab) — device-bound zone, no netifd interface

The netbird device (`wt0`/etc.) is daemon-managed (overlay IP + peer-subnet routes). The app
**never creates an OpenWRT `network.netbird` interface** for it. An earlier design did, and the
required `reload network` made netifd flush the device's IP/routes — and netbird does **not**
self-heal, so a router managed over the mesh could hard-lock. Instead:

- `setup_firewall_zone` — a dedicated `netbird` fw4 zone bound **directly to the device** via
  `list device '<iface>'` (iface from settings). fw4 matches `iifname/oifname` by name (works even
  before the device exists). **Only `reload firewall` ever runs — never `reload network`** → the
  device's data plane is never flushed (zero remote-lockdown risk).
- `setup_forwarding` — `lan ↔ netbird` forwarding rules, **opt-in, off by default, each direction
  independent**. Disabling a direction flushes the matching conntrack — by **every netbird-routed
  destination** (overlay + peer subnets, IPv4 + IPv6; prefix ≥ /8 excludes near-default/exit-node
  routes so it can never become a full-table flush) — so it takes effect on already-established flows
  **without a reconnect** (best-effort; needs the `conntrack` tool).
- `get_automation_status` — reports `zone_exists` + `zone_device` + both forwarding booleans (no
  interface concept).
- `teardown_automation` — removes only the named zone + forwarding sections (plus, defensively, a
  legacy `network.netbird` interface if an upgraded box still has one — UCI-only, **no
  `reload network`**); **never** touches `lan`/`wan`; reloads only the firewall.
- **Upgrade migration** (uci-defaults, one-time): a box upgraded from the old design has its zone
  converted to device-binding and the legacy `network.netbird` interface removed (UCI-only, no
  `reload network`).
- **Reconnect self-heal**: after `do_up` reconnects and netbird restores its routes, conntrack for
  netbird-routed destinations is flushed (both directions) so in-flight forwarded flows re-establish
  on the restored routes instead of staying pinned to a now-stale route.

## Conventions (gotchas worth knowing)

- **ucode modules** load via `loadfile()` IIFE (the runtime build does not support `export`), and
  **do not hoist function declarations** — a helper must be defined textually before its callers.
- **ACL ↔ method table** must stay strictly 1:1 (12 read + 14 write = 26).
- **DOM** is built with `E()` only (XSS).
- **Binary/state paths** are probed at runtime, never hard-coded.
- Identity is protected on two axes: `conffiles` (opkg upgrades) and `sysupgrade.conf`
  (firmware flashes).

## Maintenance

`scripts/check-flags.sh` diffs `netbird up --help` against the flags the init.d actually maps,
so upstream additions surface as a reviewable list when bumping the supported NetBird release.
