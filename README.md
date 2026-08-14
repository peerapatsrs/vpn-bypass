# vpn-bypass

CLI and localhost UI that split-route **IPv4** (and best-effort **IPv6** on macOS/Linux) around a **full-tunnel corporate VPN**, and apply **system split-DNS** on macOS: general web uses your home internet; intranet stays on the VPN.

[![npm version](https://img.shields.io/npm/v/@peerapat.srs/vpn-bypass.svg)](https://www.npmjs.com/package/@peerapat.srs/vpn-bypass)
[![node](https://img.shields.io/node/v/@peerapat.srs/vpn-bypass.svg)](https://nodejs.org)

Package: [`@peerapat.srs/vpn-bypass`](https://www.npmjs.com/package/@peerapat.srs/vpn-bypass)  
Command after install: **`vpn-bypass`**  
Source: [github.com/peerapatsrs/vpn-bypass](https://github.com/peerapatsrs/vpn-bypass)

This is **not** official corporate split-tunnel. The well-tested case is **macOS + Palo Alto GlobalProtect** (`utun`). Linux and Windows adapters exist and are less tested.

CLI and UI are Thai/English (`locale` in config, default `th`): `vpn-bypass --lang en <command>` or `vpn-bypass lang en`.

## Features

- **Default inverse mode:** public web via the home LAN gateway; RFC1918 (`10/8`, `172.16/12`, `192.168/16`) and extra VPN CIDRs stay on the tunnel; your home LAN `/24` is protected so printers/NAS still work.
- **Split-DNS (macOS):** a small local forwarder on `127.0.0.1` sends general names to home DNS and corporate suffixes / RFC1918 PTR to VPN DNS. Linux is best-effort (`resolvectl`). Windows does not change system DNS.
- **IPv6 (macOS/Linux):** when an inet6 LAN gateway exists, adds `::/1` and `8000::/1` via that gateway.
- **Localhost UI** on `127.0.0.1` (preferred port **18787**) with CSRF token, live HTTP(S) connections (LAN vs VPN), host lookup, Thai/English.
- **No sudo to open the UI.** macOS asks for an administrator password only when you Start / Stop / allow / deny / watch (route or system DNS changes). The UI process stays your user.
- **Save-and-close routes:** after `on`, you can quit; routes stay until `off`. `off` deletes **only** this tool’s ledger (`ownedRoutes` / `ownedDns`), not the VPN client’s defaults.
- **Reconnect repair:** while the UI is open (after the first admin prompt), overwritten `/1` routes and split-DNS are repaired. CLI `watch` is off by default and must keep that process running.
- **`try` is not a third mode:** probe `host:443` via LAN; VPN host routes require explicit confirm (`[y/N]` / UI type-again). No automatic failover.
- **Advanced domains mode:** full tunnel stays; only listed sites get LAN `/32` host routes. Empty list cannot enable this mode. `www` and apex are stored together.
- Zero runtime npm dependencies. Node.js 18+.

## Supported VPNs

Detection is by **tunnel interface name**, not a certified vendor list.

**Tested:** macOS + **Palo Alto GlobalProtect** (`utun` / `gpd`).

**Also detected when a tunnel is up:** `utun`, `tun`, `tap`, `ppp`, `ipsec`, WireGuard (`wg` / WinTun), AnyConnect (`cscotun`), FortiClient (`fortissl`), and interface names containing `vpn` / `pangp` / `globalprotect`.

Needs a full-tunnel IPv4 VPN with a separate tunnel iface and a reachable home LAN gateway. Not per-app VPN, not browser-only VPN, not an official GP portal split-tunnel profile.

## How inverse works

1. Adds `0.0.0.0/1` and `128.0.0.0/1` via the **LAN gateway** so they beat the VPN default (`0/0`) for the public Internet. The VPN default is **not** deleted.
2. Re-pins **RFC1918** via the VPN iface so intranet is not stolen by those `/1` routes, then pins your **home LAN subnet** via LAN so it wins over `192.168.0.0/16`.
3. On macOS, starts a **DNS forwarder** on `127.0.0.1` and points system DNS at it. Public names (e.g. `facebook.com`) go to home DNS; GP search/corp suffixes and RFC1918 reverse lookups still go to VPN DNS. `off` stops the forwarder and restores the previous servers — it must not leave `127.0.0.1` behind.
4. If GlobalProtect later points owned `/1` prefixes back at the tunnel, repair uses `route change` (macOS) or `ip route replace` (Linux) on **owned destinations only**.

The UI live table is **not** a full visit history: it polls established TCP 80/443 (and 8080/8443) in this process’s memory. Short-lived sockets, QUIC/HTTP3, and DoH in the browser are often missed. Names come from this process’s A-record cache plus reverse DNS, not browser tabs.

Tunnel/firewall visibility of general-web DNS+data can be reduced; a GlobalProtect or EDR **agent on the laptop** can still see local processes.

## Warnings

- Changing routes or system DNS needs **administrator rights** (CLI: `sudo`; UI: macOS password dialog on Start/Stop). Installing the package is not enough.
- **Closing the UI tab or the terminal does not restore routes.** Run `vpn-bypass off` (or Stop in the UI).
- Dry-run first: `vpn-bypass on --dry-run`. There is no automatic failover if a site is unreachable on home internet.

## Requirements

- Node.js 18 or later
- Admin rights to change the routing table: `sudo` on the CLI, or the macOS password dialog from the UI (Linux: `pkexec` when available; Windows: best-effort RunAs)
- An IPv4 VPN that is actually up
- A reachable home LAN gateway

## Install

```bash
npm i -g @peerapat.srs/vpn-bypass
vpn-bypass status
```

Or without a global install:

```bash
npx @peerapat.srs/vpn-bypass status
```

From a clone of this repository:

```bash
npm i
npx vpn-bypass status
# or:
npm i -g .
```

## Quick start

```bash
vpn-bypass status
vpn-bypass on --dry-run
sudo vpn-bypass on          # CLI apply
vpn-bypass ui               # no sudo; password dialog on Start
sudo vpn-bypass off
```

`on` is save-and-close: you can quit the CLI; routes stay until `off`. On macOS inverse, the DNS forwarder is spawned detached so split-DNS also survives quitting the CLI; `off` stops it and restores previous DNS.

Open the UI **without** sudo (`vpn-bypass ui` / `npm start`). Status and preview run as your user. Start / Stop / allow / deny / watch show the macOS admin password dialog, then the unprivileged UI refreshes. Closing the UI stops reconnect repair; routes already applied stay until `off`.

If a previous `sudo vpn-bypass ui` left root-owned files:

```bash
sudo chown -R "$(whoami)" ~/.config/vpn-bypass
vpn-bypass ui
```

## Modes

### Default — `inverse`

“General web via home internet, company traffic via VPN.” See [How inverse works](#how-inverse-works).

### Advanced — `domains`

Full tunnel stays. Only listed sites get host routes (`/32`) via the LAN gateway.

- An **empty list cannot enable** this mode (`EDOMAIN_EMPTY`).
- `domain add` expands **www and apex** (`example.com` ↔ `www.example.com`).
- Hosts are resolved again every time you apply.

### `try` is not a third mode

Use after inverse. Probes `host:443` via LAN. If that fails, the CLI asks `[y/N]` (default no) before adding a VPN host route. The UI requires typing the hostname again plus a checkbox. There is no automatic failover.

## CLI

```text
vpn-bypass [--lang th|en] [--help] [--version] <command>

status                         Show status (lightweight; no public-IP wait)
on [--mode inverse|domains] [--dry-run]
                               Apply routes (default mode: inverse)
off                            Delete only routes this tool added
domain add|rm|list [host]      Manage advanced domain list
try <host>                     Probe host:443 via LAN after inverse
allow <host>                   Add a host route via the VPN (after confirm)
deny <host>                    Remove that VPN host route
watch [on|off]                 Re-apply missing/overwritten owned routes (off by default; process must stay up)
lookup <host>                  Show whether a host/IP uses LAN or VPN
ui                             Open the UI on 127.0.0.1 (no sudo at launch)
lang th|en                     Save CLI/UI language in config
```

`watch on` keeps the process in the foreground. Ctrl+C stops watch; it does **not** run `off`. Prefer leaving `vpn-bypass ui` open (after the first admin password) for reconnect repair while you are at the desk.

## UI

```bash
vpn-bypass ui
# or from a clone:
npm start
```

- Listens on **`127.0.0.1` only** (preferred port **18787**, or a random free port). There is no `HOST` env to bind `0.0.0.0`.
- Per-process token (`X-Vpn-Bypass-Token`); `Host` / `Origin` must be `http://127.0.0.1:<port>`.
- Thai/English, live traffic card, lookup, and DNS status (`split` / `lan` / `vpn`).
- No admin dialog at launch. Mutating actions prompt on macOS; after success the UI stays unprivileged and refreshes status.
- Session repair while the UI process is up (after that first prompt): does **not** set `watch: true` in config; also re-applies split-DNS if GlobalProtect overwrites it.

Closing the tab does not call `off`. Closing the UI process stops automatic reconnect repair.

## Configuration

| Platform | Directory |
| --- | --- |
| macOS / Linux | `~/.config/vpn-bypass/` |
| Windows | `%APPDATA%\vpn-bypass\` |

Override the directory with `VPN_BYPASS_HOME` (or `XDG_CONFIG_HOME` on Unix). Under `sudo`, the tool prefers the invoking user’s home, not `/var/root`. Privileged apply `chown`s the config dir back to that user so the UI can keep running unprivileged.

| File | Role |
| --- | --- |
| `config.json` | Mode, domains, locale (`th`/`en`), watch flag, LAN protect |
| `applied.json` | Ledger of owned routes and DNS (`off` deletes/restores only these) |
| `apply.lock` | Apply lock |

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Routes revert to full tunnel soon after apply | GlobalProtect reconnect overwrote `/1`. Leave `vpn-bypass ui` open (after the admin password), run `watch on`, or apply again. Repair never deletes the VPN default. |
| Banner “VPN overwrote the routes” | Owned `/1` still exists but now via the tunnel. Repair or Start using again. |
| Web works on home internet but org login / hostnames are wrong | Corp suffix missing from split-DNS (check `status` DNS line). Intranet should still use VPN DNS. |
| `dig facebook.com` still hits VPN DNS | Split-DNS not applied, GP overwrote it, or you are on Windows. Re-apply or leave `vpn-bypass ui` open. `off` must restore LAN/DHCP DNS, never leave `127.0.0.1`. |
| Some sites still use the VPN after inverse | No inet6 LAN gateway, or Windows. Check `lookup`. |
| Live traffic shows an IP or CDN PTR | Expected without a prior lookup of that host. Lookup the site once to cache the name. |
| Home printer / NAS disappears | VPN pushed `192.168.0.0/16` over the LAN. The tool pins your LAN subnet (typically `/24`) via the LAN gateway; if the prefix is not `/24`, check `status`. |
| `ENOTVPN` | Connect the VPN first; the interface must be up. |
| `EPRIV` / “needs sudo” | CLI: re-run `on` / `off` / `allow` / `deny` with sudo. UI: click Start/Stop again and complete the admin password dialog. |
| `EACCES` on `~/.config/vpn-bypass` | A previous `sudo vpn-bypass ui` left root-owned files. Once: `sudo chown -R "$(whoami)" ~/.config/vpn-bypass` then `vpn-bypass ui` without sudo. |
| `EDOMAIN_EMPTY` | Add at least one domain before `on --mode domains`. |

## Development

```bash
npm test
# or
node --test
```

Tests use fixtures and inject `exec`. They **do not** add or delete real routes or change live DNS in CI.

Supported adapters: `darwin`, `linux`, `win32`. Other OS values fail with `EUNSUPPORTED`.

## Changelog

### 0.3.0

- Inverse: RFC1918 via VPN, home LAN protect, IPv6 `/1` on macOS/Linux, system split-DNS on macOS.
- Repair overwritten `/1` with `route change` / `replace`; UI session repair without turning CLI watch on.
- UI runs unprivileged; macOS admin password only on mutate. Config dir is chowned back after elevate.
- Live traffic card and `lookup`. Friendly `EACCES` if config is still root-owned.

### 0.1.0

- First public scoped package: inverse `/1` via LAN, domains mode, try/confirm, localhost UI.

## License

MIT
