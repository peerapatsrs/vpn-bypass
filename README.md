# vpn-bypass

CLI and localhost UI that split-route **IPv4** around a full-tunnel corporate VPN: general web via your home LAN, intranet via the VPN.

[![npm version](https://img.shields.io/npm/v/vpn-bypass.svg)](https://www.npmjs.com/package/vpn-bypass)
[![node](https://img.shields.io/node/v/vpn-bypass.svg)](https://nodejs.org)

This is **not** official corporate split-tunnel. The well-tested case is **macOS + Palo Alto GlobalProtect** (`utun`). Linux and Windows adapters exist and are less tested.

CLI and UI are Thai/English (`locale` in config, default `th`): `vpn-bypass --lang en <command>` or `vpn-bypass lang en`.

## Warnings

Read these before you install or apply routes.

1. **This may violate corporate policy / AUP.** You are responsible for how you use it.
2. **Administrator privileges (sudo / Windows admin) are required** to add or delete routes. Installing the package is not enough.
3. **Closing the UI tab or the terminal does not restore routes.** Run `vpn-bypass off` (or Stop in the UI).
4. **DNS still goes via the VPN.** Resolved names may not match the IPv4 path you split.
5. **IPv4 only.** IPv6 may leak or stay full-tunnel.
6. **GlobalProtect (or another VPN client) may overwrite these routes**, especially on reconnect. Watch is **off** by default and only works while that process stays running.
7. **No automatic failover.** If a site is unreachable on home internet, nothing is sent via VPN until you confirm (`[y/N]`, default no; the UI requires a hard confirm).
8. **Dry-run first:** `vpn-bypass on --dry-run`.

## Requirements

- Node.js 18 or later
- sudo (macOS/Linux) or an elevated shell (Windows) to change the routing table
- An IPv4 VPN that is actually up (detected as `utun` / `tun` / `tap` / `ppp` / `ipsec` / `gpd`)
- A reachable home LAN gateway

No runtime npm dependencies.

## Install

Once published:

```bash
npm i -g vpn-bypass
vpn-bypass status
```

Or without a global install:

```bash
npx vpn-bypass status
```

Applying routes still needs admin rights, for example:

```bash
sudo vpn-bypass on
```

### From this repository

```bash
npm i
npx vpn-bypass status
# or install the command from this folder:
npm i -g .
```

## Quick start

```bash
vpn-bypass status
sudo vpn-bypass on --dry-run
sudo vpn-bypass on
vpn-bypass ui
sudo vpn-bypass off
```

`on` is save-and-close: you can quit the process; routes stay until `off`. `off` deletes **only** ledger-owned routes (`applied.json`), not the VPN client’s own defaults.

## Modes

### Default — `inverse`

“General web via home internet, company traffic via VPN.”

- Adds `0.0.0.0/1` and `128.0.0.0/1` via the LAN gateway (covers the IPv4 Internet without deleting the VPN default).
- **Re-pins RFC1918 via the VPN interface** so intranet still works: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (plus extra VPN CIDRs the client advertised). Without this, `/1` via LAN would steal corporate private ranges.
- Protects your home LAN subnet (typically `/24`) via the LAN gateway so it wins over the RFC1918 `/16`.

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
watch [on|off]                 Re-apply missing routes (off by default; process must stay up)
lookup <host>                  Show whether a host/IP uses LAN or VPN
ui                             Open the UI on 127.0.0.1
lang th|en                     Save CLI/UI language in config
```

`watch on` keeps the process in the foreground. Ctrl+C stops watch; it does **not** run `off`.

## UI

```bash
vpn-bypass ui
# or from a clone:
npm start
```

- Listens on **`127.0.0.1` only** (preferred port **18787**, or a random free port). There is no `HOST` env to bind `0.0.0.0`.
- Per-process token (`X-Vpn-Bypass-Token`); `Host` / `Origin` must be `http://127.0.0.1:<port>`.
- Thai/English, live traffic card, and lookup.

Closing the tab does not call `off`.

## Configuration

| Platform | Directory |
| --- | --- |
| macOS / Linux | `~/.config/vpn-bypass/` |
| Windows | `%APPDATA%\vpn-bypass\` |

Override the directory with `VPN_BYPASS_HOME` (or `XDG_CONFIG_HOME` on Unix). Under `sudo`, the tool prefers the invoking user’s home, not `/var/root`.

| File | Role |
| --- | --- |
| `config.json` | Mode, domains, locale (`th`/`en`), watch flag, LAN protect |
| `applied.json` | Ledger of owned routes (`off` deletes only these) |
| `apply.lock` | Apply lock |

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Routes revert to full tunnel soon after apply | GlobalProtect reconnect overwrote `/1`. Turn watch on temporarily or apply again. Nothing permanently blocks overwrite. |
| Web works on home internet but org login / hostnames are wrong | DNS still via VPN (split-horizon). |
| Some sites still use the VPN after inverse | IPv6 / AAAA. Try disabling IPv6 on the LAN, or check `lookup`. |
| Home printer / NAS disappears | VPN pushed `192.168.0.0/16` over the LAN. The tool pins your LAN subnet (typically `/24`) via the LAN gateway; if the prefix is not `/24`, check `status`. |
| `ENOTVPN` | Connect the VPN first; the interface must be up. |
| `EPRIV` / “needs sudo” | Re-run `on` / `off` / `allow` / `deny` with admin rights. |
| `EDOMAIN_EMPTY` | Add at least one domain before `on --mode domains`. |

## Development

```bash
npm test
# or
node --test
```

Tests use fixtures and inject `exec`. They **do not** add or delete real routes in CI.

Supported adapters: `darwin`, `linux`, `win32`. Other OS values fail with `EUNSUPPORTED`.

## License

MIT
