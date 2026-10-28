# proxy2vpn

A desktop app (Rust + egui) that shows running processes and what they're connecting to through
sing-box. Pick any app and route it through the VPN with a sing-box `process_path` rule.

```
cargo build --release
./target/release/proxy2vpn            # or: proxy2vpn -c /path/to/config.json
```

## What it does

- **Apps** tab: only apps that sing-box has actually seen making connections. Each row is one
  executable path, which is exactly what a sing-box `process_path` rule matches; all PIDs of that
  binary are folded into one row.
  - **Active in last** (default **5 min**): apps idle for longer drop off the list. Choices are
    1m / 5m / 15m / 1h / 24h / since start.
  - Sort by last activity, speed, open connections, total connections, domains, traffic, CPU,
    memory, name or VPN status, by clicking a column header or using *Sort by*.
  - **Click** an app to select it. **Double-click** toggles routing.
  - **Right-click** opens a menu (more details, route, copy path, forget). *More details* opens a
    side panel (open connections, domains seen this session, running processes) with a
    **Route via VPN** / **Remove** button.
- **VPN routes** tab: routed apps (`process_path`) and domains (`domain_suffix`); add or remove them.
- **sing-box** tab: binary path, status of every running instance, Reset / Reload / Stop / Check,
  and the live sing-box log.

Routed apps and domains live in a local rule-set, `config.rules.json`, next to the config. A
change rewrites only that file. sing-box watches it and swaps the rules in place: no restart, the
TUN stays up and other apps' connections are untouched. Connections that already exist keep their
old route, so the app then closes the affected app's (or domain's) open connections through the
Clash API and they reconnect under the new rules. If sing-box isn't running with this config, a
change does a Reset instead.

## Files

| Path | Purpose |
|---|---|
| `example_config.json` | Seed config (TUN in, socks → xray, chromium/node via VPN). Also built into the binary. |
| `~/.config/proxy2vpn/config.json` | The working config the app edits and sing-box runs. Created from the example on first launch. |
| `~/.config/proxy2vpn/config.rules.json` | The routed apps and domains: a sing-box rule-set the config points at, reloaded by sing-box when it changes. |
| `~/.config/proxy2vpn/settings.json` | sing-box binary path, reset options |
| `~/.local/state/proxy2vpn/history.db` | Session history (same schema as the old `p2v.py`). **Recreated empty at every launch** and pruned to the activity window every 10 s. |
| `~/.local/state/proxy2vpn/` | also `sing-box.log`, pid files, `ctl` FIFO |
| `archive/` | The previous Python CLI (`p2v.py`), its docs and the original configs |

## Reset and reload

Routing changes don't need this (see above); it's for edits to the rest of the config.

sing-box needs root for TUN. Its own `SIGHUP` reload is unusable with TUN: it closes the old
instance but doesn't wait for the kernel to release the device, so opening it again races and
fails with `TUNSETIFF: device or resource busy`, and the process dies. The Clash API's
`PUT /configs` does nothing. So **Reset** asks for authorisation once (via cached `sudo`, otherwise
`pkexec`) and then:

1. stops the running sing-box instances: all of them by default, or only those using this config
   if you turn off the option;
2. starts sing-box with the app's config under a small root shell supervisor;
3. the supervisor listens on a user-owned FIFO (`~/.local/state/proxy2vpn/ctl`):
   - `reload`: stop sing-box, wait until it has fully exited, start it again;
   - `stop`: stop sing-box and exit.

   If sing-box crashes, the supervisor restarts it. It gives up after 3 quick failures in a row.

After that, Reload restarts sing-box with no password. If sing-box wasn't started by the
app (or by an older version of its supervisor), the next change does a Reset instead.

## Keyboard

| Key | Action |
|---|---|
| Space / Enter | route or unroute the selected app |
| ↑ ↓ (j k), Home / End | move selection |
| Esc | close details / clear filter |
| `/` or Ctrl+F | filter |
| Alt+1 / 2 / 3 | switch tabs |
| Ctrl+R | reset sing-box |
| Ctrl + / − / 0 | zoom (remembered; default 125%) |

By default the app resets sing-box at launch unless its own supervised instance is already running
with this config. You can turn that off in the sing-box tab.

On first launch the app turns on `experimental.clash_api` (with a random secret) and
`dns.reverse_mapping` in the config, because the connection view needs them. It also sets
`route.find_process` (sing-box only decides at startup whether to look up processes, and the
rule-set may start empty), adds the `proxy2vpn` rule-set with a rule sending it to the VPN outbound,
and moves any old in-config `process_path` / `domain_suffix` VPN rules into the rule-set. If a
sing-box with the old config is running, it is restarted once to pick that up.
