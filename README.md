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
  - **Click** an app to open its details (open connections, domains seen this session, running
    processes) with a **Route via VPN** / **Remove** button.
  - **Double-click** toggles routing. **Right-click** opens a menu (route, copy path, forget).
- **VPN routes** tab: routed apps (`process_path`) and domains (`domain_suffix`); add or remove them.
- **sing-box** tab: binary path, status of every running instance, Reset / Reload / Stop / Check,
  and the live sing-box log.

Every change is saved to the config (previous version kept as `config.json.bak`), validated with
`sing-box check`, then hot-reloaded.

## Files

| Path | Purpose |
|---|---|
| `example_config.json` | Seed config (TUN in, socks → xray, chromium/node via VPN). Also built into the binary. |
| `~/.config/proxy2vpn/config.json` | The working config the app edits and sing-box runs. Created from the example on first launch. |
| `~/.config/proxy2vpn/settings.json` | sing-box binary path, reset options |
| `~/.local/state/proxy2vpn/history.db` | Session history (same schema as the old `p2v.py`). **Recreated empty at every launch** and pruned to the activity window every 10 s. |
| `~/.local/state/proxy2vpn/` | also `sing-box.log`, pid files, `ctl` FIFO |
| `archive/` | The previous Python CLI (`p2v.py`), its docs and the original configs |

## Reset and reload

sing-box needs root for TUN. Its own `SIGHUP` reload is unusable with TUN: it opens the new device
while the old one is still held and dies with `TUNSETIFF: device or resource busy`. The Clash API's
`PUT /configs` does nothing. So **Reset** asks for authorisation once (via cached `sudo`, otherwise
`pkexec`) and then:

1. stops the running sing-box instances: all of them by default, or only those using this config
   if you turn off the option;
2. starts sing-box with the app's config under a small root shell supervisor;
3. the supervisor listens on a user-owned FIFO (`~/.local/state/proxy2vpn/ctl`):
   - `reload`: stop sing-box, wait until it has fully exited, start it again;
   - `stop`: stop sing-box and exit.

   If sing-box crashes, the supervisor restarts it. It gives up after 3 quick failures in a row.

After that, routing changes restart sing-box with no password. If sing-box wasn't started by the
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
`dns.reverse_mapping` in the config, because the connection view needs them.
