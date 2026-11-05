# sing-box on this PC

## Binaries

| Location | Version | Notes |
|---|---|---|
| `/home/alireza/Application/v2rayN-linux-64/bin/sing_box/sing-box` | 1.13.4 (go1.25.8) | **Active** — the one currently running (bundled with v2rayN) |
| `/home/alireza/Downloads/sing-box-1.14.0-alpha.37-linux-amd64/sing-box` | 1.14.0-alpha.37 | Alpha build; rich tags (quic, wireguard, utls, clash_api, tailscale, …) |
| `/opt/happ/bin/tun/sing-box` | 1.12.12 | Bundled with the Happ app |
| `/home/alireza/repos/sing-box` | source @ v1.13.0-rc.3 | Clone of SagerNet/sing-box (origin GitHub) |

Not on `PATH`. No systemd unit; it's run manually with `sudo` (needed for TUN).

## Running process

```
sudo sing-box run -c /home/alireza/repos/oxito/sing-box-hf.json   # pid 7420
```

## Configs

### `~/repos/oxito/sing-box-hf.json` (currently loaded)
- TUN in (`tun-hf`, 198.18.0.1/30, gvisor stack), DNS → 192.168.0.1 (router), ipv4_only
- Outbound `socks5` → 127.0.0.1:10808
- Route rules: chromium & node → `xray-proxy`; everything else → direct

## Logs

- `~/.local/state/oxito/sing-box.log` (~2200 lines, live process output)
