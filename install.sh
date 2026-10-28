#!/bin/sh
# Build and install proxy2vpn for the current user: binary, icon and app-menu entry.
set -e
cd "$(dirname "$0")"
cargo build --release
data="${XDG_DATA_HOME:-$HOME/.local/share}"
bin="$HOME/.local/bin/proxy2vpn"
install -Dm755 target/release/proxy2vpn "$bin"
install -Dm644 assets/proxy2vpn.svg "$data/icons/hicolor/scalable/apps/proxy2vpn.svg"
# absolute Exec: ~/.local/bin isn't always on the launcher's PATH
sed "s|^Exec=.*|Exec=$bin|" assets/proxy2vpn.desktop > "$data/applications/proxy2vpn.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database -q "$data/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$data/icons/hicolor" || true
echo "installed $bin"
