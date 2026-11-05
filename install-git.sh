#!/bin/sh
# Build and install oxito for the current user: binary, icon and app-menu entry.
set -e
cd "$(dirname "$0")"
cargo build --release
data="${XDG_DATA_HOME:-$HOME/.local/share}"
bin="$HOME/.local/bin/oxito"
install -Dm755 target/release/oxito "$bin"
install -Dm644 assets/oxito.svg "$data/icons/hicolor/scalable/apps/oxito.svg"
# absolute Exec: ~/.local/bin isn't always on the launcher's PATH
sed "s|^Exec=.*|Exec=$bin|" assets/oxito.desktop > "$data/applications/oxito.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database -q "$data/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$data/icons/hicolor" || true
echo "installed $bin"
