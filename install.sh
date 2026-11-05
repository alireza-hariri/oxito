#!/bin/sh
# Install oxito for the current user from the latest GitHub release: binary, icon and app-menu
# entry. For a from-source install use install-git.sh instead.
set -e

repo="alireza-hariri/oxito"
raw="https://raw.githubusercontent.com/$repo/main"
case "$(uname -m)" in
x86_64) arch="x86_64" ;;
aarch64 | arm64) arch="aarch64" ;;
*) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

url=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
	tr '\n' ' ' | grep -o "\"browser_download_url\": *\"[^\"]*oxito-linux-$arch\"" |
	grep -o 'https://[^"]*')
[ -n "$url" ] || { echo "no release binary for $arch; try install-git.sh" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fSL -o "$tmp/oxito" "$url"
curl -fsSL -o "$tmp/oxito.svg" "$raw/assets/oxito.svg"
curl -fsSL -o "$tmp/oxito.desktop" "$raw/assets/oxito.desktop"

data="${XDG_DATA_HOME:-$HOME/.local/share}"
bin="$HOME/.local/bin/oxito"
install -Dm755 "$tmp/oxito" "$bin"
install -Dm644 "$tmp/oxito.svg" "$data/icons/hicolor/scalable/apps/oxito.svg"
sed "s|^Exec=.*|Exec=$bin|" "$tmp/oxito.desktop" > "$tmp/entry.desktop"
install -Dm644 "$tmp/entry.desktop" "$data/applications/oxito.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database -q "$data/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$data/icons/hicolor" || true
echo "installed $bin"
