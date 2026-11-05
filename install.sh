#!/bin/sh
# Install oxito for the current user from the latest GitHub release: binary, icon and app-menu
# entry. For a from-source install use install-git.sh instead.
set -e

repo="alireza-hariri/oxito"
sb_repo="SagerNet/sing-box"
raw="https://raw.githubusercontent.com/$repo/main"
case "$(uname -m)" in
x86_64) arch="x86_64"; sb_arch="amd64" ;;
aarch64 | arm64) arch="aarch64"; sb_arch="arm64" ;;
*) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# download to stdout, preferring wget when available
fetch() {
	if command -v wget >/dev/null; then
		wget -qO- "$1"
	else
		curl -fsSL "$1"
	fi
}
# download to a file
get() {
	if command -v wget >/dev/null; then
		wget -qO "$2" "$1"
	else
		curl -fSL -o "$2" "$1"
	fi
}

url=$(fetch "https://api.github.com/repos/$repo/releases/latest" |
	tr '\n' ' ' | grep -o "\"browser_download_url\": *\"[^\"]*oxito-linux-$arch.tar.xz\"" |
	grep -o 'https://[^"]*')
[ -n "$url" ] || { echo "no release binary for $arch; try install-git.sh" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
get "$url" "$tmp/oxito.tar.xz"
tar xJf "$tmp/oxito.tar.xz" -C "$tmp"
get "$raw/assets/oxito.svg" "$tmp/oxito.svg"
get "$raw/assets/oxito.desktop" "$tmp/oxito.desktop"

# Latest sing-box release, e.g. sing-box-1.11.5-linux-amd64.tar.gz
sb_ver=$(fetch "https://api.github.com/repos/$sb_repo/releases/latest" | grep -o '"tag_name": *"[^"]*"' | grep -o 'v[^"]*')
[ -n "$sb_ver" ] || { echo "could not determine latest sing-box version" >&2; exit 1; }
sb_url="https://github.com/$sb_repo/releases/download/$sb_ver/sing-box-${sb_ver#v}-linux-$sb_arch.tar.gz"
get "$sb_url" "$tmp/sing-box.tar.gz"
tar xzf "$tmp/sing-box.tar.gz" -C "$tmp"
[ -f "$tmp/sing-box-linux-$sb_arch/sing-box" ] || { echo "unexpected sing-box archive layout" >&2; exit 1; }
install -Dm755 "$tmp/sing-box-linux-$sb_arch/sing-box" "$HOME/.local/oxito/sing-box"

data="${XDG_DATA_HOME:-$HOME/.local/share}"
bin="$HOME/.local/bin/oxito"
install -Dm755 "$tmp/oxito" "$bin"
install -Dm644 "$tmp/oxito.svg" "$data/icons/hicolor/scalable/apps/oxito.svg"
sed "s|^Exec=.*|Exec=$bin|" "$tmp/oxito.desktop" > "$tmp/entry.desktop"
install -Dm644 "$tmp/entry.desktop" "$data/applications/oxito.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database -q "$data/applications" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -qtf "$data/icons/hicolor" || true
echo "installed $bin and $HOME/.local/oxito/sing-box ($sb_ver)"
