#!/usr/bin/env bash
# Restore ownership only for root-owned files in this user's v2rayN installation.
# Run as your normal user; sudo is requested only for chown.
set -euo pipefail

if (( EUID == 0 )); then
    echo "Run this script as your normal user, without sudo." >&2
    exit 1
fi

install_dir="$HOME/Application/v2rayN-linux-64"
if [[ ! -d "$install_dir" || -L "$install_dir" ]]; then
    echo "Installation directory missing or is a symlink: $install_dir" >&2
    exit 1
fi

mapfile -d '' files < <(find "$install_dir" -type f -user root -print0)
if (( ${#files[@]} == 0 )); then
    echo "No root-owned files found in $install_dir"
    exit 0
fi

printf 'Close v2rayN before continuing.\n\nFiles to repair:\n'
printf '  %s\n' "${files[@]}"
printf '\nChange ownership of %d files to %s:%s? [y/N] ' \
    "${#files[@]}" "$(id -un)" "$(id -gn)"
read -r answer
case "$answer" in
    y|Y|yes|YES) ;;
    *) echo "Cancelled."; exit 0 ;;
esac

sudo chown --no-dereference --from=0 "$(id -u):$(id -g)" -- "${files[@]}"
echo "Done. System crash dumps were intentionally left unchanged."
