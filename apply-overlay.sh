#!/bin/bash
# Apply this overlay onto a clean checkout of the pinned modem73 tag.
# Usage: ./apply-overlay.sh <upstream-tree>
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
dest=${1:?usage: apply-overlay.sh <upstream-tree>}

if [[ ! -f "$dest/kiss_tnc.cc" || ! -f "$dest/packaging/Makefile.pkg" ]]; then
    echo "apply-overlay: $dest does not look like a modem73 tree" >&2
    exit 1
fi

shopt -s nullglob
patches=("$root"/patches/*.patch)
if (( ${#patches[@]} == 0 )); then
    echo "apply-overlay: no patches in $root/patches" >&2
    exit 1
fi
for patch in "${patches[@]}"; do
    git -C "$dest" apply --check "$patch"
    git -C "$dest" apply "$patch"
done
cp -a "$root/files/." "$dest/"
