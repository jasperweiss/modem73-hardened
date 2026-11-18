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

patch="$root/patches/0001-harden-build-and-sandbox.patch"
git -C "$dest" apply --check "$patch"
git -C "$dest" apply "$patch"
cp -a "$root/files/." "$dest/"
chmod +x "$dest/packaging/clang-tidy-fix.sh"
