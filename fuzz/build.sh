#!/bin/bash
# Build the kernel fuzz target against the pinned modem73 tag plus this overlay.
# The binary is not installed and is not linked into the RPM.
# Usage: fuzz/build.sh <work-tree>
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=${1:?usage: fuzz/build.sh <work-tree>}

# shellcheck disable=SC1091
. "$root/upstream.pin"

rm -rf "$work"
git clone --depth 1 --branch "$tag" "https://github.com/${repository}.git" "$work"
got=$(git -C "$work" rev-parse HEAD)
if [[ "$got" != "$commit" ]]; then
    echo "fuzz: ${tag} is ${got}, pin is ${commit}" >&2
    exit 1
fi
"$root/apply-overlay.sh" "$work"

clang++ -std=c++17 -O1 -g -march=x86-64-v2 \
    -fsanitize=address,undefined -fno-sanitize-recover=all -fsanitize=fuzzer \
    -I"$work" \
    -I"$work/deps/aicodix/dsp" \
    -I"$work/deps/aicodix/code" \
    -I"$work/deps/aicodix/modem" \
    -I"$work/phy" \
    "$root/fuzz/kernels.cc" -o "$work/fuzz-kernels"

echo "fuzz binary: $work/fuzz-kernels"
