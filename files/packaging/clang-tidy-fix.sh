#!/bin/bash
# Copy the tree into a stage directory and autofix first-party C++ there.
# The working tree is left unchanged. The final tidy pass fails the build
# when a finding was not fixed.
set -euo pipefail

if [[ $# -lt 4 || "$2" != "--" ]]; then
    echo "usage: clang-tidy-fix.sh <stage> -- <sources...> -- <compiler> <flags...>" >&2
    exit 2
fi

stage=$1
shift 2
sources=()
while [[ "$1" != "--" ]]; do
    sources+=("$1")
    shift
done
shift
compile_args=("$@")

if ! command -v clang-tidy >/dev/null 2>&1; then
    echo "clang-tidy is not installed (Fedora package: clang-tools-extra)" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to apply subscript fixes" >&2
    exit 1
fi

root=$(pwd)
script_dir=$(cd "$(dirname "$0")" && pwd)
rm -rf "$stage"
mkdir -p "$stage"
tar --exclude=build --exclude=.git --exclude=modem73 --exclude='*.o' -cf - . | tar -xf - -C "$stage"

json_quote() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    printf '"%s"' "$s"
}

{
    printf '[\n'
    sep=""
    for src in "${sources[@]}"; do
        printf '%s  {\n' "$sep"
        sep=$',\n'
        printf '    "directory": %s,\n' "$(json_quote "$stage")"
        printf '    "file": %s,\n' "$(json_quote "$src")"
        printf '    "arguments": ['
        argsep=""
        for arg in "${compile_args[@]}" -c "$src"; do
            printf '%s%s' "$argsep" "$(json_quote "$arg")"
            argsep=", "
        done
        printf ']\n  }'
    done
    printf '\n]\n'
} > "$stage/compile_commands.json"

cd "$stage"
tidy_filter=(
    --header-filter='.*\.(hh|cc)$'
    --exclude-header-filter='(^|/)deps/'
)

# FixMode=at mis-edits template calls (it deletes the container token).
# Export the locations and rewrite them as container.at(index).
# clang-tidy exits 1 when it reports the warnings it just exported.
bounds_log=$stage/bounds-tidy.log
set +e
clang-tidy -p . --config-file="$stage/.clang-tidy" \
    --checks='-*,cppcoreguidelines-pro-bounds-avoid-unchecked-container-access' \
    --export-fixes="$stage/bounds-fixes.yml" \
    "${tidy_filter[@]}" \
    "${sources[@]}" >"$bounds_log" 2>&1
bounds_status=$?
set -e
if [[ $bounds_status -gt 1 ]]; then
    echo "clang-tidy bounds export failed (exit $bounds_status)" >&2
    tail -40 "$bounds_log" >&2
    exit "$bounds_status"
fi
python3 "$script_dir/apply-bounds-fixes.py" "$stage/bounds-fixes.yml"

mapfile -d '' first_party < <(find . \( -path ./deps -o -path ./build \) -prune -o \
    \( -name '*.hh' -o -name '*.cc' \) -print0)
if ((${#first_party[@]})) && grep -n -E '\.at\(\[' "${first_party[@]}"; then
    echo "subscript rewrite left a broken .at([ form" >&2
    exit 1
fi

# Keep these exclusions aligned with .clang-tidy. The bounds check is
# intentionally absent: its --fix deletes the container token inside templates.
modernize_config='{Checks: "modernize-*,-modernize-avoid-c-arrays,-modernize-avoid-setjmp-longjmp,-modernize-avoid-variadic-functions,-modernize-use-trailing-return-type,-modernize-return-braced-init-list,-modernize-use-string-view,-modernize-use-std-string-view", FormatStyle: none}'
hash_sources() {
    find . \( -path ./deps -o -path ./build \) -prune -o \
        \( -name '*.hh' -o -name '*.cc' \) -print \
        | LC_ALL=C sort | xargs -r sha256sum | sha256sum
}
for round in 1 2 3 4 5; do
    before=$(hash_sources)
    clang-tidy -p . --config="$modernize_config" --fix --quiet \
        "${tidy_filter[@]}" "${sources[@]}" || true
    after=$(hash_sources)
    if [[ "$before" == "$after" ]]; then
        break
    fi
    echo "clang-tidy modernize round $round changed first-party sources"
done

# Casts inside the modem template are warned about with an empty fix.
# Rewrite those integer casts to static_cast before the gate.
cast_log=$stage/cast-tidy.log
set +e
clang-tidy -p . \
    --config='{Checks: "-*,modernize-avoid-c-style-cast", FormatStyle: none}' \
    --export-fixes="$stage/cast-fixes.yml" \
    "${tidy_filter[@]}" \
    "${sources[@]}" >"$cast_log" 2>&1
cast_status=$?
set -e
if [[ $cast_status -gt 1 ]]; then
    echo "clang-tidy cast export failed (exit $cast_status)" >&2
    tail -40 "$cast_log" >&2
    exit "$cast_status"
fi
python3 "$script_dir/apply-cast-fixes.py" "$stage/cast-fixes.yml"

clang-tidy -p . --config-file="$stage/.clang-tidy" \
    --warnings-as-errors='*' \
    "${tidy_filter[@]}" \
    "${sources[@]}"
cd "$root"
