#!/usr/bin/env python3
"""Apply clang-tidy subscript fixes as container.at(index).

clang-tidy FixMode=at replaces the '[' token with '.at(' for ordinary
calls, but inside a template it replaces the container token instead and
leaves the '[' in place. The exported offsets still identify the container
and the closing ']', so this rewrites each match as container.at(index).

Offsets in the export are bytes. Source files in this tree contain
non-ASCII text, so the rewrite is done on the raw bytes.
"""

import re
import sys
from pathlib import Path


REPLACEMENT = re.compile(
    r"^[ \t]*-[ \t]*FilePath:[ \t]*(?P<path>.+?)\s*$\n"
    r"^[ \t]*Offset:[ \t]*(?P<offset>\d+)\s*$\n"
    r"^[ \t]*Length:[ \t]*(?P<length>\d+)\s*$\n"
    r"^[ \t]*ReplacementText:[ \t]*(?P<text>.*?)\s*$",
    re.MULTILINE,
)


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] and value[0] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return value


def parse_fixes(text):
    """Return [(path, offset, length, replacement), ...] from export-fixes YAML."""
    fixes = []
    for match in REPLACEMENT.finditer(text):
        fixes.append(
            (
                unquote(match.group("path")),
                int(match.group("offset")),
                int(match.group("length")),
                unquote(match.group("text")),
            )
        )
    return fixes


def matching_open(src, close):
    if close < 0 or close >= len(src) or src[close : close + 1] != b"]":
        raise SystemExit(f"expected ']' at byte offset {close}")
    depth = 0
    index = close
    while index >= 0:
        char = src[index : index + 1]
        if char == b"]":
            depth += 1
        elif char == b"[":
            depth -= 1
            if depth == 0:
                return index
        index -= 1
    raise SystemExit(f"no matching '[' for ']' at byte offset {close}")


def edits_for(src, fixes):
    """Pair each '.at(' replacement with the following ')' replacement."""
    edits = []
    pending = None
    for offset, length, repl in fixes:
        if repl == ".at(":
            if pending is not None:
                raise SystemExit("unpaired '.at(' replacement")
            pending = (offset, length)
            continue
        if repl != ")":
            raise SystemExit(f"unexpected subscript replacement {repl!r}")
        if pending is None:
            raise SystemExit("unpaired ')' replacement")
        at_off, at_len = pending
        pending = None
        if at_off < 0 or at_len < 0 or at_off + at_len > len(src):
            raise SystemExit(f"'.at(' replacement out of range at {at_off}")
        if src[at_off : at_off + at_len] == b"[":
            bracket = at_off
        else:
            bracket = matching_open(src, offset)
        if src[bracket : bracket + 1] != b"[":
            raise SystemExit(f"expected '[' at byte offset {bracket}")
        if offset < 0 or offset >= len(src) or src[offset : offset + 1] != b"]":
            raise SystemExit(f"expected ']' at byte offset {offset}")
        edits.append((offset, offset + 1, b")"))
        edits.append((bracket, bracket + 1, b".at("))
    if pending is not None:
        raise SystemExit("unpaired '.at(' replacement")
    return edits


def apply_edits(src, edits):
    ordered = sorted(edits, reverse=True)
    last_start = None
    for start, end, text in ordered:
        if start < 0 or end > len(src) or start >= end:
            raise SystemExit(f"invalid edit range {start}:{end}")
        if last_start is not None and end > last_start:
            raise SystemExit(f"overlapping subscript edits at byte offset {start}")
        last_start = start
    for start, end, text in ordered:
        src = src[:start] + text + src[end:]
    return src


def skipped(path):
    parts = Path(path).parts
    return "deps" in parts or path.startswith("/usr/")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} bounds-fixes.yml")
    yaml_path = Path(sys.argv[1])
    if not yaml_path.is_file() or yaml_path.stat().st_size == 0:
        print("no subscript fixes exported")
        return
    grouped = {}
    for path, offset, length, repl in parse_fixes(yaml_path.read_text()):
        if skipped(path):
            continue
        grouped.setdefault(path, []).append((offset, length, repl))
    for path, fixes in grouped.items():
        file_path = Path(path)
        original = file_path.read_bytes()
        updated = apply_edits(original, edits_for(original, fixes))
        if updated != original:
            file_path.write_bytes(updated)
            print(f"rewrote subscripts in {file_path}")


if __name__ == "__main__":
    main()
