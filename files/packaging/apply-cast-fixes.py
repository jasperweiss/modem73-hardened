#!/usr/bin/env python3
"""Rewrite C-style casts that clang-tidy will not autofix.

modernize-avoid-c-style-cast offers static_cast when the types are known.
Inside this template it still warns, with an empty fix, when the operand is
type-dependent. Every such site here casts to an integer type, and
static_cast is the conversion that compiles for two arithmetic types.
Pointer and reference casts are left untouched and fail the build.
"""

import re
import sys
from pathlib import Path


UNFIXED = re.compile(
    r"^[ \t]*FilePath:[ \t]*(?P<path>.+?)\s*$\n"
    r"^[ \t]*FileOffset:[ \t]*(?P<offset>\d+)\s*$\n"
    r"^[ \t]*Replacements:[ \t]*\[\]\s*$",
    re.MULTILINE,
)

# A parenthesized nested cast, not a grouped expression such as (a + b).
NESTED_TYPE = re.compile(
    rb"^\s*(?:const\s+|volatile\s+|unsigned\s+|signed\s+|long\s+|short\s+)*"
    rb"(?:std\s*::\s*)?"
    rb"(?:size_t|ptrdiff_t|u?int(?:8|16|32|64)_t|uintptr_t|intptr_t|"
    rb"uint_fast(?:8|16|32|64)_t|int|char|bool|short|long|unsigned|signed)"
    rb"(?:\s+(?:const|volatile|unsigned|signed|long|short|int))*\s*$"
)


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] and value[0] == '"':
        return value[1:-1]
    return value


def parse_unfixed(text):
    found = []
    # Compiler errors are exported with an empty replacement list too.
    # Only the cast diagnostic is a rewrite site.
    for part in re.split(r"(?=DiagnosticName:)", text):
        first = part.splitlines()[0] if part else ""
        if "modernize-avoid-c-style-cast" not in first:
            continue
        for match in UNFIXED.finditer(part):
            found.append((unquote(match.group("path")), int(match.group("offset"))))
    return found


def skip_ws(src, index):
    while index < len(src) and src[index : index + 1] in b" \t\r\n":
        index += 1
    return index


def match_delim(src, open_at, open_b, close_b):
    if src[open_at : open_at + 1] != open_b:
        raise SystemExit(f"expected {open_b!r} at byte offset {open_at}")
    depth = 0
    index = open_at
    limit = len(src)
    while index < limit:
        char = src[index : index + 1]
        if char in b"'\"":
            quote = char
            index += 1
            while index < limit:
                if src[index : index + 1] == b"\\":
                    index += 2
                    continue
                if src[index : index + 1] == quote:
                    break
                index += 1
            index += 1
            continue
        if char == open_b:
            depth += 1
        elif char == close_b:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise SystemExit(f"no matching {close_b!r} for byte offset {open_at}")


def read_name(src, index):
    start = index
    while True:
        if src[index : index + 2] == b"::":
            index += 2
        if not (src[index : index + 1].isalpha() or src[index : index + 1] == b"_"):
            break
        index += 1
        while index < len(src) and (src[index : index + 1].isalnum() or src[index : index + 1] == b"_"):
            index += 1
        if src[index : index + 2] == b"::":
            continue
        break
    if index == start:
        raise SystemExit(f"expected a type name at byte offset {start}")
    if src[index : index + 1] == b"<":
        depth = 0
        while index < len(src):
            char = src[index : index + 1]
            if char == b"<":
                depth += 1
            elif char == b">":
                depth -= 1
                index += 1
                if depth == 0:
                    break
                continue
            index += 1
    return index


def postfix_end(src, index):
    index = skip_ws(src, index)
    char = src[index : index + 1]
    if char == b"(":
        close = match_delim(src, index, b"(", b")")
        inner = src[index + 1 : close]
        if NESTED_TYPE.match(inner):
            return operand_end(src, close + 1)
        index = close + 1
    elif char in b"'\"0123456789" or char.isalpha() or char == b"_":
        if char in b"'\"":
            close_quote = char
            index += 1
            while index < len(src):
                if src[index : index + 1] == b"\\":
                    index += 2
                    continue
                if src[index : index + 1] == close_quote:
                    index += 1
                    break
                index += 1
        else:
            index += 1
            while index < len(src) and (src[index : index + 1].isalnum() or src[index : index + 1] == b"_"):
                index += 1
    else:
        snippet = src[index : index + 40]
        raise SystemExit(f"unparsed cast operand at byte offset {index}: {snippet!r}")
    while True:
        nxt = skip_ws(src, index)
        op = src[nxt : nxt + 2]
        if op == b"->":
            index = read_name(src, skip_ws(src, nxt + 2))
            continue
        one = src[nxt : nxt + 1]
        if one == b".":
            index = read_name(src, skip_ws(src, nxt + 1))
            continue
        if one in b"([":
            close_b = b")" if one == b"(" else b"]"
            index = match_delim(src, nxt, one, close_b) + 1
            continue
        if op in (b"++", b"--"):
            index = nxt + 2
            continue
        return index


def operand_end(src, index):
    index = skip_ws(src, index)
    if src[index : index + 2] in (b"++", b"--"):
        return operand_end(src, index + 2)
    if src[index : index + 1] in b"&*+-!~":
        return operand_end(src, index + 1)
    return postfix_end(src, index)


def rewrite_one(src, offset):
    if offset < 0 or offset >= len(src):
        raise SystemExit(f"cast offset {offset} is outside the file")
    if src[offset : offset + 1] == b"(":
        type_close = match_delim(src, offset, b"(", b")")
        type_text = src[offset + 1 : type_close].strip()
        if b"*" in type_text or b"&" in type_text:
            raise SystemExit(f"refusing pointer cast at byte offset {offset}: {type_text!r}")
        expr_end = operand_end(src, type_close + 1)
        expr = src[type_close + 1 : expr_end].strip()
        if not type_text or not expr:
            raise SystemExit(f"empty cast at byte offset {offset}")
        replacement = b"static_cast<" + type_text + b">(" + expr + b")"
        return offset, expr_end, replacement
    name_end = read_name(src, offset)
    paren = skip_ws(src, name_end)
    if src[paren : paren + 1] != b"(":
        snippet = src[offset : offset + 40]
        raise SystemExit(f"expected a functional cast at byte offset {offset}: {snippet!r}")
    arg_close = match_delim(src, paren, b"(", b")")
    type_text = src[offset:name_end].strip()
    expr = src[paren + 1 : arg_close].strip()
    if b"*" in type_text or b"&" in type_text:
        raise SystemExit(f"refusing pointer cast at byte offset {offset}: {type_text!r}")
    replacement = b"static_cast<" + type_text + b">(" + expr + b")"
    return offset, arg_close + 1, replacement


def skipped(path):
    return "deps" in Path(path).parts or path.startswith("/usr/")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} cast-fixes.yml")
    yaml_path = Path(sys.argv[1])
    if not yaml_path.is_file() or yaml_path.stat().st_size == 0:
        print("no unfixed C-style casts")
        return
    grouped = {}
    for path, offset in parse_unfixed(yaml_path.read_text()):
        if skipped(path):
            continue
        grouped.setdefault(path, []).append(offset)
    if not grouped:
        print("no unfixed C-style casts")
        return
    for path, offsets in grouped.items():
        file_path = Path(path)
        original = file_path.read_bytes()
        edits = []
        for offset in offsets:
            try:
                edits.append(rewrite_one(original, offset))
            except SystemExit as exc:
                raise SystemExit(f"{path}: {exc}") from None
        updated = original
        for start, end, text in sorted(edits, reverse=True):
            updated = updated[:start] + text + updated[end:]
        if updated == original:
            continue
        file_path.write_bytes(updated)
        print(f"rewrote {len(edits)} C-style casts in {file_path}")


if __name__ == "__main__":
    main()
