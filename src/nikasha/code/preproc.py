# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C/C++ attribute-like macros that tree-sitter cannot parse (SPEC §11.2, P4).

Real C often puts an attribute macro between a function's type and its name::

    static void LIBXML_ATTR_FORMAT(3,0)
    xmlErrValid(xmlParserCtxtPtr ctxt, ...)

    static int SQLITE_NOINLINE helper(int x)

Without the preprocessor, tree-sitter reads the macro as the function's name. The real
definition (and often the next one) disappears into a bogus ``LIBXML_ATTR_FORMAT`` function,
and their calls are attributed to it. A genuine trace frame in ``xmlErrValid`` would then
look as if it sat in the wrong function: a false refutation (P4). Measured on libxml2 HEAD,
66 of 1,564 column-0 definitions were lost this way.

:func:`blank_attribute_macros` overwrites such a macro, with its argument list, with spaces.
Every byte offset and line number stays the same. A token is blanked only when all of these
hold:

* it is an all-capitals identifier (3+ characters, at least one letter) on a line that
  starts a file-scope declaration: nothing but identifiers, spaces and ``*`` before it on
  its line, and that line does not start with whitespace, ``#`` or a comment;
* it is followed, after at most one argument list without nested parentheses, by a
  declarator ending in ``name (``: up to four identifiers or ``*`` and at most one line
  break;
* it is not a tag name (``struct FOO``);
* a type remains once it is gone: a non-storage identifier before it (in the text as
  already blanked, so ``static UINT32 WINAPI f(void)`` keeps one of the two), or a type and
  the name after it. ``static BOOL f(void)`` is left alone, because blanking the only type
  breaks the parse.

The parser uses the blanked text only for C and C++ files whose parse has errors, and only
when the blanked parse has strictly fewer, so clean files are never affected. Deterministic
and linear: every candidate inspects a bounded window.
"""

from __future__ import annotations

import re

_CAPS_RE = re.compile(rb"(?<![\w$])[A-Z_][A-Z0-9_]{2,63}+(?![\w$])")
_ARGS_RE = re.compile(rb"\([^()\n]{0,160}+\)")
_IDENT_RE = re.compile(rb"[A-Za-z_]\w{0,127}+")
_PREFIX_RE = re.compile(rb"(?:[A-Za-z_]\w{0,127}+|[ \t*]++){0,24}+")
_STORAGE = frozenset(
    {b"static", b"inline", b"extern", b"__inline", b"__inline__", b"__forceinline",
     b"const", b"volatile", b"register", b"_Noreturn"}
)  # fmt: skip
_KEYWORDS = frozenset(
    {b"if", b"while", b"for", b"switch", b"return", b"sizeof", b"defined", b"do", b"else",
     b"case", b"goto", b"struct", b"union", b"enum", b"typedef"}
)  # fmt: skip
#: A capitalised word right after these is part of the type (``struct FOO f(void)``).
_TAG_KEYWORDS = frozenset({b"struct", b"union", b"enum", b"class"})
_MAX_PREFIX = 160
_MAX_WINDOW = 400
_MAX_IDENTS_AFTER = 4
_SKIP = frozenset(b" \t\r\n*")
_UPPER = frozenset(range(ord("A"), ord("Z") + 1))


def _declarator_after(source: bytes, pos: int) -> tuple[int, int] | None:
    """``(blank_end, identifiers)`` if ``source[pos:]`` continues ``[(args)] … name (``."""
    window = source[pos : pos + _MAX_WINDOW]
    i = 0
    args = _ARGS_RE.match(window)
    if args is not None:
        i = args.end()
    blank_end = pos + i
    newlines = 0
    for idents in range(1, _MAX_IDENTS_AFTER + 1):
        while i < len(window) and window[i] in _SKIP:
            newlines += window[i] == ord("\n")
            i += 1
        if newlines > 1:
            return None
        ident = _IDENT_RE.match(window, i)
        if ident is None or ident.group() in _KEYWORDS:
            return None
        i = ident.end()
        while i < len(window) and window[i] in b" \t":
            i += 1
        if window[i : i + 1] == b"(":
            return blank_end, idents
    return None


def _line_prefix(text: bytearray, start: int) -> bytes | None:
    """The text between the start of the line and ``start``, if short enough."""
    low = max(0, start - _MAX_PREFIX - 1)
    newline = text.rfind(b"\n", low, start)
    if newline < 0 and low > 0:
        return None
    return bytes(text[newline + 1 : start])


def blank_attribute_macros(source: bytes) -> tuple[bytes, int]:
    """Return ``source`` with attribute-like macros blanked, and how many were blanked."""
    out = bytearray(source)
    count = 0
    for match in _CAPS_RE.finditer(source):
        if not _UPPER.intersection(match.group()):
            continue
        prefix = _line_prefix(out, match.start())
        if prefix is None or (prefix and not (prefix[:1].isalpha() or prefix[:1] == b"_")):
            continue
        if _PREFIX_RE.fullmatch(prefix) is None:
            continue
        after = _declarator_after(source, match.end())
        if after is None:
            continue
        blank_end, idents_after = after
        words = _IDENT_RE.findall(prefix)
        if words and words[-1] in _TAG_KEYWORDS:
            continue
        type_before = any(word not in _STORAGE for word in words)
        if not (type_before or idents_after >= 2):  # noqa: PLR2004 (a type plus the name)
            continue
        out[match.start() : blank_end] = b" " * (blank_end - match.start())
        count += 1
    return bytes(out), count
