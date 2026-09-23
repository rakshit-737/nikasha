# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Snippet claims and the symbols they define (SPEC §9.3, §9.6; ADR 0003).

A snippet is a code block with the ``snippet`` role. It is *attributed* when a project path
or function is named within two lines of the block ("Vulnerable code (src/hdr.c, line 412):").
Only attributed snippets may later be refuted: honest reporters also quote their own
illustrations and code that has since changed, which slopcheck found makes unattributed
snippet checks unsound.

Function *definitions* inside a snippet become symbol claims (they assert the function exists);
calls inside a snippet do not (they may be the reporter's illustration).
"""

from __future__ import annotations

import re

from nikasha.extract.external_apis import is_external
from nikasha.extract.paths import PATH_RE, is_path_candidate
from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import lines_around
from nikasha.extract.symbols import acceptable
from nikasha.model.claims import SnippetClaim, SymbolClaim, SymbolKindHint
from nikasha.model.report import CodeBlock

NAME = "snippets"
DEFS_NAME = "snippet_defs"

_CONTROL = frozenset({"if", "for", "while", "switch", "return", "sizeof", "catch", "else", "do"})
#: C/C++/Java-style definition: a line that starts (after indentation) with type-ish words,
#: then ``name(``, and whose declaration continues to ``{`` without a ``;`` first.
_C_DEF_RE = re.compile(
    r"^[ \t]{0,8}(?:[A-Za-z_][\w:<>*&]{0,60}+[ \t*&]{1,6}){1,6}+\**(?P<name>[A-Za-z_]\w{0,100}+)"
    r"[ \t]{0,3}\((?P<params>[^;{}]{0,400}?)\)[ \t\w]{0,40}\{?",
    re.MULTILINE,
)
_DEFINE_RE = re.compile(
    r"^[ \t]{0,40}#[ \t]{0,3}define[ \t]{1,3}(?P<name>[A-Za-z_]\w{0,100})", re.M
)
_IND = r"^[ \t]{0,40}"
_NAME_GROUP = r"(?P<name>[A-Za-z_]\w{0,100})"
_DEF_KEYWORD_RES: tuple[re.Pattern[str], ...] = (
    # Python: def name(
    re.compile(rf"{_IND}(?:async[ \t]{{1,3}})?def[ \t]{{1,3}}{_NAME_GROUP}\(", re.M),
    # JavaScript / TypeScript: function name(
    re.compile(
        rf"{_IND}(?:export[ \t]{{1,3}})?(?:async[ \t]{{1,3}})?function\*?[ \t]{{1,3}}"
        r"(?P<name>[A-Za-z_$][\w$]{0,100})\(",
        re.M,
    ),
    # Go: func name( / func (r *T) Name(
    re.compile(
        rf"^[ \t]{{0,8}}func[ \t]{{1,3}}(?:\([^)\n]{{0,100}}\)[ \t]{{1,3}})?{_NAME_GROUP}\(", re.M
    ),
    # Rust: pub fn name
    re.compile(
        rf"{_IND}(?:pub(?:\([a-z]{{1,10}}\))?[ \t]{{1,3}})?(?:unsafe[ \t]{{1,3}})?fn[ \t]{{1,3}}"
        rf"{_NAME_GROUP}",
        re.M,
    ),
)
_FUNC_NEAR_RE = re.compile(r"`?(?P<f>[A-Za-z_][A-Za-z0-9_]{2,100})\(\)`?")
_MIN_ATTRIBUTION_LINES = 2


def _attribution(ctx: ExtractContext, block: CodeBlock) -> tuple[str | None, str | None]:
    """Path and function named within two lines before or after ``block``."""
    body = ctx.report.body
    lo, _ = lines_around(body, block.span.start, block.span.start, _MIN_ATTRIBUTION_LINES)
    _, hi = lines_around(body, block.span.end, block.span.end, _MIN_ATTRIBUTION_LINES)
    windows = ((lo, block.span.start), (block.span.end, hi))
    path: str | None = None
    func: str | None = None
    for start, end in windows:
        for m in PATH_RE.finditer(body, start, end):
            if path is None and is_path_candidate(m.group("path")):
                path = m.group("path")
        f = _FUNC_NEAR_RE.search(body, start, end)
        if func is None and f:
            func = f.group("f")
    return path, func


def definitions(block: CodeBlock) -> list[tuple[str, int, int, SymbolKindHint]]:
    """``(name, start, end, kind)`` of definitions in a snippet block (absolute offsets)."""
    text = block.span.text
    found: list[tuple[str, int, int, SymbolKindHint]] = []
    for m in _DEFINE_RE.finditer(text):
        found.append((m.group("name"), m.start("name"), m.end("name"), "macro"))
    for pattern in _DEF_KEYWORD_RES:
        for m in pattern.finditer(text):
            found.append((m.group("name"), m.start("name"), m.end("name"), "function"))
    for m in _C_DEF_RE.finditer(text):
        name = m.group("name")
        line_end = text.find("\n", m.end())
        rest = text[m.end() : line_end if line_end >= 0 else len(text)]
        if name in _CONTROL or ";" in rest.split("{", 1)[0]:
            continue
        if not (m.group(0).rstrip().endswith("{") or text[m.end() :].lstrip().startswith("{")):
            continue
        found.append((name, m.start("name"), m.end("name"), "function"))
    offset = block.span.start
    unique = {(n, s + offset, e + offset, k) for n, s, e, k in found}
    return sorted(unique, key=lambda t: (t[1], t[0]))


@register(NAME)
def extract_snippets(ctx: ExtractContext) -> list[SnippetClaim | SymbolClaim]:
    report = ctx.report
    claims: list[SnippetClaim | SymbolClaim] = []
    for block in report.code_blocks:
        if block.role_guess != "snippet":
            continue
        path, func = _attribution(ctx, block)
        code = block.span.text
        claims.append(
            make_claim(
                SnippetClaim,
                spans=[block.span],
                extractor=NAME,
                confidence=0.9 if (path or func) else 0.6,
                code=code,
                lang_hint=block.lang_hint,
                attributed_path=path,
                attributed_function=func,
                n_lines=code.count("\n") + 1,
            )
        )
        for name, start, end, kind in definitions(block):
            if not acceptable(name, ctx):
                continue
            claims.append(
                make_claim(
                    SymbolClaim,
                    spans=[report.span(start, end)],
                    extractor=DEFS_NAME,
                    confidence=0.8,
                    name=name,
                    symbol_kind_hint=kind,
                    context_path=path,
                    external=is_external(name),
                )
            )
    return claims
