# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""File, line and permalink claims (SPEC §9.4; ADR 0003 line binding).

A line number is bound to a path **only** when they are written together (``file.c:123``,
``line 123 of file.c``, ``file.c (line 123)``, ``(file.c, line 123)``), when exactly one path
appears in the same clause, or through a blob permalink. A bare ``line 123`` with no path in
its clause becomes a pathless :class:`LineClaim`, never a guess: slopcheck measured
wrong-path binding as 10% of its false contradictions.
"""

from __future__ import annotations

import bisect
import itertools
import re
from dataclasses import dataclass, field

from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.extract.spans import IntervalIndex, Region, clause_bounds, finditer_in
from nikasha.model.claims import FileClaim, LineClaim, Permalink

NAME = "paths"

_EXTENSIONS = """
    c h cc cpp cxx hpp hh hxx inc ipp tcc m mm py pyi pyx pxd js mjs cjs jsx ts tsx go rs
    java kt kts scala groovy php rb cs swift pl pm sh bash zsh lua y yy l ll S s asm am ac
    cmake mk gradle xml json yaml yml toml html htm css vue svelte erl ex exs hs ml mli
    dart jl r zig nim v sv vhd proto thrift sql
""".split()
SOURCE_EXTENSIONS: frozenset[str] = frozenset(_EXTENSIONS)

#: A relative or absolute path with at least one dotted suffix. Every quantifier is
#: possessive (Python ≥3.11), so matching never backtracks; the extension is validated in
#: code by :func:`is_path_candidate`, which keeps the regex linear-time (SPEC §9, §19.2).
PATH_PATTERN = r"(?:~?/)?(?:[\w.+-]{1,100}+/){0,20}+[\w+-]{1,100}+(?:\.[\w+-]{1,20}+){1,4}+"
PATH_RE = re.compile(rf"(?<![\w/.@:-])(?P<path>{PATH_PATTERN})(?![\w/-])")
_FILE_LINE_RE = re.compile(
    rf"(?<![\w/.@:-])(?P<path>{PATH_PATTERN}):(?P<line>\d{{1,7}})(?::(?P<col>\d{{1,5}}))?(?!\d)"
)
_LINE_OF_FILE_RE = re.compile(
    rf"\blines?\s{{1,3}}(?P<line>\d{{1,7}})(?:\s{{0,2}}[-\u2013]\s{{0,2}}(?P<end>\d{{1,7}}))?"
    rf"\s{{1,3}}(?:of|in)\s{{1,3}}(?:the\s{{1,3}}file\s{{1,3}})?`?(?P<path>{PATH_PATTERN})`?",
    re.IGNORECASE,
)
_FILE_THEN_LINE_RE = re.compile(
    rf"(?<![\w/.@:-])`?(?P<path>{PATH_PATTERN})`?\s{{0,2}}[,(]?\s{{0,2}}(?:at\s{{1,3}})?"
    rf"lines?\s{{1,3}}(?P<line>\d{{1,7}})(?:\s{{0,2}}[-\u2013]\s{{0,2}}(?P<end>\d{{1,7}}))?",
    re.IGNORECASE,
)
_BARE_LINE_RE = re.compile(
    r"\b(?:lines?\s{1,3}(?P<line>\d{1,7})(?:\s{0,2}[-\u2013]\s{0,2}(?P<end>\d{1,7}))?"
    r"|L(?P<lline>\d{1,7})(?:-L?(?P<lend>\d{1,7}))?)\b"
)
BLOB_RE = re.compile(
    r"https?://(?P<host>github\.com|gitlab\.com|[\w.-]{1,100})/(?P<owner>[\w.-]{1,100})/"
    r"(?P<repo>[\w.-]{1,100})/(?:-/)?blob/(?P<ref>[^/\s#?]{1,200})/"
    r"(?P<path>[^\s#?<>\"'`)\]]{1,1000})(?:#L(?P<l1>\d{1,7})(?:-L?(?P<l2>\d{1,7}))?)?"
)
_NUMBERED_LINE_RE = re.compile(r"^[ \t]{0,8}(?P<n>\d{1,7})[ \t]{0,4}[|:][ \t]?(?P<code>.*)$", re.M)
_FUNC_HINT_RE = re.compile(r"`?(?P<f>[A-Za-z_][A-Za-z0-9_]{2,100})\(\)`?")
_PRODUCT_DOT_JS_RE = re.compile(r"^[A-Z][A-Za-z]{1,30}\.js$")
_MIN_NUMBERED_LINES = 2


def is_path_candidate(path: str) -> bool:
    """Accept paths with a known source extension (``config.h.in`` included); reject
    look-alikes such as ``Node.js``, version numbers or a bare ``.c``."""
    if _PRODUCT_DOT_JS_RE.match(path):
        return False
    base = path.rsplit("/", 1)[-1]
    parts = base.split(".")
    if len(parts) < 2 or not parts[0] or parts[0].isdigit():  # noqa: PLR2004
        return False
    ext = parts[-1]
    if ext == "in" and len(parts) >= 3:  # noqa: PLR2004
        ext = parts[-2]
    return ext in SOURCE_EXTENSIONS


def _function_hint(body: str, clause: Region) -> str | None:
    m = _FUNC_HINT_RE.search(body, clause[0], clause[1])
    return m.group("f") if m else None


def _line_fields(body: str, clause: Region, line: str, end: str | None) -> dict[str, object]:
    first = int(line)
    last = int(end) if end else None
    return {
        "line": first,
        "end_line": last if last and last > first else None,
        "function_hint": _function_hint(body, clause),
    }


@dataclass
class _State:
    ctx: ExtractContext
    claims: list[FileClaim | LineClaim] = field(default_factory=list)
    taken: IntervalIndex = field(default_factory=IntervalIndex)
    path_spans: list[tuple[Region, str]] = field(default_factory=list)

    def free(self, region: Region) -> bool:
        return not self.taken.overlaps(region) and not self.ctx.url_index.overlaps(region)

    def line(self, region: Region, confidence: float, **fields: object) -> None:
        span = [self.ctx.report.span(*region)]
        self.claims.append(
            make_claim(LineClaim, spans=span, extractor=NAME, confidence=confidence, **fields)
        )


def _permalinks(st: _State) -> None:
    """Blob permalinks (they sit inside URLs, so they are handled first)."""
    body = st.ctx.report.body
    prose_index = IntervalIndex(st.ctx.prose)
    for m in BLOB_RE.finditer(body):
        region = (m.start(), m.end())
        if not prose_index.overlaps(region):
            continue
        path = m.group("path").rstrip(".,;:")
        l1, l2 = m.group("l1"), m.group("l2")
        start_line = int(l1) if l1 else None
        end_line = int(l2) if l2 else None
        permalink = Permalink(
            host=m.group("host"), owner=m.group("owner"), repo=m.group("repo"),
            ref=m.group("ref"), path=path, start_line=start_line, end_line=end_line,
            url=m.group(0),
        )  # fmt: skip
        st.taken.add(region)
        if start_line is not None:
            later = end_line if end_line and end_line > start_line else None
            st.line(region, 0.95, path=path, line=start_line, permalink=permalink, end_line=later)
        else:
            span = [st.ctx.report.span(*region)]
            st.claims.append(
                make_claim(FileClaim, spans=span, extractor=NAME, confidence=0.9, path=path)
            )


def _paths_with_lines(st: _State) -> None:
    body = st.ctx.report.body
    for pattern in (_FILE_LINE_RE, _LINE_OF_FILE_RE, _FILE_THEN_LINE_RE):
        for m in finditer_in(pattern, body, st.ctx.prose):
            region = (m.start(), m.end())
            path = m.group("path")
            if not st.free(region) or not is_path_candidate(path):
                continue
            st.taken.add(region)
            clause = clause_bounds(body, m.start(), m.end())
            fields = _line_fields(body, clause, m.group("line"), m.groupdict().get("end"))
            col = m.groupdict().get("col")
            st.line(region, 0.9, path=path, col=int(col) if col else None, **fields)


def _files(st: _State) -> None:
    body = st.ctx.report.body
    for m in finditer_in(PATH_RE, body, st.ctx.prose):
        region = (m.start("path"), m.end("path"))
        path = m.group("path")
        if not is_path_candidate(path) or st.ctx.url_index.overlaps(region):
            continue
        st.path_spans.append((region, path))
        if st.taken.overlaps(region):
            continue
        span = [st.ctx.report.span(*region)]
        st.claims.append(
            make_claim(FileClaim, spans=span, extractor=NAME, confidence=0.8, path=path)
        )


def _bare_lines(st: _State) -> None:
    """Bare line numbers bind to a path only if exactly one path shares the clause."""
    body = st.ctx.report.body
    path_starts = [r[0] for r, _ in st.path_spans]
    for m in finditer_in(_BARE_LINE_RE, body, st.ctx.prose):
        region = (m.start(), m.end())
        if not st.free(region):
            continue
        st.taken.add(region)
        clause = clause_bounds(body, m.start(), m.end())
        lo = bisect.bisect_left(path_starts, clause[0])
        hi = bisect.bisect_right(path_starts, clause[1])
        in_clause = {p for r, p in st.path_spans[lo:hi] if r[1] <= clause[1]}
        path = next(iter(in_clause)) if len(in_clause) == 1 else None
        line = m.group("line") or m.group("lline")
        end = m.group("end") or m.group("lend")
        st.line(region, 0.7 if path else 0.5, path=path, **_line_fields(body, clause, line, end))


@register(NAME)
def extract_paths(ctx: ExtractContext) -> list[FileClaim | LineClaim]:
    state = _State(ctx)
    for step in (_permalinks, _paths_with_lines, _files, _bare_lines):
        step(state)
    return state.claims + _numbered_block_lines(ctx)


def _numbered_block_lines(ctx: ExtractContext) -> list[LineClaim]:
    """Snippets written with line-number prefixes (``123 | code``) quote specific lines."""
    report, body = ctx.report, ctx.report.body
    out: list[LineClaim] = []
    for block in report.code_blocks:
        if block.role_guess not in ("snippet", "log"):
            continue
        matches = list(_NUMBERED_LINE_RE.finditer(body, block.span.start, block.span.end))
        numbers = [int(m.group("n")) for m in matches]
        consecutive = all(b == a + 1 for a, b in itertools.pairwise(numbers))
        if len(matches) < _MIN_NUMBERED_LINES or not consecutive:
            continue
        before_start = max(0, block.span.start - 300)
        attributed = [
            p.group("path") for p in PATH_RE.finditer(body, before_start, block.span.start)
        ]
        path = attributed[-1] if attributed else None
        for m in matches:
            out.append(make_claim(LineClaim, spans=[report.span(m.start(), m.end())],
                                  extractor=NAME, confidence=0.8 if path else 0.5, path=path,
                                  line=int(m.group("n")), quoted_line=m.group("code")))  # fmt: skip
    return out
