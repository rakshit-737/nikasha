# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Span, region and sentence helpers shared by the extractors.

All functions are linear in the size of their input; regexes are anchored or use bounded,
unambiguous quantifiers (SPEC §9 general rules).
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from nikasha.model.report import CodeBlock, CodeBlockRole, Report, Span

Region = tuple[int, int]

#: A single-backtick inline code span on one line (Markdown and the HTML ingester's output).
INLINE_CODE_RE = re.compile(r"`([^`\n]{1,300})`")
#: http(s) URLs up to the first whitespace or closing delimiter.
URL_RE = re.compile(r"https?://[^\s<>\"'`\])}]{1,2000}")
_TRAILING_PUNCT = ".,;:!?'\""


@dataclass(frozen=True, slots=True)
class InlineCode:
    span: Span  # including the backticks
    inner_start: int
    inner_end: int
    text: str  # without backticks


def spans_overlap(a: Region, b: Region) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def contains(outer: Region, inner: Region) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1]


def html_comment_regions(body: str) -> list[Region]:
    """``<!-- … -->`` comments (an unclosed one runs to the end, as in browsers). Linear."""
    regions: list[Region] = []
    pos = 0
    while (start := body.find("<!--", pos)) >= 0:
        close = body.find("-->", start + 4)
        end = len(body) if close < 0 else close + 3
        regions.append((start, end))
        pos = end
    return regions


def prose_regions(report: Report) -> list[Region]:
    """The body minus every code block and, for Markdown, every HTML comment.

    Comments are invisible when a report is rendered (issue templates are full of them), so
    they are not part of what the reporter claims.
    """
    excluded = [(b.span.start, b.span.end) for b in report.code_blocks]
    if report.source.kind == "markdown":
        code = IntervalIndex(excluded)
        excluded += [r for r in html_comment_regions(report.body) if not code.overlaps(r)]
    regions: list[Region] = []
    cursor = 0
    for start, end in sorted(excluded):
        if start > cursor:
            regions.append((cursor, start))
        cursor = max(cursor, end)
    if cursor < len(report.body):
        regions.append((cursor, len(report.body)))
    return regions


def block_regions(report: Report, roles: Sequence[CodeBlockRole]) -> list[Region]:
    return [(b.span.start, b.span.end) for b in report.code_blocks if b.role_guess in roles]


def finditer_in(
    pattern: re.Pattern[str], text: str, regions: Sequence[Region]
) -> Iterator[re.Match[str]]:
    """``pattern.finditer`` restricted to ``regions`` (offsets stay absolute)."""
    for start, end in regions:
        yield from pattern.finditer(text, start, end)


def inline_code_spans(report: Report, regions: Sequence[Region] | None = None) -> list[InlineCode]:
    body = report.body
    found: list[InlineCode] = []
    for m in finditer_in(INLINE_CODE_RE, body, regions or prose_regions(report)):
        found.append(
            InlineCode(
                span=report.span(m.start(), m.end()),
                inner_start=m.start(1),
                inner_end=m.end(1),
                text=m.group(1),
            )
        )
    return found


def url_regions(report: Report) -> list[Region]:
    """Every URL in the body (trailing punctuation trimmed)."""
    out: list[Region] = []
    for m in URL_RE.finditer(report.body):
        end = m.end()
        while end > m.start() and report.body[end - 1] in _TRAILING_PUNCT:
            end -= 1
        out.append((m.start(), end))
    return out


def in_any(offset_region: Region, regions: Sequence[Region]) -> bool:
    """Linear overlap test; prefer :class:`IntervalIndex` for more than a handful of regions."""
    return any(spans_overlap(offset_region, r) for r in regions)


class IntervalIndex:
    """A set of half-open intervals kept as sorted, disjoint, merged runs.

    ``overlaps`` and ``contains`` are ``O(log n)``; ``add`` is ``O(log n)`` plus a list shift.
    Merging overlapping or touching intervals never changes an overlap answer, and a region
    inside the union of touching containers counts as contained, which is what callers want.
    """

    __slots__ = ("_ends", "_starts")

    def __init__(self, regions: Sequence[Region] = ()) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []
        for start, end in sorted(regions):
            if self._ends and start <= self._ends[-1]:
                self._ends[-1] = max(self._ends[-1], end)
            else:
                self._starts.append(start)
                self._ends.append(end)

    def __len__(self) -> int:
        return len(self._starts)

    def overlaps(self, region: Region) -> bool:
        start, end = region
        i = bisect.bisect_left(self._starts, max(end, start + 1)) - 1
        return i >= 0 and self._ends[i] > start and self._starts[i] < max(end, start + 1)

    def contains(self, region: Region) -> bool:
        start, end = region
        i = bisect.bisect_right(self._starts, start) - 1
        return i >= 0 and self._ends[i] >= end

    def add(self, region: Region) -> None:
        start, end = region
        i = bisect.bisect_left(self._starts, start)
        # Merge with the previous run if it touches, then absorb following runs.
        if i > 0 and self._ends[i - 1] >= start:
            i -= 1
            start = self._starts[i]
            end = max(end, self._ends[i])
            del self._starts[i]
            del self._ends[i]
        while i < len(self._starts) and self._starts[i] <= end:
            end = max(end, self._ends[i])
            del self._starts[i]
            del self._ends[i]
        self._starts.insert(i, start)
        self._ends.insert(i, end)


_METADATA_LINE_RE = re.compile(
    r"^(?:\*\*|\||>)|:\*\*|\bCVSS\b|\b(?:affected|severity|component|version)s?\s{0,2}:",
    re.IGNORECASE,
)
_LEADING_COMMENT_RE = re.compile(r"\s{0,1000}<!--")
_LEADING_HEADING_RE = re.compile(r"\s{0,1000}#[^\n]{0,1000}\n?")
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s)|\n[ \t]*\n|\n(?=[ \t]*(?:[-*+]|\d{1,3}[.)]|#{1,6})\s)")


def sentence_bounds(body: str, start: int, end: int | None = None) -> Region:
    """The sentence around ``[start, end)``: bounded by ``.!?`` + space, blank lines, list
    items or headings. Looks at most 600 characters each way."""
    end = start if end is None else end
    lo = max(0, start - 600)
    s_start = lo
    for m in _SENTENCE_END_RE.finditer(body, lo, start):
        s_start = m.end()
    if s_start == lo and lo > 0:
        nl = body.rfind("\n", lo, start)
        s_start = nl + 1 if nl >= 0 else lo
    hi = min(len(body), end + 600)
    after = _SENTENCE_END_RE.search(body, end, hi)
    if after is None:
        return (s_start, hi)
    return (s_start, after.start() + (1 if body[after.start()] in ".!?" else 0))


def clause_bounds(body: str, start: int, end: int | None = None) -> Region:
    """Like :func:`sentence_bounds` but also split at ``;``."""
    s_start, s_end = sentence_bounds(body, start, end)
    end = start if end is None else end
    semi_before = body.rfind(";", s_start, start)
    semi_after = body.find(";", end, s_end)
    return (
        semi_before + 1 if semi_before >= 0 else s_start,
        semi_after if semi_after >= 0 else s_end,
    )


def first_paragraph(report: Report) -> Region:
    """The title line plus the first prose paragraph after it."""
    body = report.body
    regions = prose_regions(report)
    if not regions:
        return (0, 0)
    # Skip leading HTML comments (issue templates, licence headers), blank lines and a
    # Markdown heading line, then take up to a blank line.
    pos = regions[0][0]
    while (comment := _LEADING_COMMENT_RE.match(body, pos)) is not None:
        close = body.find("-->", comment.end())
        if close < 0:
            break
        pos = close + 3
    heading_end = pos
    heading = _LEADING_HEADING_RE.match(body, pos)
    if heading is not None:
        heading_end = heading.end()
    blank = body.find("\n\n", heading_end + 1)
    para_end = blank if blank >= 0 else len(body)
    # A metadata line ("**Affected:** … · CVSS …") is not the lead paragraph; the next one
    # counts too.
    first = body[heading_end:para_end].strip()
    if blank >= 0 and "\n" not in first and _METADATA_LINE_RE.search(first):
        nxt = body.find("\n\n", blank + 2)
        para_end = nxt if nxt >= 0 else len(body)
    return (pos, para_end)


def block_for(report: Report, region: Region) -> CodeBlock | None:
    for block in report.code_blocks:
        if contains((block.span.start, block.span.end), region):
            return block
    return None


def lines_around(body: str, start: int, end: int, n: int) -> Region:
    """Region covering ``n`` lines before ``start`` and ``n`` lines after ``end``."""
    lo = start
    for _ in range(n + 1):
        prev = body.rfind("\n", 0, max(lo - 1, 0))
        lo = prev + 1 if prev >= 0 else 0
        if lo == 0:
            break
    hi = end
    for _ in range(n + 1):
        nxt = body.find("\n", hi + 1)
        hi = nxt if nxt >= 0 else len(body)
        if hi == len(body):
            break
    return (lo, hi)
