# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Markdown intake (SPEC §8).

The Markdown source *is* the normalized body: nothing is rendered, fenced blocks stay
verbatim and inline code keeps its backticks (strong hints for the symbol extractor).
markdown-it-py only locates code blocks and headings; its line maps (``[start, end)``,
0-based) are converted to exact character spans.
"""

from __future__ import annotations

import re

from markdown_it import MarkdownIt

from nikasha.ingest.blocks import guess_role
from nikasha.ingest.text import (
    MAX_BODY_CHARS,
    first_line_title,
    normalize_text,
    report_id,
    truncate,
)
from nikasha.model.report import CodeBlock, Report, ReportSource, Span

_FENCE_CLOSE_RE = re.compile(r"^[ \t>]*(?:`{3,}|~{3,})[ \t]*$")


def _line_starts(body: str) -> list[int]:
    starts = [0]
    for i, ch in enumerate(body):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _span_for_lines(body: str, starts: list[int], first: int, last_exclusive: int) -> Span | None:
    """Span covering lines ``[first, last_exclusive)`` without the final newline."""
    if first >= last_exclusive or first >= len(starts):
        return None
    start = starts[first]
    end = starts[last_exclusive] if last_exclusive < len(starts) else len(body)
    if end > start and body[end - 1] == "\n":
        end -= 1
    if end <= start:
        return None
    return Span(start=start, end=end, text=body[start:end])


def extract_code_blocks(body: str) -> tuple[list[CodeBlock], str | None]:
    """Return the code blocks in ``body`` and the first heading's text (for the title)."""
    md = MarkdownIt("commonmark")
    tokens = md.parse(body)
    starts = _line_starts(body)
    blocks: list[CodeBlock] = []
    heading: str | None = None
    first_heading: str | None = None
    for i, tok in enumerate(tokens):
        if tok.type == "heading_open" and i + 1 < len(tokens):
            heading = tokens[i + 1].content.strip()
            if first_heading is None:
                first_heading = heading
            continue
        if tok.type not in ("fence", "code_block") or tok.map is None:
            continue
        first, last = tok.map
        if tok.type == "fence":
            first += 1
            if last - 1 >= first and last - 1 < len(starts):
                closing = body[
                    starts[last - 1] : (starts[last] - 1 if last < len(starts) else len(body))
                ]
                if _FENCE_CLOSE_RE.match(closing):
                    last -= 1
        span = _span_for_lines(body, starts, first, last)
        if span is None:
            continue
        info = tok.info.strip().split()[0] if tok.info.strip() else None
        content = tok.content.rstrip("\n")
        blocks.append(
            CodeBlock(
                span=span,
                lang_hint=info,
                content=content,
                role_guess=guess_role(content, info, heading),
            )
        )
    return blocks, first_heading


def ingest_markdown(
    original: str, *, uri: str | None = None, max_chars: int = MAX_BODY_CHARS
) -> Report:
    builder = normalize_text(original)
    body, source_map, warnings = truncate(builder.text(), builder.source_map(), max_chars)
    blocks, first_heading = extract_code_blocks(body)
    return Report(
        id=report_id("markdown", body),
        source=ReportSource(kind="markdown", uri=uri),
        title=first_heading or first_line_title(body),
        body=body,
        source_map=source_map,
        code_blocks=tuple(blocks),
        warnings=tuple(warnings),
    )
