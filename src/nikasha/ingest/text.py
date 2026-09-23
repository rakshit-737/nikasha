# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Plain-text intake and the offset-preserving normalizer every ingester builds on (SPEC §8)."""

from __future__ import annotations

import hashlib

from nikasha.model.ids import stable_id
from nikasha.model.report import Report, ReportSource, SourceKind, SourceMap, SourceSegment

#: Default cap on the normalized body (SPEC §8); longer input is truncated with a warning.
MAX_BODY_CHARS = 2_000_000

_DROPPED_CONTROLS = frozenset(chr(c) for c in range(0x20) if chr(c) not in "\t\n") | {
    "\x7f",
    "\ufeff",
}


class TextBuilder:
    """Accumulates a normalized body while recording where each piece came from.

    ``add_verbatim`` copies original text (mapped 1:1); ``add_inserted`` adds text that has no
    original counterpart (e.g. a newline for ``<br>``). The resulting :class:`SourceMap`
    maps every normalized offset back to the original input.
    """

    def __init__(self, original_length: int) -> None:
        self._parts: list[str] = []
        self._segments: list[SourceSegment] = []
        self._length = 0
        self._original_length = original_length

    @property
    def length(self) -> int:
        return self._length

    def add_verbatim(self, text: str, orig_start: int) -> None:
        if not text:
            return
        last = self._segments[-1] if self._segments else None
        if (
            last is not None
            and last.norm_start + last.length == self._length
            and last.orig_start + last.length == orig_start
        ):
            self._segments[-1] = SourceSegment(
                norm_start=last.norm_start,
                orig_start=last.orig_start,
                length=last.length + len(text),
            )
        else:
            self._segments.append(
                SourceSegment(norm_start=self._length, orig_start=orig_start, length=len(text))
            )
        self._parts.append(text)
        self._length += len(text)

    def add_inserted(self, text: str) -> None:
        self._parts.append(text)
        self._length += len(text)

    def text(self) -> str:
        return "".join(self._parts)

    def source_map(self) -> SourceMap:
        return SourceMap(segments=tuple(self._segments), original_length=self._original_length)


def normalize_text(
    original: str, *, offset: int = 0, builder: TextBuilder | None = None
) -> TextBuilder:
    """Normalize newlines (CRLF/CR → LF) and drop control characters other than tab and LF.

    Runs of unchanged characters are copied verbatim, so offsets stay exact.
    ``O(n)`` in the input length.
    """
    out = builder or TextBuilder(len(original))
    run_start = 0
    i = 0
    n = len(original)
    while i < n:
        ch = original[i]
        if ch == "\r" or ch in _DROPPED_CONTROLS:
            out.add_verbatim(original[run_start:i], offset + run_start)
            if ch == "\r":
                if i + 1 < n and original[i + 1] == "\n":
                    out.add_verbatim("\n", offset + i + 1)
                    i += 1
                else:
                    out.add_inserted("\n")
            i += 1
            run_start = i
            continue
        i += 1
    out.add_verbatim(original[run_start:n], offset + run_start)
    return out


def truncate(body: str, source_map: SourceMap, limit: int) -> tuple[str, SourceMap, list[str]]:
    """Cap ``body`` at ``limit`` characters, trimming the map to match."""
    if len(body) <= limit:
        return body, source_map, []
    segments: list[SourceSegment] = []
    for seg in source_map.segments:
        if seg.norm_start >= limit:
            break
        length = min(seg.length, limit - seg.norm_start)
        segments.append(seg.model_copy(update={"length": length}))
    warning = (
        f"report body truncated to {limit:,} characters (original normalized length {len(body):,})"
    )
    return (
        body[:limit],
        SourceMap(segments=tuple(segments), original_length=source_map.original_length),
        [warning],
    )


def report_id(kind: SourceKind, body: str) -> str:
    """Content-derived report ID: the same text always gets the same ID."""
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return stable_id("report", {"kind": kind, "body_sha256": digest})


def first_line_title(body: str, max_len: int = 200) -> str | None:
    """Use the first non-empty line as a title when it is short enough to be one."""
    for line in body.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped if len(stripped) <= max_len else None
    return None


def ingest_text(
    original: str, *, uri: str | None = None, max_chars: int = MAX_BODY_CHARS
) -> Report:
    """Build a :class:`Report` from plain text. No code blocks are inferred here; trace and
    patch extractors find their regions in the body directly."""
    builder = normalize_text(original)
    body, source_map, warnings = truncate(builder.text(), builder.source_map(), max_chars)
    return Report(
        id=report_id("text", body),
        source=ReportSource(kind="text", uri=uri),
        title=first_line_title(body),
        body=body,
        source_map=source_map,
        warnings=tuple(warnings),
    )
