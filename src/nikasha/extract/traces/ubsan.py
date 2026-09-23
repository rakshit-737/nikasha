# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""UndefinedBehaviorSanitizer reports (SPEC §9.5).

Each report is a ``file:line:col: runtime error: message`` header, then (with
``UBSAN_OPTIONS=print_stacktrace=1``) a sanitizer stack, then an optional SUMMARY::

    /src/programs/ubsan/signed_overflow.c:9:18: runtime error: signed integer overflow: …
        #0 0x00000042e27d in scale /src/programs/ubsan/signed_overflow.c:9:18
        #1 0x00000042e1e0 in main /src/programs/ubsan/signed_overflow.c:19:20
    SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/…/signed_overflow.c:9:18

``bug_type`` is a slug derived from the message (``signed-integer-overflow``,
``shift-exponent``, ``integer-divide-by-zero``, … or ``unknown``). Without a stack, frame 0
is synthesized from the header location so every report still points at a line.
"""

from __future__ import annotations

import re

from nikasha.extract.traces.asan import parse_sanitizer_frame, parse_summary_location
from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    is_native_runtime_frame,
    make_frame,
    parse_int,
    register,
    run_guarded,
    split_lines,
)
from nikasha.model.claims import Frame, TraceData, TraceFormat

#: ``path:line[:col]: runtime error: message`` (``<unknown>`` when there is no debug info).
_HEADER_RE = re.compile(
    r"^[ \t]{0,8}([^\s:]{1,4096}+):(\d{1,9})(?::(\d{1,9}))?: runtime error: ([^\n]*+)$"
)
_SUMMARY_RE = re.compile(
    r"^[ \t]{0,8}SUMMARY: UndefinedBehaviorSanitizer: ([^\s]{1,200}+)[ \t]?([^\n]*+)$"
)

#: Message substrings → bug-type slug, first match wins (more specific phrases first).
_SLUGS: tuple[tuple[str, str], ...] = (
    ("unsigned integer overflow", "unsigned-integer-overflow"),
    ("signed integer overflow", "signed-integer-overflow"),
    ("negation of", "signed-integer-overflow"),
    ("shift exponent", "shift-exponent"),
    ("left shift of", "shift-base"),
    ("division by zero", "integer-divide-by-zero"),
    ("division of", "signed-integer-overflow"),
    ("null pointer passed as argument", "nonnull-attribute"),
    ("null pointer returned from function", "returns-nonnull-attribute"),
    ("applying non-zero offset", "pointer-overflow"),
    ("pointer index expression", "pointer-overflow"),
    ("null pointer", "null-pointer-dereference"),
    ("misaligned address", "misaligned-address"),
    ("out of bounds for type", "array-bounds"),
    ("is not a valid value for type", "invalid-value-load"),
    ("is outside the range of representable values", "float-cast-overflow"),
    ("implicit conversion", "implicit-conversion"),
    ("unreachable program point", "unreachable"),
    ("end of a value-returning function", "missing-return"),
    ("through pointer to incorrect function type", "function-type-mismatch"),
    ("variable length array bound", "vla-bound"),
    ("insufficient space for an object", "object-size"),
    ("which does not point to an object of type", "vptr"),
)


def bug_type_for(message: str) -> str:
    """Map a UBSan message to a stable slug (``unknown`` if unrecognized)."""
    lowered = message.lower()
    for needle, slug in _SLUGS:
        if needle in lowered:
            return slug
    return "unknown"


def _header_frame(match: re.Match[str]) -> Frame:
    path = match.group(1).strip()
    path_or_none = None if path == "<unknown>" else path
    return make_frame(
        index=0,
        raw=match.group(0),
        path=path_or_none,
        line=parse_int(match.group(2)),
        col=parse_int(match.group(3) or ""),
        is_runtime=is_native_runtime_frame(None, path_or_none, None),
    )


def _is_note(text: str) -> bool:
    """``0x…: note: pointer points here``, its hex dump and caret lines."""
    return "note:" in text or text[:1] in (" ", "\t")


class _Report:
    def __init__(self, header: re.Match[str]) -> None:
        self.header = header
        self.frames: list[Frame] = []
        self.summary: str | None = None
        self.summary_path: str | None = None
        self.summary_line: int | None = None
        self.summary_function: str | None = None


def _scan(lines: list[Line], first: int, report: _Report) -> int:
    """Consume the stack, notes and SUMMARY after a header; return the last line index."""
    last = first
    for i in range(first + 1, len(lines)):
        text = lines[i].text
        if not text.strip():
            continue
        if _HEADER_RE.match(text):
            break
        frame = parse_sanitizer_frame(text)
        if frame is not None:
            if report.frames and frame.index == 0:
                break
            report.frames.append(frame)
        elif summary := _SUMMARY_RE.match(text):
            report.summary = text.strip()
            path, line, function = parse_summary_location(summary.group(2))
            report.summary_path, report.summary_line = path, line
            report.summary_function = function
            return i
        elif not _is_note(text):
            break
        last = i
    return last


def _build(lines: list[Line], first: int, last: int, report: _Report) -> ParsedTrace:
    message = report.header.group(4).strip()
    frames = report.frames or [_header_frame(report.header)]
    data = TraceData(
        format="ubsan",
        bug_type=bug_type_for(message),
        message=message or None,
        frames=tuple(frames),
        summary=report.summary,
        summary_path=report.summary_path,
        summary_line=report.summary_line,
        summary_function=report.summary_function,
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        header = _HEADER_RE.match(lines[i].text)
        if header is None:
            i += 1
            continue
        report = _Report(header)
        last = _scan(lines, i, report)
        found.append(_build(lines, i, last, report))
        i = last + 1
    return found


@register
class UbsanParser:
    """UndefinedBehaviorSanitizer ``runtime error:`` reports."""

    format: TraceFormat = "ubsan"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
