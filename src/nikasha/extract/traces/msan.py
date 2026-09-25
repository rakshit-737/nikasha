# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""MemorySanitizer reports (SPEC §9.5). **Unverified against real output** (ADR 0009).

Written from the documented MemorySanitizer format, not from captured fixtures, so it is not
registered in :data:`common.PARSERS` until ``scripts/capture_sanitizer_fixtures.py`` has
produced real fixtures and the ``sandbox``-marked tests pass on them.

Expected shape (``-fsanitize-memory-track-origins`` adds the origin stacks)::

    ==PID==WARNING: MemorySanitizer: use-of-uninitialized-value
        #0 0x… in main /path/a.cc:6:7
      Uninitialized value was stored to memory at
        #0 0x… in …
      Uninitialized value was created by a heap allocation
        #0 0x… in malloc …
    SUMMARY: MemorySanitizer: use-of-uninitialized-value /path/a.cc:6:7 in main
    Exiting

The first stack is the use; the "created by" origin stack becomes the allocation stack and
every other origin stack goes to ``other_stacks``.
"""

from __future__ import annotations

import re

from nikasha.extract.traces.asan import parse_sanitizer_frame, parse_summary_location
from nikasha.extract.traces.common import Line, ParsedTrace, parse_int, run_guarded, split_lines
from nikasha.extract.traces.lsan import (
    Scanned,
    is_separator,
    label_name,
    pids_in,
    scan_labelled,
)
from nikasha.model.claims import Frame, Stack, TraceData, TraceFormat

_HEADER_RE = re.compile(r"^[ \t]{0,8}==(\d{1,10})==[ \t]{0,4}WARNING: MemorySanitizer: ([^\n]*+)$")
_STOP_RE = re.compile(r"^[ \t]{0,8}==\d{1,10}==[ \t]{0,4}(?:ERROR|WARNING): \w{1,40}+:")
_ORIGIN_RE = re.compile(
    r"^[ \t]{0,8}(?:Uninitialized value [^\n]{1,200}+|Memory was marked as uninitialized)$"
)
_SUMMARY_RE = re.compile(r"^[ \t]{0,8}SUMMARY: MemorySanitizer: ([^\s]{1,200}+)[ \t]?([^\n]*+)$")
_DETAIL_RE = re.compile(r"^[ \t]{0,8}(?:Uninitialized bytes |Exiting|0x|HINT|Hint|==)")


class _Summary:
    """The SUMMARY line's pieces, filled in by the scanner's detail callback."""

    def __init__(self) -> None:
        self.text: str | None = None
        self.bug_type: str | None = None
        self.path: str | None = None
        self.line: int | None = None
        self.function: str | None = None

    def take(self, line: str) -> bool:
        if m := _SUMMARY_RE.match(line):
            self.text, self.bug_type = line.strip(), m.group(1)
            self.path, self.line, self.function = parse_summary_location(m.group(2))
            return True
        return _DETAIL_RE.match(line) is not None


def _sort_runs(scanned: Scanned) -> tuple[list[Frame], list[Frame], list[Stack]]:
    frames: list[Frame] = []
    alloc: list[Frame] = []
    other: list[Stack] = []
    for n, (label, run) in enumerate(scanned.runs):
        lowered = (label or "").lower()
        if not frames and label is None:
            frames = run
        elif "created by" in lowered and not alloc:
            alloc = run
        else:
            other.append(Stack(label=label_name(label, f"stack {n + 1}"), frames=tuple(run)))
    return frames, alloc, other


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        match = _HEADER_RE.match(lines[i].text)
        if match is None:
            i += 1
            continue
        summary = _Summary()
        scanned = scan_labelled(
            lines,
            i,
            parse_frame=parse_sanitizer_frame,
            is_label=lambda line: _ORIGIN_RE.match(line) is not None,
            on_detail=summary.take,
            is_end=lambda line: _SUMMARY_RE.match(line) is not None,
            is_stop=lambda line: _STOP_RE.match(line) is not None,
        )
        last = scanned.last
        if last + 1 < len(lines) and lines[last + 1].text.strip() == "Exiting":
            last += 1
        found.append(_build(lines, i, last=last, scanned=scanned, match=match, summary=summary))
        i = max(last, i) + 1
    return found


def _build(
    lines: list[Line],
    header: int,
    *,
    last: int,
    scanned: Scanned,
    match: re.Match[str],
    summary: _Summary,
) -> ParsedTrace:
    frames, alloc, other = _sort_runs(scanned)
    first = header - 1 if header > 0 and is_separator(lines[header - 1].text) else header
    message = match.group(2).strip() or None
    data = TraceData(
        format="msan",
        bug_type=summary.bug_type or (message.split()[0] if message else None),
        message=message,
        frames=tuple(frames),
        alloc_frames=tuple(alloc),
        other_stacks=tuple(other),
        summary=summary.text,
        summary_path=summary.path,
        summary_line=summary.line,
        summary_function=summary.function,
        pid=parse_int(match.group(1)),
        pids_seen=pids_in(lines, first, last),
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


class MsanParser:
    """MemorySanitizer reports (not registered by default; see ADR 0009)."""

    format: TraceFormat = "msan"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
