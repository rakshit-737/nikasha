# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""LeakSanitizer reports (SPEC §9.5). Checked against real output (ADR 0009).

Registered in :data:`common.PARSERS`. The real fixtures in ``tests/fixtures/traces/lsan/``
come from ``scripts/capture_sanitizer_fixtures.py`` (already-fixed public bugs, ADR 0009).

Expected shape (standalone LSan, or ASan's built-in leak check)::

    ==PID==ERROR: LeakSanitizer: detected memory leaks

    Direct leak of N byte(s) in K object(s) allocated from:
        #0 0x… in malloc (…)
        #1 0x… in func /path/file.c:LINE:COL
    Indirect leak of …
    SUMMARY: AddressSanitizer: N byte(s) leaked in K allocation(s).

The first leak stack (a direct one when present) is the primary stack and is also the
allocation stack; every other leak stack goes to ``other_stacks``. This module also holds
:func:`scan_labelled`, the label-driven scanner the MSan and TSan parsers share.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from nikasha.extract.traces.asan import parse_sanitizer_frame
from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    parse_int,
    register,
    run_guarded,
    split_lines,
)
from nikasha.model.claims import Frame, Stack, TraceData, TraceFormat

_HEADER_RE = re.compile(r"^[ \t]{0,8}==(\d{1,10})==[ \t]{0,4}ERROR: LeakSanitizer: ([^\n]*+)$")
_STOP_RE = re.compile(r"^[ \t]{0,8}==\d{1,10}==[ \t]{0,4}(?:ERROR|WARNING): \w{1,40}+:")
_LEAK_RE = re.compile(
    r"^[ \t]{0,8}(Direct|Indirect) leak of (\d{1,12}) byte\(s\) in (\d{1,12}) object\(s\) "
    r"allocated from:"
)
_SUMMARY_RE = re.compile(r"^[ \t]{0,8}SUMMARY: (?:Leak|Address)Sanitizer: ([^\n]*+)$")
_PID_RE = re.compile(r"==(\d{1,10})==")

#: Unrecognized non-blank lines tolerated in a row before a report is considered over.
MAX_GAP = 3
#: Shortest ``=====`` run accepted as the separator sanitizers print above a header.
MIN_SEPARATOR = 18


# --- the shared label-driven scanner ------------------------------------------------------


@dataclass
class Scanned:
    """What :func:`scan_labelled` found after a header: labelled frame runs and the end."""

    runs: list[tuple[str | None, list[Frame]]] = field(default_factory=list)
    last: int = 0


def scan_labelled(
    lines: list[Line],
    first: int,
    *,
    parse_frame: Callable[[str], Frame | None],
    is_label: Callable[[str], bool],
    on_detail: Callable[[str], bool],
    is_end: Callable[[str], bool],
    is_stop: Callable[[str], bool],
) -> Scanned:
    """Scan a report body after the header at ``first``.

    Frame lines are grouped into runs (a new run starts at ``#0`` or after any other line),
    each tagged with the label line that preceded it. ``on_detail`` records a recognized
    non-frame line and returns whether it was one. ``is_end`` marks the report's last line
    (its SUMMARY); ``is_stop`` a line that already belongs to the next report.
    """
    out = Scanned(last=first)
    label: str | None = None
    run: list[Frame] = []
    gap = 0

    def flush() -> None:
        nonlocal run
        if run:
            out.runs.append((label, run))
            run = []

    for i in range(first + 1, len(lines)):
        text = lines[i].text
        if is_stop(text):
            break
        frame = parse_frame(text)
        if frame is not None:
            if frame.index == 0 and run:
                flush()
            run.append(frame)
            out.last, gap = i, 0
            continue
        flush()
        if not text.strip():
            continue
        if is_end(text):
            on_detail(text)
            out.last = i
            break
        if is_label(text):
            label, gap = text.strip(), 0
        elif on_detail(text):
            label, out.last, gap = None, i, 0
        else:
            label, gap = None, gap + 1
            if gap > MAX_GAP:
                break
    flush()
    return out


def is_separator(text: str) -> bool:
    """A line of only ``=`` signs, long enough to be a sanitizer's report separator."""
    stripped = text.strip()
    return len(stripped) >= MIN_SEPARATOR and set(stripped) == {"="}


def pids_in(lines: list[Line], first: int, last: int) -> tuple[int, ...]:
    """Every distinct ``==PID==`` value between two line indices, in order of appearance."""
    seen: list[int] = []
    for line in lines[first : last + 1]:
        for match in _PID_RE.finditer(line.text):
            pid = parse_int(match.group(1))
            if pid is not None and pid not in seen:
                seen.append(pid)
    return tuple(seen)


def label_name(label: str | None, fallback: str) -> str:
    """A stack label without its trailing colon or ``here``/``at``."""
    name = (label or fallback).strip().removesuffix(":").strip()
    for suffix in (" here", " at"):
        name = name.removesuffix(suffix)
    return name or fallback


# --- LeakSanitizer ----------------------------------------------------------------------


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        match = _HEADER_RE.match(lines[i].text)
        if match is None:
            i += 1
            continue
        summary: list[str] = []

        def on_detail(line: str, summary: list[str] = summary) -> bool:
            if m := _SUMMARY_RE.match(line):
                summary.append(m.group(0).strip())
                return True
            stripped = line.strip()
            return stripped.startswith(("0x", "-", "Objects leaked", "HINT", "Hint"))

        scanned = scan_labelled(
            lines,
            i,
            parse_frame=parse_sanitizer_frame,
            is_label=lambda line: _LEAK_RE.match(line) is not None,
            on_detail=on_detail,
            is_end=lambda line: _SUMMARY_RE.match(line) is not None,
            is_stop=lambda line: (
                _STOP_RE.match(line) is not None or _HEADER_RE.match(line) is not None
            ),
        )
        found.append(_build(lines, i, scanned, match, summary))
        i = max(scanned.last, i) + 1
    return found


def _build(
    lines: list[Line], header: int, scanned: Scanned, match: re.Match[str], summary: list[str]
) -> ParsedTrace:
    runs = scanned.runs
    direct = [n for n, (label, _) in enumerate(runs) if (label or "").lstrip().startswith("Direct")]
    primary = direct[0] if direct else (0 if runs else None)
    others = tuple(
        Stack(label=label_name(label, f"leak {n + 1}"), frames=tuple(run))
        for n, (label, run) in enumerate(runs)
        if n != primary
    )
    frames = tuple(runs[primary][1]) if primary is not None else ()
    first = header - 1 if header > 0 and is_separator(lines[header - 1].text) else header
    pid = parse_int(match.group(1))
    data = TraceData(
        format="lsan",
        bug_type="memory-leak",
        message=match.group(2).strip() or None,
        frames=frames,
        alloc_frames=frames,
        other_stacks=others,
        summary=summary[0] if summary else None,
        pid=pid,
        pids_seen=pids_in(lines, first, scanned.last),
        thread=None,
    )
    return ParsedTrace(start=lines[first].start, end=lines[scanned.last].end, data=data)


@register
class LsanParser:
    """LeakSanitizer reports (fixtures: ``tests/fixtures/traces/lsan/``)."""

    format: TraceFormat = "lsan"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
