# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""ThreadSanitizer reports (SPEC §9.5). **Unverified against real output** (ADR 0009).

Written from the documented ThreadSanitizer format, not from captured fixtures, so it is not
registered in :data:`common.PARSERS` until ``scripts/capture_sanitizer_fixtures.py`` has
produced real fixtures and the ``sandbox``-marked tests pass on them.

Expected shape (TSan frames carry no ``0x…`` pc and put the module last)::

    ==================
    WARNING: ThreadSanitizer: data race (pid=9337)
      Write of size 4 at 0x7fe3c3075190 by thread T1:
        #0 Thread1 /path/simple_race.c:8:10 (a.out+0xd0b7c)
      Previous write of size 4 at 0x7fe3c3075190 by main thread:
        #0 main /path/simple_race.c:13:10 (a.out+0xd0bd6)
      Location is global 'Global' of size 4 at 0x… (a.out+0x…)
      Thread T1 (tid=9338, running) created by main thread at:
        #0 pthread_create …
    SUMMARY: ThreadSanitizer: data race /path/simple_race.c:8:10 in Thread1
    ==================

The first (non-"Previous") access stack is primary; a "Location is heap block … allocated by"
stack is the allocation stack; every other labelled stack goes to ``other_stacks``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import partial
from typing import Literal

from nikasha.extract.traces.asan import split_frame_rest
from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    is_native_runtime_frame,
    make_frame,
    parse_hex,
    parse_int,
    run_guarded,
    split_lines,
    split_location,
)
from nikasha.extract.traces.lsan import Scanned, is_separator, label_name, scan_labelled
from nikasha.model.claims import Frame, MemoryAccess, Stack, TraceData, TraceFormat

_HEX = r"0x[0-9a-fA-F]{1,16}"
_HEADER_RE = re.compile(r"^[ \t]{0,8}WARNING: ThreadSanitizer: ([^\n]*+)$")
_PID_RE = re.compile(r"\(pid=(\d{1,10})\)")
_FRAME_RE = re.compile(
    rf"^[ \t]{{0,16}}#(\d{{1,6}})[ \t]{{1,4}}(?:{_HEX}[ \t]{{1,4}})?(?:in[ \t]{{1,4}})?([^\n]*+)$"
)
_OFFSET_RE = re.compile(r"0x[0-9a-fA-F]{1,16}")
_MAX_MODULE = 1000
_BUILD_ID = " (BuildId: "
_ACCESS_RE = re.compile(
    rf"^[ \t]{{0,8}}(Previous )?(?:[Aa]tomic )?([Rr]ead|[Ww]rite) of size (\d{{1,12}}) "
    rf"at ({_HEX}) by ([^\n:]{{1,200}}+)"
)
_THREAD_RE = re.compile(r"\bthread (T\d{1,10})\b")
_HEAP_LOCATION_RE = re.compile(r"^[ \t]{0,8}Location is heap block ")
_SUMMARY_RE = re.compile(r"^[ \t]{0,8}SUMMARY: ThreadSanitizer: ([^\n]*+)$")
_DETAIL_RE = re.compile(r"^[ \t]{0,8}(?:Location is |Mutex |Thread |ThreadSanitizer: |HINT|Hint)")
_ACCESS_KINDS: dict[str, Literal["READ", "WRITE"]] = {"read": "READ", "write": "WRITE"}


def _split_module_suffix(rest: str) -> tuple[str | None, str]:
    """Split a trailing `` (module+0xOFF)`` off ``rest``; module names may contain ``+``."""
    if not rest.endswith(")"):
        return None, rest
    open_at = rest.rfind("(")
    if open_at <= 0 or rest[open_at - 1] not in " \t":
        return None, rest
    inner = rest[open_at + 1 : -1]
    plus = inner.rfind("+")
    module = inner[:plus]
    if plus <= 0 or len(module) > _MAX_MODULE or ")" in module:
        return None, rest
    if _OFFSET_RE.fullmatch(inner[plus + 1 :]) is None:
        return None, rest
    return module, rest[: open_at - 1].rstrip()


def parse_tsan_frame(line: str) -> Frame | None:
    """Parse ``#N func path:line:col (module+0x…)``; a leading ``0x…`` pc is tolerated."""
    match = _FRAME_RE.match(line)
    if match is None:
        return None
    rest = match.group(2).rstrip()
    build_id = rest.rfind(_BUILD_ID)
    if build_id >= 0 and rest.endswith(")"):
        rest = rest[:build_id].rstrip()
    module, rest = _split_module_suffix(rest)
    parts = split_frame_rest(rest)
    function = parts.function
    if function is not None and function.split(" ", 1)[0] == "<null>":
        function = None
    path = parts.path if parts.path != "<null>" else None
    module = module or parts.module
    return make_frame(
        index=int(match.group(1)),
        raw=line,
        function=function,
        path=path,
        line=parts.line,
        col=parts.col,
        module=module,
        is_runtime=is_native_runtime_frame(function, path, module),
    )


def _thread(by: str) -> str | None:
    if by.strip().startswith("main thread"):
        return "T0"
    found = _THREAD_RE.search(by)
    return found.group(1) if found else None


@dataclass
class _Details:
    """Access and SUMMARY facts gathered while the body is scanned."""

    access: MemoryAccess | None = None
    access_address: int | None = None
    thread: str | None = None
    summary: str | None = None
    summary_rest: str | None = None
    labels: list[str] = field(default_factory=list)

    def take(self, line: str) -> bool:
        if m := _SUMMARY_RE.match(line):
            self.summary, self.summary_rest = line.strip(), m.group(1)
            return True
        return _DETAIL_RE.match(line) is not None


def _is_label(line: str, details: _Details) -> bool:
    stripped = line.strip()
    if not stripped.endswith(":"):
        return False
    if (m := _ACCESS_RE.match(line)) and m.group(1) is None and details.access is None:
        details.access = MemoryAccess(kind=_ACCESS_KINDS[m.group(2).lower()], size=int(m.group(3)))
        details.access_address = parse_hex(m.group(4))
        details.thread = _thread(m.group(5))
    return True


def _sort_runs(scanned: Scanned) -> tuple[list[Frame], list[Frame], list[Stack]]:
    frames: list[Frame] = []
    alloc: list[Frame] = []
    other: list[Stack] = []
    for n, (label, run) in enumerate(scanned.runs):
        text = label or ""
        access = _ACCESS_RE.match(text)
        if not frames and ((access is not None and access.group(1) is None) or label is None):
            frames = run
        elif _HEAP_LOCATION_RE.match(text) and not alloc:
            alloc = run
        else:
            other.append(Stack(label=label_name(label, f"stack {n + 1}"), frames=tuple(run)))
    return frames, alloc, other


def _summary_parts(rest: str | None) -> tuple[str | None, int | None, str | None]:
    """``data race /p/a.c:8:10 in Thread1`` → path, line, function (type words skipped)."""
    if not rest:
        return None, None, None
    location, sep, function = rest.rpartition(" in ")
    if not sep:
        location, function = rest, ""
    parsed = split_location(location.rsplit(" ", 1)[-1])
    if parsed is None:
        return None, None, function.strip() or None
    return parsed[0], parsed[1], function.strip() or None


def _bug_type(header: str) -> str | None:
    words = header.split(" (", 1)[0].strip()
    return "-".join(words.lower().split()) or None


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        match = _HEADER_RE.match(lines[i].text)
        if match is None:
            i += 1
            continue
        details = _Details()
        scanned = scan_labelled(
            lines,
            i,
            parse_frame=parse_tsan_frame,
            is_label=partial(_is_label, details=details),
            on_detail=details.take,
            is_end=lambda line: _SUMMARY_RE.match(line) is not None,
            is_stop=lambda line: _HEADER_RE.match(line) is not None,
        )
        last = scanned.last
        if last + 1 < len(lines) and is_separator(lines[last + 1].text):
            last += 1
        found.append(
            _build(lines, i, last=last, scanned=scanned, message=match.group(1), details=details)
        )
        i = max(last, i) + 1
    return found


def _build(
    lines: list[Line],
    header: int,
    *,
    last: int,
    scanned: Scanned,
    message: str,
    details: _Details,
) -> ParsedTrace:
    frames, alloc, other = _sort_runs(scanned)
    first = header - 1 if header > 0 and is_separator(lines[header - 1].text) else header
    pid_match = _PID_RE.search(message)
    pid = parse_int(pid_match.group(1)) if pid_match else None
    path, line, function = _summary_parts(details.summary_rest)
    data = TraceData(
        format="tsan",
        bug_type=_bug_type(message),
        message=message.strip() or None,
        access=details.access,
        access_address=details.access_address,
        frames=tuple(frames),
        alloc_frames=tuple(alloc),
        other_stacks=tuple(other),
        summary=details.summary,
        summary_path=path,
        summary_line=line,
        summary_function=function,
        pid=pid,
        pids_seen=(pid,) if pid is not None else (),
        thread=details.thread,
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


class TsanParser:
    """ThreadSanitizer reports (not registered by default; see ADR 0009)."""

    format: TraceFormat = "tsan"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
