# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Valgrind (Memcheck) error reports (SPEC §9.5).

Every line carries a ``==PID==`` prefix. Each error is its own trace: the error line, its
``at``/``by`` stack, then optional address and allocation/free stacks::

    ==1== Invalid write of size 2
    ==1==    at 0x48501B3: memmove (vg_replace_strmem.c:1429)
    ==1==    by 0x40102D: util_copy_value (util.c:15)
    ==1==  Address 0x4a5e7b0 is 0 bytes after a block of size 64 alloc'd
    ==1==    at 0x4841AE6: malloc (vg_replace_malloc.c:447)
    ==1==    by 0x401004: util_copy_value (util.c:11)

An error ends at the next ``==PID==`` line with no text. The tool banner, HEAP/ERROR
SUMMARY, and a trailing valgrind internal assertion (``valgrind: m_mallocfree.c:… Assertion
… failed``, ``host stacktrace:``, ``Thread 1: status = …``) belong to no error: their frames
are valgrind's own or a post-mortem of the scheduler, so they are never parsed as program
frames.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    is_native_runtime_frame,
    make_frame,
    parse_hex,
    parse_int,
    register,
    run_guarded,
    split_lines,
    split_location,
)
from nikasha.model.claims import Frame, MemoryAccess, MemoryRegion, Stack, TraceData, TraceFormat

#: ``==1== body`` (``--1--`` and ``**1**`` are valgrind's other prefixes).
_PREFIX_RE = re.compile(r"^[ \t]{0,8}(==|--|\*\*)(\d{1,10})\1 ?")
_FRAME_RE = re.compile(r"^[ \t]{1,16}(at|by) 0x([0-9A-Fa-f]{1,16}): ([^\n]*+)$")
_ADDRESS_RE = re.compile(r"^[ \t]{1,16}Address (0x[0-9A-Fa-f]{1,16}) ")
_BLOCK_RE = re.compile(
    r"^[ \t]{1,16}Address 0x[0-9A-Fa-f]{1,16} is (\d{1,12}) bytes (after|before|inside) "
    r"a (?:recently re-allocated )?block of size (\d{1,12}) (alloc'd|free'd)"
)
_INVALID_ACCESS_RE = re.compile(r"^Invalid (read|write) of size (\d{1,12})")
_UNINIT_VALUE_RE = re.compile(r"^Use of uninitialised value of size (\d{1,12})")
_SIGNAL_RE = re.compile(
    r"^Process terminating with default action of signal \d{1,3} \((SIG\w{1,12}+)\)"
)
_LEAK_RE = re.compile(
    r"^[\d,]{1,30}+ (?:\([\d,]{1,30}+ direct, [\d,]{1,30}+ indirect\) )?bytes in "
    r"[\d,]{1,30}+ blocks are (definitely|indirectly|possibly) lost"
)

#: Error-line prefixes with a fixed bug type (the regexes above cover the parametrised ones).
_FIXED_KINDS: tuple[tuple[str, str], ...] = (
    ("Conditional jump or move depends on uninitialised value", "uninitialised-conditional"),
    ("Invalid free() / delete / delete[] / realloc()", "invalid-free"),
    ("Mismatched free() / delete / delete []", "mismatched-free"),
    ("Syscall param ", "syscall-param"),
    ("Source and destination overlap", "overlapping-copy"),
    ("Jump to the invalid address", "invalid-jump"),
    ("Argument '", "fishy-argument"),
)
_ACCESS_KINDS: dict[str, Literal["READ", "WRITE"]] = {"read": "READ", "write": "WRITE"}
_RELATIONS: dict[str, Literal["right", "left", "inside"]] = {
    "after": "right",
    "before": "left",
    "inside": "inside",
}


def classify(body: str) -> tuple[str, MemoryAccess | None] | None:
    """Return ``(bug_type, access)`` if ``body`` is a Memcheck error line."""
    if match := _INVALID_ACCESS_RE.match(body):
        kind = _ACCESS_KINDS[match.group(1)]
        return f"invalid-{match.group(1)}", MemoryAccess(kind=kind, size=int(match.group(2)))
    if _UNINIT_VALUE_RE.match(body):
        return "uninitialised-value", None
    if match := _SIGNAL_RE.match(body):
        return match.group(1), None
    if match := _LEAK_RE.match(body):
        return f"leak-{match.group(1)}-lost", None
    for prefix, slug in _FIXED_KINDS:
        if body.startswith(prefix):
            return slug, None
    return None


def block_region(address: int, match: re.Match[str]) -> MemoryRegion:
    """The heap block described by ``Address A is N bytes <rel> a block of size M``.

    Valgrind measures N from the block edge nearest to A, so with ``start``/``end`` the
    half-open block ``[start, start + M)``:

    * ``after``:  A = end + N        → start = A - N - M  (``0 bytes after`` is A == end)
    * ``before``: A = start - N      → start = A + N
    * ``inside``: A = start + N      → start = A - N
    """
    distance, relation, size = int(match.group(1)), _RELATIONS[match.group(2)], int(match.group(3))
    if relation == "right":
        start = address - distance - size
    elif relation == "left":
        start = address + distance
    else:
        start = address - distance
    return MemoryRegion(
        start=start, end=start + size, size=size, relation=relation, distance=distance
    )


def parse_frame(body: str, index: int) -> Frame | None:
    """``   at 0x4841AE6: malloc (vg_replace_malloc.c:447)`` / ``by 0x…: f (in /lib/x.so)``."""
    match = _FRAME_RE.match(body)
    if match is None:
        return None
    rest = match.group(3).strip()
    function, path, line, module = rest, None, None, None
    open_paren = rest.rfind(" (")
    if open_paren >= 0 and rest.endswith(")"):
        function, inner = rest[:open_paren], rest[open_paren + 2 : -1]
        if inner.startswith("in "):
            module = inner[3:].strip() or None
        elif (location := split_location(inner)) is not None:
            path, line = location[0], location[1]
    name = None if function in ("???", "") else function
    return make_frame(
        index=index,
        raw=body,
        function=name,
        path=path,
        line=line,
        module=module,
        is_runtime=is_native_runtime_frame(name, path, module),
    )


@dataclass
class _Error:
    """Mutable accumulator for one Memcheck error."""

    pid: int
    bug_type: str
    message: str
    access: MemoryAccess | None
    frames: list[Frame] = field(default_factory=list)
    alloc: list[Frame] = field(default_factory=list)
    free: list[Frame] = field(default_factory=list)
    other: list[Stack] = field(default_factory=list)
    address: int | None = None
    region: MemoryRegion | None = None

    def add_run(self, label: str | None, run: list[Frame]) -> None:
        """File a finished stack under the line that introduced it."""
        lowered = (label or "").lower()
        if label is None and not self.frames:
            self.frames = run
        elif ("alloc'd" in lowered or "block was alloc" in lowered) and not self.alloc:
            self.alloc = run
        elif "free'd" in lowered and not self.free:
            self.free = run
        elif not self.frames:
            self.frames = run  # e.g. after "Access not within mapped region at address 0x0"
        else:
            self.other.append(
                Stack(label=(label or "stack").strip().rstrip(":"), frames=tuple(run))
            )


def _body(text: str, pid: int) -> str | None:
    """The text after this error's ``==PID==`` prefix, or None if the line is not one."""
    match = _PREFIX_RE.match(text)
    if match is None or parse_int(match.group(2)) != pid:
        return None
    return text[match.end() :]


def _detail(error: _Error, body: str) -> None:
    if match := _ADDRESS_RE.match(body):
        error.address = parse_hex(match.group(1))
        if block := _BLOCK_RE.match(body):
            error.region = block_region(error.address, block)


def _scan(lines: list[Line], first: int, error: _Error) -> int:
    """Consume one error's stacks; return the index of its last line."""
    last, label = first, None
    run: list[Frame] = []
    for i in range(first + 1, len(lines)):
        body = _body(lines[i].text, error.pid)
        if body is None or not body.strip() or classify(body) is not None:
            break
        frame = parse_frame(body, len(run))
        if frame is not None:
            run.append(frame)
        else:
            if run:
                error.add_run(label, run)
                run = []
            _detail(error, body)
            label = body.strip()
        last = i
    if run:
        error.add_run(label, run)
    return last


def _build(lines: list[Line], first: int, last: int, error: _Error) -> ParsedTrace:
    data = TraceData(
        format="valgrind",
        bug_type=error.bug_type,
        message=error.message,
        access=error.access,
        address=error.address,
        access_address=error.address,
        region_address=error.address,
        region=error.region,
        frames=tuple(error.frames),
        alloc_frames=tuple(error.alloc),
        free_frames=tuple(error.free),
        other_stacks=tuple(error.other),
        pid=error.pid,
        pids_seen=(error.pid,),
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


def _error_at(line: Line) -> _Error | None:
    match = _PREFIX_RE.match(line.text)
    if match is None:
        return None
    body = line.text[match.end() :]
    kind = classify(body)
    pid = parse_int(match.group(2))
    if kind is None or pid is None:
        return None
    return _Error(pid=pid, bug_type=kind[0], message=body.strip(), access=kind[1])


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        error = _error_at(lines[i])
        if error is None:
            i += 1
            continue
        last = _scan(lines, i, error)
        found.append(_build(lines, i, last, error))
        i = last + 1
    return found


@register
class ValgrindParser:
    """Valgrind Memcheck errors."""

    format: TraceFormat = "valgrind"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
