# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""AddressSanitizer reports (SPEC §9.5).

An ASan report runs from its ``==PID==ERROR: AddressSanitizer:`` header to
``==PID==ABORTING`` (or, when that is missing, to the SUMMARY line and shadow-byte dump)::

    ==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7bc73b5e00c0 at pc …
    WRITE of size 96 at 0x7bc73b5e00c0 thread T0
        #0 0x0000004a44a1 in __asan_memcpy (/work/libhdr/build/hdrcat+0x4a44a1) (BuildId: …)
        #1 0x0000004ed539 in util_copy_value /work/libhdr/src/util.c:15:5
    0x7bc73b5e00c0 is located 0 bytes after 64-byte region [0x7bc73b5e0080,0x7bc73b5e00c0)
    allocated by thread T0 here:
        #0 0x0000004a6818 in malloc (/work/libhdr/build/hdrcat+0x4a6818)
    SUMMARY: AddressSanitizer: heap-buffer-overflow (/work/…/hdrcat+0x4a44a1) in __asan_memcpy
    ==1==ABORTING

The first stack is the faulting thread's; stacks introduced by "(previously) allocated by"
and "freed by" become the alloc/free stacks; any other labelled stack ("Thread T1 created by
T0 here:") goes to ``other_stacks``. The ``#N`` frame parser here is shared with UBSan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, NamedTuple

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

_HEX = r"0x[0-9a-fA-F]{1,16}"

#: ``    #3 0x0000004eca34 in hdr_parse_block /work/libhdr/src/hdr.c:134:17`` (the ``in`` is
#: absent from unsymbolized frames: ``#0 0x4a44a1  (/work/hdrcat+0x4a44a1)``).
FRAME_RE = re.compile(
    rf"^[ \t]{{0,16}}#(\d{{1,6}})[ \t]{{1,4}}{_HEX}[ \t]{{1,4}}(?:in[ \t]{{1,4}})?([^\n]*+)$"
)
_PID_PREFIX_RE = re.compile(r"^[ \t]{0,8}==(\d{1,10})==[ \t]{0,4}")
_PID_RE = re.compile(r"==(\d{1,10})==")
_HEADER_RE = re.compile(r"^[ \t]{0,8}==(\d{1,10})==[ \t]{0,4}ERROR: AddressSanitizer: ([^\n]*+)$")
_OTHER_HEADER_RE = re.compile(r"^[ \t]{0,8}==\d{1,10}==[ \t]{0,4}(?:ERROR|WARNING): \w{1,40}+:")
_ABORTING_RE = re.compile(r"^[ \t]{0,8}==\d{1,10}==[ \t]{0,4}ABORTING")
_ADDRESS_RE = re.compile(rf"\bon (?:unknown )?(?:address )?({_HEX})")
_THREAD_RE = re.compile(r"\b(T\d{1,10})\b")
_ACCESS_RE = re.compile(
    rf"^[ \t]{{0,8}}(READ|WRITE) of size (\d{{1,12}}) at ({_HEX})(?: thread (T\d{{1,10}}))?"
)
_SIGNAL_ACCESS_RE = re.compile(r"^The signal is caused by a (READ|WRITE) memory access")
_LOCATED_RE = re.compile(rf"^[ \t]{{0,8}}(?:Address )?({_HEX}) is located ")
_RELATION = r"(after|before|to the right of|to the left of|inside of)"
_HEAP_REGION_RE = re.compile(
    rf"^[ \t]{{0,8}}{_HEX} is located (\d{{1,12}}) bytes {_RELATION} (\d{{1,12}})-byte region "
    rf"\[({_HEX}),({_HEX})\)"
)
_GLOBAL_REGION_RE = re.compile(
    rf"^[ \t]{{0,8}}{_HEX} is located (\d{{1,12}}) bytes {_RELATION} global variable "
    rf"'[^'\n]{{0,300}}+' defined in '[^'\n]{{0,2000}}+' \(({_HEX})\) of size (\d{{1,12}})"
)
_SUMMARY_RE = re.compile(r"^[ \t]{0,8}SUMMARY: AddressSanitizer: ([^\s]{1,200}+)[ \t]?([^\n]*+)$")
_SYMVER_RE = re.compile(r"@{1,2}[A-Za-z_][A-Za-z0-9_.]{0,64}\Z")
_BUILD_ID = " (BuildId: "

_RELATIONS: dict[str, Literal["right", "left", "inside"]] = {
    "after": "right",
    "to the right of": "right",
    "before": "left",
    "to the left of": "left",
    "inside of": "inside",
}
_ACCESS_KINDS: dict[str, Literal["READ", "WRITE"]] = {"READ": "READ", "WRITE": "WRITE"}
#: Unrecognized lines tolerated in a row before the report is considered over.
_MAX_GAP = 3
#: Shortest ``=====`` run accepted as the separator ASan prints above its header.
_MIN_SEPARATOR = 20


# --- the ``#N 0x… in func location`` frame line (shared with UBSan) ----------------------


def _strip_symbol_version(name: str) -> str:
    """``__libc_start_main@GLIBC_2.2.5`` → ``__libc_start_main``."""
    at = name.find("@")
    if at > 0 and _SYMVER_RE.match(name, at):
        return name[:at]
    return name


class FrameParts(NamedTuple):
    """The pieces of a native frame's ``func location`` text."""

    function: str | None
    path: str | None = None
    line: int | None = None
    col: int | None = None
    module: str | None = None


def split_frame_rest(rest: str) -> FrameParts:
    """Split ``func path:line:col`` / ``func (module+0x…)`` into its parts."""
    rest = rest.strip()
    build_id = rest.rfind(_BUILD_ID)
    if build_id >= 0 and rest.endswith(")"):
        rest = rest[:build_id].rstrip()
    if rest.endswith(")") and "(" in rest:
        open_paren = rest.rfind("(")
        inner = rest[open_paren + 1 : -1]
        if "+0x" in inner or inner.startswith("/"):
            function = rest[:open_paren].strip()
            return FrameParts(function or None, module=inner.split("+0x")[0] or None)
    head, _, last = rest.rpartition(" ")
    location = split_location(last)
    if location is not None:
        return FrameParts(head.strip() or None, *location)
    if last == "<null>" and head:
        return FrameParts(head.strip())
    return FrameParts(rest or None)


def parse_sanitizer_frame(line: str) -> Frame | None:
    """Parse one ``#N 0x… in func location`` frame, as printed by every sanitizer."""
    match = FRAME_RE.match(line)
    if match is None:
        return None
    parts = split_frame_rest(match.group(2))
    function = _strip_symbol_version(parts.function) if parts.function else None
    return make_frame(
        index=int(match.group(1)),
        raw=line,
        function=function,
        path=parts.path,
        line=parts.line,
        col=parts.col,
        module=parts.module,
        is_runtime=is_native_runtime_frame(function, parts.path, parts.module),
    )


def parse_summary_location(rest: str) -> tuple[str | None, int | None, str | None]:
    """``/src/a.c:9:18 in func`` or ``(module+0x…) (BuildId: …) in func`` → path, line, func."""
    location, sep, function = rest.rpartition(" in ")
    if not sep:
        location, function = rest, ""
    token = location.strip().split(" ", 1)[0] if location.strip() else ""
    parsed = split_location(token)
    path, line = (parsed[0], parsed[1]) if parsed else (None, None)
    return path, line, function.strip() or None


# --- report assembly -------------------------------------------------------------------


@dataclass
class _Stacks:
    """Frame runs sorted into the primary, alloc, free and other stacks."""

    frames: list[Frame] = field(default_factory=list)
    alloc: list[Frame] = field(default_factory=list)
    free: list[Frame] = field(default_factory=list)
    other: list[Stack] = field(default_factory=list)

    def add(self, label: str | None, run: list[Frame]) -> None:
        lowered = (label or "").lower()
        if "freed by" in lowered and not self.free:
            self.free = run
        elif "allocated by" in lowered and not self.alloc:
            self.alloc = run
        elif not self.frames and "created by" not in lowered:
            self.frames = run
        else:
            name = (label or f"stack {len(self.other) + 1}").removesuffix(":").strip()
            self.other.append(Stack(label=name.removesuffix(" here"), frames=tuple(run)))


@dataclass
class _Report:
    """Mutable accumulator for one report while its lines are scanned."""

    pid: int
    header: str
    stacks: _Stacks = field(default_factory=_Stacks)
    access: MemoryAccess | None = None
    access_address: int | None = None
    region_address: int | None = None
    region: MemoryRegion | None = None
    thread: str | None = None
    summary: str | None = None
    summary_type: str | None = None
    summary_path: str | None = None
    summary_line: int | None = None
    summary_function: str | None = None


def _strip_pid(text: str) -> str:
    match = _PID_PREFIX_RE.match(text)
    return text[match.end() :] if match else text


def _region(match: re.Match[str], *, heap: bool) -> MemoryRegion:
    distance = int(match.group(1))
    relation = _RELATIONS[match.group(2)]
    if heap:
        start, end = parse_hex(match.group(4)), parse_hex(match.group(5))
        size = int(match.group(3))
    else:
        start, size = parse_hex(match.group(3)), int(match.group(4))
        end = start + size
    return MemoryRegion(start=start, end=end, size=size, relation=relation, distance=distance)


def _apply_detail(report: _Report, text: str) -> bool:
    """Record an access, region or SUMMARY line; return whether the line was one."""
    body = _strip_pid(text)
    if match := _ACCESS_RE.match(body):
        report.access = MemoryAccess(kind=_ACCESS_KINDS[match.group(1)], size=int(match.group(2)))
        report.access_address = parse_hex(match.group(3))
        report.thread = match.group(4) or report.thread
        return True
    if match := _SIGNAL_ACCESS_RE.match(body):
        report.access = MemoryAccess(kind=_ACCESS_KINDS[match.group(1)])
        return True
    if match := _LOCATED_RE.match(body):
        report.region_address = parse_hex(match.group(1))
        if heap := _HEAP_REGION_RE.match(body):
            report.region = _region(heap, heap=True)
        elif glob := _GLOBAL_REGION_RE.match(body):
            report.region = _region(glob, heap=False)
        return True
    if match := _SUMMARY_RE.match(body):
        report.summary = text.strip()
        report.summary_type = match.group(1)
        path, line, function = parse_summary_location(match.group(2))
        report.summary_path, report.summary_line, report.summary_function = path, line, function
        return True
    return False


def _looks_like_report_line(text: str) -> bool:
    """Lines that belong inside a report even when no field is taken from them."""
    stripped = text.strip()
    return (
        text[:1] in (" ", "\t")
        or stripped.startswith(("==", "=>", "0x", "Address ", "Hint", "HINT"))
        or "Sanitizer" in stripped
    )


@dataclass
class _Cursor:
    """Scan state: the current frame run, its label, and the report's last line so far."""

    last: int
    gap: int = 0
    label: str | None = None
    run: list[Frame] = field(default_factory=list)

    def flush(self, stacks: _Stacks) -> None:
        if self.run:
            stacks.add(self.label, self.run)
            self.run, self.label = [], None

    def take_frame(self, stacks: _Stacks, i: int, frame: Frame) -> None:
        if frame.index == 0:
            self.flush(stacks)
        self.run.append(frame)
        self.last, self.gap = i, 0

    def take_line(self, report: _Report, i: int, text: str) -> bool:
        """Handle a non-frame line; return False once the report is over."""
        self.flush(report.stacks)
        stripped = text.strip()
        if not stripped:
            return True
        if _apply_detail(report, text) or (
            not stripped.endswith(":") and _looks_like_report_line(text)
        ):
            self.last, self.gap, self.label = i, 0, None
        elif stripped.endswith(":"):
            self.label = stripped  # a stack label only extends the report once frames follow
        else:
            self.gap, self.label = self.gap + 1, None
        return self.gap <= _MAX_GAP


def _scan(lines: list[Line], first: int, report: _Report) -> int:
    """Scan the report body after its header; return the index of its last line."""
    cursor = _Cursor(last=first)
    for i in range(first + 1, len(lines)):
        text = lines[i].text
        if _OTHER_HEADER_RE.match(text):
            break
        if (frame := parse_sanitizer_frame(text)) is not None:
            cursor.take_frame(report.stacks, i, frame)
        elif _ABORTING_RE.match(text):
            cursor.flush(report.stacks)
            return i
        elif not cursor.take_line(report, i, text):
            break
    cursor.flush(report.stacks)
    return cursor.last


def _bug_type(report: _Report) -> str | None:
    if report.summary_type:
        return report.summary_type
    words = report.header.split()
    if words and words[0] == "attempting" and len(words) > 1:
        return words[1]
    return words[0] if words else None


def _pids(lines: list[Line], first: int, last: int) -> tuple[int, ...]:
    seen: list[int] = []
    for line in lines[first : last + 1]:
        for match in _PID_RE.finditer(line.text):
            pid = int(match.group(1))
            if pid not in seen:
                seen.append(pid)
    return tuple(seen)


def _build(report: _Report, lines: list[Line], first: int, last: int) -> ParsedTrace:
    address = _ADDRESS_RE.search(report.header)
    thread = report.thread
    if thread is None and (found := _THREAD_RE.search(report.header)):
        thread = found.group(1)
    data = TraceData(
        format="asan",
        bug_type=_bug_type(report),
        message=report.header.strip() or None,
        access=report.access,
        address=parse_hex(address.group(1)) if address else None,
        access_address=report.access_address,
        region_address=report.region_address,
        region=report.region,
        frames=tuple(report.stacks.frames),
        alloc_frames=tuple(report.stacks.alloc),
        free_frames=tuple(report.stacks.free),
        other_stacks=tuple(report.stacks.other),
        summary=report.summary,
        summary_path=report.summary_path,
        summary_line=report.summary_line,
        summary_function=report.summary_function,
        pid=report.pid,
        pids_seen=_pids(lines, first, last),
        thread=thread,
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


def _is_separator(text: str) -> bool:
    stripped = text.strip()
    return len(stripped) >= _MIN_SEPARATOR and set(stripped) == {"="}


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        match = _HEADER_RE.match(lines[i].text)
        if match is None:
            i += 1
            continue
        pid = parse_int(match.group(1))
        report = _Report(pid=pid if pid is not None else 0, header=match.group(2))
        last = _scan(lines, i, report)
        first = i - 1 if i > 0 and _is_separator(lines[i - 1].text) else i
        found.append(_build(report, lines, first, last))
        i = last + 1
    return found


@register
class AsanParser:
    """AddressSanitizer reports."""

    format: TraceFormat = "asan"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
