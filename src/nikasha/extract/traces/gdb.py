# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""gdb backtraces (``bt`` / ``bt full``, SPEC §9.5).

A trace is an optional ``Program received signal …`` line followed by ``#N`` frames::

    Program received signal SIGFPE, Arithmetic exception.
    0x00000000004004ee in ratio (a=700, b=0) at /src/programs/gdb/divide_sigfpe.c:8
    8           return a / b;
    #0  0x00000000004004ee in ratio (a=700, b=0) at /src/programs/gdb/divide_sigfpe.c:8
    #1  0x0000000000400496 in main (argc=1, argv=0x7ffdfbdf58f8) at /src/…/divide_sigfpe.c:19
    #2  0x00007ffff7a2d1ca in __libc_start_call_main () from /lib64/libc.so.6

The address and ``in`` are absent for inlined frames (``#6  malloc_printerr (…) at
malloc.c:5341``). Arguments may contain quoted strings with parentheses, so the argument list
is matched by scanning, not by regex. ``bt full`` local-variable lines, "No locals.", source
lines and ``warning:`` lines are skipped. ``thread apply all bt`` output yields one stack per
thread: the first is ``frames``, the rest go to ``other_stacks`` under their ``Thread N``
heading.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    is_native_runtime_frame,
    make_frame,
    register,
    run_guarded,
    split_lines,
    split_location,
)
from nikasha.model.claims import Frame, Stack, TraceData, TraceFormat

_FRAME_RE = re.compile(r"^[ \t]{0,2}#(\d{1,6})[ \t]{1,8}(?:0x[0-9a-fA-F]{1,16} in )?([^\n]*+)$")
_SIGNAL_RE = re.compile(
    r"^(?:Program|Thread ([\d.]{1,20}+)(?: \"[^\"\n]{0,256}+\")?) "
    r"(?:received|terminated with) signal (SIG[A-Z0-9]{1,16}+),? ?([^\n]{0,500}+)$"
)
_THREAD_HEADING_RE = re.compile(r"^Thread [\d.]{1,20}+ \(")
_CONTINUATION_RE = re.compile(r"^[ \t]{1,16}(at|from) ([^\n]{1,4096}+)$")
#: Lines allowed between the signal line and ``#0`` (current location, source line, warnings).
_MAX_PREAMBLE = 12
#: Blank/heading lines tolerated between two threads' backtraces.
_MAX_THREAD_GAP = 3
_SIGNAL_HANDLER = "<signal handler called>"


def _close_paren(text: str, open_at: int) -> int:
    """Index of the ``)`` matching ``text[open_at]``, skipping ``"strings"`` and ``'c'``
    character literals (``str=0x… "malloc(): invalid size"``); -1 if unbalanced."""
    depth, quote, escaped = 0, "", False
    for i in range(open_at, len(text)):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _location(tail: str) -> tuple[str | None, int | None, str | None]:
    """``at path:line`` → (path, line, None); ``from /lib64/libc.so.6`` → (None, None, lib)."""
    tail = tail.strip()
    if tail.startswith("at "):
        parsed = split_location(tail[3:].strip())
        if parsed is not None:
            return parsed[0], parsed[1], None
    elif tail.startswith("from "):
        return None, None, tail[5:].strip() or None
    return None, None, None


def parse_frame(text: str) -> Frame | None:
    """Parse one ``#N …`` backtrace line."""
    match = _FRAME_RE.match(text)
    if match is None:
        return None
    rest = match.group(2).strip()
    if rest.startswith(_SIGNAL_HANDLER):
        return make_frame(index=int(match.group(1)), raw=text, is_runtime=True)
    args_at = rest.find(" (")
    if args_at < 0:
        function, tail = rest.split(" ", 1)[0], ""
    else:
        close = _close_paren(rest, args_at + 1)
        function, tail = rest[:args_at], rest[close + 1 :] if close >= 0 else ""
    name = None if function in ("??", "") else function
    path, line, module = _location(tail)
    return make_frame(
        index=int(match.group(1)),
        raw=text,
        function=name,
        path=path,
        line=line,
        module=module,
        is_runtime=is_native_runtime_frame(name, path, module),
    )


def _attach(frame: Frame, text: str) -> Frame | None:
    """Merge a wrapped ``    at file.c:12`` continuation into a frame lacking a location."""
    if frame.path or frame.module or not _CONTINUATION_RE.match(text):
        return None
    path, line, module = _location(text)
    if path is None and module is None:
        return None
    return make_frame(
        index=frame.index,
        raw=f"{frame.raw} {text.strip()}",
        function=frame.function,
        path=path,
        line=line,
        module=module,
        is_runtime=is_native_runtime_frame(frame.function, path, module),
    )


@dataclass
class _Backtrace:
    stacks: list[tuple[str | None, list[Frame]]] = field(default_factory=list)
    label: str | None = None

    def add(self, frame: Frame) -> None:
        if not self.stacks or (frame.index == 0 and self.stacks[-1][1]):
            self.stacks.append((self.label, []))
            self.label = None
        self.stacks[-1][1].append(frame)


def _next_is_new_thread(lines: list[Line], i: int) -> str | None:
    """If a new thread's ``#0`` follows within a few blank/heading lines, return its heading."""
    heading = None
    for j in range(i, min(i + _MAX_THREAD_GAP + 1, len(lines))):
        text = lines[j].text
        if _THREAD_HEADING_RE.match(text):
            heading = text.strip().rstrip(":")
        elif (frame := parse_frame(text)) is not None:
            return (heading or f"stack at #{frame.index}") if frame.index == 0 else None
        elif text.strip():
            return None
    return None


def _is_skippable(text: str) -> bool:
    """``bt full`` locals, "No locals.", ``warning:`` and truncation notes."""
    stripped = text.strip()
    return (
        text[:1] in (" ", "\t")
        or stripped == "No locals."
        or stripped.startswith(("warning:", "Backtrace stopped", "(More stack frames follow"))
    )


def _scan(lines: list[Line], first: int, bt: _Backtrace) -> int:
    """Collect frames from line ``first`` (a ``#0``); return the index of the last frame line."""
    last = first
    i = first
    while i < len(lines):
        text = lines[i].text
        frame = parse_frame(text)
        if frame is not None:
            bt.add(frame)
            last = i
        elif bt.stacks and (merged := _attach(bt.stacks[-1][1][-1], text)) is not None:
            bt.stacks[-1][1][-1] = merged
            last = i
        elif _is_skippable(text) and text.strip():
            last = i if not text.strip().startswith("warning:") else last
        elif (heading := _next_is_new_thread(lines, i)) is not None:
            bt.label = heading
        else:
            break
        i += 1
    return last


def _signal_before(lines: list[Line], first: int) -> tuple[int, re.Match[str]] | None:
    for j in range(first - 1, max(-1, first - _MAX_PREAMBLE - 1), -1):
        if match := _SIGNAL_RE.match(lines[j].text):
            return j, match
        if parse_frame(lines[j].text) is not None:
            return None
    return None


def _build(lines: list[Line], first: int, last: int, bt: _Backtrace) -> ParsedTrace:
    signal = _signal_before(lines, first)
    start = signal[0] if signal else first
    match = signal[1] if signal else None
    frames = bt.stacks[0][1] if bt.stacks else []
    others = tuple(Stack(label=label or "stack", frames=tuple(f)) for label, f in bt.stacks[1:])
    message = match.group(3).strip().removesuffix(".") if match else ""
    data = TraceData(
        format="gdb",
        bug_type=match.group(2) if match else None,
        message=message or None,
        frames=tuple(frames),
        other_stacks=others,
        thread=match.group(1) if match else None,
    )
    return ParsedTrace(start=lines[start].start, end=lines[last].end, data=data)


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        frame = parse_frame(lines[i].text)
        if frame is None or frame.index != 0:
            i += 1
            continue
        bt = _Backtrace()
        last = _scan(lines, i, bt)
        found.append(_build(lines, i, last, bt))
        i = last + 1
    return found


@register
class GdbParser:
    """gdb ``bt`` output."""

    format: TraceFormat = "gdb"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
