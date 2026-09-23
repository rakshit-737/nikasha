# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Go panics and fatal errors (SPEC §9.5).

::

    panic: job 3 has no owner

    goroutine 8 [running]:
    main.worker(0x0?, 0x0?)
            /src/programs/go/goroutine_panic.go:22 +0x9b
    created by main.main in goroutine 1
            /src/programs/go/goroutine_panic.go:30 +0x33

    goroutine 1 [sync.WaitGroup.Wait]:
    sync.(*WaitGroup).Wait(0x1b9caa6d60a0)
            /usr/lib/golang/src/sync/waitgroup.go:206 +0x85
    exit status 2

A trace is a ``panic:`` / ``fatal error:`` line followed by goroutine blocks, each a
``goroutine N [state]:`` heading and pairs of a ``func(args)`` line and a tab-indented
``path:line +0xoff`` line. ``frames`` are the panicking goroutine's (the one ``[running]``, or
else the first); every other goroutine goes to ``other_stacks`` labelled ``goroutine N
[state]``. ``go run``'s ``exit status N`` line closes the trace when present.

``created by F in goroutine N`` is kept as the goroutine's last frame (function ``F``, at the
``go`` statement's line): it is where the goroutine came from, and the location Go prints for
it is real project code a checker can verify. Frames under GOROOT (``/usr/lib/golang/src/``,
``/usr/local/go/src/``, …) or in package ``runtime`` are runtime frames.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    make_frame,
    register,
    run_guarded,
    split_lines,
    split_location,
)
from nikasha.model.claims import Frame, Stack, TraceData, TraceFormat

_PANIC_RE = re.compile(r"^(panic|fatal error): ([^\n]{0,4000}+)$")
_GOROUTINE_RE = re.compile(r"^goroutine (\d{1,12}) [^\[\n]{0,300}+\[([^\]\n]{1,300}+)\]:[ \t]*+$")
_EXIT_RE = re.compile(r"^exit status \d{1,3}[ \t]*+$")
_CREATED_BY = "created by "
_GOROOT_MARKERS = (
    "/usr/lib/golang/src/",
    "/usr/local/go/src/",
    "/usr/lib/go/src/",
    "/usr/share/go/src/",
    "/golang.org/toolchain@",
    "/go/src/runtime/",
    "$GOROOT/src/",
)
_RUNTIME_FUNCTIONS = ("runtime.", "runtime/")
#: Lines allowed between the panic line and the first goroutine heading
#: (``[signal SIGSEGV …]``, nested ``panic:`` lines, ``[recovered]`` notes, blanks).
_MAX_PREAMBLE = 10
_RUNNING = "running"


def is_goroot_frame(function: str | None, path: str | None) -> bool:
    """Whether a frame is in the Go runtime or standard library."""
    if function and function.startswith(_RUNTIME_FUNCTIONS):
        return True
    return bool(path) and any(marker in (path or "") for marker in _GOROOT_MARKERS)


def _function_name(text: str) -> str:
    """``main.(*registry).add(...)`` → ``main.(*registry).add``."""
    text = text.strip()
    if text.startswith(_CREATED_BY):
        return text[len(_CREATED_BY) :].split(" in goroutine ", 1)[0].strip()
    if text.endswith(")") and "(" in text:
        return text[: text.rfind("(")]
    return text


def _frame(func_line: str, loc_line: str, index: int) -> Frame | None:
    """Pair a function line with its indented ``path:line +0x…`` location line."""
    location = loc_line.strip()
    if " +0x" in location:
        location = location.rsplit(" +0x", 1)[0]
    parsed = split_location(location)
    if parsed is None:
        return None
    function = _function_name(func_line) or None
    return make_frame(
        index=index,
        raw=f"{func_line}\n{loc_line}",
        function=function,
        path=parsed[0],
        line=parsed[1],
        is_runtime=is_goroot_frame(function, parsed[0]),
    )


@dataclass
class _Goroutine:
    number: str
    state: str
    frames: list[Frame] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"goroutine {self.number} [{self.state}]"


def _read_goroutine(lines: list[Line], heading: int, goroutine: _Goroutine) -> int:
    """Read frame pairs after a heading; return the index of the block's last line."""
    last, i = heading, heading + 1
    while i + 1 < len(lines):
        func_line, loc_line = lines[i].text, lines[i + 1].text
        if not func_line.strip() or func_line[:1] in (" ", "\t") or loc_line[:1] not in " \t":
            break
        frame = _frame(func_line, loc_line, len(goroutine.frames))
        if frame is None:
            break
        goroutine.frames.append(frame)
        last, i = i + 1, i + 2
    return last


_Heading = tuple[int, re.Match[str]]


def _next_heading(lines: list[Line], after: int) -> _Heading | None:
    """The next goroutine heading, if only blank lines separate it from line ``after``."""
    for j in range(after + 1, len(lines)):
        if match := _GOROUTINE_RE.match(lines[j].text):
            return j, match
        if lines[j].text.strip():
            return None
    return None


def _read_goroutines(lines: list[Line], first: _Heading) -> tuple[list[_Goroutine], int]:
    goroutines: list[_Goroutine] = []
    heading: _Heading | None = first
    last = first[0]
    while heading is not None:
        index, match = heading
        goroutine = _Goroutine(match.group(1), match.group(2).strip())
        goroutines.append(goroutine)
        last = _read_goroutine(lines, index, goroutine)
        heading = _next_heading(lines, last)
    return goroutines, last


def _first_heading(lines: list[Line], panic: int) -> _Heading | None:
    for j in range(panic + 1, min(panic + 1 + _MAX_PREAMBLE, len(lines))):
        if match := _GOROUTINE_RE.match(lines[j].text):
            return j, match
    return None


def _build(
    lines: list[Line], panic: re.Match[str], first: int, last: int, goroutines: list[_Goroutine]
) -> ParsedTrace:
    running = [g for g in goroutines if g.state.startswith(_RUNNING)]
    primary = running[0] if running else goroutines[0]
    others = tuple(
        Stack(label=g.label, frames=tuple(g.frames)) for g in goroutines if g is not primary
    )
    data = TraceData(
        format="go",
        bug_type=panic.group(1),
        message=panic.group(2).strip() or None,
        frames=tuple(primary.frames),
        other_stacks=others,
        thread=f"goroutine {primary.number}",
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        panic = _PANIC_RE.match(lines[i].text)
        heading = _first_heading(lines, i) if panic else None
        if panic is None or heading is None:
            i += 1
            continue
        goroutines, last = _read_goroutines(lines, heading)
        if last + 1 < len(lines) and _EXIT_RE.match(lines[last + 1].text):
            last += 1
        found.append(_build(lines, panic, i, last, goroutines))
        i = last + 1
    return found


@register
class GoPanicParser:
    """Go panics (``panic:`` / ``fatal error:`` with goroutine dumps)."""

    format: TraceFormat = "go"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
