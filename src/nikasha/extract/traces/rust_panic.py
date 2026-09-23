# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Rust panics and ``RUST_BACKTRACE`` backtraces (SPEC §9.5).

::

    thread 'main' (1) panicked at /src/programs/rust/index_oob.rs:5:5:
    index out of bounds: the len is 3 but the index is 3
    stack backtrace:
       0: __rustc::rust_begin_unwind
                 at /builddir/…/library/std/src/panicking.rs:679:5
       3: index_oob::pick
                 at /src/programs/rust/index_oob.rs:5:5
    note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.

The header may omit the thread id (``thread 'main' panicked at src/main.rs:2:5:``), and
pre-1.73 Rust put the message on the header (``panicked at 'msg', src/main.rs:2:5``). The
message is every line up to ``stack backtrace:`` or the ``note:`` line. ``RUST_BACKTRACE=full``
frames carry an address (``  19:     0x55d7… - unwrap_none[1d78…]::lookup``); the ``[hash]``
crate disambiguators and legacy ``::h<hash>`` suffixes are stripped from function names (the
raw line keeps them).

Without a backtrace (``note: run with `RUST_BACKTRACE=1` …``) frame 0 is synthesized from the
panic location, so the trace still points at a line. Frames in ``std``/``core``/``alloc``/
``__rustc``, or with source under the toolchain's ``library/`` tree, are runtime frames.
"""

from __future__ import annotations

import re

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
from nikasha.model.claims import Frame, TraceData, TraceFormat

_HEADER_RE = re.compile(
    r"^thread '([^'\n]{0,256}+)'(?: \((\d{1,20})\))? panicked at ([^\n]{1,4096}+)$"
)
_BACKTRACE_RE = re.compile(r"^stack backtrace:[ \t]*+$")
_FRAME_RE = re.compile(
    r"^[ \t]{0,16}+(\d{1,6}): {1,32}+(?:0x[0-9a-fA-F]{1,16} - )?([^\n]{1,8000}+)$"
)
_AT_RE = re.compile(r"^[ \t]{1,64}+at ([^\n]{1,4096}+)$")
_CRATE_HASH_RE = re.compile(r"\[[0-9a-f]{16}\]")
_LEGACY_HASH_RE = re.compile(r"::h[0-9a-f]{16}$")
_RUNTIME_CRATE_RE = re.compile(
    r"^[<&\s]{0,8}+(?:dyn )?(?:std|core|alloc|__rustc|backtrace_rs|panic_unwind|panic_abort)::"
)
_LIBRARY_MARKERS = ("/library/std/", "/library/core/", "/library/alloc/", "/library/panic_")
_NOTE = "note:"
_UNKNOWN = "<unknown>"


def clean_function(name: str) -> str:
    """Strip ``[16-hex]`` crate disambiguators and legacy ``::h<hash>`` suffixes."""
    return _LEGACY_HASH_RE.sub("", _CRATE_HASH_RE.sub("", name.strip()))


def is_rust_runtime(function: str | None, path: str | None) -> bool:
    """Whether a frame is in the Rust standard library, runtime or libc."""
    if function and _RUNTIME_CRATE_RE.match(function):
        return True
    if function and function.startswith("<fn(") and (path is None or "/library/" in path):
        return True
    if path and any(marker in path for marker in _LIBRARY_MARKERS):
        return True
    return is_native_runtime_frame(function, path, None)


def _location(text: str) -> tuple[str | None, str]:
    """Split the header's tail into (old-style quoted message, ``path:line:col``)."""
    text = text.strip().removesuffix(":")
    if text.startswith("'") and "', " in text:
        message, _, location = text[1:].rpartition("', ")
        return message, location
    return None, text


def _frame(number: str, name: str, at_line: str | None, raw: str) -> Frame:
    function: str | None = clean_function(name)
    if function == _UNKNOWN:
        function = None
    path = line = col = None
    if at_line is not None and (parsed := split_location(at_line.strip())) is not None:
        path, line, col = parsed
    return make_frame(
        index=int(number),
        raw=raw,
        function=function,
        path=path,
        line=line,
        col=col,
        is_runtime=is_rust_runtime(function, path),
    )


def _read_frames(lines: list[Line], first: int) -> tuple[list[Frame], int]:
    """Read ``N: func`` / ``at path:line:col`` pairs after ``stack backtrace:``."""
    frames: list[Frame] = []
    last, i = first, first + 1
    while i < len(lines):
        match = _FRAME_RE.match(lines[i].text)
        if match is None:
            break
        at_match = _AT_RE.match(lines[i + 1].text) if i + 1 < len(lines) else None
        raw = lines[i].text + (f"\n{lines[i + 1].text}" if at_match else "")
        frames.append(
            _frame(match.group(1), match.group(2), at_match.group(1) if at_match else None, raw)
        )
        last = i + 1 if at_match else i
        i = last + 1
    return frames, last


def _read_message(lines: list[Line], header: int) -> tuple[list[str], int]:
    """Message lines after the header, up to the backtrace, a note or a blank line."""
    message: list[str] = []
    last = header
    for i in range(header + 1, len(lines)):
        text = lines[i].text
        if not text.strip() or _BACKTRACE_RE.match(text) or text.startswith(_NOTE):
            break
        if _HEADER_RE.match(text):
            break
        message.append(text)
        last = i
    return message, last


def _synthesized(location: str, raw: str) -> list[Frame]:
    parsed = split_location(location)
    if parsed is None:
        return []
    path, line, col = parsed
    runtime = is_rust_runtime(None, path)
    return [make_frame(index=0, raw=raw, path=path, line=line, col=col, is_runtime=runtime)]


def _read_panic(lines: list[Line], header: int, match: re.Match[str]) -> ParsedTrace:
    old_message, location = _location(match.group(3))
    message_lines, last = _read_message(lines, header)
    frames: list[Frame] = []
    if last + 1 < len(lines) and _BACKTRACE_RE.match(lines[last + 1].text):
        frames, last = _read_frames(lines, last + 1)
    if last + 1 < len(lines) and lines[last + 1].text.startswith(_NOTE):
        last += 1
    if not frames:
        frames = _synthesized(location, lines[header].text)
    message = old_message if old_message is not None else "\n".join(message_lines).strip()
    data = TraceData(
        format="rust",
        bug_type="panic",
        message=message or None,
        frames=tuple(frames),
        thread=match.group(1),
    )
    return ParsedTrace(start=lines[header].start, end=lines[last].end, data=data)


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        match = _HEADER_RE.match(lines[i].text)
        if match is None:
            i += 1
            continue
        trace = _read_panic(lines, i, match)
        found.append(trace)
        while i < len(lines) and lines[i].start < trace.end:
            i += 1
    return found


@register
class RustPanicParser:
    """Rust panics, with or without ``RUST_BACKTRACE``."""

    format: TraceFormat = "rust"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
