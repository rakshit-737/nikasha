# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Node.js uncaught errors (SPEC §9.5).

::

    /src/programs/node/type_error.js:7
      return session.user.name;
                          ^

    TypeError: Cannot read properties of undefined (reading 'name')
        at userName (/src/programs/node/type_error.js:7:23)
        at async main (/src/programs/node/unhandled_rejection.js:17:3)
        at Module._compile (node:internal/modules/cjs/loader:1871:14)

    Node.js v24.18.0

The anchor is an ``ErrorType: message`` line (``Error [ERR_CODE]: …`` too) followed by ``at``
frames. The optional ``path:line`` + source + caret header above it starts the trace; the
``Node.js vNN`` footer ends it. A property block (``    at f (x.js:1:2) {`` … ``}``) after
the last frame is included in the span.

Frames: ``at func (path:line:col)``, ``at path:line:col``, ``at async func (…)``, ``at new
Class (…)``; ``[as alias]`` and ``file://`` prefixes are dropped. ``node:internal/…`` and
other ``node:`` built-ins (and pre-v16 ``internal/…`` paths) are runtime frames.
"""

from __future__ import annotations

import re

from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    make_frame,
    register,
    run_guarded,
    split_lines,
    split_location,
)
from nikasha.model.claims import Frame, TraceData, TraceFormat

_ERROR_RE = re.compile(
    r"^(?:Uncaught )?([A-Za-z_$][\w$.]{0,200}+)(?: \[[A-Z0-9_]{1,100}+\])?(?:: ([^\n]{0,4000}+))?$"
)
_FRAME_RE = re.compile(r"^[ \t]{1,16}+at ([^\n]{1,4000}+)$")
_CARET_RE = re.compile(r"^[ \t]{0,4000}+\^{1,4000}+[ \t]*+$")
_FOOTER_RE = re.compile(r"^Node\.js v\d{1,4}+[\w.+-]{0,40}+[ \t]*+$")
_ALIAS_RE = re.compile(r" \[as [^\]\n]{1,200}+\]$")
_ANONYMOUS = ("<anonymous>", "native")
_RUNTIME_PATHS = ("node:", "internal/")
_PREFIXES = ("async ", "new ")
#: Lines between the last frame and the ``Node.js vNN`` footer.
_MAX_FOOTER_GAP = 2
#: Longest ``{ … }`` property block followed after the last frame.
_MAX_PROPERTY_LINES = 200


def _split_frame(body: str) -> tuple[str | None, str | None, int | None, int | None, bool]:
    """``func (loc)`` / ``loc`` → (function, path, line, col, location_understood)."""
    body = body.strip().removesuffix(" {").rstrip()
    function, location = None, body
    if body.endswith(")") and " (" in body:
        split_at = body.index(" (")
        function, location = body[:split_at], body[split_at + 2 : -1]
    if function is not None:
        function = _ALIAS_RE.sub("", function)
        for prefix in _PREFIXES:
            function = function.removeprefix(prefix)
    if location in _ANONYMOUS:
        return function or None, None, None, None, True
    parsed = split_location(location.removeprefix("file://"))
    if parsed is None:
        return function or None, None, None, None, False
    return function or None, parsed[0], parsed[1], parsed[2], True


def parse_frame(text: str, index: int, *, strict: bool) -> Frame | None:
    """Parse one ``    at …`` line (``strict``: the location must be understood)."""
    match = _FRAME_RE.match(text)
    if match is None:
        return None
    function, path, line, col, understood = _split_frame(match.group(1))
    if strict and not understood:
        return None
    return make_frame(
        index=index,
        raw=text,
        function=function,
        path=path,
        line=line,
        col=col,
        is_runtime=bool(path and path.startswith(_RUNTIME_PATHS)),
    )


def _header_start(lines: list[Line], error: int) -> int:
    """Walk back over ``path:line`` / source / caret / blank lines above the error line."""
    j = error - 1
    if j >= 0 and not lines[j].text.strip():
        j -= 1
    if j < 1 or not _CARET_RE.match(lines[j].text):
        return error
    candidate = j - 2
    if candidate >= 0 and split_location(lines[candidate].text.strip()) is not None:
        return candidate
    return error


def _after_frames(lines: list[Line], last: int) -> int:
    """Extend past a ``{ … }`` property block and the ``Node.js vNN`` footer."""
    if lines[last].text.rstrip().endswith(" {"):
        for j in range(last + 1, min(last + 1 + _MAX_PROPERTY_LINES, len(lines))):
            if lines[j].text.rstrip() == "}":
                last = j
                break
    for j in range(last + 1, min(last + 2 + _MAX_FOOTER_GAP, len(lines))):
        if _FOOTER_RE.match(lines[j].text):
            return j
        if lines[j].text.strip():
            break
    return last


def _read_frames(lines: list[Line], first: int) -> tuple[list[Frame], int]:
    frames: list[Frame] = []
    last = first
    for i in range(first, len(lines)):
        frame = parse_frame(lines[i].text, len(frames), strict=False)
        if frame is None:
            break
        frames.append(frame)
        last = i
    return frames, last


def _error_at(lines: list[Line], i: int) -> re.Match[str] | None:
    """The error line on ``i`` if an understood ``at`` frame follows it."""
    match = _ERROR_RE.match(lines[i].text)
    if match is None or i + 1 >= len(lines):
        return None
    return match if parse_frame(lines[i + 1].text, 0, strict=True) else None


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        error = _error_at(lines, i)
        if error is None:
            i += 1
            continue
        frames, last = _read_frames(lines, i + 1)
        last = _after_frames(lines, last)
        start = _header_start(lines, i)
        if found and lines[start].start < found[-1].end:
            start = i
        data = TraceData(
            format="node",
            bug_type=error.group(1),
            message=(error.group(2) or "").strip() or None,
            frames=tuple(frames),
        )
        found.append(ParsedTrace(start=lines[start].start, end=lines[last].end, data=data))
        i = last + 1
    return found


@register
class NodeParser:
    """Node.js uncaught exceptions."""

    format: TraceFormat = "node"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
