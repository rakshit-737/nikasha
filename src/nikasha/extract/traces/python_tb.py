# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Python tracebacks, including chained exceptions (SPEC §9.5).

::

    Traceback (most recent call last):
      File "/src/app/config.py", line 14, in read_timeout
        return int(lookup("timeout"))
                   ~~~~~~^^^^^^^^^^^
    KeyError: 'timeout'

    During handling of the above exception, another exception occurred:

    Traceback (most recent call last):
      File "/src/app/config.py", line 16, in read_timeout
        raise ValueError("timeout is not configured")
    ValueError: timeout is not configured

A whole chain is ONE trace. ``frames`` belong to the last (propagated) traceback and are
ordered **innermost first** (index 0 raised), the reverse of Python's printing order, so
frame 0 means "where it broke" in every format. Earlier tracebacks go to ``other_stacks`` in
printed order, labelled ``context: <Type>`` ("During handling …") or ``cause: <Type>`` ("The
above exception was the direct cause …"), where ``<Type>`` is that earlier exception.

Source and caret (``~~~^^^``) lines are skipped. Frames in the interpreter's standard library
(``…/lib/python3.X/…`` outside ``site-packages``/``dist-packages``, and ``<frozen …>``) are
runtime frames: they are never the project's code. Third-party packages stay app frames.
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
)
from nikasha.model.claims import Frame, Stack, TraceData, TraceFormat

_HEADER_RE = re.compile(r"^([ \t]{0,40}+)Traceback \(most recent call last\):[ \t]*+$")
_FILE_RE = re.compile(
    r"^[ \t]{1,48}+File \"([^\"\n]{1,4096}+)\", line (\d{1,9})(?:, in ([^\n]{1,1000}+))?$"
)
#: ``Type: message`` / ``Type`` (a dotted identifier at the traceback's own indentation).
_EXCEPTION_RE = re.compile(r"^([A-Za-z_][\w.]{0,300}+)(?:: ?([^\n]{0,4000}+))?$")
_STDLIB_RE = re.compile(r"/(?:lib|lib64|Lib)/python\d(?:\.\d{1,3})?/|/Python\d{1,4}/Lib/")
_THIRD_PARTY = ("site-packages", "dist-packages")

_CHAIN_MARKERS: dict[str, str] = {
    "During handling of the above exception, another exception occurred:": "context",
    "The above exception was the direct cause of the following exception:": "cause",
}
#: Lines scanned after an exception line for a chain marker and the next header.
_MAX_CHAIN_GAP = 4


def is_stdlib_path(path: str | None) -> bool:
    """Whether a frame's file is part of the interpreter itself."""
    if not path:
        return False
    if path.startswith("<frozen "):
        return True
    return bool(_STDLIB_RE.search(path)) and not any(p in path for p in _THIRD_PARTY)


@dataclass
class _Block:
    """One printed ``Traceback …`` block: frames outermost first, as printed."""

    frames: list[Frame] = field(default_factory=list)
    exc_type: str | None = None
    message: str | None = None


def _frame(match: re.Match[str], raw: str) -> Frame:
    path = match.group(1)
    function = (match.group(3) or "").strip() or None
    return make_frame(
        index=0,
        raw=raw,
        function=function,
        path=path,
        line=int(match.group(2)),
        is_runtime=is_stdlib_path(path),
    )


def _is_indented_body(text: str, indent: str) -> bool:
    """A source line, caret line or "[Previous line repeated N more times]" of a frame."""
    return (
        bool(text.strip())
        and text.startswith(indent)
        and text[len(indent) : len(indent) + 1] in (" ", "\t")
    )


def _read_block(lines: list[Line], header: int, indent: str) -> tuple[_Block, int]:
    """Read frames and the exception line after ``header``; return the block and last index."""
    block, last = _Block(), header
    for i in range(header + 1, len(lines)):
        text = lines[i].text
        if match := _FILE_RE.match(text):
            block.frames.append(_frame(match, text))
            last = i
        elif not _is_indented_body(text, indent):
            body = text[len(indent) :] if text.startswith(indent) else ""
            exc = _EXCEPTION_RE.match(body)
            if exc and block.frames:
                block.exc_type, last = exc.group(1), i
                block.message = (exc.group(2) or "").strip() or None
            break
    return block, last


def _chained_header(lines: list[Line], after: int, indent: str) -> tuple[str, int] | None:
    """After an exception line, find ``marker`` + next ``Traceback`` header: (relation, index)."""
    relation = None
    for j in range(after + 1, min(after + 1 + _MAX_CHAIN_GAP, len(lines))):
        text = lines[j].text
        stripped = text.strip()
        if not stripped:
            continue
        if relation is None:
            relation = _CHAIN_MARKERS.get(stripped)
            if relation is None:
                return None
        elif (match := _HEADER_RE.match(text)) and match.group(1) == indent:
            return relation, j
        else:
            return None
    return None


def _innermost_first(frames: list[Frame]) -> tuple[Frame, ...]:
    ordered = reversed(frames)
    return tuple(f.model_copy(update={"index": i}) for i, f in enumerate(ordered))


def _build(blocks: list[_Block], relations: list[str], start: int, end: int) -> ParsedTrace:
    final = blocks[-1]
    others = tuple(
        Stack(label=f"{rel}: {block.exc_type or 'unknown'}", frames=_innermost_first(block.frames))
        for block, rel in zip(blocks[:-1], relations, strict=True)
    )
    data = TraceData(
        format="python",
        bug_type=final.exc_type,
        message=final.message,
        frames=_innermost_first(final.frames),
        other_stacks=others,
    )
    return ParsedTrace(start=start, end=end, data=data)


def _read_chain(lines: list[Line], header: int, indent: str) -> tuple[ParsedTrace, int]:
    block, last = _read_block(lines, header, indent)
    blocks, relations = [block], []
    while block.exc_type and (chained := _chained_header(lines, last, indent)):
        block, block_last = _read_block(lines, chained[1], indent)
        if not block.frames:  # cut off right after the next header: end at the last full one
            break
        blocks.append(block)
        relations.append(chained[0])
        last = block_last
    return _build(blocks, relations, lines[header].start, lines[last].end), last


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        match = _HEADER_RE.match(lines[i].text)
        if match is None:
            i += 1
            continue
        trace, last = _read_chain(lines, i, match.group(1))
        if trace.data.frames:
            found.append(trace)
        i = last + 1
    return found


@register
class PythonTracebackParser:
    """CPython tracebacks."""

    format: TraceFormat = "python"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
