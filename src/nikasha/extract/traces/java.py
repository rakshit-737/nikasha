# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Java (JVM) stack traces (SPEC §9.5).

::

    Exception in thread "main" CausedBy$StorageException: bad port setting
            at CausedBy.readPort(CausedBy.java:19)
            at CausedBy.main(CausedBy.java:28)
    Caused by: java.lang.NumberFormatException: For input string: "80x"
            at java.base/java.lang.Integer.parseInt(Integer.java:565)
            at CausedBy.parsePort(CausedBy.java:12)
            ... 3 more

The header is ``Exception in thread "name" Type: message`` or a bare ``Type: message``
(``printStackTrace()``) directly followed by an ``at`` line. ``Caused by:`` and ``Suppressed:``
sections become ``other_stacks`` labelled ``caused by: <Type>`` / ``suppressed: <Type>``;
their ``... N more`` lines (frames shared with the enclosing trace) are kept in the span but
not re-expanded, so each stack holds exactly the frames printed for it.

Frames: ``function`` is ``Class.method``; ``module`` is the JPMS module (``java.base``);
``path`` is the source file placed under its package directory (``java/lang/Integer.java``,
or just ``CausedBy.java`` in the default package), which is what a source tree's path suffix
looks like. ``(Native Method)`` and ``(Unknown Source)`` frames have no path. Frames in
``java.*``, ``jdk.*``, ``sun.*`` and ``com.sun.*`` (or a ``java.*``/``jdk.*`` module) are
runtime frames.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nikasha.extract.traces.common import (
    Line,
    ParsedTrace,
    make_frame,
    parse_int,
    register,
    run_guarded,
    split_lines,
)
from nikasha.model.claims import Frame, Stack, TraceData, TraceFormat

_THREAD_HEADER_RE = re.compile(r"^Exception in thread \"([^\"\n]{0,256}+)\" ([^\n]{1,4000}+)$")
_TYPE_RE = re.compile(r"^[A-Za-z_$][\w$]{0,200}+(?:\.[A-Za-z_$][\w$]{0,200}+){0,40}+$")
_FRAME_RE = re.compile(r"^[ \t]{1,32}+at ([^\s()]{1,2000}+)\(([^()\n]{0,1000}+)\)[ \t]*+$")
_MORE_RE = re.compile(r"^[ \t]{1,32}+\.\.\. \d{1,9} more[ \t]*+$")
_NESTED_RE = re.compile(r"^([ \t]{0,32}+)(Caused by|Suppressed): ([^\n]{1,4000}+)$")
_MODULE_RE = re.compile(r"^[A-Za-z_][\w.]{0,200}+(?:@[\w.+-]{1,64}+)?$")
_RUNTIME_PACKAGES = ("java.", "jdk.", "sun.", "com.sun.")
_THROWABLE_SUFFIXES = ("Exception", "Error", "Throwable")
_RUNTIME_MODULES = ("java.", "jdk.")
#: ``loader/module@version/Class.method`` has at most three ``/``-separated parts.
_LOADER_PARTS = 3


def split_header(text: str) -> tuple[str, str | None] | None:
    """``Type: message`` → (type, message); ``None`` if the type is not a class name."""
    exc_type, sep, message = text.partition(": ")
    exc_type = exc_type.strip()
    if not sep and exc_type.endswith(":"):
        exc_type = exc_type[:-1]
    if not _TYPE_RE.match(exc_type):
        return None
    return exc_type, message.strip() or None


def _split_qualified(qualified: str) -> tuple[str | None, str]:
    """``java.base/java.lang.Integer.parseInt`` → (``java.base``, ``java.lang.Integer.parseInt``).

    Also handles ``app//com.x.Y.m`` (class-loader name, unnamed module).
    """
    parts = qualified.split("/")
    if len(parts) >= _LOADER_PARTS and parts[1] == "":
        return None, "/".join(parts[2:])
    if len(parts) >= _LOADER_PARTS - 1 and _MODULE_RE.match(parts[0]) and "$" not in parts[0]:
        return parts[0].split("@", 1)[0], "/".join(parts[1:])
    return None, qualified


def _source_path(class_name: str, source: str) -> tuple[str | None, int | None]:
    """``(Integer.java:565)`` of ``java.lang.Integer`` → (``java/lang/Integer.java``, 565)."""
    file_name, _, line = source.partition(":")
    file_name = file_name.strip()
    if not file_name or " " in file_name:  # "Native Method", "Unknown Source"
        return None, None
    package = class_name.rpartition(".")[0]
    path = f"{package.replace('.', '/')}/{file_name}" if package else file_name
    return path, parse_int(line.strip())


def parse_frame(text: str, index: int) -> Frame | None:
    """Parse ``\\tat [module/]pkg.Class.method(File.java:N)``."""
    match = _FRAME_RE.match(text)
    if match is None:
        return None
    module, name = _split_qualified(match.group(1))
    class_name, _, method = name.rpartition(".")
    if not class_name:
        return None
    path, line = _source_path(class_name, match.group(2))
    runtime = name.startswith(_RUNTIME_PACKAGES) or bool(
        module and module.startswith(_RUNTIME_MODULES)
    )
    return make_frame(
        index=index,
        raw=text,
        function=f"{class_name.rpartition('.')[2]}.{method}",
        path=path,
        line=line,
        module=module,
        is_runtime=runtime,
    )


@dataclass
class _Section:
    """One exception in the trace: the header's, or a ``Caused by:``/``Suppressed:`` one."""

    label: str | None
    exc_type: str
    message: str | None
    frames: list[Frame] = field(default_factory=list)


def _scan(lines: list[Line], first: int, sections: list[_Section]) -> int:
    """Read frames, ``... N more`` and nested sections after the header; return last index."""
    last = first
    for i in range(first + 1, len(lines)):
        text = lines[i].text
        current = sections[-1]
        if (frame := parse_frame(text, len(current.frames))) is not None:
            current.frames.append(frame)
        elif _MORE_RE.match(text):
            pass
        elif (nested := _NESTED_RE.match(text)) and (head := split_header(nested.group(3))):
            sections.append(_Section(nested.group(2).lower(), head[0], head[1]))
        else:
            break
        last = i
    return last


def _header_at(lines: list[Line], i: int) -> tuple[_Section, str | None] | None:
    """The trace header on line ``i`` (thread form, or bare form followed by a frame)."""
    text = lines[i].text
    if match := _THREAD_HEADER_RE.match(text):
        head = split_header(match.group(2))
        return (_Section(None, head[0], head[1]), match.group(1)) if head else None
    if i + 1 < len(lines) and parse_frame(lines[i + 1].text, 0) is not None:
        head = split_header(text)
        if head and ("." in head[0] or "$" in head[0] or head[0].endswith(_THROWABLE_SUFFIXES)):
            return _Section(None, head[0], head[1]), None
    return None


def _build(
    lines: list[Line], first: int, last: int, sections: list[_Section], thread: str | None
) -> ParsedTrace:
    main = sections[0]
    others = tuple(
        Stack(label=f"{s.label}: {s.exc_type}", frames=tuple(s.frames)) for s in sections[1:]
    )
    data = TraceData(
        format="java",
        bug_type=main.exc_type,
        message=main.message,
        frames=tuple(main.frames),
        other_stacks=others,
        thread=thread,
    )
    return ParsedTrace(start=lines[first].start, end=lines[last].end, data=data)


def _parse(text: str) -> list[ParsedTrace]:
    lines = split_lines(text)
    found: list[ParsedTrace] = []
    i = 0
    while i < len(lines):
        header = _header_at(lines, i)
        if header is None:
            i += 1
            continue
        sections = [header[0]]
        last = _scan(lines, i, sections)
        found.append(_build(lines, i, last, sections, header[1]))
        i = last + 1
    return found


@register
class JavaParser:
    """JVM exception stack traces."""

    format: TraceFormat = "java"

    def parse(self, text: str) -> list[ParsedTrace]:
        return run_guarded(_parse, text)
