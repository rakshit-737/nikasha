# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared machinery for the trace parsers (SPEC §9.5).

Each format lives in its own module and registers a :class:`TraceParser`. Parsers are
permissive: unknown lines are skipped, never fatal, and every regex must run in linear time
(no nested or ambiguous quantifiers over overlapping character classes).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from typing import NamedTuple, Protocol

from nikasha.model.base import Model
from nikasha.model.claims import Frame, TraceData, TraceFormat

#: Hard cap on the text handed to a single parser (defence against resource exhaustion).
MAX_TRACE_TEXT = 1_000_000

#: Function-name prefixes that belong to sanitizer or libc runtimes, not the application.
RUNTIME_FUNCTION_PREFIXES: tuple[str, ...] = (
    "__interceptor_",
    "___interceptor_",
    "__asan_",
    "__asan::",
    "__sanitizer_",
    "__sanitizer::",
    "__ubsan_",
    "__ubsan::",
    "__lsan_",
    "__lsan::",
    "__msan_",
    "__msan::",
    "__tsan_",
    "__tsan::",
    "__interception::",
)

#: Exact function names that are runtime frames. ``main`` is deliberately *not* here.
RUNTIME_FUNCTIONS: frozenset[str] = frozenset(
    {
        "__libc_start_main",
        "__libc_start_call_main",
        "__libc_start_main_impl",
        "_start",
        "start_thread",
        "clone",
        "clone3",
        "__clone",
        "__clone3",
        "__GI___clone",
        "__GI___clone3",
        "abort",
        "raise",
        "__GI_raise",
        "__GI_abort",
        "__pthread_kill_implementation",
        "__pthread_kill_internal",
        "pthread_kill",
        "__restore_rt",
    }
)

#: Substrings of module or file paths that mark runtime libraries.
RUNTIME_MODULE_MARKERS: tuple[str, ...] = (
    "libc.so",
    "libc-",
    "libstdc++",
    "libc++",
    "libpthread",
    "ld-linux",
    "ld-musl",
    "libasan",
    "libubsan",
    "liblsan",
    "libtsan",
    "libmsan",
    "libclang_rt",
    "compiler-rt/lib/",
    "vg_replace_malloc",
    "vg_replace_strmem",
    "vgpreload_",
)

#: libc and allocator entry points. Sanitizers intercept them inside the binary itself and
#: valgrind replaces them from its preload, so no libc path gives them away: the name does.
LIBC_FUNCTIONS: frozenset[str] = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "reallocarray",
        "free",
        "cfree",
        "aligned_alloc",
        "posix_memalign",
        "memalign",
        "valloc",
        "pvalloc",
        "strdup",
        "strndup",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "memchr",
        "strlen",
        "strnlen",
        "strcpy",
        "strncpy",
        "stpcpy",
        "strcat",
        "strncat",
        "strcmp",
        "strncmp",
        "strchr",
        "strrchr",
        "strstr",
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "vprintf",
        "vfprintf",
        "vsprintf",
        "vsnprintf",
        "puts",
        "fputs",
        "fwrite",
        "fread",
        "malloc_printerr",
        # pthread entry points: TSan intercepts them inside the binary (real output prints
        # ``#0 pthread_mutex_lock <null> (pigz+0x…)``), so only the name gives them away.
        "pthread_create",
        "pthread_join",
        "pthread_detach",
        "pthread_mutex_init",
        "pthread_mutex_destroy",
        "pthread_mutex_lock",
        "pthread_mutex_trylock",
        "pthread_mutex_unlock",
        "pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock",
        "pthread_rwlock_unlock",
        "pthread_cond_wait",
        "pthread_cond_timedwait",
        "pthread_cond_signal",
        "pthread_cond_broadcast",
        "pthread_spin_lock",
        "pthread_spin_unlock",
    }
)

#: Prefixes of glibc-internal and C++-runtime symbols. gdb and valgrind print these with bare
#: source file names (``malloc.c``), so the path markers above cannot catch them.
LIBC_INTERNAL_PREFIXES: tuple[str, ...] = (
    "__GI_",
    "_IO_",
    "__libc_",
    "__printf",
    "__vfprintf",
    "__vfwprintf",
    "__assert",
    "__pthread_",
    "_int_",
    "__memmove_",
    "__memcpy_",
    "__memset_",
    "__strlen_",
    "__strcpy_",
    "__strcmp_",
    "__memcmp_",
    "__strchr_",
    "__nss_",
    "_dl_",
    "operator new",
    "operator delete",
)

_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
_DOUBLE_SLASH_RE = re.compile(r"/{2,}")


def normalize_path(raw: str | None) -> str | None:
    """Normalize a path from a trace for suffix matching (SPEC §9.5).

    Backslashes become slashes; drive letters, ``/proc/self/cwd/``, and leading ``./`` are
    stripped; ``/./`` and repeated slashes are collapsed. Build roots cannot be known
    without the repository, so they are kept: PathTrie resolves them by suffix (M2).
    """
    if raw is None:
        return None
    path = raw.strip().replace("\\", "/")
    if not path:
        return None
    if _DRIVE_RE.match(path):
        path = path[2:]
    path = _DOUBLE_SLASH_RE.sub("/", path)
    while "/./" in path:
        path = path.replace("/./", "/")
    path = path.removeprefix("/proc/self/cwd/")
    while path.startswith("./"):
        path = path[2:]
    return path or None


def is_runtime_frame(
    function: str | None,
    path: str | None,
    module: str | None,
    *,
    extra_prefixes: Iterable[str] = (),
) -> bool:
    """Return whether a frame belongs to a runtime (sanitizer, libc, loader, VM)."""
    if function:
        if function in RUNTIME_FUNCTIONS:
            return True
        prefixes = RUNTIME_FUNCTION_PREFIXES + tuple(extra_prefixes)
        if function.startswith(prefixes):
            return True
    for location in (path, module):
        if location and any(marker in location for marker in RUNTIME_MODULE_MARKERS):
            return True
    return False


def is_native_runtime_frame(function: str | None, path: str | None, module: str | None) -> bool:
    """:func:`is_runtime_frame` plus libc entry points and glibc internals (native traces).

    A libc *name* alone marks a frame as runtime only when the frame has no path or a bare
    file name (``malloc.c``, as gdb prints glibc sources); a project that defines its own
    ``strdup`` in ``src/str.c`` keeps that frame as an application frame.
    """
    if function in LIBC_FUNCTIONS and (path is None or "/" not in path or "/glibc" in path):
        return True
    return is_runtime_frame(function, path, module, extra_prefixes=LIBC_INTERNAL_PREFIXES)


def make_frame(
    *,
    index: int,
    raw: str,
    function: str | None = None,
    path: str | None = None,
    line: int | None = None,
    col: int | None = None,
    module: str | None = None,
    is_runtime: bool | None = None,
) -> Frame:
    """Build a :class:`Frame`, normalizing the path and classifying runtime frames."""
    normalized = normalize_path(path)
    runtime = is_runtime_frame(function, normalized, module) if is_runtime is None else is_runtime
    return Frame(
        index=index,
        function=function or None,
        path=normalized,
        original_path=path if path and path != normalized else None,
        line=line,
        col=col,
        module=module or None,
        is_runtime=runtime,
        raw=raw.rstrip("\r\n"),
    )


def parse_hex(text: str) -> int:
    """Parse ``0x…`` (or bare hex) into an int."""
    return int(text, 16)


#: Longest digit run :func:`parse_int` accepts (keeps ``int()`` far from its digit limit).
_MAX_INT_DIGITS = 18


def parse_int(text: str) -> int | None:
    """Parse a short run of ASCII digits, or return ``None`` (``"²"`` is a digit to ``str``)."""
    if 0 < len(text) <= _MAX_INT_DIGITS and text.isascii() and text.isdigit():
        return int(text)
    return None


def split_location(text: str) -> tuple[str, int, int | None] | None:
    """Split ``path:line[:col]`` into its parts, or return ``None`` if it is not one.

    Only the last two ``:``-separated fields are inspected, so drive letters and colons
    inside the path survive: ``C:\\src\\a.c:12`` → ``("C:\\src\\a.c", 12, None)``.
    """
    head, sep, last = text.rpartition(":")
    last_num = parse_int(last) if sep else None
    if last_num is None or not head:
        return None
    path, sep2, mid = head.rpartition(":")
    mid_num = parse_int(mid) if sep2 else None
    if mid_num is not None and path:
        return path, mid_num, last_num
    return head, last_num, None


class ParsedTrace(Model):
    """One trace found in a text: offsets ``[start, end)`` relative to that text."""

    start: int
    end: int
    data: TraceData


class TraceParser(Protocol):
    """A parser for one trace format."""

    format: TraceFormat

    def parse(self, text: str) -> list[ParsedTrace]:
        """Return every trace of this format in ``text`` (empty if none). Never raises on
        malformed input."""
        ...


PARSERS: dict[str, TraceParser] = {}


def register(parser_factory: Callable[[], TraceParser]) -> Callable[[], TraceParser]:
    """Class decorator: instantiate and register a parser under its ``format``."""
    parser = parser_factory()
    if parser.format in PARSERS:
        raise ValueError(f"duplicate trace parser for {parser.format!r}")
    PARSERS[parser.format] = parser
    return parser_factory


def run_guarded(parse: Callable[[str], list[ParsedTrace]], text: str) -> list[ParsedTrace]:
    """Run a parser body on at most :data:`MAX_TRACE_TEXT` characters, never raising.

    Parsers are written not to fail; this is the backstop that keeps the "never raises on
    malformed input" contract even if one does (``ValidationError`` is a ``ValueError``).
    """
    try:
        return parse(text[:MAX_TRACE_TEXT])
    except (ValueError, IndexError, OverflowError):
        return []


class Line(NamedTuple):
    """One line of a text: ``text[start:end]`` is its content, without ``\\r\\n``."""

    start: int
    end: int
    text: str


def split_lines(text: str) -> list[Line]:
    """Split on ``\\n`` only (unlike :meth:`str.splitlines`), keeping exact offsets."""
    lines: list[Line] = []
    pos = 0
    for raw in text.split("\n"):
        content = raw.removesuffix("\r")
        lines.append(Line(pos, pos + len(content), content))
        pos += len(raw) + 1
    return lines


def line_offsets(text: str) -> list[int]:
    """Return the start offset of every line in ``text`` (plus ``len(text)`` at the end)."""
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)
    if offsets[-1] != len(text):
        offsets.append(len(text))
    return offsets
