# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""SQLite amalgamation line mapping (SPEC §11.5 SHOULD).

Reports against SQLite often cite ``sqlite3.c:<line>``: the amalgamation shipped in the
release zip, which is not in git. SQLite's ``tool/mksqlite3c.tcl`` marks every inlined file
with banners (verified against the real 3.45.1 amalgamation, see
``tests/integration/test_sqlite_amalgamation.py``)::

    /************** Include msvc.h in the middle of sqliteInt.h ******************/
    /************** Begin file msvc.h ********************************************/
    ...
    /************** End of msvc.h ************************************************/
    /************** Continuing where we left off in sqliteInt.h ******************/

The ``Include`` banner *replaces* the ``#include`` line of the parent, so it consumes one
source line of the parent; the other banners consume none. Banners always have exactly 14
leading stars: the 8-star ``Begin file sqlite3rtree.h`` markers inside the generated
``sqlite3.h`` and the closing ``End of sqlite3.c`` line are deliberately not recognised, so
those lines stay attributed to ``sqlite3.h`` (itself generated, so never judged).

Mapping is pure and offline. Fetching the zip is **online only** (P3): nothing is requested
unless the caller passes ``online=True``. The zip is cached under ``<cache>/amalgamation``,
and only the single member ``sqlite-amalgamation-<code>/sqlite3.c`` is read, with a size cap.
"""

from __future__ import annotations

import io
import re
import zipfile
from bisect import bisect_right
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from nikasha.config import cache_dir
from nikasha.errors import NikashaError

# Names in banners are plain file names (``os_unix.c``, ``fts5.h``); bounded, anchored and
# star runs capped, so each pattern is linear-time.
_NAME = r"([A-Za-z0-9_.+-]{1,200})"
_TAIL = r" \*{0,200}/$"
BEGIN_RE = re.compile(r"^/\*{14} Begin file " + _NAME + _TAIL)
END_RE = re.compile(r"^/\*{14} End of " + _NAME + _TAIL)
CONTINUE_RE = re.compile(r"^/\*{14} Continuing where we left off in " + _NAME + _TAIL)
INCLUDE_RE = re.compile(r"^/\*{14} Include " + _NAME + " in the middle of " + _NAME + _TAIL)

AMALGAMATION_BASE = "https://www.sqlite.org"
MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_SQLITE3_C_BYTES = 64 * 1024 * 1024
_YEARS = (2000, 2100)
_VERSION_RE = re.compile(r"^(?:version-)?(3)\.(\d{1,2})\.(\d{1,2})(?:\.(\d{1,2}))?$")


@dataclass(frozen=True, slots=True)
class MappedLine:
    """``amal_line`` of the amalgamation is ``line`` of the source file ``file``."""

    amal_line: int
    file: str
    line: int


@dataclass(frozen=True, slots=True)
class _Segment:
    amal_start: int  # first amalgamation line of the run (1-based)
    file: str
    src_start: int  # the source line that ``amal_start`` shows


@dataclass(slots=True)
class _Open:
    name: str
    next_line: int = 1


class AmalgamationMap:
    """Maps amalgamation line numbers back to ``(file, line)`` of the inlined sources."""

    def __init__(self, segments: Sequence[_Segment], n_lines: int, files: Sequence[str]) -> None:
        self._segments = tuple(segments)
        self._starts = [s.amal_start for s in self._segments]
        self.n_lines = n_lines
        #: Every file named by a ``Begin file`` banner, in order of first appearance.
        self.files = tuple(files)

    @classmethod
    def from_text(cls, text: str) -> AmalgamationMap:
        segments: list[_Segment] = []
        files: list[str] = []
        # The open files, innermost last. The preamble (licence text before the first
        # banner) belongs to no file.
        stack: list[_Open] = []

        def resume(at: int) -> None:
            top = stack[-1] if stack else None
            segments.append(_Segment(at, top.name, top.next_line) if top else _Segment(at, "", 0))

        n = 0
        # Split on newlines only: str.splitlines() also breaks on form feeds and other
        # separators, which would shift every later line number.
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        for n, raw in enumerate(lines, start=1):
            line = raw.removesuffix("\r")
            if line.startswith("/**************"):
                if (m := INCLUDE_RE.match(line)) is not None:
                    if stack and stack[-1].name == m.group(2):
                        stack[-1].next_line += 1  # the banner stands for the #include
                    segments.append(_Segment(n, "", 0))
                    continue
                if (m := BEGIN_RE.match(line)) is not None:
                    if m.group(1) not in files:
                        files.append(m.group(1))
                    stack.append(_Open(m.group(1)))
                    segments.append(_Segment(n, "", 0))
                    resume(n + 1)
                    continue
                if (m := END_RE.match(line)) is not None:
                    if stack and stack[-1].name == m.group(1):
                        stack.pop()
                    segments.append(_Segment(n, "", 0))
                    resume(n + 1)
                    continue
                if CONTINUE_RE.match(line) is not None:
                    segments.append(_Segment(n, "", 0))
                    resume(n + 1)
                    continue
            if stack:
                stack[-1].next_line += 1
        return cls(_dedupe(segments), n, files)

    def lookup(self, amal_line: int) -> MappedLine | None:
        """The source location of ``amal_line``, or ``None`` for a banner, the preamble,
        or a line past the end."""
        if amal_line < 1 or amal_line > self.n_lines:
            return None
        i = bisect_right(self._starts, amal_line) - 1
        if i < 0:
            return None
        seg = self._segments[i]
        if not seg.file:
            return None
        return MappedLine(amal_line, seg.file, seg.src_start + (amal_line - seg.amal_start))


def _dedupe(segments: list[_Segment]) -> list[_Segment]:
    """Keep the last segment for each start line (a banner then its file on the next)."""
    out: list[_Segment] = []
    for seg in segments:
        if out and out[-1].amal_start == seg.amal_start:
            out[-1] = seg
        else:
            out.append(seg)
    return out


def resolve_source(name: str, tree_paths: Iterable[str]) -> str | None:
    """The repo path of banner file ``name`` at a ref: ``src/<name>`` first (the core), else
    the single tree path ending in ``/<name>``. ``None`` when absent or ambiguous; the file
    is then generated (``parse.c``, ``opcodes.c``, ``sqlite3.h``) or unknown."""
    paths = set(tree_paths)
    if f"src/{name}" in paths:
        return f"src/{name}"
    hits = sorted(p for p in paths if p == name or p.endswith(f"/{name}"))
    return hits[0] if len(hits) == 1 else None


# --- fetching (online only) ---------------------------------------------------------------


def version_code(version: str) -> str:
    """``3.45.1`` (or the tag ``version-3.45.1``) to the download code ``3450100``.

    Releases before 3.7.4 used another naming scheme, so they are refused."""
    m = _VERSION_RE.match(version.strip())
    if m is None:
        raise NikashaError(f"not a SQLite 3.x version: {version[:40]!r}")
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    extra = int(m.group(4) or 0)
    if (minor, patch) < (7, 4):
        raise NikashaError(f"SQLite {version[:40]} predates the amalgamation naming scheme")
    return f"{major}{minor:02d}{patch:02d}{extra:02d}"


def amalgamation_url(version: str, year: int) -> str:
    """``https://www.sqlite.org/<year>/sqlite-amalgamation-<code>.zip``."""
    if not _YEARS[0] <= year <= _YEARS[1]:
        raise NikashaError(f"implausible release year {year}")
    return f"{AMALGAMATION_BASE}/{year}/sqlite-amalgamation-{version_code(version)}.zip"


def extract_sqlite3_c(zip_bytes: bytes, code: str) -> str:
    """Read only ``sqlite-amalgamation-<code>/sqlite3.c`` from the zip, capped."""
    member = f"sqlite-amalgamation-{code}/sqlite3.c"
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            info = zf.getinfo(member)
            if info.file_size > MAX_SQLITE3_C_BYTES:
                raise NikashaError(f"{member} is larger than {MAX_SQLITE3_C_BYTES:,} bytes")
            with zf.open(info) as fh:
                data = fh.read(MAX_SQLITE3_C_BYTES + 1)
    except (KeyError, zipfile.BadZipFile, OSError, ValueError) as exc:
        raise NikashaError(f"not a SQLite amalgamation zip ({type(exc).__name__})") from None
    if len(data) > MAX_SQLITE3_C_BYTES:
        raise NikashaError(f"{member} is larger than {MAX_SQLITE3_C_BYTES:,} bytes")
    return data.decode("utf-8", errors="replace")


Fetcher = Callable[[str], bytes]


def _default_fetcher(url: str) -> bytes:
    from nikasha.integrations.h1 import fetch_bytes  # noqa: PLC0415 - CLI-heavy, online only

    body, _headers = fetch_bytes(url, max_bytes=MAX_ZIP_BYTES, service="sqlite.org", timeout=60)
    return body


def load_amalgamation(
    version: str,
    years: Sequence[int],
    *,
    online: bool,
    cache: Path | None = None,
    fetcher: Fetcher | None = None,
) -> AmalgamationMap:
    """The map for ``version``'s official amalgamation.

    A cached ``sqlite3.c`` is used offline. Otherwise, with ``online=True`` only, the zip is
    tried under each of ``years`` (the release year is part of the URL and not derivable
    from the version) and the first one found is cached."""
    code = version_code(version)
    target = None
    if cache is not None:
        target = cache / f"sqlite-amalgamation-{code}" / "sqlite3.c"
        if target.is_file():
            return AmalgamationMap.from_text(target.read_text("utf-8", errors="replace"))
    if not online:
        raise NikashaError(
            "the SQLite amalgamation is only downloaded with --online (nothing was requested)"
        )
    fetch = fetcher or _default_fetcher
    errors: list[str] = []
    for year in years:
        url = amalgamation_url(version, year)
        try:
            body = fetch(url)
        except NikashaError as exc:
            errors.append(str(exc))
            continue
        text = extract_sqlite3_c(body, code)
        if target is not None:
            from nikasha.integrations.h1 import write_private  # noqa: PLC0415

            write_private(target, text)
        return AmalgamationMap.from_text(text)
    raise NikashaError(
        f"no amalgamation found for SQLite {version[:40]}: " + "; ".join(errors[-3:])
    )


def default_cache() -> Path:
    return cache_dir() / "amalgamation"


_LOADED: dict[str, AmalgamationMap] = {}


def cached_amalgamation(
    version: str, years: Sequence[int], *, online: bool, fetcher: Fetcher | None = None
) -> AmalgamationMap:
    """:func:`load_amalgamation` with the default cache, memoised per process (a check sees
    many ``sqlite3.c`` lines of one release). Failures are not memoised."""
    code = version_code(version)
    found = _LOADED.get(code)
    if found is None:
        found = load_amalgamation(
            version, years, online=online, cache=default_cache(), fetcher=fetcher
        )
        _LOADED[code] = found
    return found
