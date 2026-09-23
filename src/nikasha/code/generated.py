# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Generated and release-only files (SPEC §11.5; critical for P4).

Genuine reports often cite files that are not in git: amalgamations (SQLite's ``sqlite3.c``),
parser-generator output (``parse.c`` from ``parse.y``), configure-generated headers
(``config.h``), bundled JavaScript. Refuting those would be a false "fabricated". A cited
path counts as generated when it matches a project or generic pattern, **or** when a
template for it exists at the same ref (``X.in``, ``X.cmake``, ``X.in.cmake``,
``X-cmake.h.in`` style, or ``X.y`` for ``X.c``).

A path that is not in the tree may still carry a build root (``/src/lib/parse.c`` in a
trace). For those, globs are also tried against every trailing run of path components, and
templates are located with the caller's suffix resolver (the trace's PathTrie). Both lean
towards "generated, not judged", the conservative direction (P4).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Iterator, Sequence
from dataclasses import dataclass
from functools import cache
from pathlib import PurePosixPath

from nikasha.resolve.products import GeneratedEntry, KnownProject, load_known_projects


@dataclass(frozen=True, slots=True)
class GeneratedMatch:
    path: str
    kind: str
    reason: str
    entry: GeneratedEntry | None = None


@cache
def _glob_regex(glob: str) -> re.Pattern[str]:
    """Translate a path glob (``*`` within a component, ``**`` across components)."""
    out: list[str] = []
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def glob_match(glob: str, path: str) -> bool:
    """Match a repo-relative path; a glob without ``/`` matches the basename (like
    ``.gitignore``), so ``sqlite3.c`` also covers ``bld/sqlite3.c``."""
    target = path.lstrip("/")
    if "/" not in glob:
        target = target.rsplit("/", 1)[-1]
    return _glob_regex(glob).match(target) is not None


_MAX_SUFFIXES = 32


def _suffixes(path: str) -> Iterator[str]:
    """``a/b/c.c``, ``b/c.c``, ``c.c``: the path and its trailing component runs."""
    parts = path.split("/")
    for i in range(min(len(parts), _MAX_SUFFIXES)):
        yield "/".join(parts[i:])


def _template_candidates(path: str) -> list[str]:
    p = PurePosixPath(path)
    candidates = [f"{path}.in", f"{path}.cmake", f"{path}.in.cmake"]
    if p.suffix == ".h":
        candidates.append(str(p.with_name(f"{p.stem}-cmake.h.in")))
    if p.suffix == ".c":
        candidates.append(str(p.with_suffix(".y")))
    return candidates


def generated_match(
    path: str,
    *,
    project: KnownProject | None = None,
    tree_paths: Collection[str] = (),
    resolve: Callable[[str], Sequence[str]] | None = None,
) -> GeneratedMatch | None:
    """Is ``path`` generated or release-only for ``project`` at a ref whose files are
    ``tree_paths``? ``path`` is repo-relative when it was found in the tree; otherwise it may
    carry a build root, and ``resolve`` (a longest-suffix lookup) is used for templates."""
    rel = path.lstrip("/")
    missing = bool(tree_paths) and rel not in tree_paths
    candidates = list(_suffixes(rel)) if missing else [rel]
    entries = (project.generated if project else ()) + load_known_projects().generic_generated
    for entry in entries:
        if any(glob_match(entry.path_glob, c) for c in candidates):
            return GeneratedMatch(rel, entry.kind, f"matches {entry.path_glob!r}", entry)
    if missing:
        for template in _template_candidates(rel):
            if template in tree_paths:
                return GeneratedMatch(rel, "generated", f"built from {template}")
            found = resolve(template) if resolve is not None else ()
            if found:
                return GeneratedMatch(rel, "generated", f"built from {found[0]}")
    return None
