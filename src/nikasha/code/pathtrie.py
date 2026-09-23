# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Resolve a reported path to repository files by longest component suffix (SPEC §11.4).

Reports cite paths from somebody else's machine: ``/src/curl/lib/http.c``,
``C:\\build\\libhdr\\src\\util.c``, ``../../lib/http.c``. The repository only knows
``lib/http.c``. A :class:`PathTrie` stores every repository path with its components
**reversed** (``http.c`` → ``lib``), so the files sharing the longest suffix of *whole*
components with a query are exactly the files under the deepest trie node the reversed query
reaches.

Complexity (``C`` = total components over all repository paths, ``q`` = components in the
query, ``r`` = number of results):

* build: ``O(C)`` time and space. Every node keeps the list of paths passing through it,
  which is one entry per component, so the space bound is unchanged;
* :meth:`PathTrie.resolve`: ``O(q + r log r)`` (the walk, then sorting the result; a node's
  list is sorted once and cached until the next :meth:`PathTrie.add` touches it);
* :meth:`PathTrie.match_depth`: ``O(q)``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence

__all__ = ["PathTrie", "normalize_components"]

#: A Windows drive prefix (``C:``), matched only at the start. Fixed width, so linear.
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def normalize_components(path: str) -> tuple[str, ...]:
    """Split *path* into clean components, resolving ``.`` and ``..`` lexically.

    Backslashes count as separators, a leading drive letter is dropped, empty and ``.``
    components vanish, and ``..`` removes the previous component (or nothing at the root).
    The result is relative: ``/a/b`` and ``a/b`` give the same components. ``O(len(path))``.
    """
    text = _DRIVE_RE.sub("", path.replace("\\", "/"), count=1)
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return tuple(parts)


class _Node:
    """One trie node: children by component, and every path whose suffix reaches it."""

    __slots__ = ("children", "is_sorted", "paths")

    def __init__(self) -> None:
        self.children: dict[str, _Node] = {}
        self.paths: list[str] = []
        self.is_sorted = True

    def sorted_paths(self) -> list[str]:
        if not self.is_sorted:
            self.paths.sort()
            self.is_sorted = True
        return list(self.paths)


class PathTrie:
    """A trie over reversed path components, built from a repository's file list.

    Paths are stored in normalized POSIX form (see :func:`normalize_components`); adding the
    same path twice is a no-op.
    """

    __slots__ = ("_known", "_root")

    def __init__(self, paths: Iterable[str] = ()) -> None:
        self._root = _Node()
        self._known: set[str] = set()
        for path in paths:
            self.add(path)

    def __len__(self) -> int:
        return len(self._known)

    def __contains__(self, path: object) -> bool:
        return isinstance(path, str) and "/".join(normalize_components(path)) in self._known

    def add(self, path: str) -> None:
        """Insert one repository path. ``O(components)``."""
        parts = normalize_components(path)
        clean = "/".join(parts)
        if not parts or clean in self._known:
            return
        self._known.add(clean)
        node = self._root
        for part in reversed(parts):
            node = node.children.setdefault(part, _Node())
            node.paths.append(clean)
            node.is_sorted = False

    def _deepest(self, path: str) -> tuple[_Node, int]:
        node, depth = self._root, 0
        for part in reversed(normalize_components(path)):
            child = node.children.get(part)
            if child is None:
                break
            node, depth = child, depth + 1
        return node, depth

    def match_depth(self, path: str) -> int:
        """How many trailing components of *path* some repository path shares. ``O(q)``."""
        return self._deepest(path)[1]

    def resolve(self, path: str) -> list[str]:
        """Every repository path sharing the longest whole-component suffix with *path*.

        Sorted. ``[]`` when not even the basename matches. ``O(q + r log r)``.
        """
        node, depth = self._deepest(path)
        return node.sorted_paths() if depth else []

    def disambiguate(
        self,
        path: str,
        candidates: Sequence[str] | None,
        defines: Callable[[str], bool],
    ) -> list[str]:
        """Narrow an ambiguous resolution with a predicate such as "defines the frame's function".

        *candidates* defaults to :meth:`resolve` of *path* when ``None``. Returns the sorted
        candidates for which *defines* holds; when none does, all candidates, so a failed
        tie-break never loses the file. ``O(r)`` calls to *defines*.
        """
        pool = sorted(set(self.resolve(path) if candidates is None else candidates))
        chosen = [candidate for candidate in pool if defines(candidate)]
        return chosen or pool
