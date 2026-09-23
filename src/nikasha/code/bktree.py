# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""A BK-tree over symbol names for "did you mean" suggestions (SPEC §11.4).

A report that names ``hdr_parse_lines`` when the code has ``hdr_parse_line`` deserves a
suggestion, not just "symbol not found". The tree indexes **lowercased** names under the
Levenshtein metric (``rapidfuzz.distance.Levenshtein.distance`` is the only borrowed piece);
the triangle inequality lets :meth:`BKTree.search` skip every subtree whose edge label ``e``
satisfies ``|e - d| > radius``, where ``d`` is the query's distance to the subtree's root.

Words that are equal after lowercasing share one node, which keeps each distinct original
spelling, so duplicates never create zero-length edges.

Complexity (``n`` distinct lowercased words, ``L`` the longest word, ``h`` the tree height,
one distance costs ``O(L · ⌈L/64⌉)`` with rapidfuzz's bit-parallel algorithm):

* :meth:`BKTree.add`: ``O(h)`` distance computations; ``h`` is ``O(log n)`` for typical
  symbol sets and ``O(n)`` in the worst case;
* :meth:`BKTree.search`: at most ``n`` distance computations; for the small radii used here
  it visits a small fraction of the tree in practice;
* :meth:`BKTree.suggest`: one search plus ``O(m log m)`` ranking of the ``m`` hits.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from rapidfuzz.distance import Levenshtein

__all__ = ["BKTree", "name_parts", "token_jaccard"]

#: One snake/camel part: an acronym before a capitalised word (``HTTP`` in ``HTTPHeader``),
#: a capitalised or lower-case word, a bare acronym, or a digit run. Bounded quantifiers keep
#: every match attempt O(1), so a scan is linear; a run longer than 64 characters splits.
_PART_RE = re.compile(r"[A-Z]{1,64}(?=[A-Z][a-z])|[A-Z]?[a-z]{1,64}|[A-Z]{1,64}|[0-9]{1,64}")


def name_parts(name: str) -> frozenset[str]:
    """The lowercased snake_case/camelCase parts of *name*.

    ``hdr_decode_chunked_value`` → ``{hdr, decode, chunked, value}``;
    ``readHTTPHeader`` → ``{read, http, header}``. ``O(len(name))``.
    """
    return frozenset(match.group().lower() for match in _PART_RE.finditer(name))


def token_jaccard(a: str, b: str) -> float:
    """Jaccard similarity of the :func:`name_parts` of two names (0.0 when both are empty)."""
    left, right = name_parts(a), name_parts(b)
    union = left | right
    return len(left & right) / len(union) if union else 0.0


class _Node:
    """A lowercased key, its original spellings, and children keyed by edge distance."""

    __slots__ = ("children", "key", "originals")

    def __init__(self, key: str, original: str) -> None:
        self.key = key
        self.originals: list[str] = [original]
        self.children: dict[int, _Node] = {}


class BKTree:
    """A Burkhard-Keller tree of symbol names under case-insensitive Levenshtein distance."""

    __slots__ = ("_root", "_size")

    def __init__(self, words: Iterable[str] = ()) -> None:
        self._root: _Node | None = None
        self._size = 0
        for word in words:
            self.add(word)

    def __len__(self) -> int:
        """The number of distinct original spellings stored."""
        return self._size

    def add(self, word: str) -> None:
        """Insert *word*; an exact duplicate is ignored. ``O(h)`` distances."""
        key = word.lower()
        if self._root is None:
            self._root = _Node(key, word)
            self._size = 1
            return
        node = self._root
        while True:
            distance = Levenshtein.distance(key, node.key)
            if distance == 0:
                if word not in node.originals:
                    node.originals.append(word)
                    self._size += 1
                return
            child = node.children.get(distance)
            if child is None:
                node.children[distance] = _Node(key, word)
                self._size += 1
                return
            node = child

    def search(self, query: str, radius: int) -> list[tuple[int, str]]:
        """Every stored word within *radius* of *query*, as ``(distance, original)``.

        Sorted by distance, then word. A negative radius finds nothing. Iterative, so deep
        (degenerate) trees cannot overflow the stack.
        """
        if self._root is None or radius < 0:
            return []
        key = query.lower()
        hits: list[tuple[int, str]] = []
        stack = [self._root]
        while stack:
            node = stack.pop()
            distance = Levenshtein.distance(key, node.key)
            if distance <= radius:
                hits.extend((distance, original) for original in node.originals)
            low, high = distance - radius, distance + radius
            stack.extend(child for edge, child in node.children.items() if low <= edge <= high)
        hits.sort()
        return hits

    def suggest(self, query: str, k: int = 3) -> list[str]:
        """Up to *k* "did you mean" names for *query*, best first.

        The radius is ``max(1, len(query) // 4)``. Hits rank by
        ``(distance, -token_jaccard, word)``, so ties on edit distance prefer names sharing
        more snake/camel parts, and the final tie-break on the word makes the order
        deterministic. A case-insensitively equal name (distance 0) is a valid suggestion.
        """
        if k <= 0:
            return []
        radius = max(1, len(query) // 4)
        ranked = sorted(
            self.search(query, radius),
            key=lambda hit: (hit[0], -token_jaccard(query, hit[1]), hit[1]),
        )
        return [word for _, word in ranked[:k]]
