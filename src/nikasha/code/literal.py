# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Literal search (SPEC §11.4): where does this exact text occur at a commit?

The fallback for languages without a parser, and the primary search for command-line
options, quoted lines and endpoints (checks C03, C07, C14). It is a fixed-string
``git grep -n -I -F [-w]`` through :meth:`nikasha.code.gitio.GitRepo.grep`, which batches
tree arguments and never interprets the literal as a pattern or an option.

Results are capped, and the cap is reported (``truncated``), so a check can say "at least N
matches" instead of guessing. Matched lines are clipped to :data:`MAX_TEXT_CHARS`, because
one minified file can put megabytes on a single line. ``command`` is the equivalent git
command, recorded as evidence (P6).
"""

from __future__ import annotations

import shlex
from collections.abc import Sequence
from dataclasses import dataclass

from nikasha.code.gitio import GitRepo, GrepHit

MAX_LITERAL_CHARS = 1000
MAX_TEXT_CHARS = 400
DEFAULT_MAX_HITS = 200


@dataclass(frozen=True, slots=True)
class LiteralResult:
    literal: str
    commit: str
    hits: tuple[GrepHit, ...]
    truncated: bool
    command: str

    @property
    def paths(self) -> tuple[str, ...]:
        """Distinct matching paths, in the order git reported them."""
        return tuple(dict.fromkeys(h.path for h in self.hits))


def searchable(literal: str) -> str | None:
    """The literal as it will be searched, or ``None`` when it cannot be.

    Surrounding whitespace is dropped (indentation in a quote is not evidence). Empty,
    multi-line or over-long literals are refused: the caller picks a line to search.
    """
    text = literal.strip()
    if not text or "\n" in text or "\r" in text or "\0" in text:
        return None
    if len(text) > MAX_LITERAL_CHARS:
        return None
    return text


def literal_search(
    repo: GitRepo,
    literal: str,
    commit: str,
    *,
    pathspecs: Sequence[str] = (),
    word: bool = False,
    max_hits: int = DEFAULT_MAX_HITS,
) -> LiteralResult | None:
    """Search ``commit`` for ``literal``; ``None`` if the literal is not searchable.

    Raises :class:`~nikasha.errors.ExternalToolError` when git cannot finish the search
    (a bad revision, a broken object store, a timeout). That is deliberately not an empty
    result: callers must report the claim as unsearched, never as absent (P4).
    """
    text = searchable(literal)
    if text is None:
        return None
    flags = ["-n", "-I", "-F", *(["-w"] if word else [])]
    command = shlex.join(["git", "grep", *flags, "-e", text, commit, "--", *pathspecs])
    found = repo.grep(text, [commit], pathspecs=pathspecs, word=word, max_hits=max_hits + 1)
    hits = tuple(GrepHit(h.rev, h.path, h.line, h.text[:MAX_TEXT_CHARS]) for h in found[:max_hits])
    return LiteralResult(text, commit, hits, len(found) > max_hits, command)
