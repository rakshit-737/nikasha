# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Reading the source lines an evidence card shows (SPEC §15.2).

Excerpts are fetched at render time rather than stored on the evidence, for two reasons.
They are *derived* data — ``(commit, path, lines)`` determines them completely — so putting
them in the evidence would make an identifier depend on presentation. And a report carrying
every excerpt inline would repeat the same function body once per finding about it.

The provider is a plain callable, so a caller with no repository (rendering a saved
``RESULT.json``) passes ``None`` and the cards render without code.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager

from nikasha.code.gitio import GitRepo
from nikasha.model.evidence import CodeLocation
from nikasha.render.html.context import EXCERPT_CONTEXT, ExcerptProvider
from nikasha.resolve.repo import open_repo

#: Never read more than this from one blob; a generated file can be enormous.
MAX_BLOB_BYTES = 2 * 1024 * 1024

#: Never render more than this many lines in one card.
MAX_LINES = 60


def lines_around(
    source: str, start: int, end: int, *, context: int = EXCERPT_CONTEXT
) -> Sequence[tuple[int, str]]:
    """Numbered lines covering ``start``..``end`` with ``context`` lines either side."""
    lines = source.splitlines()
    low, high = min(start, end), max(start, end)
    if not lines or low > len(lines):
        # A range past the end of the file is a stale or wrong location. Showing the file's
        # tail instead would put unrelated code under a "lines X to Y" caption (P6).
        return []
    first = max(1, low - context)
    last = min(len(lines), high + context)
    if last - first + 1 > MAX_LINES:
        last = first + MAX_LINES - 1
    return [(n, lines[n - 1]) for n in range(first, last + 1)]


def provider_for(repo: GitRepo, *, context: int = EXCERPT_CONTEXT) -> ExcerptProvider:
    """An :data:`ExcerptProvider` reading blobs from an already-open repository."""

    def provide(location: CodeLocation) -> Sequence[tuple[int, str]] | None:
        blob = repo.read_file(location.commit, location.path)
        if blob is None or len(blob) > MAX_BLOB_BYTES:
            return None
        return lines_around(
            blob.decode("utf-8", "replace"),
            location.start_line,
            location.end_line,
            context=context,
        )

    return provide


@contextmanager
def repo_excerpts(repo_url: str, *, online: bool = False) -> Iterator[ExcerptProvider]:
    """Open the cached clone of ``repo_url`` just long enough to render a report."""
    repo = open_repo(repo_url, online=online)
    with repo:
        yield provider_for(repo)


__all__ = ["MAX_BLOB_BYTES", "MAX_LINES", "lines_around", "provider_for", "repo_excerpts"]
