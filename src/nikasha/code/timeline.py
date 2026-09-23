# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Symbol timelines (SPEC §11.4): in which releases is a symbol *defined*?

Two strategies, compared in ADR 0004:

* **full**: index every release tree (blobs parsed once), then answer from SQLite.
* **lazy**: ``git grep -F -w -l <name>`` across all release trees in batches, then parse only
  the matching files to confirm a definition (a mention is not a definition).

When no release defines the symbol, a time-bounded ``git log --all -S`` asks whether the text
ever appeared anywhere in history. **P4 safeguards:** if that search times out, or the
repository is shallow, the timeline is marked *incomplete*, and checks must never claim the
symbol "never existed" (SPEC §12 C03). And a release that mentions the name only in files
that did not parse cleanly is *uncertain*, not absent: tree-sitter loses about 0.4% of C
definitions to preprocessor conditionals (measured on curl HEAD, ADR 0004).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

from nikasha.code.gitio import HistoryTimeoutError
from nikasha.code.index import CodeIndex
from nikasha.resolve.refs import Release, ReleaseList

Strategy = Literal["lazy", "full"]


@dataclass(frozen=True, slots=True)
class ReleasePresence:
    """Whether a release defines the symbol.

    ``referenced``: the name appears as a word in some file. ``paths``: the files defining it.
    ``partial``: files that mention it but did not parse cleanly, so a definition there may
    have been missed; with no definition found, such a release is uncertain, not absent.
    """

    release: str
    defined: bool
    referenced: bool
    paths: tuple[str, ...] = ()
    partial: tuple[str, ...] = ()

    @property
    def uncertain(self) -> bool:
        return not self.defined and bool(self.partial)


@dataclass
class Timeline:
    symbol: str
    strategy: Strategy
    presence: list[ReleasePresence]
    history_complete: bool = True
    #: ``True``: the text never appeared in any commit; ``None``: not searched / unknown.
    never_in_history: bool | None = None
    first_commit_with_text: str | None = None
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)

    @property
    def runs(self) -> list[tuple[str, str]]:
        """Run-length encoded ``(first, last)`` release ranges where the symbol is defined."""
        runs: list[tuple[str, str]] = []
        start: str | None = None
        prev: str | None = None
        for p in self.presence:
            if p.defined and start is None:
                start = p.release
            if not p.defined and start is not None:
                runs.append((start, prev or start))
                start = None
            prev = p.release
        if start is not None:
            runs.append((start, prev or start))
        return runs

    @property
    def ever_defined(self) -> bool:
        return any(p.defined for p in self.presence)

    def defined_in(self, release: str) -> bool:
        return any(p.release == release and p.defined for p in self.presence)

    @property
    def uncertain_releases(self) -> list[str]:
        """Releases where absence cannot be claimed (see :class:`ReleasePresence`)."""
        return [p.release for p in self.presence if p.uncertain]


def _bare(name: str) -> str:
    return name.replace("::", ".").replace("#", ".").rsplit(".", 1)[-1]


def build_timeline(
    index: CodeIndex,
    releases: ReleaseList,
    name: str,
    *,
    strategy: Strategy = "lazy",
    history_timeout: float = 20.0,
    releases_subset: list[Release] | None = None,
) -> Timeline:
    """Compute where ``name`` is defined across the final releases of the main line."""
    started = time.monotonic()
    finals = releases_subset if releases_subset is not None else releases.finals()
    presence = _full(index, finals, name) if strategy == "full" else _lazy(index, finals, name)
    timeline = Timeline(name, strategy, presence)
    if not timeline.ever_defined:
        _history(index, timeline, history_timeout)
    timeline.seconds = time.monotonic() - started
    return timeline


def _mentions(index: CodeIndex, releases: list[Release], name: str) -> dict[str, list[str]]:
    """``commit -> sorted paths`` mentioning ``name`` as a word, one batched grep."""
    commits = [r.commit for r in releases]
    hits = index.repo.grep(_bare(name), commits, word=True, files_only=True, max_hits=200_000)
    by_commit: dict[str, set[str]] = {}
    for hit in hits:
        by_commit.setdefault(hit.rev, set()).add(hit.path)
    return {commit: sorted(paths) for commit, paths in by_commit.items()}


def _partial(index: CodeIndex, commit: str, paths: list[str]) -> tuple[str, ...]:
    """Of ``paths``, those that did not parse cleanly."""
    return tuple(
        p for p in paths
        if (facts := index.facts_at(commit, p)) is not None and not facts.parsed_ok
    )  # fmt: skip


def _lazy(index: CodeIndex, finals: list[Release], name: str) -> list[ReleasePresence]:
    mentions = _mentions(index, finals, name)
    out: list[ReleasePresence] = []
    for release in finals:
        paths = mentions.get(release.commit, [])
        defined_in = [
            p for p in paths
            if (facts := index.facts_at(release.commit, p)) is not None and facts.definitions(name)
        ]  # fmt: skip
        partial = () if defined_in else _partial(index, release.commit, paths)
        out.append(
            ReleasePresence(release.name, bool(defined_in), bool(paths), tuple(defined_in), partial)
        )
    return out


def _full(index: CodeIndex, finals: list[Release], name: str) -> list[ReleasePresence]:
    defined: dict[str, tuple[str, ...]] = {}
    for release in finals:
        index.index_commit(release.commit)
        defined[release.name] = tuple(
            sorted({p for p, _ in index.definitions(release.commit, name)})
        )
    # Mentions are only needed where nothing was found: one grep over those releases.
    missing = [r for r in finals if not defined[r.name]]
    mentions = _mentions(index, missing, name) if missing else {}
    out: list[ReleasePresence] = []
    for release in finals:
        paths = defined[release.name]
        if paths:
            out.append(ReleasePresence(release.name, True, True, paths))
            continue
        mentioned = mentions.get(release.commit, [])
        partial = _partial(index, release.commit, mentioned)
        out.append(ReleasePresence(release.name, False, bool(mentioned), (), partial))
    return out


def _history(index: CodeIndex, timeline: Timeline, timeout: float) -> None:
    if index.repo.is_shallow():
        timeline.history_complete = False
        timeline.notes.append("repository is shallow: history is incomplete")
        return
    try:
        first = index.repo.pickaxe_first(_bare(timeline.symbol), timeout=timeout)
    except HistoryTimeoutError:
        timeline.history_complete = False
        timeline.notes.append(f"history search timed out after {timeout:g}s")
        return
    timeline.first_commit_with_text = first
    timeline.never_in_history = first is None
