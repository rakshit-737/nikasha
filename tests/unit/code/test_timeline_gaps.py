# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""P4 for the release timeline: a capped or failed mention search is not absence."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from nikasha.code import timeline as timeline_mod
from nikasha.code.gitio import GitRepo, HistoryTimeoutError, HistoryUnavailableError
from nikasha.code.index import CodeIndex
from nikasha.code.timeline import build_timeline
from nikasha.errors import ExternalToolError
from nikasha.resolve.refs import ReleaseList

STRATEGIES = ["lazy", "full"]


@pytest.fixture
def idx(vulnlab_repo: Path, tmp_path: Path) -> Iterator[CodeIndex]:
    repo = GitRepo(vulnlab_repo)
    with repo, CodeIndex(repo, tmp_path / "index.sqlite") as index:
        yield index


@pytest.fixture
def releases(vulnlab_repo: Path) -> ReleaseList:
    with GitRepo(vulnlab_repo) as repo:
        return ReleaseList.from_tags(repo.tags())


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_a_capped_mention_search_marks_history_incomplete(
    idx: CodeIndex, releases: ReleaseList, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    # memcpy is mentioned (never defined) in several releases: a cap of 1 truncates.
    monkeypatch.setattr(timeline_mod, "MAX_MENTION_FILES", 1)
    tl = build_timeline(idx, releases, "memcpy", strategy=strategy)  # type: ignore[arg-type]
    assert tl.history_complete is False
    assert tl.never_in_history is None
    assert any("stopped at 1 files" in note for note in tl.notes)


def test_an_uncapped_mention_search_stays_complete(idx: CodeIndex, releases: ReleaseList) -> None:
    tl = build_timeline(idx, releases, "memcpy")
    assert tl.history_complete is True
    assert not tl.notes


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_a_failed_mention_search_marks_history_incomplete(
    idx: CodeIndex, releases: ReleaseList, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    def grep(*_: Any, **__: Any) -> list[Any]:
        raise ExternalToolError("git grep failed with exit code 128")

    monkeypatch.setattr(idx.repo, "grep", grep)
    tl = build_timeline(idx, releases, "hdr_decode_chunked_value", strategy=strategy)  # type: ignore[arg-type]
    assert tl.history_complete is False
    assert tl.never_in_history is None
    assert any("exit code 128" in note for note in tl.notes)


@pytest.mark.parametrize(
    ("error", "words"),
    [
        (HistoryUnavailableError("git was not found on PATH"), "failed: git was not found"),
        (HistoryTimeoutError("git log timed out after 20s"), "timed out"),
    ],
)
def test_history_notes_say_what_happened(
    idx: CodeIndex,
    releases: ReleaseList,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    words: str,
) -> None:
    def pickaxe(*_: Any, **__: Any) -> str | None:
        raise error

    monkeypatch.setattr(idx.repo, "pickaxe_first", pickaxe)
    tl = build_timeline(idx, releases, "hdr_decode_chunked_value")
    assert tl.history_complete is False
    (note,) = tl.notes
    assert words in note
    if isinstance(error, HistoryUnavailableError):
        assert "timed out" not in note


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_a_failed_definition_search_marks_history_incomplete(
    idx: CodeIndex, releases: ReleaseList, monkeypatch: pytest.MonkeyPatch, strategy: str
) -> None:
    """A git failure while looking for definitions is a gap, never an absence (P4)."""

    def fail(*_: Any, **__: Any) -> Any:
        raise ExternalToolError("git cat-file failed with exit code 128")

    monkeypatch.setattr(idx, "definitions", fail)
    monkeypatch.setattr(idx, "facts_at", fail)
    tl = build_timeline(idx, releases, "util_copy_value", strategy=strategy)  # type: ignore[arg-type]
    assert tl.history_complete is False
    assert tl.never_in_history is None
    assert not tl.ever_defined
    assert any("exit code 128" in note for note in tl.notes)


def test_an_unexpected_history_failure_marks_history_incomplete(
    idx: CodeIndex, releases: ReleaseList, monkeypatch: pytest.MonkeyPatch
) -> None:
    def pickaxe(*_: Any, **__: Any) -> str | None:
        raise ExternalToolError("git log failed with exit code 128")

    monkeypatch.setattr(idx.repo, "pickaxe_first", pickaxe)
    tl = build_timeline(idx, releases, "hdr_decode_chunked_value")
    assert tl.history_complete is False
    assert tl.never_in_history is None
    assert any("exit code 128" in note for note in tl.notes)
