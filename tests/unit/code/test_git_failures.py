# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""A git failure inside the call graph or the lazy index is never read as "absent" (P4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nikasha.code import callgraph
from nikasha.code.facts import CallSite
from nikasha.code.gitio import GitRepo, GitResult
from nikasha.code.index import CodeIndex
from nikasha.errors import ExternalToolError


class _BrokenRepo:
    def grep(self, *_: Any, **__: Any) -> list[Any]:
        raise ExternalToolError("git grep failed with exit code 128")


class _Index:
    repo = _BrokenRepo()

    def facts_at(self, commit: str, path: str) -> None:
        return None


def _indirect_call() -> CallSite:
    return CallSite(callee="handler", line=7, indirect=True, caller_qname="dispatch")


def test_a_failed_address_taken_search_keeps_the_indirect_edge_possible() -> None:
    """``none`` would read as "cannot call"; an unanswered search must stay a possibility."""
    calls = [("src/dispatch.c", _indirect_call())]
    found = callgraph._indirect(_Index(), "c0ffee", calls, "target")  # type: ignore[arg-type]
    assert [e.line for e in found] == [7]
    assert "could not be searched" in found[0].note


def test_the_lazy_index_raises_a_typed_error_not_an_empty_answer(
    vulnlab_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty list would be "not defined"; callers must see the failure and not search."""
    real_run = GitRepo.run

    def run(self: GitRepo, argv: list[str], **kw: Any) -> GitResult:
        if argv[:1] == ["grep"]:
            return GitResult(tuple(argv), 128, b"", b"fatal: bad object", 0)
        return real_run(self, argv, **kw)

    repo = GitRepo(vulnlab_repo)
    with repo, CodeIndex(repo, tmp_path / "index.sqlite") as index:
        commit = repo.rev_parse("v1.2.0")
        assert commit is not None
        monkeypatch.setattr(GitRepo, "run", run)
        with pytest.raises(ExternalToolError):
            index.definitions(commit, "util_copy_value")
        monkeypatch.setattr(GitRepo, "run", real_run)
        assert [p for p, _ in index.definitions(commit, "util_copy_value")] == ["src/util.c"]
