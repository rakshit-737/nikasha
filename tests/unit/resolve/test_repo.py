# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The repository cache (resolve/repo.py, ADR 0006): offline by default, full bare clones."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from nikasha.code.gitio import GitResult
from nikasha.resolve import repo as repo_mod
from nikasha.resolve.repo import RepoNotAvailableError, acquire, cache_path

URL = "https://github.com/example/proj"


class FakeGit:
    """Stands in for run_git: records calls and never touches the network."""

    def __init__(self, *, clone_ok: bool = True) -> None:
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.clone_ok = clone_ok

    def __call__(self, args: Sequence[str], **kwargs: object) -> GitResult:
        self.calls.append((list(args), kwargs))
        if args[0] == "clone" and self.clone_ok:
            dest = Path(args[-1])
            dest.mkdir(parents=True)
            (dest / "HEAD").write_text("ref: refs/heads/main\n")
        stderr = b"" if self.clone_ok else b"Cloning...\nfatal: repository not found\n"
        return GitResult(tuple(args), 0 if self.clone_ok else 128, b"", stderr, 1)


@pytest.fixture
def fake_git(monkeypatch: pytest.MonkeyPatch) -> FakeGit:
    fake = FakeGit()
    monkeypatch.setattr(repo_mod, "run_git", fake)
    return fake


def test_cache_layout(tmp_path: Path) -> None:
    assert cache_path(URL + ".git", tmp_path) == tmp_path / "github.com/example/proj.git"


def test_offline_cache_miss_names_the_fix(tmp_path: Path, fake_git: FakeGit) -> None:
    with pytest.raises(RepoNotAvailableError, match=r"nikasha index --repo .* --online"):
        acquire(URL, cache_root=tmp_path)
    assert fake_git.calls == []  # offline: git is never asked to reach the network


def test_online_clone_is_a_full_bare_clone(tmp_path: Path, fake_git: FakeGit) -> None:
    location = acquire(URL + "/tree/main/lib", online=True, cache_root=tmp_path)
    assert location.url == URL
    assert location.git_dir == tmp_path / "github.com/example/proj.git"
    ((args, kwargs),) = fake_git.calls
    assert args[:3] == ["clone", "--bare", "--quiet"]
    assert "--filter=blob:none" not in args  # ADR 0006: lazy fetches would break offline mode
    assert args[3] == URL
    assert kwargs["online"] is True


def test_failed_clone_reports_gits_last_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(repo_mod, "run_git", FakeGit(clone_ok=False))
    with pytest.raises(RepoNotAvailableError, match="fatal: repository not found"):
        acquire(URL, online=True, cache_root=tmp_path)


def test_cached_repository_is_used_offline_and_fetched_online(
    tmp_path: Path, fake_git: FakeGit
) -> None:
    acquire(URL, online=True, cache_root=tmp_path)
    fake_git.calls.clear()
    acquire(URL, cache_root=tmp_path)
    assert fake_git.calls == []
    acquire(URL, online=True, cache_root=tmp_path)
    ((args, kwargs),) = fake_git.calls
    assert args[0] == "fetch"
    assert "origin" in args
    assert kwargs["online"] is True
    assert kwargs["git_dir"] == tmp_path / "github.com/example/proj.git"


def test_worktree_git_file_is_followed(tmp_path: Path, vulnlab_repo: Path) -> None:
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / ".git").write_text(f"gitdir: {vulnlab_repo}\n")
    assert acquire(str(worktree)).git_dir == vulnlab_repo.resolve()


def test_git_file_pointing_nowhere_is_not_a_repository(tmp_path: Path) -> None:
    worktree = tmp_path / "wt"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: ../missing\n")
    with pytest.raises(RepoNotAvailableError, match="not a git repository"):
        acquire(str(worktree))
