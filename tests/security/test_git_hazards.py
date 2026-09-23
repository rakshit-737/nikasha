# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Repositories are attacker-controlled (SPEC §19.3).

A malicious repository's config wires every known git execution hook to ``touch CANARY``.
A control step proves plain git really runs them; then every Nikasha git code path runs
against the same repository and the canary must never appear.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from nikasha.code.gitio import GitRepo, run_git
from nikasha.errors import ExternalToolError, ForbiddenCommandError

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or os.name != "posix", reason="needs git and a POSIX shell"
)

_CLEAN_ENV = {
    **{k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(repo), *args], env=_CLEAN_ENV, capture_output=True, check=False
    )


@pytest.fixture
def evil_repo(tmp_path: Path) -> tuple[Path, Path]:
    repo = tmp_path / "evil"
    canary = tmp_path / "CANARY"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / ".gitattributes").write_text("* diff=evil filter=evil\n")
    (repo / "src.c").write_text("int vulnerable_function(void) { return 0; }\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "one")
    (repo / "src.c").write_text("int vulnerable_function(void) { return 1; }\n")
    _git(repo, "commit", "-q", "-am", "two")
    _git(repo, "tag", "v1.0")

    touch = f"touch {canary}"
    hooks = repo / "evil-hooks"
    hooks.mkdir()
    for hook in (
        "pre-commit",
        "post-checkout",
        "post-merge",
        "reference-transaction",
        "fsmonitor-watchman",
    ):
        path = hooks / hook
        path.write_text(f"#!/bin/sh\n{touch}\n")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
    (repo / "evil.cfg").write_text(f"[core]\n\tpager = {touch}\n")
    settings = {
        "core.fsmonitor": touch,
        "core.pager": touch,
        "core.sshCommand": touch,
        "core.askPass": touch,
        "core.editor": touch,
        "core.hooksPath": str(hooks),
        "core.alternateRefsCommand": touch,
        "diff.external": touch,
        "diff.evil.textconv": touch,
        "filter.evil.clean": touch,
        "filter.evil.smudge": touch,
        "filter.evil.process": touch,
        "credential.helper": f"!{touch}",
        "tar.tar.command": touch,
        "pager.log": touch,
        "pager.show": touch,
        "pager.grep": touch,
        "sequence.editor": touch,
        "remote.origin.url": f"ext::sh -c {touch.replace(' ', '% ')}",
        "include.path": str(repo / "evil.cfg"),
    }
    for key, value in settings.items():
        _git(repo, "config", key, value)
    return repo / ".git", canary


@pytest.mark.parametrize(
    "argv",
    [
        # textconv driver, through the worktree's .gitattributes
        ["-C", "{repo}", "log", "-p", "-1"],
        # tar.tar.command from the repository config: why Nikasha never uses `git archive`
        ["--git-dir={git_dir}", "archive", "--format=tar", "HEAD"],
    ],
    ids=["textconv", "archive-tar-command"],
)
def test_control_plain_git_does_run_the_hooks(evil_repo, argv):
    git_dir, canary = evil_repo
    args = [a.format(repo=git_dir.parent, git_dir=git_dir) for a in argv]
    subprocess.run(["git", *args], env=_CLEAN_ENV, capture_output=True, check=False)
    assert canary.exists(), "the malicious config must be live, or this test proves nothing"


def test_no_nikasha_code_path_runs_repository_commands(evil_repo):
    git_dir, canary = evil_repo
    with GitRepo(git_dir) as repo:
        tags = repo.tags()
        assert [t.name for t in tags] == ["v1.0"]
        assert repo.rev_parse("v1.0")
        assert repo.rev_parse("v1.0", kind="tree")
        entries = repo.ls_tree("v1.0")
        assert {e.path for e in entries} >= {"src.c", ".gitattributes"}
        assert b"vulnerable_function" in (repo.read_file("v1.0", "src.c") or b"")
        blob = next(e for e in entries if e.path == "src.c")
        assert repo.read_blob(blob.sha)
        assert repo.grep("vulnerable_function", ["v1.0", "v1.0~1"], word=True)
        assert repo.grep("vulnerable_function", ["v1.0"], files_only=True)
        assert repo.pickaxe_first("return 1") is not None
        assert repo.commit_epoch("v1.0")
        assert repo.tip_before("main", 4_000_000_000)
        repo.default_branch()
        repo.is_shallow()
        assert repo.export_tree("v1.0", git_dir.parent.parent / "export") >= 2
    for args in (
        ["log", "-p", "-2"],
        ["show", "v1.0"],
        ["log", "--stat", "-1"],
        ["grep", "-n", "-e", "return", "v1.0"],
    ):
        run_git(args, git_dir=git_dir)
    # Online fetch from the ext:: remote must be refused by protocol policy, not executed.
    run_git(["fetch", "origin"], git_dir=git_dir, online=True)
    assert not canary.exists(), "a git hook or driver ran a command"


@pytest.mark.parametrize(
    "rev",
    ["--upload-pack=touch /tmp/pwned", "-c", "--exec=/bin/sh", "HEAD\nrm -rf", ""],
)
def test_injected_revisions_are_refused(evil_repo, rev):
    git_dir, canary = evil_repo
    with GitRepo(git_dir) as repo, pytest.raises(ForbiddenCommandError):
        repo.rev_parse(rev)
    assert not canary.exists()


@pytest.mark.parametrize(
    "args",
    [
        ["clone", "--upload-pack=touch x", "a", "b"],
        ["clone", "-u", "touch x", "a", "b"],
        ["archive", "--format=tar", "HEAD"],
        ["grep", "--open-files-in-pager=touch x", "-e", "a"],
        ["grep", "-O", "-e", "a"],
        ["log", "--ext-diff"],
        ["cat-file", "--textconv", "HEAD:src.c"],
        ["clone", "-c", "core.fsmonitor=touch x", "a", "b"],
        ["fetch", "--config=core.pager=touch x"],
        ["status"],
        ["checkout", "v1.0"],
        ["config", "core.pager", "x"],
    ],
)
def test_dangerous_invocations_are_refused(evil_repo, args):
    git_dir, _ = evil_repo
    with pytest.raises(ForbiddenCommandError):
        run_git(args, git_dir=git_dir)


@pytest.mark.parametrize(
    "args",
    [
        ["grep", "-e", "--open-files-in-pager=touch x", "-e", "-O", "v1.0", "--"],
        ["grep", "-F", "-e", "--upload-pack=touch x", "v1.0", "--", "--exec=x"],
        ["log", "-1", "--", "--ext-diff"],
    ],
)
def test_data_positions_may_quote_options(evil_repo, args):
    """A pattern after ``-e`` and paths after ``--`` are data: searched, never refused or run."""
    git_dir, canary = evil_repo
    run_git(args, git_dir=git_dir)
    assert not canary.exists()


@pytest.mark.parametrize(
    "args",
    [
        ["grep", "-e", "a", "--open-files-in-pager=touch x", "v1.0"],  # only one value after -e
        ["log", "-e", "--ext-diff"],  # -e is grep's pattern flag only
        ["grep", "-O", "--", "a"],  # before `--` is still checked
    ],
)
def test_only_true_data_positions_are_exempt(evil_repo, args):
    git_dir, _ = evil_repo
    with pytest.raises(ForbiddenCommandError):
        run_git(args, git_dir=git_dir)


def test_nikasha_runs_in_the_evil_worktree_too(evil_repo, monkeypatch):
    """Running from inside the malicious checkout (cwd = its worktree) is still safe."""
    git_dir, canary = evil_repo
    monkeypatch.chdir(git_dir.parent)
    with GitRepo(git_dir) as repo:
        repo.grep("vulnerable_function", ["v1.0"])
        repo.pickaxe_first("return 1")
    run_git(["log", "-p", "-2"], git_dir=git_dir)
    assert not canary.exists()


def test_export_skips_symlinks_and_keeps_exec_bits(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "run.sh").write_text("#!/bin/sh\n")
    (repo / "run.sh").chmod(0o755)
    (repo / "link").symlink_to("/etc/passwd")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "x")
    dest = tmp_path / "out"
    with GitRepo(repo / ".git") as r:
        assert r.export_tree("HEAD", dest) == 1
    assert (dest / "run.sh").stat().st_mode & 0o111
    assert not (dest / "link").exists()


def test_offline_never_lazy_fetches(tmp_path, monkeypatch):
    """Offline, GIT_NO_LAZY_FETCH is set, so a partial clone cannot reach the network."""
    from nikasha.code.gitio import hardened_env  # noqa: PLC0415

    assert hardened_env()["GIT_NO_LAZY_FETCH"] == "1"
    assert "GIT_NO_LAZY_FETCH" not in hardened_env(online=True)


def test_pickaxe_timeout_is_reported(evil_repo, monkeypatch):
    git_dir, _ = evil_repo
    from nikasha.code import gitio  # noqa: PLC0415

    def slow(*_a, **_k):
        raise ExternalToolError("git log timed out after 0s")

    monkeypatch.setattr(gitio, "run_git", slow)
    with GitRepo(git_dir) as repo, pytest.raises(gitio.HistoryTimeoutError):
        repo.pickaxe_first("anything")
