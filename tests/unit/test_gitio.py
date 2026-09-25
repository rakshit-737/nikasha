# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import os
import shutil
from pathlib import Path

import pytest

from nikasha.code import gitio
from nikasha.errors import ForbiddenCommandError
from nikasha.model.evidence import CommandRecord

pytestmark = pytest.mark.skipif(gitio.git_executable() is None, reason="git not installed")


def _config_values(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, a in enumerate(argv) if a == "-c"]


def test_every_invocation_carries_hardening_config() -> None:
    argv = gitio.build_argv(["ls-tree", "-r", "HEAD"])
    assert argv[1] == "--no-pager"
    assert set(gitio.HARDENING_CONFIG) <= set(_config_values(argv))


def test_diff_external_is_not_relied_upon() -> None:
    # An empty diff.external does not disable external diff; --no-ext-diff does.
    assert not any(s.startswith("diff.external") for s in gitio.HARDENING_CONFIG)


@pytest.mark.parametrize("sub", ["log", "show"])
def test_log_and_show_disable_textconv_and_ext_diff(sub: str) -> None:
    argv = gitio.build_argv([sub, "-1"])
    i = argv.index(sub)
    assert argv[i + 1 : i + 3] == ["--no-ext-diff", "--no-textconv"]


@pytest.mark.parametrize(
    "sub", ["checkout", "status", "diff", "config", "submodule", "filter-branch", "!sh"]
)
def test_forbidden_subcommands_are_rejected(sub: str) -> None:
    with pytest.raises(ForbiddenCommandError):
        gitio.build_argv([sub])


def test_empty_command_is_rejected() -> None:
    with pytest.raises(ForbiddenCommandError):
        gitio.build_argv([])


@pytest.mark.parametrize("sub", ["apply", "worktree"])
def test_test_only_subcommands_need_opt_in(sub: str) -> None:
    with pytest.raises(ForbiddenCommandError):
        gitio.build_argv([sub])
    assert sub in gitio.build_argv([sub], allow_test_only=True)


def test_git_dir_adds_safe_directory(tmp_path: Path) -> None:
    argv = gitio.build_argv(["rev-parse", "HEAD"], git_dir=tmp_path)
    resolved = str(tmp_path.resolve())
    assert f"safe.directory={resolved}" in _config_values(argv)
    assert f"--git-dir={resolved}" in argv
    assert argv.index(f"--git-dir={resolved}") < argv.index("rev-parse")


def test_env_scrubs_inherited_git_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_DIR", "/attacker")
    monkeypatch.setenv("GIT_EXTERNAL_DIFF", "touch /tmp/pwned")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'core.pager=sh'")
    env = gitio.hardened_env()
    assert "GIT_DIR" not in env
    assert "GIT_EXTERNAL_DIFF" not in env
    assert "GIT_CONFIG_PARAMETERS" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_OPTIONAL_LOCKS"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_user_config_is_opt_in() -> None:
    assert "GIT_CONFIG_GLOBAL" not in gitio.hardened_env(use_user_config=True)


def test_git_version_reports_something() -> None:
    version = gitio.git_version()
    assert version
    assert version[0].isdigit()


def test_run_git_executes_allowed_command(tmp_path: Path) -> None:
    # `rev-parse --git-dir` outside a repository fails cleanly rather than raising.
    result = gitio.run_git(["rev-parse", "--is-bare-repository"], git_dir=tmp_path)
    assert result.returncode != 0
    assert Path(result.argv[0]).stem.lower() == "git"  # e.g. git, git.exe, git.EXE
    assert result.duration_ms >= 0


def _copy_repo(src: Path, dest: Path) -> Path:
    shutil.copytree(src, dest)
    return dest


def test_grep_failure_is_not_absence(vulnlab_repo: Path, tmp_path: Path) -> None:
    # A bad revision exits 128 with no output; that must not read as "no match" (P4).
    repo = gitio.GitRepo(vulnlab_repo)
    records: list[CommandRecord] = []
    with pytest.raises(gitio.ExternalToolError):  # type: ignore[attr-defined]
        repo.grep("x", ["deadbeef" * 5], record=records)
    assert [r.exit_code for r in records] == [128]


def test_pickaxe_failure_counts_as_incomplete_history(vulnlab_repo: Path, tmp_path: Path) -> None:
    clone = _copy_repo(vulnlab_repo, tmp_path / "broken.git")
    for obj in (clone / "objects").rglob("*"):
        if obj.is_file() and obj.parent.name not in ("info",):
            obj.chmod(0o666)
            obj.unlink()
    with pytest.raises(gitio.HistoryTimeoutError):
        gitio.GitRepo(clone).pickaxe_first("foo")


def test_cat_file_missing_name_with_spaces_is_none(vulnlab_repo: Path) -> None:
    # "HEAD:a b missing" has three tokens; it must not be parsed as a size (crash).
    with gitio.GitRepo(vulnlab_repo) as repo:
        assert repo.read_file("HEAD", "a b") is None
        assert repo.read_file("HEAD", "x 5") is None


@pytest.mark.parametrize("text", ["", "a\x1b[31mb", "a\rb", "a\x7fb"])
def test_pickaxe_unsearchable_text_is_not_absence(vulnlab_repo: Path, text: str) -> None:
    # "Could not search" must never read as "never in history" (P4).
    with pytest.raises(gitio.HistoryUnavailableError):
        gitio.GitRepo(vulnlab_repo).pickaxe_first(text)


def test_pickaxe_allows_tab_indented_text(vulnlab_repo: Path) -> None:
    assert gitio.GitRepo(vulnlab_repo).pickaxe_first("\tno-such-text-anywhere-42") is None


def test_pickaxe_without_git_is_unavailable_not_a_timeout(
    vulnlab_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A missing git binary did not time out; the reason must survive (P6).
    repo = gitio.GitRepo(vulnlab_repo)
    monkeypatch.setattr(gitio, "git_executable", lambda: None)
    with pytest.raises(gitio.HistoryUnavailableError, match="not found"):
        repo.pickaxe_first("foo")


def test_pickaxe_timeout_is_a_timeout(vulnlab_repo: Path) -> None:
    with pytest.raises(gitio.HistoryTimeoutError) as info:
        gitio.GitRepo(vulnlab_repo).pickaxe_first("foo", timeout=1e-6)
    assert not isinstance(info.value, gitio.HistoryUnavailableError)
    assert isinstance(info.value.__cause__, gitio.GitTimeoutError)
