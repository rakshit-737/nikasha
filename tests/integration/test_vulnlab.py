# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the hermetic vulnlab demo repository and its builder."""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_BUILDER = _ROOT / "scripts" / "build_vulnlab.py"
_EXPECTED = _ROOT / "examples" / "vulnlab" / "expected.json"

_spec = importlib.util.spec_from_file_location("build_vulnlab", _BUILDER)
assert _spec is not None
assert _spec.loader is not None
bv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bv)

TAGS = ["v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"]

FORBIDDEN = [
    "hdr_decode_chunked_value",
    "hdr_emit",
    "hdr_ctx",
    "HDR_ERR_TOO_LONG",
    "chunk_off",
    "unsafe-fold",
    "unsafe_fold",
]

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, str]]:
    dest = tmp_path_factory.mktemp("vulnlab") / "repo.git"
    tags = bv.build_vulnlab(dest)
    return dest, tags


def _file_at(dest: Path, tag: str, path: str) -> str:
    text: str = bv._git(["show", f"{tag}:{path}"], cwd=dest, env=bv._git_env()).decode()
    return text


def _grep(dest: Path, tag: str, pattern: str, *, word: bool = False, fixed: bool = False) -> bool:
    flags = ["-I", "-l"]
    if word:
        flags.append("-w")
    if fixed:
        flags.append("-F")
    result = subprocess.run(
        ["git", "grep", *flags, "-e", pattern, tag],
        cwd=dest,
        env=bv._git_env(),
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _line_of(dest: Path, tag: str, path: str, needle: str) -> int:
    for i, line in enumerate(_file_at(dest, tag, path).splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} not found in {tag}:{path}")


def _tokens(source: str) -> str:
    """Reduce C source to significant tokens: drop comments and all whitespace."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//[^\n]*", "", source)
    return re.sub(r"\s+", "", source)


def test_deterministic_and_matches_expected(tmp_path: Path) -> None:
    first = bv.build_vulnlab(tmp_path / "a.git")
    second = bv.build_vulnlab(tmp_path / "b.git")
    assert first == second
    assert first == json.loads(_EXPECTED.read_text(encoding="utf-8"))


def test_tags_main_and_license(repo: tuple[Path, dict[str, str]]) -> None:
    dest, tags = repo
    assert sorted(tags) == TAGS
    main = bv._git(["rev-parse", "main"], cwd=dest, env=bv._git_env()).decode().strip()
    assert main == tags["v1.3.0"]
    for tag in TAGS:
        # Raises CalledProcessError (failing the test) if LICENSE is missing at the tag.
        bv._git(["cat-file", "-e", f"{tag}:LICENSE"], cwd=dest, env=bv._git_env())


def test_util_symbol_evolution(repo: tuple[Path, dict[str, str]]) -> None:
    dest, _ = repo
    assert not _grep(dest, "v1.0.0", "util_copy_value", word=True)
    for tag in ("v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"):
        assert _grep(dest, tag, "util_copy_value", word=True)

    assert _grep(dest, "v1.0.0", "util_trim", word=True)
    assert not _grep(dest, "v1.0.0", "util_strip", word=True)
    for tag in ("v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0"):
        assert not _grep(dest, tag, "util_trim", word=True)
        assert _grep(dest, tag, "util_strip", word=True)


def test_hdr_get_replaced_by_hdr_find(repo: tuple[Path, dict[str, str]]) -> None:
    dest, _ = repo
    for tag in ("v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1"):
        assert _grep(dest, tag, "hdr_get", word=True)
        assert not _grep(dest, tag, "hdr_find", word=True)
    assert not _grep(dest, "v1.3.0", "hdr_get", word=True)
    assert _grep(dest, "v1.3.0", "hdr_find", word=True)


def test_hdr_c_is_short(repo: tuple[Path, dict[str, str]]) -> None:
    dest, _ = repo
    for tag in TAGS:
        assert len(_file_at(dest, tag, "src/hdr.c").splitlines()) < 300


def test_no_forbidden_identifiers(repo: tuple[Path, dict[str, str]]) -> None:
    dest, _ = repo
    for tag in TAGS:
        for token in FORBIDDEN:
            assert not _grep(dest, tag, token, fixed=True), f"{token} found at {tag}"


def test_util_copy_value_line_numbers_shift(repo: tuple[Path, dict[str, str]]) -> None:
    dest, _ = repo
    lines = {
        tag: _line_of(dest, tag, "src/util.c", "char *util_copy_value")
        for tag in ("v1.1.0", "v1.2.0", "v1.2.1")
    }
    assert len(set(lines.values())) == 3, lines


def test_v121_is_comments_and_whitespace_only(repo: tuple[Path, dict[str, str]]) -> None:
    dest, _ = repo
    for path in ("src/hdr.c", "src/util.c"):
        before = _file_at(dest, "v1.2.0", path)
        after = _file_at(dest, "v1.2.1", path)
        assert before != after, f"{path} is unchanged; expected a comment/whitespace edit"
        assert _tokens(before) == _tokens(after), f"{path} changed more than comments/whitespace"


def test_v130_fix_reverse_applies(repo: tuple[Path, dict[str, str]]) -> None:
    """The bug fix is a small self-contained hunk in src/util.c (hdr_get->hdr_find aside)."""
    dest, _ = repo
    full = bv._git(["diff", "--name-only", "v1.2.1", "v1.3.0"], cwd=dest, env=bv._git_env())
    changed = full.decode().split()
    # The fix (util.c) plus the hdr_get -> hdr_find rename (hdr.h, hdr.c, README).
    assert changed == ["README", "include/hdr.h", "src/hdr.c", "src/util.c"], changed
    util_diff = bv._git(
        ["diff", "v1.2.1", "v1.3.0", "--", "src/util.c"], cwd=dest, env=bv._git_env()
    ).decode()
    # A single added-hunk bounds check; no lines removed from util.c.
    assert "+    if (len >= HDR_VALUE_MAX)" in util_diff
    assert "\n-" not in util_diff.split("@@", 1)[-1]


@pytest.mark.slow
def test_every_tag_compiles(repo: tuple[Path, dict[str, str]], tmp_path: Path) -> None:
    compiler = next((c for c in ("cc", "clang", "gcc") if shutil.which(c)), None)
    if compiler is None:
        pytest.skip("no C compiler available")
    if shutil.which("make") is None or shutil.which("tar") is None:
        pytest.skip("make or tar unavailable")
    dest, _ = repo
    for tag in TAGS:
        work = tmp_path / tag
        work.mkdir()
        archive = bv._git(["archive", "--format=tar", tag], cwd=dest, env=bv._git_env())
        subprocess.run(["tar", "-x"], cwd=work, input=archive, check=True)
        subprocess.run(
            ["make", f"CC={compiler}", "CFLAGS=-std=c99 -Wall -Wextra -Werror"],
            cwd=work,
            check=True,
            capture_output=True,
        )
