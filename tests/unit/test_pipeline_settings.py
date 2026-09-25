# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha.toml`` ``[questions]`` and ``[ignore]`` reach the pipeline (SPEC §16.1)."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest

from nikasha.fuse.questions import CLOSING
from nikasha.pipeline import IGNORED_KIND, IgnoringContext, check_report, ignored_glob
from nikasha.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
FABRICATED = ROOT / "examples" / "reports" / "fabricated_hdr_overflow.md"

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def test_ignored_glob_uses_the_settings_dialect() -> None:
    globs = ("vendor/**", "config.h")
    assert ignored_glob(globs, "vendor/zlib/inflate.c") == "vendor/**"
    assert ignored_glob(globs, "./vendor/zlib/inflate.c") == "vendor/**"
    assert ignored_glob(globs, "build/config.h") == "config.h"
    assert ignored_glob(globs, "src/hdr.c") is None
    assert ignored_glob((), "vendor/x.c") is None


def _context(ignore: tuple[str, ...], resolved: list[str]) -> IgnoringContext:
    ctx = IgnoringContext.__new__(IgnoringContext)
    ctx.ignore = ignore
    ctx.resolve_path = lambda path: resolved  # type: ignore[method-assign]
    return ctx


def test_an_ignored_path_reads_as_never_judged() -> None:
    ctx = _context(("vendor/**",), [])
    match = ctx.generated("vendor/zlib/inflate.c")
    assert match is not None
    assert match.kind == IGNORED_KIND
    assert match.reason == "[ignore] vendor/**"


def test_the_resolved_path_is_matched_too() -> None:
    ctx = _context(("third_party/**",), ["third_party/zlib/inflate.c"])
    match = ctx.generated("zlib/inflate.c")
    assert match is not None
    assert match.reason == "[ignore] third_party/**"


def _checked(vulnlab_repo: Path, tmp_path: Path, **kwargs: Any) -> Any:
    return check_report(
        FABRICATED, repo=str(vulnlab_repo), index_path=tmp_path / "i.sqlite", **kwargs
    )


@needs_git
def test_ignore_withholds_judgement_and_never_adds_a_refutation(
    vulnlab_repo: Path, tmp_path: Path
) -> None:
    plain = _checked(vulnlab_repo, tmp_path)
    ignored = _checked(vulnlab_repo, tmp_path, ignore=("src/**",))
    refuted = {e.check_id for e in plain.evidence if e.outcome == "REFUTES"}
    still = {e.check_id for e in ignored.evidence if e.outcome == "REFUTES"}
    assert still < refuted  # P4: ignoring only removes judgements
    assert "C03" not in still
    marked = [e for e in ignored.evidence if e.details.get("generated") == "[ignore] src/**"]
    assert marked
    assert all(e.outcome == "NEUTRAL" and e.strength == 0 for e in marked)
    again = _checked(vulnlab_repo, tmp_path, ignore=("src/**",))
    assert again.result.model_dump_json(exclude={"timings"}) == ignored.result.model_dump_json(
        exclude={"timings"}
    )


@needs_git
def test_question_overrides_reach_the_questions(vulnlab_repo: Path, tmp_path: Path) -> None:
    settings = Settings.model_validate(
        {
            "questions": {
                "C03.never_in_history_core": "Where is `{{ symbol }}` defined in {{ where }}?"
            }
        }
    )
    checked = _checked(vulnlab_repo, tmp_path, question_overrides=settings.question_overrides())
    texts = [q.text for q in checked.verdict.questions]
    assert any(t.startswith("Where is `hdr_decode_chunked_value`") for t in texts), texts
    assert all(t.endswith(CLOSING) for t in texts)
