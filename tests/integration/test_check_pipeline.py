# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""`nikasha check` end to end on the vulnlab fixtures (SPEC §22, M3 definition of done).

These are the golden tests: the whole pipeline — intake, extraction, resolution, indexing,
every check, fusion, the verdict ladder and the questions — run offline against the real
demo history, and the verdict for each fixture is pinned.

The five fixtures were written to land on five different verdicts, so a change that makes
one of them right by making another wrong shows up here immediately. In particular
`genuine_hdr_overflow.md` must **never** come out UNGROUNDED: that is the false-accusation
case P4 exists to prevent, and it is asserted separately and loudly.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from nikasha.pipeline import check_report
from nikasha.render.terminal import exit_code

ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "examples" / "reports"

pytestmark = [
    pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed"),
    pytest.mark.slow,
]

#: The verdict each fixture must produce, and why it is that verdict.
EXPECTED: dict[str, tuple[str, str]] = {
    "fabricated_hdr_overflow": (
        "UNGROUNDED",
        "the core symbol never existed, corroborated by the trace and the patch",
    ),
    "genuine_hdr_overflow": ("GROUNDED", "every claim checks out at the named version"),
    "mixed_wrong_version": ("MIXED", "the evidence fits a different release than the report names"),
    "already_fixed": ("MIXED", "the proposed patch is already applied at the named version"),
    "vague": ("INSUFFICIENT", "there is nothing concrete enough to check"),
}


@pytest.fixture(scope="module")
def checked(vulnlab_repo: Path, tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """Run every fixture once; the whole module reads these results."""
    index_dir = tmp_path_factory.mktemp("check-index")
    out: dict[str, object] = {}
    for name in EXPECTED:
        out[name] = check_report(
            REPORTS / f"{name}.md",
            repo=str(vulnlab_repo),
            index_path=index_dir / f"{name}.sqlite",
        )
    return out


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_fixture_gets_its_expected_verdict(checked, name) -> None:
    label, why = EXPECTED[name]
    report = checked[name]
    assert report.verdict.label == label, (
        f"{name}: expected {label} ({why}), got {report.verdict.label} "
        f"at score {report.verdict.score} via rule {report.verdict.rule!r}"
    )


def test_a_genuine_report_is_never_called_ungrounded(checked) -> None:
    """P4, the one mistake this tool must not make."""
    for name in ("genuine_hdr_overflow", "mixed_wrong_version", "already_fixed"):
        assert checked[name].verdict.label != "UNGROUNDED", name


def test_the_fabricated_report_is_actually_refuted(checked) -> None:
    report = checked["fabricated_hdr_overflow"]
    refutations = [e for e in report.evidence if e.outcome == "REFUTES"]
    groups = {e.group for e in refutations}
    assert len(groups) >= 2, f"only {groups} refuted; UNGROUNDED needs corroboration"
    assert report.verdict.score < 15


def test_every_run_is_deterministic(vulnlab_repo, tmp_path) -> None:
    """The same report and the same commit must give byte-identical JSON (P2)."""
    first = check_report(
        REPORTS / "fabricated_hdr_overflow.md",
        repo=str(vulnlab_repo),
        index_path=tmp_path / "a.sqlite",
    )
    second = check_report(
        REPORTS / "fabricated_hdr_overflow.md",
        repo=str(vulnlab_repo),
        index_path=tmp_path / "b.sqlite",
    )
    assert first.result.to_json(include_timings=False) == second.result.to_json(
        include_timings=False
    )


def test_every_verdict_maps_to_its_documented_exit_code(checked) -> None:
    for name, (label, _) in EXPECTED.items():
        assert exit_code(checked[name].verdict.label) == exit_code(label), name


def test_evidence_is_explainable(checked) -> None:
    """P6: every piece of evidence names its check, its claims and a readable summary."""
    for name in EXPECTED:
        for item in checked[name].evidence:
            assert item.check_id, name
            assert item.summary.strip(), f"{name}/{item.check_id} has an empty summary"
            assert item.group, f"{name}/{item.check_id} has no group"


def test_questions_are_asked_where_the_report_needs_them(checked) -> None:
    """A report that is not simply GROUNDED should come with something to ask back."""
    for name in ("fabricated_hdr_overflow", "already_fixed", "vague"):
        questions = checked[name].verdict.questions
        assert len(questions) <= 6, name
        for question in questions:
            assert question.text.strip(), name


def test_no_output_describes_the_reporter(checked) -> None:
    """P1: the wording targets claims, never people, anywhere in the result."""
    banned = ("ai-generated", "slop", "fabricated by", "fake report", "hallucinat")
    for name in EXPECTED:
        blob = checked[name].result.to_json(include_timings=False).lower()
        for word in banned:
            assert word not in blob, f"{name} mentions {word!r}"
