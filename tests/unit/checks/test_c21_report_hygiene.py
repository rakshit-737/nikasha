# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C21 REPORT_HYGIENE: structural absence only, never a word about who wrote it (SPEC §12)."""

from __future__ import annotations

import re
from typing import Any, get_args

from check_helpers import MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c21_report_hygiene import CATEGORIES, FLAGGED, ReportHygiene
from nikasha.model.claims import (
    BehaviorClaim,
    Claim,
    ClaimKind,
    FileClaim,
    LineClaim,
    PatchClaim,
    PocClaim,
    ReferenceClaim,
    SnippetClaim,
    SymbolClaim,
    TraceClaim,
    VersionClaim,
    VersionSpec,
)

#: Words that would mean this check had started judging the person, not the report (P1).
FORBIDDEN_WORDS = frozenset(
    {
        "ai",
        "author",
        "chatgpt",
        "fabricated",
        "fake",
        "llm",
        "reporter",
        "style",
        "tone",
        "written",
        "wrote",
        "you",
        "your",
    }
)


def _run(make_ctx: MakeContext, claims: list[Claim]) -> Any:
    ctx = make_ctx(claims=claims)
    (evidence,) = ReportHygiene().run(ctx, list(ctx.claims))
    return evidence


def _version(raw: str = "1.2.0", **fields: Any) -> VersionClaim:
    fields.setdefault("parsed", VersionSpec(numbers=(1, 2, 0), raw=raw))
    return claim(VersionClaim, raw=raw, relation="tested_on", **fields)


def _trace() -> TraceClaim:
    return claim(TraceClaim, format="asan", bug_type="heap-buffer-overflow")


def _poc(**fields: Any) -> PocClaim:
    return claim(PocClaim, poc_kind="cli", content="hdrcat poc.txt", **fields)


def test_a_report_with_nothing_in_it_is_missing_everything(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[])
    (evidence,) = ReportHygiene().run(ctx, [])
    assert evidence.check_id == "C21"
    assert evidence.group == "info"
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["missing"] == ["version", "poc", "trace", "location"]
    assert evidence.details["present"] == []


def test_the_runner_reaches_a_report_with_no_claims(make_ctx: MakeContext) -> None:
    """``run_checks`` normally skips a check with no applicable claim, but not this one.

    A report with nothing in it is exactly what hygiene exists to describe, and it is what
    drives SPEC §14.3 rule 2 (INSUFFICIENT). C21 therefore sets ``runs_on_empty``, so the
    emptiest reports of all still arrive at the verdict with an explanation attached.
    """
    assert ReportHygiene().runs_on_empty is True
    (run,) = run_checks(make_ctx(claims=[]), checks=[ReportHygiene()])
    (evidence,) = run.evidence
    assert evidence.check_id == "C21"
    assert evidence.details["missing"] == ["version", "poc", "trace", "location"]


def test_a_check_without_runs_on_empty_is_still_skipped(make_ctx: MakeContext) -> None:
    """The opt-in must stay an opt-in: every other check keeps the cheap skip."""

    class Ordinary(ReportHygiene):
        id = "C21-test-double"
        runs_on_empty = False

    (run,) = run_checks(make_ctx(claims=[]), checks=[Ordinary()])
    assert run.evidence == ()


def test_a_complete_report_reports_nothing_missing(make_ctx: MakeContext) -> None:
    evidence = _run(make_ctx, [_version(), claim(FileClaim, path="src/util.c"), _trace(), _poc()])
    assert evidence.details["missing"] == []
    assert evidence.details["present"] == ["version", "poc", "trace", "location"]
    assert evidence.summary.startswith("the report gives ")


def test_a_thin_report_names_exactly_what_is_absent(make_ctx: MakeContext) -> None:
    evidence = _run(make_ctx, [claim(FileClaim, path="src/util.c")])
    assert evidence.details["missing"] == ["version", "poc", "trace"]
    assert evidence.details["present"] == ["location"]
    assert evidence.summary == (
        "the report does not give an affected version, a proof-of-concept or a crash trace;"
        " it does give a file, line or symbol"
    )


class TestWhatCountsAsAVersion:
    def test_a_parsed_version_counts(self, make_ctx: MakeContext) -> None:
        assert "version" not in _run(make_ctx, [_version()]).details["missing"]

    def test_a_version_word_that_pins_nothing_does_not_count(self, make_ctx: MakeContext) -> None:
        vague = claim(VersionClaim, raw="affected versions", relation="unspecified", parsed=None)
        evidence = _run(make_ctx, [vague])
        assert "version" in evidence.details["missing"]
        assert evidence.details["counts"]["version"] == 0

    def test_a_commit_counts(self, make_ctx: MakeContext) -> None:
        pinned = claim(
            VersionClaim, raw="f8fdd43", relation="tested_on", parsed=None, commit="f8fdd43"
        )
        assert "version" not in _run(make_ctx, [pinned]).details["missing"]

    def test_a_branch_counts(self, make_ctx: MakeContext) -> None:
        pinned = claim(VersionClaim, raw="main", relation="latest", parsed=None, special_ref="main")
        assert "version" not in _run(make_ctx, [pinned]).details["missing"]


class TestWhatCountsAsALocation:
    def test_a_file_a_line_and_a_symbol_all_count(self, make_ctx: MakeContext) -> None:
        evidence = _run(
            make_ctx,
            [
                claim(FileClaim, path="src/util.c"),
                claim(LineClaim, path="src/util.c", line=14),
                claim(SymbolClaim, name="util_copy_value"),
            ],
        )
        assert evidence.details["counts"]["location"] == 3
        assert "location" not in evidence.details["missing"]

    def test_other_kinds_do_not_fill_the_gap(self, make_ctx: MakeContext) -> None:
        evidence = _run(
            make_ctx,
            [
                claim(ReferenceClaim, ref_kind="cve", value="CVE-2026-0001"),
                claim(BehaviorClaim, subject_symbol="util_copy_value", predicate="calls_api"),
            ],
        )
        assert evidence.details["missing"] == list(FLAGGED)


def test_a_snippet_and_a_patch_are_counted_but_never_flagged(make_ctx: MakeContext) -> None:
    """SPEC §14.3 rule 2 accepts either as the artifact that saves a thin report."""
    evidence = _run(
        make_ctx,
        [
            claim(SnippetClaim, code="memcpy(dst, value, len);", n_lines=1),
            claim(PatchClaim, diff="--- a\n+++ b\n", files=("src/util.c",), hunks=()),
        ],
    )
    assert evidence.details["counts"]["snippet"] == 1
    assert evidence.details["counts"]["patch"] == 1
    assert evidence.details["missing"] == list(FLAGGED)


def test_the_counts_cover_every_category(make_ctx: MakeContext) -> None:
    evidence = _run(make_ctx, [_trace()])
    assert sorted(evidence.details["counts"]) == sorted(CATEGORIES)
    assert evidence.details["counts"]["trace"] == 1


def test_missing_keys_are_stable_and_machine_readable(make_ctx: MakeContext) -> None:
    """SPEC §14.4 keys the reporter questions off these, so they are identifiers."""
    evidence = _run(make_ctx, [_trace()])
    assert evidence.details["missing"] == ["version", "poc", "location"]
    assert set(evidence.details["missing"]) <= set(FLAGGED)


def test_the_summary_describes_the_report_and_never_the_reporter(make_ctx: MakeContext) -> None:
    """P1: no style, tone or authorship wording is allowed anywhere near this check."""
    for claims in ([], [_trace()], [_version(), claim(FileClaim, path="src/util.c")]):
        ctx = make_ctx(claims=list(claims))
        (evidence,) = ReportHygiene().run(ctx, list(ctx.claims))
        words = set(re.findall(r"[a-z]+", evidence.summary.lower()))
        assert words.isdisjoint(FORBIDDEN_WORDS)
        assert evidence.summary.startswith("the report ")


def test_applies_to_covers_every_claim_kind() -> None:
    assert ReportHygiene().applies_to == frozenset(get_args(ClaimKind))


def test_evidence_cites_no_single_claim(make_ctx: MakeContext) -> None:
    """What is absent belongs to the report, not to any one claim (SPEC §15.1)."""
    assert _run(make_ctx, [_trace()]).claim_ids == ()


class TestNeverCountsAgainstTheReporter:
    """C21 has no refuting outcome: it is always NEUTRAL with strength 0."""

    def test_the_strength_is_always_zero(self, make_ctx: MakeContext) -> None:
        for claims in ([], [_trace()], [_version(), _poc()]):
            ctx = make_ctx(claims=list(claims))
            (evidence,) = ReportHygiene().run(ctx, list(ctx.claims))
            assert evidence.outcome == "NEUTRAL"
            assert evidence.strength == 0.0
            assert "gated" not in evidence.details
            assert "withheld_strength" not in evidence.details

    def test_a_reporter_artifact_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        evidence = _run(
            make_ctx, [claim(FileClaim, path="src/util.c", provenance="reporter_artifact")]
        )
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0

    def test_a_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        evidence = _run(make_ctx, [claim(FileClaim, path="src/util.c", negated=True)])
        assert evidence.outcome == "NEUTRAL"

    def test_a_poc_counts_although_it_is_the_reporters_own_artifact(
        self, make_ctx: MakeContext
    ) -> None:
        evidence = _run(make_ctx, [_poc(provenance="reporter_artifact")])
        assert "poc" not in evidence.details["missing"]


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    claims: list[Claim] = [_version(), _trace()]
    first = _run(make_ctx, claims)
    second = _run(make_ctx, claims)
    assert first.id == second.id
    assert first.model_dump() == second.model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_trace()])
    (run,) = run_checks(ctx, checks=[ReportHygiene()])
    assert run.check_id == "C21"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["NEUTRAL"]
