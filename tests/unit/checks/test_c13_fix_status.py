# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C13 FIX_STATUS, against the real vulnlab history (SPEC §12).

vulnlab's ``main`` is linear, so at ``v1.2.0`` exactly two later commits touch
``src/util.c``: the comment-only ``v1.2.1`` and the ``v1.3.0`` bounds-check fix.
"""

from __future__ import annotations

from check_helpers import MakeContext, claim

from nikasha.checks.base import run_checks
from nikasha.checks.c13_fix_status import FixStatus
from nikasha.model.claims import Claim, FileClaim, LineClaim, SymbolClaim


def _run(make_ctx: MakeContext, claims: list[Claim], tag: str = "v1.2.0") -> list:
    ctx = make_ctx(claims=claims, tag=tag)
    return FixStatus().run(ctx, claims)


def test_a_file_touched_after_the_claimed_version_is_reported(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path="src/util.c")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.check_id == "C13"
    assert evidence.group == "info"
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["path"] == "src/util.c"
    assert evidence.details["branch"] == "main"
    assert evidence.details["n_commits"] == 2
    assert evidence.details["truncated"] is False
    assert "may already be fixed" in evidence.summary


def test_the_commits_are_the_real_ones_newest_first(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    (evidence,) = _run(make_ctx, [claim(FileClaim, path="src/util.c")])
    assert [entry["sha"] for entry in evidence.details["commits"]] == [
        commits["v1.3.0"],
        commits["v1.2.1"],
    ]


def test_the_newest_commit_is_named_with_its_own_utc_date(
    make_ctx: MakeContext, commits: dict[str, str]
) -> None:
    (evidence,) = _run(make_ctx, [claim(FileClaim, path="src/util.c")])
    assert evidence.summary == (
        f"src/util.c was modified after the claimed version by {commits['v1.3.0'][:12]}"
        " (2026-04-25) and 1 later commit on main, which may already be fixed"
    )
    assert evidence.details["commits"][0]["date"] == "2026-04-25"
    assert evidence.details["commits"][1]["date"] == "2026-03-20"


def test_a_file_untouched_since_the_claimed_version_is_not_mentioned(
    make_ctx: MakeContext,
) -> None:
    assert _run(make_ctx, [claim(FileClaim, path="tools/hdrcat.c")]) == []


def test_the_newest_release_has_nothing_after_it(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(FileClaim, path="src/util.c")], tag="v1.3.0") == []


def test_an_older_release_sees_every_later_commit(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(FileClaim, path="src/util.c")], tag="v1.0.0")
    assert evidence.details["n_commits"] == 4


def test_a_symbol_is_followed_to_the_file_that_defines_it(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="util_copy_value")])
    assert evidence.details["path"] == "src/util.c"
    assert evidence.details["n_commits"] == 2


def test_a_symbol_defined_nowhere_is_left_to_c03(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(SymbolClaim, name="hdr_decode_chunked_value")]) == []


def test_a_line_claim_is_followed_to_its_file(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(LineClaim, path="util.c", line=14)])
    assert evidence.details["path"] == "src/util.c"


def test_claims_on_one_path_share_one_finding(make_ctx: MakeContext) -> None:
    a = claim(FileClaim, path="src/util.c")
    b = claim(LineClaim, path="src/util.c", line=14)
    (evidence,) = _run(make_ctx, [a, b])
    assert evidence.claim_ids == tuple(sorted({a.id, b.id}))


def test_one_finding_per_path_sorted_by_path(make_ctx: MakeContext) -> None:
    found = _run(
        make_ctx,
        [claim(FileClaim, path="src/util.c"), claim(FileClaim, path="src/hdr.c")],
    )
    assert [e.details["path"] for e in found] == ["src/hdr.c", "src/util.c"]


def test_an_unknown_path_is_left_to_c02(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(FileClaim, path="src/nope.c")]) == []


def test_a_pathless_line_claim_is_skipped(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(LineClaim, path=None, line=3)]) == []


def test_evidence_pins_the_file_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(FileClaim, path="src/util.c")])
    (evidence,) = FixStatus().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert (
        location.permalink
        == f"https://github.com/nikasha-demo/libhdr/blob/{ctx.commit}/src/util.c#L1"
    )


class TestNeverCountsAgainstTheReporter:
    """C13 is information for the maintainer: it has no refuting outcome at all (P1, P4)."""

    def test_a_reporter_artifact_claim_is_still_only_informational(
        self, make_ctx: MakeContext
    ) -> None:
        c = claim(FileClaim, path="src/util.c", provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        # The ADR 0003 gate never has to fire, because nothing here is ever a refutation.
        assert "gated" not in evidence.details
        assert "withheld_strength" not in evidence.details

    def test_a_negated_claim_is_still_only_informational(self, make_ctx: MakeContext) -> None:
        c = claim(FileClaim, path="src/util.c", negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert "gated" not in evidence.details

    def test_every_outcome_this_check_can_produce_is_neutral(self, make_ctx: MakeContext) -> None:
        found = _run(
            make_ctx,
            [
                claim(FileClaim, path="src/util.c"),
                claim(FileClaim, path="src/hdr.c"),
                claim(SymbolClaim, name="util_copy_value"),
            ],
        )
        assert {e.outcome for e in found} == {"NEUTRAL"}
        assert {e.strength for e in found} == {0.0}


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    c = claim(FileClaim, path="src/util.c")
    first = _run(make_ctx, [c])
    second = _run(make_ctx, [c])
    assert [e.id for e in first] == [e.id for e in second]
    assert first[0].model_dump() == second[0].model_dump()


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(FileClaim, path="src/util.c")])
    (run,) = run_checks(ctx, checks=[FixStatus()])
    assert run.check_id == "C13"
    assert run.error is None
    assert [e.outcome for e in run.evidence] == ["NEUTRAL"]
