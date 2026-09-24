# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C03 SYMBOL_EXISTS, against the real vulnlab history (SPEC §12).

The vulnlab facts these tests lean on (``examples/vulnlab/README.md``):
``util_copy_value`` arrives in v1.1.0 and stays; ``util_trim`` exists only in v1.0.0;
``hdr_get`` runs from v1.0.0 to v1.2.1 and is replaced by ``hdr_find`` in v1.3.0;
``memcpy`` is called but never defined; nothing in the history ever mentions
``hdr_parse_lines``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from check_helpers import MakeContext, claim

from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c03_symbol_exists import SymbolExists
from nikasha.code.gitio import GitRepo
from nikasha.code.timeline import ReleasePresence, Timeline
from nikasha.model.claims import SymbolClaim

#: A name that is in no release and in no commit: the only kind that may be called absent.
NEVER = "hdr_parse_lines"


def _run(make_ctx: MakeContext, claims: list[SymbolClaim], tag: str = "v1.2.0") -> list:
    ctx = make_ctx(claims=claims, tag=tag)
    return SymbolExists().run(ctx, claims)


# --- defined at the ref --------------------------------------------------------------------


def test_a_defined_symbol_supports(make_ctx: MakeContext) -> None:
    c = claim(SymbolClaim, name="util_copy_value")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.6
    assert evidence.check_id == "C03"
    assert evidence.group == "locus"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["definitions"] == [
        {"path": "src/util.c", "kind": "function", "start_line": 8, "end_line": 18}
    ]
    assert "src/util.c:8" in evidence.summary


def test_a_core_symbol_that_exists_supports_more_strongly(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="util_copy_value", role="core")])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 1.0


def test_a_macro_definition_counts_as_a_definition(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="HDR_VALUE_MAX")])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["definitions"][0]["path"] == "src/util.h"
    assert evidence.details["definitions"][0]["kind"] == "macro"


def test_evidence_carries_the_definition_span_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(SymbolClaim, name="util_copy_value")])
    (evidence,) = SymbolExists().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert location.commit == ctx.commit
    assert location.path == "src/util.c"
    assert (location.start_line, location.end_line) == (8, 18)
    assert (
        location.permalink
        == f"https://github.com/nikasha-demo/libhdr/blob/{ctx.commit}/src/util.c#L8-L18"
    )


def test_the_file_the_report_names_is_searched_first(make_ctx: MakeContext) -> None:
    c = claim(SymbolClaim, name="util_copy_value", context_path="util.c")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.details["definitions"][0]["path"] == "src/util.c"


def test_a_symbol_in_a_different_file_than_claimed_still_exists(make_ctx: MakeContext) -> None:
    # Where it lives is C05's question; C03 only asks whether it is there at all.
    c = claim(SymbolClaim, name="util_copy_value", context_path="src/hdr.c")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["definitions"][0]["path"] == "src/util.c"


# --- referenced or external ------------------------------------------------------------------


def test_a_symbol_that_is_only_called_here_is_neutral(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="memcpy")])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["references"][0]["path"] == "src/hdr.c"
    assert evidence.details["n_references"] == 3
    assert evidence.details["command"].startswith("git grep")
    # Only "no parsed definition" is established: an unparsed file may hold it (P4).
    assert "no definition of it was found in the files that could be parsed" in evidence.summary
    assert "not defined in this repository" not in evidence.summary


def test_an_external_symbol_is_not_judged(make_ctx: MakeContext) -> None:
    c = claim(SymbolClaim, name="hdr_decode_chunked_value", external=True, role="core")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["external"] is True


# --- absent here, present elsewhere -----------------------------------------------------------


def test_a_symbol_added_later_refutes_weakly_and_names_the_release(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="hdr_find")])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.8
    assert evidence.details["runs"] == [["v1.3.0", "v1.3.0"]]
    assert evidence.details["defined_in"] == ["v1.3.0"]
    assert evidence.summary.endswith("it is defined in v1.3.0")


def test_a_symbol_removed_before_the_ref_reports_the_run_it_had(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="hdr_get")], tag="v1.3.0")
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -0.8
    assert evidence.details["runs"] == [["v1.0.0", "v1.2.1"]]
    assert "v1.0.0-v1.2.1" in evidence.summary


def test_a_symbol_from_the_oldest_release_only_is_absent_at_a_later_ref(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="util_trim")])
    assert evidence.outcome == "REFUTES"
    assert evidence.details["defined_in"] == ["v1.0.0"]
    assert evidence.details["releases_searched"] == [
        "v1.0.0",
        "v1.1.0",
        "v1.2.0",
        "v1.2.1",
        "v1.3.0",
    ]


# --- never in any release, and never in history -------------------------------------------------


def test_a_name_absent_from_every_release_and_commit_refutes_a_core_claim(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name=NEVER, role="core")])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -3.0
    assert evidence.details["never_in_history"] is True
    assert evidence.details["history_complete"] is True
    assert evidence.details["suggestions"] == ["hdr_parse_line"]
    assert evidence.summary.endswith("did you mean hdr_parse_line?")
    assert "never appears anywhere in this repository's history" in evidence.summary


def test_the_same_name_in_a_supporting_claim_refutes_only_half_as_hard(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name=NEVER)])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.5


def test_a_name_with_no_close_match_gets_no_suggestion(make_ctx: MakeContext) -> None:
    c = claim(SymbolClaim, name="hdr_decode_chunked_value", role="core")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "REFUTES"
    assert evidence.details["suggestions"] == []
    assert "did you mean" not in evidence.summary


class TestP4NeverSaysNeverOnIncompleteEvidence:
    """The safeguards that stop C03 turning a gap in the evidence into an accusation."""

    def test_a_timed_out_history_search_is_downgraded_and_says_so(
        self, make_ctx: MakeContext
    ) -> None:
        c = claim(SymbolClaim, name=NEVER, role="core")
        ctx = make_ctx(claims=[c])
        ctx.history_timeout = 0.000001  # a real `log -S` that cannot finish in a microsecond
        (evidence,) = SymbolExists().run(ctx, [c])
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -1.5  # absent_in_sampled_core, not never_in_history_core
        assert evidence.details["history_complete"] is False
        assert "timed out" in evidence.details["history_gap"]
        assert "history is incomplete" in evidence.summary
        assert "never appears anywhere" not in evidence.summary

    def test_an_incomplete_history_says_nothing_at_all_about_a_supporting_claim(
        self, make_ctx: MakeContext
    ) -> None:
        c = claim(SymbolClaim, name=NEVER)
        ctx = make_ctx(claims=[c])
        ctx.history_timeout = 0.000001
        (evidence,) = SymbolExists().run(ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["history_complete"] is False

    def test_a_shallow_repository_is_never_proof_of_absence(
        self, make_ctx: MakeContext, vulnlab_repo: Path, tmp_path: Path
    ) -> None:
        c = claim(SymbolClaim, name=NEVER, role="core")
        ctx = make_ctx(claims=[c])
        shallow_dir = tmp_path / "shallow.git"
        shutil.copytree(vulnlab_repo, shallow_dir)
        # What `git clone --depth` leaves behind: the grafted boundary commit.
        (shallow_dir / "shallow").write_text(ctx.commit + "\n", encoding="ascii")
        with GitRepo(shallow_dir) as shallow:
            assert shallow.is_shallow()
            ctx.resolution.repo = shallow
            (evidence,) = SymbolExists().run(ctx, [c])
        assert evidence.outcome == "REFUTES"
        assert evidence.strength == -1.5
        assert evidence.details["history_gap"] == "the repository is a shallow clone"

    def test_a_release_that_did_not_parse_cleanly_blocks_every_refutation(
        self, make_ctx: MakeContext
    ) -> None:
        c = claim(SymbolClaim, name=NEVER, role="core")
        ctx = make_ctx(claims=[c])
        _seed_uncertain(ctx, NEVER, release="v1.2.0", path="src/hdr.c")
        (evidence,) = SymbolExists().run(ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["uncertain_releases"] == ["v1.2.0"]
        assert "did not parse cleanly" in evidence.summary

    def test_a_generated_file_is_never_judged(self, make_ctx: MakeContext) -> None:
        c = claim(SymbolClaim, name=NEVER, role="core", context_path="src/config.h")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["generated"] == "matches 'config.h'"
        assert "not judged" in evidence.summary


def _seed_uncertain(ctx: CheckContext, name: str, *, release: str, path: str) -> None:
    """Mark one release of the real timeline as "mentions the name in an unparsed file".

    Every vulnlab file parses cleanly, so the one condition that cannot be produced from
    the fixture repository is injected into the real timeline instead of faked wholesale.
    """
    real = ctx.timeline(name)
    presence = [
        ReleasePresence(p.release, False, True, (), (path,)) if p.release == release else p
        for p in real.presence
    ]
    ctx._timelines[name] = Timeline(
        symbol=real.symbol,
        strategy=real.strategy,
        presence=presence,
        history_complete=real.history_complete,
        never_in_history=real.never_in_history,
    )


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(SymbolClaim, name="hdr_find", provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -0.8

    def test_a_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = claim(SymbolClaim, name=NEVER, role="core", negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]
        assert evidence.details["withheld_strength"] == -3.0

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = claim(SymbolClaim, name="util_copy_value", provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 0.6


def test_a_nameless_claim_is_skipped(make_ctx: MakeContext) -> None:
    assert _run(make_ctx, [claim(SymbolClaim, name="   ")]) == []


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    claims = [claim(SymbolClaim, name="util_copy_value"), claim(SymbolClaim, name="hdr_find")]
    first = _run(make_ctx, claims)
    second = _run(make_ctx, claims)
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[claim(SymbolClaim, name=NEVER, role="core")])
    (run,) = run_checks(ctx, checks=[SymbolExists()])
    assert run.check_id == "C03"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


# --- review fixes -----------------------------------------------------------------------------


def test_claims_left_when_the_budget_runs_out_are_recorded_identically(
    make_ctx: MakeContext,
) -> None:
    claims = [claim(SymbolClaim, name="util_copy_value"), claim(SymbolClaim, name=NEVER)]
    ctx = make_ctx(claims=claims)
    ctx.deadline = 0.0  # already spent
    evidence = SymbolExists().run(ctx, claims)
    assert [e.outcome for e in evidence] == ["NEUTRAL", "NEUTRAL"]
    assert [e.details["outcome"] for e in evidence] == ["budget_expired"] * 2
    assert all(e.strength == 0.0 for e in evidence)
    assert (
        evidence[1].summary == f"{NEVER} was not checked: the check's time budget ran out before it"
    )


def test_text_found_by_a_completed_history_search_is_not_refuted(make_ctx: MakeContext) -> None:
    c = claim(SymbolClaim, name=NEVER, role="core")
    ctx = make_ctx(claims=[c])
    real = ctx.timeline(NEVER)
    ctx._timelines[NEVER] = Timeline(
        symbol=real.symbol,
        strategy=real.strategy,
        presence=real.presence,
        history_complete=True,
        never_in_history=False,
        first_commit_with_text=ctx.commit,
    )
    (evidence,) = SymbolExists().run(ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["outcome"] == "in_history_not_released"
    assert evidence.details["history_complete"] is True
    assert evidence.details["first_commit_with_text"] == ctx.commit
    assert "did not run" not in evidence.summary


def test_a_qualified_spelling_finds_the_bare_definition(make_ctx: MakeContext) -> None:
    for spelling in ("Util::util_copy_value", "util.util_copy_value", "Util#util_copy_value"):
        (evidence,) = _run(make_ctx, [claim(SymbolClaim, name=spelling, role="core")])
        assert evidence.outcome == "SUPPORTS", spelling
        assert evidence.details["definitions"][0]["path"] == "src/util.c"


def test_a_qualified_spelling_of_an_existing_name_is_never_called_absent(
    make_ctx: MakeContext,
) -> None:
    (evidence,) = _run(make_ctx, [claim(SymbolClaim, name="std::memcpy", role="core")])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.details["outcome"] == "referenced_only"


def test_a_definition_wins_over_a_generated_context_path(make_ctx: MakeContext) -> None:
    c = claim(SymbolClaim, name="util_copy_value", context_path="src/config.h")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.details["definitions"][0]["path"] == "src/util.c"
