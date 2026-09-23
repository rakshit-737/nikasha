# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C18 API_USAGE, against the real vulnlab tree (SPEC §12).

The call graph facts these tests assert come from ``examples/vulnlab/README.md``: at v1.2.0
``hdr_parse_line`` calls ``util_copy_value`` directly (src/hdr.c:104), ``hdr_get`` reaches
``hdr_casecmp`` through the ten-line ``hdr_find_line``, and ``hdr_parse_block`` calls
``hdr_parse_line`` but never ``util_copy_value`` itself.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from conftest import MakeContext, claim
from nikasha.checks.base import CheckContext, run_checks
from nikasha.checks.c18_api_usage import ApiUsage, Site, absence_uncertainty, calls_inside
from nikasha.code.facts import CallSite
from nikasha.model.claims import BehaviorClaim

OTHER_PREDICATES = ("missing_bounds_check", "missing_null_check", "uses_freed", "integer_overflow")


def _run(make_ctx: MakeContext, claims: list[BehaviorClaim], tag: str = "v1.2.0") -> list:
    ctx = make_ctx(claims=claims, tag=tag)
    return ApiUsage().run(ctx, claims)


def _calls(subject: str, obj: str | None = None, **fields: Any) -> BehaviorClaim:
    return claim(BehaviorClaim, subject_symbol=subject, predicate="calls_api", object=obj, **fields)


def _site(ctx: CheckContext, path: str, name: str, **changes: Any) -> Site:
    """A :class:`Site` built from the real parsed facts, optionally perturbed for a P4 test."""
    facts = ctx.facts(path)
    assert facts is not None
    (symbol,) = [s for s in facts.symbols if s.name == name]
    return Site(path, symbol, replace(facts, **changes) if changes else facts)


# --- calls_api: the one predicate C18 decides ---------------------------------------------


def test_a_direct_call_supports(make_ctx: MakeContext) -> None:
    c = _calls("hdr_parse_line", "util_copy_value")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.8
    assert evidence.check_id == "C18"
    assert evidence.group == "behavior"
    assert evidence.claim_ids == (c.id,)
    assert evidence.details["edge"] == "direct"
    assert evidence.details["call_sites"] == ["src/hdr.c:104"]
    assert "hdr_parse_line calls util_copy_value" in evidence.summary


def test_a_one_hop_call_through_a_small_wrapper_supports(make_ctx: MakeContext) -> None:
    """SPEC §12 counts "within 1 hop": an optimizer erases the wrapper's frame."""
    (evidence,) = _run(make_ctx, [_calls("hdr_get", "hdr_casecmp")])
    assert evidence.outcome == "SUPPORTS"
    assert evidence.strength == 0.8
    assert evidence.details["edge"] == "inlined_2hop"
    assert "via hdr_find_line" in evidence.summary


def test_a_call_that_is_not_made_refutes_and_lists_the_real_calls(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_calls("hdr_parse_block", "util_copy_value")])
    assert evidence.outcome == "REFUTES"
    assert evidence.strength == -1.2
    assert evidence.details["edge"] == "none"
    assert evidence.details["calls"] == [
        "free",
        "hdr_parse_line",
        "malloc",
        "memcpy",
        "strchr",
        "strlen",
    ]
    assert "does not call util_copy_value" in evidence.summary
    assert "it calls free, hdr_parse_line, malloc, memcpy, strchr, strlen" in evidence.summary


def test_a_refutation_locates_the_subject_at_the_exact_commit(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_calls("hdr_parse_block", "util_copy_value")])
    (evidence,) = ApiUsage().run(ctx, list(ctx.claims))
    (location,) = evidence.locations
    assert (location.path, location.start_line, location.end_line) == ("src/hdr.c", 118, 143)
    assert location.commit == ctx.commit
    assert location.permalink is not None
    assert location.permalink.endswith(f"/blob/{ctx.commit}/src/hdr.c#L118-L143")


def test_support_shows_both_the_definition_and_the_call_site(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_calls("hdr_parse_line", "util_copy_value")])
    (evidence,) = ApiUsage().run(ctx, list(ctx.claims))
    assert [(loc.path, loc.start_line, loc.end_line) for loc in evidence.locations] == [
        ("src/hdr.c", 83, 116),
        ("src/hdr.c", 104, 104),
    ]


def test_a_call_claimed_against_a_release_that_dropped_the_function(make_ctx: MakeContext) -> None:
    """v1.3.0 renamed ``hdr_get`` to ``hdr_find``; a missing subject is never a refutation."""
    (evidence,) = _run(make_ctx, [_calls("hdr_get", "util_strip")], tag="v1.3.0")
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert "not defined at this commit" in evidence.details["uncertain"]
    (before,) = _run(make_ctx, [_calls("hdr_get", "util_strip")])
    assert before.outcome == "SUPPORTS"


def test_a_calls_api_claim_with_no_named_api_is_neutral(make_ctx: MakeContext) -> None:
    (evidence,) = _run(make_ctx, [_calls("util_strip")])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert "does not name the API" in evidence.summary
    assert [loc.path for loc in evidence.locations] == ["src/util.c"]


# --- the other four predicates: NEUTRAL, but the locus is still shown ----------------------


@pytest.mark.parametrize("predicate", OTHER_PREDICATES)
def test_other_predicates_are_neutral_but_locate_the_code(
    make_ctx: MakeContext, predicate: str
) -> None:
    c = claim(BehaviorClaim, subject_symbol="util_copy_value", predicate=predicate)
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.strength == 0.0
    assert evidence.details["predicate"] == predicate
    (location,) = evidence.locations
    assert (location.path, location.start_line, location.end_line) == ("src/util.c", 8, 18)
    assert location.permalink is not None
    assert "dataflow" in evidence.summary


def test_an_other_predicate_on_an_unknown_symbol_suggests_neighbours(
    make_ctx: MakeContext,
) -> None:
    c = claim(BehaviorClaim, subject_symbol="util_copy_valu", predicate="missing_bounds_check")
    (evidence,) = _run(make_ctx, [c])
    assert evidence.outcome == "NEUTRAL"
    assert evidence.locations == ()
    assert "util_copy_value" in evidence.details["suggestions"]


# --- P4: absence is never proof -----------------------------------------------------------


class TestAbsenceSafeguards:
    """A refutation requires code that *could* have shown the call (P4)."""

    def test_an_undefined_subject_is_not_refuted(self, make_ctx: MakeContext) -> None:
        (evidence,) = _run(make_ctx, [_calls("hdr_fold_lines", "memcpy")])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["uncertain"] == "the function is not defined at this commit"

    def test_a_clean_parse_with_no_pointer_calls_permits_the_refutation(
        self, ctx: CheckContext
    ) -> None:
        assert absence_uncertainty([_site(ctx, "src/util.c", "util_strip")], "malloc") is None

    def test_a_partially_parsed_file_blocks_the_refutation(self, ctx: CheckContext) -> None:
        site = _site(ctx, "src/util.c", "util_strip", parsed_ok=False)
        reason = absence_uncertainty([site], "malloc")
        assert reason is not None
        assert "did not parse cleanly" in reason

    def test_an_indirect_call_blocks_the_refutation(self, ctx: CheckContext) -> None:
        facts = ctx.facts("src/util.c")
        assert facts is not None
        pointer_call = CallSite(caller_qname="util_strip", callee="cb", line=30, indirect=True)
        site = _site(ctx, "src/util.c", "util_strip", calls=(*facts.calls, pointer_call))
        reason = absence_uncertainty([site], "malloc")
        assert reason is not None
        assert "could dispatch anywhere" in reason
        assert "src/util.c:30" in reason

    def test_an_indirect_call_outside_the_subject_does_not_block_it(
        self, ctx: CheckContext
    ) -> None:
        """The pointer call must be inside the subject; another function's is irrelevant."""
        facts = ctx.facts("src/util.c")
        assert facts is not None
        elsewhere = CallSite(caller_qname="util_copy_value", callee="cb", line=15, indirect=True)
        site = _site(ctx, "src/util.c", "util_strip", calls=(*facts.calls, elsewhere))
        assert absence_uncertainty([site], "malloc") is None

    def test_an_address_taken_callee_blocks_the_refutation(self, ctx: CheckContext) -> None:
        site = _site(ctx, "src/util.c", "util_strip", addr_taken=frozenset({"malloc"}))
        reason = absence_uncertainty([site], "malloc")
        assert reason is not None
        assert "address of malloc is taken" in reason

    def test_calls_are_attributed_to_the_enclosing_definition(self, ctx: CheckContext) -> None:
        inside = calls_inside(_site(ctx, "src/util.c", "util_copy_value"))
        assert sorted({call.callee for call in inside}) == ["malloc", "memcpy", "strlen"]


# --- the framework contracts ---------------------------------------------------------------


class TestRefutationGate:
    """ADR 0003: only project-attributed, non-negated claims may be refuted."""

    def test_reporter_artifact_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _calls("hdr_parse_block", "util_copy_value", provenance="reporter_artifact")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.strength == 0.0
        assert evidence.details["gated"] == ["reporter_artifact"]
        assert evidence.details["withheld_strength"] == -1.2

    def test_negated_claim_is_not_refuted(self, make_ctx: MakeContext) -> None:
        c = _calls("hdr_parse_block", "util_copy_value", negated=True)
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "NEUTRAL"
        assert evidence.details["gated"] == ["negated"]

    def test_support_is_not_gated(self, make_ctx: MakeContext) -> None:
        c = _calls("hdr_parse_line", "util_copy_value", provenance="third_party")
        (evidence,) = _run(make_ctx, [c])
        assert evidence.outcome == "SUPPORTS"
        assert evidence.strength == 0.8


def test_identical_input_gives_identical_evidence_ids(make_ctx: MakeContext) -> None:
    claims = [
        _calls("hdr_parse_block", "util_copy_value"),
        _calls("hdr_parse_line", "util_copy_value"),
        claim(BehaviorClaim, subject_symbol="util_copy_value", predicate="missing_bounds_check"),
    ]
    first = _run(make_ctx, claims)
    second = _run(make_ctx, claims)
    assert [e.id for e in first] == [e.id for e in second]
    assert [e.model_dump() for e in first] == [e.model_dump() for e in second]


def test_registered_and_runnable_through_the_runner(make_ctx: MakeContext) -> None:
    ctx = make_ctx(claims=[_calls("hdr_parse_block", "util_copy_value")])
    (run,) = run_checks(ctx, checks=[ApiUsage()])
    assert run.check_id == "C18"
    assert run.error is None
    assert run.seconds >= 0.0
    assert [e.outcome for e in run.evidence] == ["REFUTES"]


def test_only_behavior_claims_are_selected(ctx: CheckContext) -> None:
    check = ApiUsage()
    assert check.applies_to == frozenset({"behavior"})
    assert check.run(ctx, []) == []
