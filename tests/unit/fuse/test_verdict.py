# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ordered verdict ladder (SPEC §14.3).

Six rules, first match wins. The tests below fire each rule and then skip each rule for
every reason it can be skipped, because the interesting failures of a ladder are the ones
where a later rule quietly reaches a verdict an earlier rule should have taken — or, far
worse for P4, where UNGROUNDED is reached on thinner evidence than the spec allows.

Strengths come from the real ``lr_defaults.yaml`` rather than invented numbers, so a change
to the table that would move a verdict shows up here.
"""

from __future__ import annotations

import pytest

from nikasha.checks.strengths import default_strengths
from nikasha.fuse.scoring import confidence_of, fuse
from nikasha.fuse.verdict import (
    NEVER_EXISTED,
    SUBSTANTIVE_KINDS,
    VERSION_MISMATCH,
    Decision,
    Thresholds,
    decide,
    outcome_key,
)
from nikasha.model.claims import (
    Claim,
    PatchClaim,
    PocClaim,
    SnippetClaim,
    SymbolClaim,
    TraceClaim,
)
from nikasha.model.evidence import Evidence, Outcome
from nikasha.model.report import Span

STRENGTHS = default_strengths()
LIMITS = Thresholds()


def ev(
    eid: str,
    check_id: str,
    key: str,
    group: str,
    *,
    outcome: Outcome | None = None,
    claim_id: str | None = None,
) -> Evidence:
    """One evidence item carrying its strengths-table key in ``details['outcome']``."""
    strength = STRENGTHS.get(check_id, key)
    if outcome is None:
        if strength > 0.0:
            outcome = "SUPPORTS"
        elif strength < 0.0:
            outcome = "REFUTES"
        else:
            outcome = "NEUTRAL"
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=(claim_id or f"claim-{eid}",),
        outcome=outcome,
        strength=strength,
        group=group,
        summary=f"{check_id}/{key}",
        details={"outcome": key},
    )


SPAN = Span(start=0, end=4, text="body")

SYMBOL_CLAIM = SymbolClaim(
    id="claim-symbol",
    spans=(SPAN,),
    extractor="test",
    confidence=1.0,
    role="core",
    name="hdr_parse",
)
SNIPPET_CLAIM = SnippetClaim(
    id="claim-snippet",
    spans=(SPAN,),
    extractor="test",
    confidence=1.0,
    role="core",
    code="int x;",
    n_lines=1,
)
TRACE_CLAIM = TraceClaim(
    id="claim-trace",
    spans=(SPAN,),
    extractor="test",
    confidence=1.0,
    role="core",
    format="asan",
)
PATCH_CLAIM = PatchClaim(
    id="claim-patch",
    spans=(SPAN,),
    extractor="test",
    confidence=1.0,
    role="core",
    diff="--- a\n+++ b\n",
    files=("src/hdr.c",),
    hunks=(),
)
POC_CLAIM = PocClaim(
    id="claim-poc",
    spans=(SPAN,),
    extractor="test",
    confidence=1.0,
    role="core",
    poc_kind="python",
)

SUBSTANTIVE: dict[str, Claim] = {
    "snippet": SNIPPET_CLAIM,
    "trace": TRACE_CLAIM,
    "patch": PATCH_CLAIM,
    "poc": POC_CLAIM,
}


def verdict(
    evidence: list[Evidence],
    claims: list[Claim] | None = None,
    *,
    thresholds: Thresholds | None = None,
) -> Decision:
    """Fuse and decide. Claims default to a snippet so rule 2 stays out of the way."""
    return decide(
        fuse(evidence),
        evidence,
        [SNIPPET_CLAIM] if claims is None else claims,
        thresholds=thresholds,
    )


# Every never-existed outcome strong enough to open rule 3a, and the one that is not.
CORE_NEVER = sorted(pair for pair in NEVER_EXISTED if STRENGTHS.get(*pair) <= -2.0)
WEAK_NEVER = sorted(pair for pair in NEVER_EXISTED if STRENGTHS.get(*pair) > -2.0)

# Enough support to clear the GROUNDED bar on its own, so a cap or a veto is visible.
SUPPORT_LIFT = [
    ev("sup1", "C07", "contained", "snippets"),
    ev("sup2", "C09", "all_edges_real", "calls"),
]


def test_the_decision_always_reports_the_ledger_score() -> None:
    for items in ([], SUPPORT_LIFT, [ev("a", "C03", "never_in_history_core", "symbols")]):
        ledger = fuse(items)
        assert verdict(list(items)).score == ledger.score
        assert verdict(list(items)).confidence in {"low", "medium", "high"}


# --- rule 1: REPRODUCED --------------------------------------------------------------------


def test_rule_1_a_c19_signature_match_is_reproduced() -> None:
    items = [
        ev("repro", "C19", "signature_match", "repro"),
        ev("snip", "C07", "contained", "snippets"),
        ev("trace", "C08", "all_consistent", "traces"),
    ]
    decision = verdict(items)
    assert decision.label == "REPRODUCED"
    assert decision.rule.startswith("1:")
    assert decision.key_evidence == ("repro",)
    assert decision.score == 100
    assert decision.confidence == "high"
    assert decision.capped is False


@pytest.mark.parametrize("key", ["different_signature", "no_crash"])
def test_rule_1_is_skipped_when_the_poc_did_not_match_the_signature(key: str) -> None:
    items = [ev("repro", "C19", key, "repro"), ev("snip", "C07", "contained", "snippets")]
    decision = verdict(items)
    assert decision.label != "REPRODUCED"
    assert not decision.rule.startswith("1:")


def test_rule_1_reads_the_strengths_table_when_no_outcome_was_recorded() -> None:
    bare = Evidence(
        id="repro",
        check_id="C19",
        claim_ids=("claim-repro",),
        outcome="SUPPORTS",
        strength=0.5,
        group="repro",
        summary="a crash, but not the claimed one",
    )
    assert outcome_key(bare) == "different_signature"
    assert verdict([bare, *SUPPORT_LIFT]).label != "REPRODUCED"


# --- rule 2: INSUFFICIENT (nothing to check) -----------------------------------------------


def test_rule_2_one_checkable_claim_and_nothing_substantive_is_insufficient() -> None:
    items = [ev("a", "C02", "exists", "files", claim_id="c1")]
    decision = verdict(items, claims=[SYMBOL_CLAIM])
    assert decision.label == "INSUFFICIENT"
    assert decision.rule.startswith("2:")
    assert f"fewer than {LIMITS.min_checkable_claims} checkable claims" in decision.rule
    assert decision.notes


def test_rule_2_is_skipped_once_two_claims_are_checkable() -> None:
    items = [
        ev("a", "C02", "exists", "files", claim_id="c1"),
        ev("b", "C03", "defined", "symbols", claim_id="c2"),
    ]
    decision = verdict(items, claims=[SYMBOL_CLAIM])
    assert not decision.rule.startswith("2:")


@pytest.mark.parametrize("kind", sorted(SUBSTANTIVE_KINDS))
def test_rule_2_is_skipped_when_the_report_carries_something_substantive(kind: str) -> None:
    items = [ev("a", "C02", "exists", "files", claim_id="c1")]
    decision = verdict(items, claims=[SUBSTANTIVE[kind]])
    assert not decision.rule.startswith("2:")


def test_error_evidence_does_not_make_a_claim_checkable() -> None:
    items = [
        ev("a", "C02", "exists", "files", claim_id="c1"),
        ev("b", "C03", "defined", "symbols", claim_id="c2", outcome="ERROR"),
    ]
    decision = verdict(items, claims=[SYMBOL_CLAIM])
    assert decision.label == "INSUFFICIENT"
    assert decision.rule.startswith("2:")


# --- rule 3: UNGROUNDED, the hardest verdict to reach (P4) ---------------------------------


@pytest.mark.parametrize(("check_id", "key"), CORE_NEVER)
def test_rule_3a_fires_for_a_core_locus_that_never_existed(check_id: str, key: str) -> None:
    items = [
        ev("core", check_id, key, "symbols"),
        ev("snip", "C06", "elsewhere_in_file", "snippets"),
    ]
    decision = verdict(items)
    assert decision.label == "UNGROUNDED"
    assert decision.rule.startswith("3a:")
    assert decision.key_evidence == ("core",)
    assert decision.score < LIMITS.ungrounded_score
    assert decision.capped is False


def test_rule_3a_needs_refutations_from_a_second_independent_group() -> None:
    items = [
        ev("core", "C03", "never_in_history_core", "symbols"),
        ev("more", "C02", "never_in_history", "symbols"),
    ]
    decision = verdict(items)
    assert decision.score < LIMITS.ungrounded_score
    assert len({e.group for e in items}) < LIMITS.ungrounded_core_groups
    assert decision.label == "MIXED"


def test_rule_3a_needs_a_score_below_fifteen() -> None:
    items = [
        ev("core", "C03", "never_in_history_core", "symbols"),
        ev("snip", "C06", "elsewhere_in_file", "snippets"),
        ev("trace", "C08", "all_consistent", "traces"),
    ]
    decision = verdict(items)
    assert decision.score >= LIMITS.ungrounded_score
    assert decision.label == "MIXED"


@pytest.mark.parametrize(("check_id", "key"), WEAK_NEVER)
def test_rule_3a_needs_the_never_existed_refutation_to_reach_minus_two(
    check_id: str, key: str
) -> None:
    """A *supporting* locus that never existed is -1.5: real, but not enough on its own."""
    assert -2.0 < STRENGTHS.get(check_id, key) < 0.0
    items = [
        ev("weak", check_id, key, "symbols"),
        ev("ver", "C01", "future_release", "versions"),
    ]
    decision = verdict(items)
    assert decision.score < LIMITS.ungrounded_score
    assert decision.label == "MIXED"


def test_rule_3a_needs_the_never_existed_kind_not_just_a_strong_refutation() -> None:
    items = [
        ev("trace", "C08", "inconsistent", "traces"),
        ev("snip", "C06", "elsewhere_in_file", "snippets"),
    ]
    decision = verdict(items)
    assert decision.score < LIMITS.ungrounded_score
    assert len({e.group for e in items}) >= LIMITS.ungrounded_core_groups
    assert decision.label == "MIXED"


def test_rule_3b_strong_refutations_from_three_independent_groups() -> None:
    items = [
        ev("t", "C08", "inconsistent", "traces"),
        ev("l", "C04", "past_end", "lines"),
        ev("v", "C01", "future_release", "versions"),
    ]
    decision = verdict(items)
    assert decision.label == "UNGROUNDED"
    assert decision.rule.startswith("3b:")
    assert decision.key_evidence == ("l", "t", "v")
    assert decision.score < LIMITS.ungrounded_score_strict


def test_rule_3b_needs_three_groups_not_two() -> None:
    items = [
        ev("t", "C08", "inconsistent", "traces"),
        ev("l", "C04", "past_end", "lines"),
    ]
    decision = verdict(items)
    assert decision.score < LIMITS.ungrounded_score_strict
    assert decision.label == "MIXED"


def test_rule_3b_needs_a_score_below_ten() -> None:
    items = [
        ev("t", "C08", "inconsistent", "traces"),
        ev("l", "C04", "past_end", "lines"),
        ev("v", "C01", "future_release", "versions"),
        ev("s", "C07", "contained", "snippets"),
        ev("y", "C03", "defined_core", "symbols"),
    ]
    decision = verdict(items)
    strong = {e.group for e in items if e.strength <= LIMITS.ungrounded_strong_strength}
    assert len(strong) >= LIMITS.ungrounded_strong_groups
    assert LIMITS.ungrounded_score_strict <= decision.score < LIMITS.ungrounded_score
    assert decision.label == "MIXED"


def test_rule_3b_needs_every_group_to_refute_strongly() -> None:
    items = [
        ev("t", "C08", "inconsistent", "traces"),
        ev("l", "C04", "past_end", "lines"),
        ev("c", "C18", "does_not_call_api", "calls"),
    ]
    assert STRENGTHS.get("C18", "does_not_call_api") > LIMITS.ungrounded_strong_strength
    decision = verdict(items)
    assert decision.score < LIMITS.ungrounded_score_strict
    assert decision.label == "MIXED"


def test_one_group_of_refutations_never_reaches_ungrounded_however_low_the_score() -> None:
    """The P4 guarantee: correlated findings cannot manufacture a fabrication verdict."""
    items = [ev(f"e{i}", "C03", "never_in_history_core", "symbols") for i in range(10)]
    decision = verdict(items)
    assert decision.score == 0
    assert decision.label == "MIXED"
    assert decision.rule.startswith("6:")


@pytest.mark.parametrize(("check_id", "key"), sorted(NEVER_EXISTED))
def test_a_lone_never_existed_refutation_is_never_ungrounded(check_id: str, key: str) -> None:
    decision = verdict([ev("solo", check_id, key, "symbols")])
    assert decision.label == "MIXED"
    assert decision.score < 50


def test_thresholds_are_configurable_and_actually_bind() -> None:
    items = [
        ev("t", "C08", "inconsistent", "traces"),
        ev("l", "C04", "past_end", "lines"),
    ]
    assert verdict(items).label == "MIXED"
    relaxed = Thresholds(ungrounded_strong_groups=2)
    assert verdict(items, thresholds=relaxed).label == "UNGROUNDED"


# --- rule 4: the version-mismatch cap -------------------------------------------------------


def test_the_support_lift_alone_would_be_grounded() -> None:
    decision = verdict(list(SUPPORT_LIFT))
    assert decision.label == "GROUNDED"
    assert decision.score >= LIMITS.grounded_score


@pytest.mark.parametrize(("check_id", "key"), sorted(VERSION_MISMATCH))
def test_rule_4_every_version_mismatch_caps_the_verdict_at_mixed(check_id: str, key: str) -> None:
    mismatch = ev("mm", check_id, key, "versions")
    items = [mismatch, *SUPPORT_LIFT]
    decision = verdict(items)
    assert decision.label == "MIXED"
    assert decision.capped is True
    assert decision.rule.startswith("4:")
    assert decision.key_evidence == ("mm",)
    assert decision.triggers == (f"{check_id}:{key}",)
    assert decision.notes
    # Rule 5 would otherwise have called this GROUNDED: the cap is what stops it.
    assert decision.score >= LIMITS.grounded_score
    assert min(e.strength for e in items) > LIMITS.grounded_max_refutation


def test_rule_4_reports_every_trigger_sorted() -> None:
    items = [
        ev("m2", "C12", "other_release_only", "patches"),
        ev("m1", "C10", "other_release_fits", "versions"),
        *SUPPORT_LIFT,
    ]
    decision = verdict(items)
    assert decision.label == "MIXED"
    assert decision.triggers == ("C10:other_release_fits", "C12:other_release_only")
    assert decision.key_evidence == ("m1", "m2")


def test_rule_4_is_skipped_when_no_outcome_is_a_version_mismatch() -> None:
    items = [ev("ok", "C10", "claimed_release_fits", "versions"), *SUPPORT_LIFT]
    decision = verdict(items)
    assert decision.label == "GROUNDED"
    assert decision.capped is False
    assert decision.triggers == ()


def test_rule_3_still_wins_over_rule_4() -> None:
    items = [
        ev("core", "C02", "never_in_history", "files"),
        ev("mm", "C02", "missing_here_present_elsewhere", "versions"),
    ]
    assert ("C02", "missing_here_present_elsewhere") in VERSION_MISMATCH
    decision = verdict(items)
    assert decision.label == "UNGROUNDED"
    assert decision.rule.startswith("3a:")
    assert decision.capped is False


# --- rule 5: GROUNDED ------------------------------------------------------------------------


def test_rule_5_grounded_needs_a_high_score_and_no_real_refutation() -> None:
    items = [
        ev("a", "C07", "contained", "snippets"),
        ev("b", "C08", "all_consistent", "traces"),
        ev("c", "C03", "defined_core", "symbols"),
    ]
    decision = verdict(items)
    assert decision.label == "GROUNDED"
    assert decision.rule.startswith("5:")
    assert decision.score == 99
    assert decision.confidence == "high"
    assert decision.capped is False


def test_rule_5_needs_a_score_of_at_least_seventy_five() -> None:
    items = [
        ev("a", "C03", "defined_core", "symbols"),
        ev("b", "C15", "cve_matches_product", "refs"),
        ev("c", "C05", "fits_nearby_release", "lines"),
    ]
    decision = verdict(items)
    assert decision.score == 73
    assert decision.score < LIMITS.grounded_score
    # The refutation is not what blocks it: only the score is short.
    assert min(e.strength for e in items) > LIMITS.grounded_max_refutation
    assert decision.label == "MIXED"
    assert decision.rule.startswith("6:")


def test_rule_5_is_vetoed_by_a_refutation_exactly_at_the_threshold() -> None:
    items = [
        ev("a", "C07", "contained", "snippets"),
        ev("b", "C08", "all_consistent", "traces"),
        ev("c", "C18", "does_not_call_api", "calls"),
    ]
    assert STRENGTHS.get("C18", "does_not_call_api") == LIMITS.grounded_max_refutation
    decision = verdict(items)
    assert decision.score >= LIMITS.grounded_score
    assert decision.label == "MIXED"
    assert decision.rule.startswith("6:")


def test_rule_5_tolerates_a_refutation_just_above_the_threshold() -> None:
    items = [
        ev("a", "C07", "contained", "snippets"),
        ev("b", "C08", "all_consistent", "traces"),
        ev("c", "C09", "missing_edge", "calls"),
    ]
    assert STRENGTHS.get("C09", "missing_edge") > LIMITS.grounded_max_refutation
    decision = verdict(items)
    assert decision.label == "GROUNDED"
    assert decision.rule.startswith("5:")


def test_a_withheld_refutation_does_not_veto_grounded() -> None:
    """Gated claims (ADR 0003) are recorded at strength 0.0 and must not block rule 5."""
    gated = Evidence(
        id="gated",
        check_id="C03",
        claim_ids=("claim-gated",),
        outcome="NEUTRAL",
        strength=0.0,
        group="symbols",
        summary="not project-attributed, so the refutation was withheld",
        details={"outcome": "never_in_history_core", "withheld_strength": -3.0},
    )
    decision = verdict([*SUPPORT_LIFT, gated])
    assert decision.label == "GROUNDED"


# --- rule 6: the fallback ----------------------------------------------------------------


def test_rule_6_is_insufficient_below_the_total_weight_floor() -> None:
    items = [
        ev("a", "C14", "present", "files"),
        ev("b", "C09", "missing_edge", "calls"),
    ]
    ledger = fuse(items)
    assert ledger.total_absolute < LIMITS.insufficient_total
    decision = verdict(items)
    assert decision.label == "INSUFFICIENT"
    assert decision.rule.startswith("6:")
    assert str(LIMITS.insufficient_total) in decision.rule
    assert decision.notes


def test_rule_6_is_mixed_once_the_total_weight_reaches_the_floor() -> None:
    items = [
        ev("a", "C02", "exists", "files"),
        ev("b", "C09", "missing_edge", "calls"),
    ]
    ledger = fuse(items)
    assert ledger.total_absolute == LIMITS.insufficient_total
    decision = verdict(items)
    assert decision.label == "MIXED"
    assert decision.rule.startswith("6:")
    assert decision.key_evidence == ("b", "a")


# --- rule ordering: an earlier rule always wins --------------------------------------------


def test_rule_1_wins_over_rule_2() -> None:
    items = [ev("repro", "C19", "signature_match", "repro", claim_id="c1")]
    assert verdict(items, claims=[SYMBOL_CLAIM]).label == "REPRODUCED"
    # Without the C19 match the same input is INSUFFICIENT under rule 2.
    without = [ev("repro", "C19", "different_signature", "repro", claim_id="c1")]
    assert verdict(without, claims=[SYMBOL_CLAIM]).rule.startswith("2:")


def test_rule_1_wins_over_rule_3() -> None:
    refuted = [
        ev("core", "C03", "never_in_history_core", "symbols"),
        ev("file", "C02", "never_in_history", "files"),
    ]
    assert verdict(refuted).label == "UNGROUNDED"
    assert verdict([ev("repro", "C19", "signature_match", "repro"), *refuted]).label == "REPRODUCED"


def test_rule_2_wins_over_rule_3() -> None:
    items = [
        ev("core", "C03", "never_in_history_core", "symbols", claim_id="c1"),
        ev("file", "C02", "never_in_history", "files", claim_id="c1"),
    ]
    assert verdict(items, claims=[SNIPPET_CLAIM]).label == "UNGROUNDED"
    decision = verdict(items, claims=[SYMBOL_CLAIM])
    assert decision.label == "INSUFFICIENT"
    assert decision.rule.startswith("2:")


def test_rule_4_wins_over_rule_5() -> None:
    mismatch = ev("mm", "C10", "other_release_fits", "versions")
    assert verdict(list(SUPPORT_LIFT)).label == "GROUNDED"
    decision = verdict([mismatch, *SUPPORT_LIFT])
    assert decision.label == "MIXED"
    assert decision.capped is True


def test_rule_5_wins_over_rule_6() -> None:
    # Total weight 1.1 is under the rule-6 floor, so rule 6 would say INSUFFICIENT.
    items = [
        ev("a", "C03", "defined", "symbols"),
        ev("b", "C02", "exists", "files"),
    ]
    ledger = fuse(items)
    assert ledger.total_absolute < LIMITS.insufficient_total
    assert ledger.score >= LIMITS.grounded_score
    decision = verdict(items)
    assert decision.label == "GROUNDED"
    assert decision.rule.startswith("5:")


def test_the_whole_ladder_in_order() -> None:
    reproduced = [ev("repro", "C19", "signature_match", "repro")]
    ungrounded = [
        ev("core", "C03", "never_in_history_core", "symbols"),
        ev("file", "C02", "never_in_history", "files"),
    ]
    capped = [ev("mm", "C10", "other_release_fits", "versions"), *SUPPORT_LIFT]
    thin = [ev("a", "C02", "exists", "files"), ev("b", "C09", "missing_edge", "calls")]
    expected = [
        (reproduced, "REPRODUCED", "1:"),
        (ungrounded, "UNGROUNDED", "3a:"),
        (capped, "MIXED", "4:"),
        (list(SUPPORT_LIFT), "GROUNDED", "5:"),
        (thin, "MIXED", "6:"),
    ]
    for items, label, rule in expected:
        decision = verdict(items)
        assert decision.label == label
        assert decision.rule.startswith(rule)
    # Rule 2 needs a report with nothing substantive in it, so it gets its own row.
    lone = [ev("a", "C02", "exists", "files", claim_id="c1")]
    assert verdict(lone, claims=[SYMBOL_CLAIM]).rule.startswith("2:")


# --- confidence -----------------------------------------------------------------------------


def test_confidence_comes_from_the_ledger() -> None:
    items = [
        ev("a", "C07", "contained", "snippets"),
        ev("b", "C08", "all_consistent", "traces"),
        ev("c", "C03", "defined_core", "symbols"),
    ]
    ledger = fuse(items)
    assert decide(ledger, items, [SNIPPET_CLAIM]).confidence == confidence_of(ledger)


def test_reproduced_is_high_confidence_by_definition() -> None:
    """ADR 0007 decision 2: rule 1 is a documented exception to the confidence formula.

    The formula distrusts a large lambda that comes from a single group, because several
    findings in one group may be restatements of one fact. A reproduction is not
    statistical evidence: the PoC ran and the crash signature matched. So rule 1 reports
    high confidence even though the formula, applied blindly, would say medium.
    """
    items = [ev("repro", "C19", "signature_match", "repro")]
    ledger = fuse(items)
    assert abs(ledger.log_odds) >= 4.0
    assert len(ledger.groups) == 1
    assert confidence_of(ledger) == "medium"
    assert decide(ledger, items, [POC_CLAIM]).confidence == "high"


# --- the LLM is never decisive (P2) --------------------------------------------------------


def test_an_llm_refutation_never_counts_as_a_corroborating_group() -> None:
    """A capped model answer must not be the second group that opens rule 3a."""
    core = ev("core", "C03", "never_in_history_core", "symbols")
    model = Evidence(
        id="llm",
        check_id="C20",
        claim_ids=("claim-llm",),
        outcome="REFUTES",
        strength=-STRENGTHS.get("C20", "llm_cap"),
        group="llm",
        summary="model review",
        details={"outcome": "refuted"},
        produced_by="llm",
    )
    assert verdict([core]).label != "UNGROUNDED"
    decision = verdict([core, model])
    assert decision.score < LIMITS.ungrounded_score
    assert decision.label != "UNGROUNDED"


@pytest.mark.parametrize("strength", [-0.5, -1.2, -3.0])
def test_an_llm_refutation_never_blocks_grounded(strength: float) -> None:
    """Rule 5's refutation gate reads deterministic evidence only (P2, ADR 0007).

    With the threshold at -0.4 the default capped answer (-0.5) would veto GROUNDED if
    the gate counted it; an uncapped item must not either.
    """
    items = [
        ev("a", "C07", "contained", "snippets"),
        ev("b", "C08", "all_consistent", "traces"),
        ev("c", "C03", "defined_core", "symbols"),
    ]
    model = Evidence(
        id="llm",
        check_id="C20",
        claim_ids=("claim-llm",),
        outcome="REFUTES",
        strength=strength,
        group="llm",
        summary="model review",
        details={"outcome": "refuted"},
        produced_by="llm",
    )
    limits = Thresholds(grounded_max_refutation=-0.4)
    decision = verdict([*items, model], thresholds=limits)
    assert decision.score >= limits.grounded_score
    assert decision.label == "GROUNDED"
    assert "llm" not in decision.key_evidence


def test_a_deterministic_refutation_still_blocks_grounded_at_the_same_threshold() -> None:
    items = [
        ev("a", "C07", "contained", "snippets"),
        ev("b", "C08", "all_consistent", "traces"),
        ev("c", "C09", "missing_edge", "calls"),
    ]
    limits = Thresholds(grounded_max_refutation=-0.4)
    assert STRENGTHS.get("C09", "missing_edge") <= limits.grounded_max_refutation
    assert verdict(items, thresholds=limits).label != "GROUNDED"


def test_rule_1_needs_a_supporting_deterministic_signature_match() -> None:
    errored = ev("repro", "C19", "signature_match", "repro", outcome="ERROR")
    assert verdict([errored, *SUPPORT_LIFT]).label != "REPRODUCED"


def test_an_errored_c12_is_not_read_as_already_applied() -> None:
    errored = Evidence(
        id="c12-error",
        check_id="C12",
        claim_ids=("claim-patch",),
        outcome="ERROR",
        strength=0.0,
        group="patch",
        summary="apply failed to run",
        details={},
    )
    assert outcome_key(errored) is None
    decision = verdict([errored, *SUPPORT_LIFT])
    assert not decision.capped
    assert "c12-error" not in decision.key_evidence
