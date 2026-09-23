# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Log-odds fusion, group damping and confidence (SPEC §14.1, §14.3).

Fusion is pure arithmetic over :class:`Evidence`, so every case here is hand-built: no
repository, no git, no fixtures. That is deliberate — the layer that decides a verdict must
be reproducible from its inputs alone (P2, P6).
"""

from __future__ import annotations

import itertools
import math

import pytest

from nikasha.fuse.scoring import (
    DAMPING_BASE,
    DEFAULT_PRIOR,
    HIGH_GROUPS,
    HIGH_LOG_ODDS,
    MEDIUM_LOG_ODDS,
    Ledger,
    confidence_of,
    fuse,
    scoring_evidence,
    sigmoid,
)
from nikasha.model.evidence import Evidence, Outcome


def ev(
    eid: str,
    strength: float,
    group: str = "symbols",
    *,
    outcome: Outcome | None = None,
    check_id: str = "C03",
) -> Evidence:
    """One evidence item. ``outcome`` defaults to the sign of ``strength``."""
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
        claim_ids=(f"claim-{eid}",),
        outcome=outcome,
        strength=strength,
        group=group,
        summary=f"{check_id} {outcome} {strength}",
        details={"outcome": "defined"},
    )


# --- group damping -----------------------------------------------------------------------


def test_weights_halve_down_the_group_in_descending_strength_order() -> None:
    ledger = fuse([ev("a", 1.0), ev("b", -4.0), ev("c", 3.0), ev("d", -2.0)])
    assert [c.evidence_id for c in ledger.contributions] == ["b", "c", "d", "a"]
    assert [c.rank for c in ledger.contributions] == [0, 1, 2, 3]
    assert [c.weight for c in ledger.contributions] == [1.0, 0.5, 0.25, 0.125]
    assert [c.contribution for c in ledger.contributions] == [-4.0, 1.5, -0.5, 0.125]
    assert ledger.log_odds == -2.875
    assert ledger.score == 5


def test_damping_ranks_by_magnitude_not_by_sign() -> None:
    # A -4.0 refutation outranks a +3.0 support: |strength| decides who gets the full weight.
    ledger = fuse([ev("support", 3.0), ev("refute", -4.0)])
    assert [(c.evidence_id, c.weight) for c in ledger.contributions] == [
        ("refute", 1.0),
        ("support", 0.5),
    ]


def test_ties_are_broken_by_evidence_id_not_by_input_order() -> None:
    forwards = fuse([ev("zz", -2.0), ev("aa", -2.0)])
    backwards = fuse([ev("aa", -2.0), ev("zz", -2.0)])
    assert [c.evidence_id for c in forwards.contributions] == ["aa", "zz"]
    assert forwards == backwards


def test_each_group_starts_its_own_damping_ladder() -> None:
    ledger = fuse([ev("a", 2.0, "symbols"), ev("b", 2.0, "traces"), ev("c", 2.0, "files")])
    assert [c.weight for c in ledger.contributions] == [1.0, 1.0, 1.0]
    assert [c.group for c in ledger.contributions] == ["files", "symbols", "traces"]
    assert ledger.log_odds == 6.0
    assert ledger.groups == ("files", "symbols", "traces")


def test_ten_correlated_findings_cannot_outweigh_three_independent_ones() -> None:
    """The whole reason damping exists (SPEC §14.1)."""
    correlated = [ev(f"t{i}", -1.0, "traces") for i in range(10)]
    independent = [ev("s", 1.0, "symbols"), ev("f", 1.0, "files"), ev("l", 1.0, "lines")]

    # Undamped, the pile would bury the three findings: -10.0 against +3.0.
    assert sum(e.strength for e in correlated) == -10.0
    assert sum(e.strength for e in independent) == 3.0

    piled = fuse(correlated)
    assert piled.log_odds == pytest.approx(-1.998046)
    assert piled.log_odds > -2.0, "a whole group is worth less than twice its strongest item"

    both = fuse(correlated + independent)
    assert both.log_odds == pytest.approx(1.001954)
    assert both.log_odds > 0.0
    assert both.score == 73
    assert both.score > fuse(correlated).score
    assert both.score > 50, "three independent findings outweigh ten correlated ones"


@pytest.mark.parametrize("n", [1, 2, 5, 10, 20, 50])
def test_one_group_never_reaches_twice_its_strongest_item(n: int) -> None:
    ledger = fuse([ev(f"e{i:03d}", -3.0, "traces") for i in range(n)])
    # 1 + 1/2 + 1/4 + ... converges to 2, so a group is capped at twice its strongest item
    # however many correlated findings land in it.
    assert -6.0 <= ledger.log_odds <= -3.0
    assert ledger.log_odds >= -3.0 * n
    assert len(ledger.contributions) == n
    assert ledger.groups == ("traces",)


@pytest.mark.parametrize("n", [1, 2, 4, 8, 16])
def test_a_groups_total_is_the_truncated_geometric_series(n: int) -> None:
    ledger = fuse([ev(f"e{i:03d}", -3.0, "traces") for i in range(n)])
    assert ledger.log_odds == pytest.approx(-6.0 * (1.0 - 0.5**n), abs=1e-6)
    assert ledger.log_odds > -6.0


def test_the_damping_base_is_one_half() -> None:
    assert DAMPING_BASE == 0.5
    ledger = fuse([ev(f"e{i}", -2.0, "traces") for i in range(4)])
    assert [c.weight for c in ledger.contributions] == [DAMPING_BASE**i for i in range(4)]


# --- evidence that must not count ---------------------------------------------------------


def _noise() -> list[Evidence]:
    return [
        ev("n1", 0.0, "traces", outcome="NEUTRAL"),
        ev("n2", -3.0, "traces", outcome="ERROR"),
        ev("n3", 0.0, "traces", outcome="SUPPORTS"),
        ev("n4", 0.0, "traces", outcome="REFUTES"),
    ]


def test_zero_strength_neutral_and_error_evidence_contributes_nothing() -> None:
    assert scoring_evidence(_noise()) == []
    assert fuse(_noise()) == fuse([])
    assert fuse(_noise()).log_odds == 0.0
    assert fuse(_noise()).score == 50
    assert fuse(_noise()).contributions == ()
    assert fuse(_noise()).total_absolute == 0.0


def test_non_scoring_evidence_does_not_consume_a_damping_slot() -> None:
    real = [ev("r1", -2.0, "traces"), ev("r2", -1.0, "traces")]
    noise = _noise()
    # Interleaved, and the ERROR item is the strongest thing in the list: if it were ranked,
    # it would take the full weight and halve the two real findings.
    mixed = fuse([noise[0], real[0], noise[1], real[1], noise[2], noise[3]])
    assert mixed == fuse(real)
    assert [c.evidence_id for c in mixed.contributions] == ["r1", "r2"]
    assert [c.rank for c in mixed.contributions] == [0, 1]
    assert [c.weight for c in mixed.contributions] == [1.0, 0.5]
    assert mixed.log_odds == -2.5


def test_a_group_of_only_neutral_evidence_never_appears() -> None:
    ledger = fuse([ev("a", 2.0, "symbols"), ev("n", 0.0, "files", outcome="NEUTRAL")])
    assert ledger.groups == ("symbols",)
    assert [c.group for c in ledger.contributions] == ["symbols"]


# --- lambda and the score -----------------------------------------------------------------


def test_the_default_prior_is_no_opinion() -> None:
    assert DEFAULT_PRIOR == 0.0
    empty = fuse([])
    assert empty.log_odds == 0.0
    assert empty.score == 50


def test_log_odds_is_the_prior_plus_every_contribution() -> None:
    items = [ev("a", 1.5, "symbols"), ev("b", -0.5, "traces"), ev("c", 0.75, "symbols")]
    ledger = fuse(items, prior=-0.25)
    assert ledger.prior == -0.25
    assert ledger.log_odds == pytest.approx(
        -0.25 + sum(c.contribution for c in ledger.contributions)
    )
    assert ledger.log_odds == pytest.approx(-0.25 + 1.5 + 0.375 - 0.5)


def test_the_prior_shifts_the_score() -> None:
    items = [ev("a", 1.0, "symbols")]
    assert fuse(items, prior=0.0).log_odds == 1.0
    assert fuse(items, prior=2.0).log_odds == 3.0
    assert fuse(items, prior=2.0).score > fuse(items, prior=0.0).score
    assert fuse([], prior=-2.0).score == round(100 * sigmoid(-2.0))


STRENGTH_SAMPLES = (-6.0, -3.0, -1.5, -0.4, 0.0, 0.4, 1.0, 2.0, 6.0)
GROUP_SAMPLES = ("alpha", "beta", "gamma")


def test_the_score_is_always_the_rounded_logistic_and_stays_in_range() -> None:
    for i, combo in enumerate(itertools.product(STRENGTH_SAMPLES, repeat=3)):
        items = [
            ev(f"e{j}", strength, GROUP_SAMPLES[(i + j) % len(GROUP_SAMPLES)])
            for j, strength in enumerate(combo)
        ]
        ledger = fuse(items)
        assert ledger.score == round(100 * sigmoid(ledger.log_odds))
        assert 0 <= ledger.score <= 100


def test_total_absolute_is_undamped_and_ignores_non_scoring_evidence() -> None:
    ledger = fuse(
        [
            ev("a", -2.0, "traces"),
            ev("b", -2.0, "traces"),
            ev("c", 1.0, "symbols"),
            ev("d", 0.0, "files", outcome="NEUTRAL"),
        ]
    )
    assert ledger.total_absolute == 5.0
    assert ledger.log_odds == -2.0


def test_running_replays_the_arithmetic_line_by_line() -> None:
    ledger = fuse([ev("a", -2.0, "traces"), ev("b", -2.0, "traces"), ev("c", 1.0, "symbols")])
    running = ledger.running()
    assert [(c.evidence_id, total) for c, total in running] == [
        ("c", 1.0),
        ("a", -1.0),
        ("b", -2.0),
    ]
    assert running[-1][1] == ledger.log_odds


def test_the_calibration_version_is_recorded_on_the_ledger() -> None:
    assert fuse([]).calibration == "defaults-v1"
    assert fuse([], calibration="calibration-v2").calibration == "calibration-v2"


# --- sigmoid ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "x",
    [-1e308, -1e6, -10_000.0, -745.2, -709.0, -1.0, 0.0, 1.0, 709.0, 745.2, 10_000.0, 1e6, 1e308],
)
def test_sigmoid_never_overflows(x: float) -> None:
    value = sigmoid(x)
    assert math.isfinite(value)
    assert 0.0 <= value <= 1.0


def test_sigmoid_is_centred_and_symmetric() -> None:
    assert sigmoid(0.0) == 0.5
    for x in (0.25, 1.0, 4.0, 40.0, 400.0):
        assert sigmoid(-x) == pytest.approx(1.0 - sigmoid(x))


def test_sigmoid_is_monotonic() -> None:
    xs = [-1e6, -50.0, -4.0, -2.0, -0.5, 0.0, 0.5, 2.0, 4.0, 50.0, 1e6]
    values = [sigmoid(x) for x in xs]
    assert values == sorted(values)


def test_extreme_evidence_saturates_the_score_without_raising() -> None:
    assert fuse([ev("a", -1e6, "traces")]).score == 0
    assert fuse([ev("a", 1e6, "traces")]).score == 100


# --- determinism (P2) ----------------------------------------------------------------------


def _mixed_bag() -> list[Evidence]:
    return [
        ev("e1", -2.0, "traces"),
        ev("e2", -2.0, "traces"),
        ev("e3", 1.0, "symbols"),
        ev("e4", 0.0, "files", outcome="NEUTRAL"),
        ev("e5", -0.4, "lines"),
        ev("e6", 3.0, "symbols"),
    ]


def test_every_permutation_of_the_input_gives_an_identical_ledger() -> None:
    items = _mixed_bag()
    baseline = fuse(items)
    ledgers: set[Ledger] = set()
    for permutation in itertools.permutations(items):
        shuffled = fuse(list(permutation))
        assert shuffled == baseline
        assert shuffled.contributions == baseline.contributions
        assert shuffled.log_odds == baseline.log_odds
        assert shuffled.score == baseline.score
        ledgers.add(shuffled)
    assert len(ledgers) == 1


def test_reversing_the_input_does_not_move_a_single_contribution() -> None:
    items = _mixed_bag()
    forwards = fuse(items)
    backwards = fuse(list(reversed(items)))
    assert forwards.contributions == backwards.contributions
    # groups sorted, then strongest first inside each group, ties by evidence ID
    assert [c.evidence_id for c in forwards.contributions] == ["e5", "e6", "e3", "e1", "e2"]


# --- confidence (SPEC §14.3) ---------------------------------------------------------------


def test_the_confidence_bands_match_the_spec() -> None:
    assert HIGH_LOG_ODDS == 4.0
    assert HIGH_GROUPS == 3
    assert MEDIUM_LOG_ODDS == 2.0


def test_high_confidence_needs_a_large_lambda_and_three_groups() -> None:
    ledger = fuse([ev("a", 2.0, "symbols"), ev("b", 2.0, "traces"), ev("c", 2.0, "files")])
    assert ledger.log_odds == 6.0
    assert len(ledger.groups) == 3
    assert confidence_of(ledger) == "high"


def test_high_confidence_is_reachable_exactly_at_four() -> None:
    ledger = fuse([ev("a", 2.0, "symbols"), ev("b", 1.0, "traces"), ev("c", 1.0, "files")])
    assert ledger.log_odds == 4.0
    assert confidence_of(ledger) == "high"
    weaker = fuse([ev("a", 1.5, "symbols"), ev("b", 1.0, "traces"), ev("c", 1.0, "files")])
    assert weaker.log_odds == 3.5
    assert confidence_of(weaker) == "medium"


def test_a_large_lambda_from_two_groups_is_only_medium() -> None:
    """A big lambda from one or two groups is exactly the correlated case damping distrusts."""
    two = fuse([ev("a", 3.0, "symbols"), ev("b", 3.0, "traces")])
    assert two.log_odds == 6.0
    assert len(two.groups) == 2
    assert confidence_of(two) == "medium"

    one = fuse([ev(f"e{i}", 6.0, "symbols") for i in range(4)])
    assert abs(one.log_odds) >= HIGH_LOG_ODDS
    assert len(one.groups) == 1
    assert confidence_of(one) == "medium"


def test_a_neutral_third_group_does_not_buy_high_confidence() -> None:
    ledger = fuse(
        [
            ev("a", 3.0, "symbols"),
            ev("b", 3.0, "traces"),
            ev("c", 0.0, "files", outcome="NEUTRAL"),
        ]
    )
    assert ledger.log_odds == 6.0
    assert ledger.groups == ("symbols", "traces")
    assert confidence_of(ledger) == "medium"


def test_confidence_uses_the_magnitude_so_refutations_can_be_high() -> None:
    ledger = fuse([ev("a", -2.0, "symbols"), ev("b", -2.0, "traces"), ev("c", -2.0, "files")])
    assert ledger.log_odds == -6.0
    assert confidence_of(ledger) == "high"


def test_medium_starts_at_two_and_anything_smaller_is_low() -> None:
    assert confidence_of(fuse([ev("a", 2.0, "symbols")])) == "medium"
    assert confidence_of(fuse([ev("a", -2.0, "symbols")])) == "medium"
    assert confidence_of(fuse([ev("a", 1.9, "symbols")])) == "low"
    assert confidence_of(fuse([ev("a", -1.9, "symbols")])) == "low"
    assert confidence_of(fuse([])) == "low"
