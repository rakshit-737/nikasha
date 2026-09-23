# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``nikasha explain`` view (SPEC §14.5): the log-odds ledger behind a verdict.

The point of this view is that a reader can redo the arithmetic by hand, so the tests
check the numbers, not the prose: one row per contribution, the printed strength, weight
and contribution of each, a running total that ends exactly at ``ledger.log_odds``, and a
totals panel carrying the score, the groups, Σ|strength|, the calibration name, the
verdict and the rule that fired (P6).

Rendering goes into a ``StringIO``-backed console so the output does not depend on the
encoding of the terminal running the suite (P2).
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from nikasha.fuse.scoring import Ledger, fuse
from nikasha.model.evidence import Evidence
from nikasha.model.verdict import Verdict
from nikasha.render.explain_view import ledger_table, render_explain

WIDTH = 100
CALIBRATION = "calib-test-v7"


def console(width: int = WIDTH) -> Console:
    return Console(record=True, width=width, file=io.StringIO(), legacy_windows=False)


def render(ledger: Ledger, verdict: Verdict, items: dict[str, Evidence] | None = None) -> str:
    out = console()
    render_explain(out, ledger, verdict, items)
    return out.export_text()


def evidence(
    eid: str,
    *,
    check_id: str,
    group: str,
    outcome: str,
    strength: float,
    summary: str,
) -> Evidence:
    return Evidence(
        id=eid,
        check_id=check_id,
        claim_ids=(f"claim-{eid}",),
        outcome=outcome,  # type: ignore[arg-type]
        strength=strength,
        group=group,
        summary=summary,
    )


#: Two groups, a damped second item inside one of them, and one NEUTRAL item that must
#: never take a damping slot (SPEC §14.1).
EVIDENCE: tuple[Evidence, ...] = (
    evidence(
        "e1",
        check_id="C03",
        group="symbol",
        outcome="REFUTES",
        strength=-2.5,
        summary="not defined in any release",
    ),
    evidence(
        "e2",
        check_id="C02",
        group="file",
        outcome="SUPPORTS",
        strength=1.25,
        summary="src/hdr.c exists at v1.2.0",
    ),
    evidence(
        "e3",
        check_id="C04",
        group="symbol",
        outcome="REFUTES",
        strength=-0.5,
        summary="line 412 is past the end of the file",
    ),
    evidence(
        "e4",
        check_id="C21",
        group="hygiene",
        outcome="NEUTRAL",
        strength=0.0,
        summary="informational only",
    ),
)
BY_ID = {item.id: item for item in EVIDENCE}


def verdict_of(ledger: Ledger) -> Verdict:
    return Verdict(
        label="MIXED",
        score=ledger.score,
        confidence="medium",
        rule="6: the evidence does not separate",
    )


# --- the ledger table --------------------------------------------------------------------


def test_one_row_per_contribution_with_a_running_total() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    table = ledger_table(ledger, BY_ID)

    # The NEUTRAL item scores nothing and consumes no damping slot.
    assert len(ledger.contributions) == 3
    assert table.row_count == len(ledger.contributions)

    text = render(ledger, verdict_of(ledger), BY_ID)
    running = ledger.running()
    cursor = 0
    for contribution, total in running:
        for cell in (
            contribution.check_id,
            contribution.group,
            f"{contribution.strength:+.2f}",
            f"{contribution.weight:.3f}",
            f"{contribution.contribution:+.3f}",
            f"{total:+.3f}",
        ):
            found = text.find(cell, cursor)
            assert found >= 0, (contribution.evidence_id, cell)
        # Rows appear in the order the contributions were applied.
        cursor = text.index(contribution.check_id, cursor) + 1
        assert BY_ID[contribution.evidence_id].summary in text


def test_the_last_running_total_is_the_ledger_log_odds() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    running = ledger.running()
    assert running
    assert running[-1][1] == pytest.approx(ledger.log_odds)

    text = render(ledger, verdict_of(ledger), BY_ID)
    printed = [line for line in text.splitlines() if line.strip()]
    last_row = next(line for line in printed if line.lstrip().startswith("C04"))
    assert last_row.rstrip().endswith(f"{ledger.log_odds:+.3f}")


def test_damping_halves_the_second_finding_in_a_group() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    weights = {c.evidence_id: c.weight for c in ledger.contributions}
    assert weights == {"e1": 1.0, "e2": 1.0, "e3": 0.5}

    text = render(ledger, verdict_of(ledger), BY_ID)
    assert "0.500" in text
    assert "-0.250" in text


def test_an_empty_ledger_renders_and_shows_the_prior() -> None:
    ledger = fuse((), prior=0.75, calibration=CALIBRATION)
    assert ledger.contributions == ()
    assert ledger_table(ledger).row_count == 1

    verdict = Verdict(label="INSUFFICIENT", score=ledger.score, confidence="low")
    text = render(ledger, verdict, {})
    assert "no evidence moved the score" in text
    assert "+0.750" in text
    assert "Prior" in text
    assert "INSUFFICIENT" in text


def test_a_row_falls_back_to_the_evidence_id_when_no_summary_is_available() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    text = render(ledger, verdict_of(ledger), None)
    for item in ledger.contributions:
        assert item.evidence_id in text


# --- the totals panel --------------------------------------------------------------------


def test_the_totals_panel_carries_every_number_behind_the_verdict() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    verdict = verdict_of(ledger)
    text = render(ledger, verdict, BY_ID)

    assert f"{ledger.prior:+.3f}" in text
    assert f"{ledger.log_odds:+.3f}" in text
    assert f"{ledger.score}/100" in text
    assert ", ".join(ledger.groups) in text
    assert ledger.groups == ("file", "symbol")
    assert "Σ|strength|" in text
    assert f"{ledger.total_absolute:.2f}" in text
    assert ledger.total_absolute == pytest.approx(4.25)
    assert CALIBRATION in text
    assert verdict.label in text
    assert f"confidence: {verdict.confidence}" in text
    assert verdict.rule is not None
    assert verdict.rule in text
    assert "How the verdict was reached" in text


def test_a_verdict_without_a_rule_still_renders() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    verdict = Verdict(label="MIXED", score=ledger.score, confidence="medium", rule=None)
    text = render(ledger, verdict, BY_ID)
    assert "Rule" in text
    assert "MIXED" in text


# --- determinism (P2) --------------------------------------------------------------------


def test_the_same_input_renders_byte_for_byte_the_same() -> None:
    ledger = fuse(EVIDENCE, calibration=CALIBRATION)
    verdict = verdict_of(ledger)
    assert render(ledger, verdict, BY_ID) == render(ledger, verdict, BY_ID)


def test_reordering_the_evidence_does_not_change_the_view() -> None:
    forward = fuse(EVIDENCE, calibration=CALIBRATION)
    backward = fuse(tuple(reversed(EVIDENCE)), calibration=CALIBRATION)
    assert forward == backward
    assert render(forward, verdict_of(forward), BY_ID) == render(
        backward, verdict_of(backward), BY_ID
    )
