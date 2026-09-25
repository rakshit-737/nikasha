# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""SPEC §14.2: keep the defaults below 50 labelled reports per class."""

from __future__ import annotations

from typing import Any

import pytest

from nikasha.bench.calibrate import (
    MIN_PER_CLASS,
    CalibrationError,
    calibrate,
    class_counts,
    features,
    should_fit,
    to_yaml,
)


def rec(label: str, source: str = "S2", verdict: str = "MIXED", **kw: Any) -> dict[str, Any]:
    return {"label": label, "source": source, "verdict": verdict, "evidence": [], **kw}


def test_threshold_is_fifty() -> None:
    assert MIN_PER_CLASS == 50


@pytest.mark.parametrize(
    ("genuine", "fabricated", "fit"),
    [(0, 0, False), (49, 50, False), (50, 49, False), (50, 50, True), (500, 51, True)],
)
def test_should_fit_needs_fifty_per_class(genuine: int, fabricated: int, fit: bool) -> None:
    ok, reason = should_fit({"genuine": genuine, "fabricated": fabricated})
    assert ok is fit
    assert ("kept defaults" in reason) is (not fit)


def test_synthetic_errors_and_unlabelled_do_not_count() -> None:
    records = [
        rec("genuine"),
        rec("genuine", source="S5"),
        rec("fabricated", verdict="ERROR"),
        rec("insufficient"),
        rec("fabricated", source="S1"),
    ]
    assert class_counts(records) == {"genuine": 1, "fabricated": 1}


def test_offline_bench_keeps_the_defaults() -> None:
    """Offline there are never 50 real reports per class, so nothing is fitted."""
    records = [rec("genuine", source="S2")] * 4 + [rec("fabricated", source="S5")] * 400
    outcome = calibrate(records)
    assert outcome.fitted is False
    assert outcome.strengths == {}
    assert "fewer than 50" in outcome.reason
    with pytest.raises(CalibrationError):
        to_yaml(outcome, 1)


def test_features_count_check_outcome_pairs() -> None:
    records = [
        rec("genuine", evidence=[{"check": "C03", "outcome": "SUPPORTS"}] * 2),
        rec("fabricated", evidence=[{"check": "C03", "outcome": "REFUTES"}]),
    ]
    keys, rows = features(records)
    assert keys == ["C03.REFUTES", "C03.SUPPORTS"]
    assert rows == [[0.0, 2.0], [1.0, 0.0]]


def test_fitting_with_enough_data() -> None:
    pytest.importorskip("sklearn")
    good = [rec("genuine", evidence=[{"check": "C03", "outcome": "SUPPORTS"}])] * 60
    bad = [rec("fabricated", evidence=[{"check": "C03", "outcome": "REFUTES"}])] * 60
    outcome = calibrate(good + bad)
    assert outcome.fitted is True
    assert outcome.strengths["C03.SUPPORTS"] > 0 > outcome.strengths["C03.REFUTES"]
    assert outcome.brier is not None
    assert "calibration-v2" in to_yaml(outcome, 2)


def test_only_the_real_split_counts() -> None:
    """S5 mutations and the S6 vulnlab fixtures are the project's own; S7 is unknown."""
    records = [
        rec("genuine", source="S6"),
        rec("fabricated", source="S6"),
        rec("genuine", source="S5"),
        rec("genuine", source="S7"),
        rec("genuine", source="S4"),
    ]
    assert class_counts(records) == {"genuine": 1, "fabricated": 0}
    many = [rec("genuine", source="S6")] * 60 + [rec("fabricated", source="S6")] * 60
    assert calibrate(many).fitted is False
