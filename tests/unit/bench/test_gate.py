# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The M3.5 gate metrics (ADR 0003)."""

from __future__ import annotations

from typing import Any

from nikasha.bench.gate import best_j, compute, random_best_j, wilson_upper


def _rec(label: str, verdict: str, score: float, refuted: bool = False, **ablation: str) -> Any:
    return {
        "label": label,
        "verdict": verdict,
        "score": score,
        "evidence": [{"outcome": "REFUTES" if refuted else "SUPPORTS"}],
        "ablation": ablation,
    }


def test_gate_numbers() -> None:
    records = [
        _rec("genuine", "GROUNDED", 90),
        _rec("genuine", "MIXED", 50, refuted=True),
        _rec("genuine", "UNGROUNDED", 10, refuted=True, C01="MIXED"),
        _rec("genuine", "INSUFFICIENT", 50),
        _rec("fabricated", "UNGROUNDED", 5, refuted=True),
        _rec("fabricated", "INSUFFICIENT", 50),
        {"label": "fabricated", "verdict": "ERROR", "score": None, "evidence": []},
    ]
    g = compute(records)
    assert g["n_genuine"] == 4
    assert g["n_fabricated"] == 2
    assert g["errors"] == {"genuine": 0, "fabricated": 1}
    assert g["flag_rate"] == {"genuine": 0.5, "fabricated": 0.5, "j": 0.0}
    assert g["false_ungrounded_on_genuine"]["count"] == 1
    assert g["recall_ungrounded"] == 0.5
    assert g["j_ungrounded"] == 0.25
    assert g["p4"]["rate_within_limit"] is False
    assert g["ablation"]["C01"]["false_ungrounded_on_genuine"] == 0


def test_best_j_and_controls() -> None:
    assert best_j([1, 2], [3, 4]) == 1.0
    assert best_j([], [1]) is None
    control = random_best_j(49, 126)
    assert control is not None
    assert 0.0 < control < 0.4
    assert random_best_j(49, 126) == control  # seeded
    assert wilson_upper(0, 126) == 0.0296
    assert wilson_upper(0, 0) is None
