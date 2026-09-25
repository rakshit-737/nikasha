# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""SPEC §17.4 metrics on hand-built records."""

from __future__ import annotations

from typing import Any

from nikasha.bench.metrics import brier, compute, ece, percentile, render_markdown

#: Split so that REUSE does not read this module's templates as its own licence tags.
_SPDX = "SPDX"


def rec(
    id: str, source: str, label: str, verdict: str, score: int | None, **extra: Any
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": id,
        "source": source,
        "label": label,
        "verdict": verdict,
        "score": score,
        "expected": None,
        "mutation": None,
        "rule": "r",
        "ablation": {},
        "timing": {"seconds": 1.0},
    }
    base.update(extra)
    return base


RECORDS = [
    rec("g1", "S2", "genuine", "GROUNDED", 90),
    rec("g2", "S2", "genuine", "UNGROUNDED", 10),
    rec("f1", "S1", "fabricated", "UNGROUNDED", 5),
    rec("f2", "S1", "fabricated", "MIXED", 40),
    rec("f3", "S3", "fabricated", "INSUFFICIENT", 50),
    rec(
        "m3",
        "S5",
        "genuine",
        "MIXED",
        60,
        mutation="M3",
        expected="MIXED",
        ablation={"C10": "GROUNDED", "C03": "MIXED"},
        timing={"seconds": 9.0},
    ),
    rec("m1", "S5", "fabricated", "MIXED", 70, mutation="M1", expected="UNGROUNDED"),
]


def test_headline_rates() -> None:
    m = compute(RECORDS)
    assert m["false_ungrounded_on_genuine"] == {"count": 1, "of": 3, "rate": 0.3333}
    assert m["recall_ungrounded"] == {"real_s1_s3": 0.3333, "synthetic_s5": 0.0}
    assert m["recall_ungrounded_or_mixed"] == {"real_s1_s3": 0.6667, "synthetic_s5": 1.0}
    assert m["mixed_rate_on_m3"] == 1.0
    assert m["coverage"] == round(6 / 7, 4)
    assert m["expected_match"] == {"matched": 1, "of": 2, "rate": 0.5}
    assert m["mismatches"] == [
        {"id": "m1", "expected": "UNGROUNDED", "verdict": "MIXED", "rule": "r"}
    ]
    assert m["by_source"] == {"S1": 2, "S2": 2, "S3": 1, "S5": 2}
    assert m["confusion"]["fabricated"]["UNGROUNDED"] == 1


def test_ablation_counts_changes_and_correctness() -> None:
    m = compute(RECORDS)
    assert m["ablation"] == {
        "C03": {"changed": 0, "became_wrong": 0, "became_right": 0, "new_false_ungrounded": 0},
        "C10": {"changed": 1, "became_wrong": 1, "became_right": 0, "new_false_ungrounded": 0},
    }


def test_latency_lives_under_timing() -> None:
    m = compute(RECORDS)
    assert m["timing"] == {"p50_seconds": 1.0, "p95_seconds": 9.0}


def test_percentile_brier_ece() -> None:
    assert percentile([], 50) is None
    assert percentile([3.0, 1.0, 2.0], 50) == 2.0
    assert percentile([1.0, 2.0, 3.0, 4.0], 95) == 4.0
    assert brier([(1.0, 1), (0.0, 0)]) == 0.0
    assert brier([(0.0, 1)]) == 1.0
    assert ece([(1.0, 1), (0.0, 0)]) == 0.0
    assert ece([(0.9, 0), (0.9, 0)]) == 0.9
    assert brier([]) is None
    assert ece([]) is None


def test_empty_input_gives_none_not_zero() -> None:
    m = compute([])
    assert m["false_ungrounded_on_genuine"]["rate"] is None
    assert m["coverage"] is None


def test_markdown_is_deterministic_and_escapes_cells() -> None:
    records = [*RECORDS[:-1], {**RECORDS[-1], "rule": "a | b"}]
    m = compute(records)
    first = render_markdown(m, date="2026-01-01", split="all", commit="abc")
    assert first == render_markdown(m, date="2026-01-01", split="all", commit="abc")
    assert "a \\| b" in first
    assert f"{_SPDX}-License-Identifier: CC-BY-4.0" in first
    assert "False-UNGROUNDED on genuine | 1/3" in first


def test_reliability_bins_group_scores() -> None:
    from nikasha.bench.metrics import reliability_bins  # noqa: PLC0415

    records = [
        {"label": "genuine", "score": 95, "verdict": "GROUNDED"},
        {"label": "fabricated", "score": 91, "verdict": "GROUNDED"},
        {"label": "fabricated", "score": 5, "verdict": "UNGROUNDED"},
    ]
    assert reliability_bins(records) == [(0.05, 0.0, 1), (0.93, 0.5, 2)]


def test_results_md_keeps_latency_out_of_the_deterministic_table() -> None:
    from nikasha.bench.metrics import compute, render_markdown  # noqa: PLC0415

    base = {"id": "a", "source": "S6", "label": "genuine", "verdict": "GROUNDED", "score": 90,
            "expected": "GROUNDED", "rule": "5"}  # fmt: skip
    fast = render_markdown(
        compute([{**base, "timing": {"seconds": 0.1}}]), date="2026-01-01", split="s", commit="c"
    )
    slow = render_markdown(
        compute([{**base, "timing": {"seconds": 9.0}}]), date="2026-01-01", split="s", commit="c"
    )
    head = "## Timing (non-deterministic)"
    assert fast.split(head)[0] == slow.split(head)[0]
    assert fast != slow
