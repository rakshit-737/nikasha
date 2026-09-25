# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""SVG charts ([bench] extra only)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from nikasha.bench.charts import ChartsUnavailableError, render_charts
from nikasha.bench.metrics import compute

RECORDS = [
    {"id": "a", "source": "S6", "label": "genuine", "verdict": "GROUNDED", "score": 90,
     "rule": "5", "ablation": {"C03": "MIXED"}, "timing": {"seconds": 1.5}},
    {"id": "b", "source": "S6", "label": "fabricated", "verdict": "UNGROUNDED", "score": 3,
     "rule": "3a", "ablation": {"C03": "MIXED"}, "timing": {"seconds": 0.5}},
]  # fmt: skip


def test_missing_matplotlib_is_a_clear_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "matplotlib", None)
    with pytest.raises(ChartsUnavailableError, match="bench"):
        render_charts(RECORDS, compute(RECORDS), tmp_path)


def test_charts_are_svg_and_deterministic(tmp_path: Path) -> None:
    pytest.importorskip("matplotlib")
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first = render_charts(RECORDS, compute(RECORDS), tmp_path / "a")
    second = render_charts(RECORDS, compute(RECORDS), tmp_path / "b")
    assert [p.name for p in first] == [
        "confusion.svg",
        "scores.svg",
        "reliability.svg",
        "ablation.svg",
        "latency.svg",
    ]
    for a, b in zip(first, second, strict=True):
        assert a.read_text(encoding="utf-8").lstrip().startswith("<?xml")
        assert a.read_bytes() == b.read_bytes()
