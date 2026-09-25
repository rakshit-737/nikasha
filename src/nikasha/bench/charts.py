# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""SVG charts for a bench run (SPEC §17.3), drawn with matplotlib from the ``[bench]`` extra.

matplotlib is imported inside :func:`render_charts`, so the core never needs it. SVGs are
written with a fixed ``svg.hashsalt`` and no date metadata so that identical inputs give
identical files.
"""

from __future__ import annotations

import importlib
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from nikasha.bench.metrics import LABELS, VERDICTS, reliability_bins
from nikasha.errors import NikashaError


class ChartsUnavailableError(NikashaError):
    """matplotlib is not installed."""


def render_charts(
    records: Sequence[Mapping[str, Any]], metrics: Mapping[str, Any], target: Path
) -> tuple[Path, ...]:
    """Confusion matrix, score distributions, reliability, ablation and latency CDF (SVG)."""
    try:
        mpl = importlib.import_module("matplotlib")
        mpl.use("Agg")
        plt = importlib.import_module("matplotlib.pyplot")
    except ImportError as exc:
        raise ChartsUnavailableError(
            "charts need the bench extra: pip install 'nikasha[bench]'"
        ) from exc
    mpl.rcParams["svg.hashsalt"] = "nikasha-bench"
    written: list[Path] = []

    def save(fig: Any, name: str) -> None:  # noqa: ANN401 - matplotlib is untyped here
        path = target / name
        fig.savefig(path, format="svg", metadata={"Date": None})
        plt.close(fig)
        written.append(path)

    confusion = metrics["confusion"]
    fig, ax = plt.subplots(figsize=(7, 3))
    grid = [[confusion[label][v] for v in VERDICTS] for label in LABELS]
    ax.imshow(grid, cmap="Blues")
    ax.set_xticks(range(len(VERDICTS)), VERDICTS, rotation=30, ha="right")
    ax.set_yticks(range(len(LABELS)), LABELS)
    for i, row in enumerate(grid):
        for j, value in enumerate(row):
            ax.text(j, i, str(value), ha="center", va="center")
    ax.set_title("Label by verdict")
    fig.tight_layout()
    save(fig, "confusion.svg")

    fig, ax = plt.subplots(figsize=(6, 3))
    for label in LABELS:
        scores = [r["score"] for r in records if r["label"] == label and r["score"] is not None]
        if scores:
            ax.hist(scores, bins=range(0, 105, 5), alpha=0.6, label=label)
    ax.set_xlabel("grounding score")
    ax.legend()
    fig.tight_layout()
    save(fig, "scores.svg")

    _reliability(plt, records, save)

    fig, ax = plt.subplots(figsize=(6, 3))
    checks = list(metrics["ablation"])
    ax.barh(checks, [metrics["ablation"][c]["changed"] for c in checks])
    ax.set_xlabel("verdicts changed when the check is dropped")
    fig.tight_layout()
    save(fig, "ablation.svg")

    fig, ax = plt.subplots(figsize=(6, 3))
    seconds = sorted(float(r["timing"]["seconds"]) for r in records if r.get("timing"))
    if seconds:
        ax.step(seconds, [(i + 1) / len(seconds) for i in range(len(seconds))], where="post")
    ax.set_xlabel("seconds per report")
    ax.set_ylabel("fraction")
    fig.tight_layout()
    save(fig, "latency.svg")
    return tuple(written)


def _reliability(plt: Any, records: Sequence[Mapping[str, Any]], save: Any) -> None:  # noqa: ANN401
    """Reliability diagram: mean predicted P(genuine) against the observed fraction."""
    fig, ax = plt.subplots(figsize=(4, 4))
    bins = reliability_bins(records)
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey", linewidth=1)
    if bins:
        ax.plot([b[0] for b in bins], [b[1] for b in bins], marker="o")
    ax.set_xlabel("predicted P(genuine) = score / 100")
    ax.set_ylabel("observed fraction genuine")
    ax.set_title("Reliability")
    fig.tight_layout()
    save(fig, "reliability.svg")
