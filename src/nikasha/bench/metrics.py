# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Bench metrics (SPEC §17.4), in plain Python so the core needs no numpy.

Every function here is pure: records in, numbers out. Latency is the only input that
comes from a clock, so it is reported under a separate ``timing`` key and never mixed into
the deterministic part of ``metrics.json``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

#: Split so that REUSE does not read this module's templates as its own licence tags.
_SPDX = "SPDX"

Record = Mapping[str, Any]

VERDICTS = ("REPRODUCED", "GROUNDED", "MIXED", "UNGROUNDED", "INSUFFICIENT", "ERROR")
LABELS = ("genuine", "fabricated", "insufficient")
#: Sources whose fabricated reports count toward real-world recall (SPEC §17.4).
REAL_FABRICATED_SOURCES = ("S1", "S3")


def _rate(hits: int, total: int) -> float | None:
    return round(hits / total, 4) if total else None


def percentile(values: Sequence[float], q: float) -> float | None:
    """Nearest-rank percentile (``q`` in 0..100); ``None`` for no values."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(q / 100 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def brier(pairs: Sequence[tuple[float, int]]) -> float | None:
    """Mean squared error of probability ``p`` against outcome ``y`` in {0, 1}."""
    if not pairs:
        return None
    return round(sum((p - y) ** 2 for p, y in pairs) / len(pairs), 4)


def ece(pairs: Sequence[tuple[float, int]], bins: int = 10) -> float | None:
    """Expected calibration error with ``bins`` equal-width bins."""
    if not pairs:
        return None
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for p, y in pairs:
        buckets[min(int(p * bins), bins - 1)].append((p, y))
    total = 0.0
    for bucket in buckets:
        if bucket:
            confidence = sum(p for p, _ in bucket) / len(bucket)
            accuracy = sum(y for _, y in bucket) / len(bucket)
            total += len(bucket) / len(pairs) * abs(confidence - accuracy)
    return round(total, 4)


def calibration_pairs(records: Sequence[Record]) -> list[tuple[float, int]]:
    """(P(genuine) = score/100, 1 if genuine) for every genuine or fabricated record."""
    pairs: list[tuple[float, int]] = []
    for r in records:
        if r.get("label") in ("genuine", "fabricated") and r.get("score") is not None:
            pairs.append((float(r["score"]) / 100.0, 1 if r["label"] == "genuine" else 0))
    return pairs


def reliability_bins(records: Sequence[Record], bins: int = 10) -> list[tuple[float, float, int]]:
    """(mean predicted, observed fraction genuine, count) per non-empty equal-width bin."""
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bins)]
    for p, y in calibration_pairs(records):
        buckets[min(int(p * bins), bins - 1)].append((p, y))
    return [
        (
            round(sum(p for p, _ in b) / len(b), 4),
            round(sum(y for _, y in b) / len(b), 4),
            len(b),
        )
        for b in buckets
        if b
    ]


def confusion(records: Sequence[Record]) -> dict[str, dict[str, int]]:
    """Label x verdict counts, every cell present."""
    table = {label: dict.fromkeys(VERDICTS, 0) for label in LABELS}
    for r in records:
        table[str(r["label"])][str(r["verdict"])] += 1
    return table


def _correct(verdict: str, expected: str | None) -> bool:
    return expected is None or verdict == expected


def ablation(records: Sequence[Record]) -> dict[str, dict[str, int]]:
    """Drop-one ablation: what happens to each verdict without one check's evidence."""
    out: dict[str, dict[str, int]] = {}
    for r in records:
        for check, verdict in sorted(dict(r.get("ablation") or {}).items()):
            row = out.setdefault(
                check,
                {"changed": 0, "became_wrong": 0, "became_right": 0, "new_false_ungrounded": 0},
            )
            if verdict == r["verdict"]:
                continue
            row["changed"] += 1
            before = _correct(str(r["verdict"]), r.get("expected"))
            after = _correct(str(verdict), r.get("expected"))
            row["became_wrong"] += int(before and not after)
            row["became_right"] += int(after and not before)
            row["new_false_ungrounded"] += int(
                r["label"] == "genuine" and verdict == "UNGROUNDED" and r["verdict"] != verdict
            )
    return dict(sorted(out.items()))


def compute(records: Sequence[Record]) -> dict[str, Any]:
    """All SPEC §17.4 metrics for ``records``."""
    genuine = [r for r in records if r["label"] == "genuine"]
    fabricated = [r for r in records if r["label"] == "fabricated"]
    real_fab = [r for r in fabricated if r["source"] in REAL_FABRICATED_SOURCES]
    synth_fab = [r for r in fabricated if r["source"] == "S5"]
    m3 = [r for r in records if r.get("mutation") == "M3"]
    with_expected = [r for r in records if r.get("expected") is not None]
    mismatches = [
        {"id": r["id"], "expected": r["expected"], "verdict": r["verdict"], "rule": r["rule"]}
        for r in with_expected
        if r["verdict"] != r["expected"]
    ]
    pairs = calibration_pairs(records)
    by_source: dict[str, int] = {}
    for r in records:
        by_source[str(r["source"])] = by_source.get(str(r["source"]), 0) + 1

    def recall(rows: Sequence[Record], verdicts: tuple[str, ...]) -> float | None:
        return _rate(sum(r["verdict"] in verdicts for r in rows), len(rows))

    seconds = [float(r["timing"]["seconds"]) for r in records if r.get("timing")]
    return {
        "cases": len(records),
        "by_source": dict(sorted(by_source.items())),
        "errors": sum(r["verdict"] == "ERROR" for r in records),
        "false_ungrounded_on_genuine": {
            "count": sum(r["verdict"] == "UNGROUNDED" for r in genuine),
            "of": len(genuine),
            "rate": recall(genuine, ("UNGROUNDED",)),
        },
        "recall_ungrounded": {
            "real_s1_s3": recall(real_fab, ("UNGROUNDED",)),
            "synthetic_s5": recall(synth_fab, ("UNGROUNDED",)),
        },
        "recall_ungrounded_or_mixed": {
            "real_s1_s3": recall(real_fab, ("UNGROUNDED", "MIXED")),
            "synthetic_s5": recall(synth_fab, ("UNGROUNDED", "MIXED")),
        },
        "mixed_rate_on_m3": recall(m3, ("MIXED",)),
        "coverage": recall(records, ("REPRODUCED", "GROUNDED", "MIXED", "UNGROUNDED")),
        "expected_match": {
            "matched": len(with_expected) - len(mismatches),
            "of": len(with_expected),
            "rate": _rate(len(with_expected) - len(mismatches), len(with_expected)),
        },
        "mismatches": mismatches,
        "calibration": {"n": len(pairs), "brier": brier(pairs), "ece": ece(pairs)},
        "confusion": confusion(records),
        "ablation": ablation(records),
        "timing": {
            "p50_seconds": percentile(seconds, 50),
            "p95_seconds": percentile(seconds, 95),
        },
    }


def render_markdown(metrics: Mapping[str, Any], *, date: str, split: str, commit: str) -> str:
    """RESULTS.md: neutral wording, numbers only (SPEC §17.5)."""
    fu = metrics["false_ungrounded_on_genuine"]
    em = metrics["expected_match"]
    cal = metrics["calibration"]
    lines = [
        "<!--",
        f"{_SPDX}-FileCopyrightText: 2026 The Nikasha Authors",
        f"{_SPDX}-License-Identifier: CC-BY-4.0",
        "-->",
        "",
        f"# NikashaBench results, {date}",
        "",
        f"Split: `{split}` · cases: {metrics['cases']} · nikasha commit: `{commit}`",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| False-UNGROUNDED on genuine | {fu['count']}/{fu['of']} ({_fmt(fu['rate'])}) |",
        f"| Recall of UNGROUNDED, S1/S3 | {_fmt(metrics['recall_ungrounded']['real_s1_s3'])} |",
        f"| Recall of UNGROUNDED, S5 | {_fmt(metrics['recall_ungrounded']['synthetic_s5'])} |",
        "| Recall of UNGROUNDED or MIXED, S1/S3 | "
        f"{_fmt(metrics['recall_ungrounded_or_mixed']['real_s1_s3'])} |",
        "| Recall of UNGROUNDED or MIXED, S5 | "
        f"{_fmt(metrics['recall_ungrounded_or_mixed']['synthetic_s5'])} |",
        f"| MIXED rate on M3 | {_fmt(metrics['mixed_rate_on_m3'])} |",
        f"| Coverage | {_fmt(metrics['coverage'])} |",
        f"| Matches expected verdict | {em['matched']}/{em['of']} ({_fmt(em['rate'])}) |",
        f"| Brier / ECE (n={cal['n']}) | {_fmt(cal['brier'])} / {_fmt(cal['ece'])} |",
        "",
        "## Verdicts that differed from the expected one",
        "",
    ]
    if metrics["mismatches"]:
        lines += ["| Case | Expected | Verdict | Rule |", "|---|---|---|---|"]
        lines += [
            f"| `{m['id']}` | {m['expected']} | {m['verdict']} | {_cell(m['rule'])} |"
            for m in metrics["mismatches"]
        ]
    else:
        lines.append("None.")
    lines += ["", "## Drop-one ablation", ""]
    if metrics["ablation"]:
        lines += [
            "| Check | Verdicts changed | Became wrong | Became right | New false UNGROUNDED |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {check} | {row['changed']} | {row['became_wrong']} | {row['became_right']} "
            f"| {row['new_false_ungrounded']} |"
            for check, row in metrics["ablation"].items()
        ]
    else:
        lines.append("No check produced evidence.")
    lines += [
        "",
        "## Timing (non-deterministic)",
        "",
        "Wall-clock latency depends on the machine; it is kept apart from the tables above,",
        "which are meant to depend on the inputs only.",
        "",
        f"p50 / p95 latency (s): {_fmt(metrics['timing']['p50_seconds'])} / "
        f"{_fmt(metrics['timing']['p95_seconds'])}",
    ]
    return "\n".join(lines) + "\n"


def _fmt(value: object) -> str:
    return "n/a" if value is None else str(value)


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")
