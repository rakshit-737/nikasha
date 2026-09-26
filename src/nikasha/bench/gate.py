# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The M3.5 gate metrics (ADR 0003) over ``bench run`` results.

Positives are ``fabricated`` records (curl's published AI-slop list), negatives are
``genuine`` ones (reports curl confirmed and resolved). Every number is computed the same
way slopcheck computed its own, so the two can be put side by side:

* the **flag rate**, the share of reports with at least one ``REFUTES`` evidence item
  (slopcheck: at least one contradiction);
* **Youden J** for that flag, for the ``UNGROUNDED`` verdict, for ``UNGROUNDED or MIXED``,
  and the best J of a threshold sweep over the score, next to the median best J of a
  seeded random score swept the same way (slopcheck's control);
* **false UNGROUNDED on genuine** with a Wilson 95% upper bound, against the P4 limit;
* per-check **ablation** of those numbers.

Nothing here is tuned: thresholds are the fusion's own, and the random control is seeded.
``ERROR`` records are counted and left out of every rate.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from typing import Any

Record = Mapping[str, Any]

#: slopcheck's published numbers on the same corpus (ADR 0003), for the comparison table.
SLOPCHECK = {
    "flag_rate_genuine": 0.294,
    "flag_rate_fabricated": 0.286,
    "best_j": 0.083,
    "random_feature_median_best_j": 0.092,
}
P4_LIMIT = 0.01
RANDOM_TRIALS = 200
RANDOM_SEED = 20260923


def _rate(hits: int, total: int) -> float | None:
    return None if total == 0 else round(hits / total, 4)


def wilson_upper(hits: int, total: int, z: float = 1.96) -> float | None:
    """Upper end of the Wilson 95% interval for ``hits / total``."""
    if total == 0:
        return None
    p = hits / total
    denom = 1 + z * z / total
    centre = p + z * z / (2 * total)
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return round((centre + margin) / denom, 4)


def _j(pos_hits: int, n_pos: int, neg_hits: int, n_neg: int) -> float | None:
    if n_pos == 0 or n_neg == 0:
        return None
    return round(pos_hits / n_pos - neg_hits / n_neg, 4)


def _flagged(record: Record) -> bool:
    return any(e.get("outcome") == "REFUTES" for e in record.get("evidence") or ())


def best_j(scores_pos: Sequence[float], scores_neg: Sequence[float]) -> float | None:
    """Best J over every threshold ``t`` with "fabricated" predicted when ``score <= t``."""
    if not scores_pos or not scores_neg:
        return None
    best = 0.0
    for t in sorted(set(scores_pos) | set(scores_neg)):
        pos_rate = sum(s <= t for s in scores_pos) / len(scores_pos)
        neg_rate = sum(s <= t for s in scores_neg) / len(scores_neg)
        best = max(best, pos_rate - neg_rate)
    return round(best, 4)


def random_best_j(n_pos: int, n_neg: int) -> float | None:
    """Median best J of a seeded uniform random score (slopcheck's control)."""
    if n_pos == 0 or n_neg == 0:
        return None
    rng = random.Random(RANDOM_SEED)  # noqa: S311 - a seeded statistical control
    values: list[float] = []
    for _ in range(RANDOM_TRIALS):
        pos = [rng.random() for _ in range(n_pos)]
        neg = [rng.random() for _ in range(n_neg)]
        values.append(best_j(pos, neg) or 0.0)
    values.sort()
    mid = len(values) // 2
    return round((values[mid - 1] + values[mid]) / 2, 4)


def _verdict_block(pos: Sequence[str], neg: Sequence[str]) -> dict[str, Any]:
    u_pos = sum(v == "UNGROUNDED" for v in pos)
    u_neg = sum(v == "UNGROUNDED" for v in neg)
    um_pos = sum(v in ("UNGROUNDED", "MIXED") for v in pos)
    um_neg = sum(v in ("UNGROUNDED", "MIXED") for v in neg)
    return {
        "false_ungrounded_on_genuine": {
            "count": u_neg,
            "of": len(neg),
            "rate": _rate(u_neg, len(neg)),
            "wilson95_upper": wilson_upper(u_neg, len(neg)),
        },
        "recall_ungrounded": _rate(u_pos, len(pos)),
        "recall_ungrounded_or_mixed": _rate(um_pos, len(pos)),
        "mixed_or_ungrounded_on_genuine": _rate(um_neg, len(neg)),
        "j_ungrounded": _j(u_pos, len(pos), u_neg, len(neg)),
        "j_ungrounded_or_mixed": _j(um_pos, len(pos), um_neg, len(neg)),
    }


def _distribution(rows: Sequence[Record]) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        out[str(r["verdict"])] = out.get(str(r["verdict"]), 0) + 1
    return dict(sorted(out.items()))


def compute(records: Sequence[Record]) -> dict[str, Any]:
    """Every M3.5 gate number for ``records``."""
    usable = [r for r in records if r["verdict"] != "ERROR"]
    pos = [r for r in usable if r["label"] == "fabricated"]
    neg = [r for r in usable if r["label"] == "genuine"]
    flag_pos = sum(_flagged(r) for r in pos)
    flag_neg = sum(_flagged(r) for r in neg)
    score_pos = [float(r["score"]) for r in pos if r.get("score") is not None]
    score_neg = [float(r["score"]) for r in neg if r.get("score") is not None]
    main = _verdict_block([str(r["verdict"]) for r in pos], [str(r["verdict"]) for r in neg])
    fu = main["false_ungrounded_on_genuine"]
    checks = sorted({c for r in usable for c in (r.get("ablation") or {})})
    ablation = {}
    for check in checks:
        block = _verdict_block(
            [str((r.get("ablation") or {}).get(check, r["verdict"])) for r in pos],
            [str((r.get("ablation") or {}).get(check, r["verdict"])) for r in neg],
        )
        ablation[check] = {
            "false_ungrounded_on_genuine": block["false_ungrounded_on_genuine"]["count"],
            "recall_ungrounded": block["recall_ungrounded"],
            "recall_ungrounded_or_mixed": block["recall_ungrounded_or_mixed"],
            "j_ungrounded_or_mixed": block["j_ungrounded_or_mixed"],
        }
    return {
        "cases": len(records),
        "errors": {
            "genuine": sum(r["verdict"] == "ERROR" and r["label"] == "genuine" for r in records),
            "fabricated": sum(
                r["verdict"] == "ERROR" and r["label"] == "fabricated" for r in records
            ),
        },
        "n_genuine": len(neg),
        "n_fabricated": len(pos),
        "verdicts": {"genuine": _distribution(neg), "fabricated": _distribution(pos)},
        "flag_rate": {
            "genuine": _rate(flag_neg, len(neg)),
            "fabricated": _rate(flag_pos, len(pos)),
            "j": _j(flag_pos, len(pos), flag_neg, len(neg)),
        },
        **main,
        "score_sweep": {
            "best_j": best_j(score_pos, score_neg),
            "random_median_best_j": random_best_j(len(score_pos), len(score_neg)),
        },
        "p4": {
            "limit": P4_LIMIT,
            "rate_within_limit": fu["rate"] is not None and fu["rate"] <= P4_LIMIT,
            "upper_bound_within_limit": fu["wilson95_upper"] is not None
            and fu["wilson95_upper"] <= P4_LIMIT,
        },
        "slopcheck": dict(SLOPCHECK),
        "ablation": ablation,
    }
