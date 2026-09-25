# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Strength calibration from bench results (SPEC §14.2).

Per-(check, outcome) strengths are fitted with L2-regularised logistic regression and
stratified 5-fold cross-validation, but **only** when there are at least
:data:`MIN_PER_CLASS` labelled reports in each of the genuine and fabricated classes.
Below that the defaults in ``lr_defaults.yaml`` are kept and the reason is recorded.
numpy and scikit-learn are imported lazily and are allowed only in the ``[bench]`` extra.
Only the real split counts (S1 to S4): synthetic S5 mutations would teach the model its
own mutations, and the S6 vulnlab fixtures are the project's own fictional reports.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nikasha.bench.manifests import SOURCES
from nikasha.bench.metrics import brier, ece
from nikasha.errors import NikashaError

#: Split so that REUSE does not read this module's templates as its own licence tags.
_SPDX = "SPDX"

MIN_PER_CLASS = 50
_CALIBRATION_FILE = re.compile(r"calibration-v([1-9][0-9]{0,8})\.yaml")
CLASSES = ("genuine", "fabricated")


class CalibrationError(NikashaError):
    """Calibration was asked to fit but cannot."""


@dataclass(frozen=True, slots=True)
class CalibrationOutcome:
    """What calibration decided, and (if it fitted) the fitted strengths."""

    fitted: bool
    reason: str
    counts: dict[str, int]
    strengths: dict[str, float] = field(default_factory=dict)
    brier: float | None = None
    ece: float | None = None


def _usable(record: Mapping[str, Any]) -> bool:
    return (
        record.get("label") in CLASSES
        and SOURCES.get(str(record.get("source"))) == "real"
        and record.get("verdict") != "ERROR"
    )


def class_counts(records: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Labelled, non-synthetic, non-error reports per class."""
    counts = dict.fromkeys(CLASSES, 0)
    for r in records:
        if _usable(r):
            counts[str(r["label"])] += 1
    return counts


def should_fit(counts: Mapping[str, int], minimum: int = MIN_PER_CLASS) -> tuple[bool, str]:
    """SPEC §14.2: keep the defaults below ``minimum`` labelled reports per class."""
    short = {c: counts.get(c, 0) for c in CLASSES if counts.get(c, 0) < minimum}
    if short:
        detail = ", ".join(f"{c}={n}" for c, n in sorted(short.items()))
        return False, f"kept defaults: fewer than {minimum} labelled reports per class ({detail})"
    return True, f"fitting: at least {minimum} labelled reports in every class"


def features(records: Sequence[Mapping[str, Any]]) -> tuple[list[str], list[list[float]]]:
    """One column per (check, outcome) key, holding the count of such evidence items."""
    keys = sorted({f"{e['check']}.{e['outcome']}" for r in records for e in r.get("evidence", [])})
    index = {k: i for i, k in enumerate(keys)}
    rows: list[list[float]] = []
    for r in records:
        row = [0.0] * len(keys)
        for e in r.get("evidence", []):
            row[index[f"{e['check']}.{e['outcome']}"]] += 1.0
        rows.append(row)
    return keys, rows


def calibrate(
    records: Sequence[Mapping[str, Any]], *, minimum: int = MIN_PER_CLASS
) -> CalibrationOutcome:
    """Decide whether to fit, and fit if the data allows it."""
    counts = class_counts(records)
    fit, reason = should_fit(counts, minimum)
    if not fit:
        return CalibrationOutcome(fitted=False, reason=reason, counts=counts)
    usable = [r for r in records if _usable(r)]
    try:
        np = importlib.import_module("numpy")
        linear_model = importlib.import_module("sklearn.linear_model")
        model_selection = importlib.import_module("sklearn.model_selection")
    except ImportError as exc:
        raise CalibrationError(
            "calibration needs the bench extra: pip install 'nikasha[bench]'"
        ) from exc
    keys, rows = features(usable)
    x = np.asarray(rows, dtype=float)
    y = np.asarray([1 if r["label"] == "genuine" else 0 for r in usable])
    model = linear_model.LogisticRegression(C=1.0, max_iter=1000)
    folds = model_selection.StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    probs = model_selection.cross_val_predict(model, x, y, cv=folds, method="predict_proba")[:, 1]
    model.fit(x, y)
    pairs = [(float(p), int(t)) for p, t in zip(probs, y, strict=True)]
    strengths = {k: round(float(c), 3) for k, c in zip(keys, model.coef_[0], strict=True)}
    return CalibrationOutcome(
        fitted=True,
        reason=reason,
        counts=counts,
        strengths=dict(sorted(strengths.items())),
        brier=brier(pairs),
        ece=ece(pairs),
    )


def to_yaml(outcome: CalibrationOutcome, version: int) -> str:
    """``calibration-vN.yaml`` text for a fitted outcome."""
    if not outcome.fitted:
        raise CalibrationError(outcome.reason)
    lines = [
        f"# {_SPDX}-FileCopyrightText: 2026 The Nikasha Authors",
        f"# {_SPDX}-License-Identifier: Apache-2.0",
        f"version: calibration-v{version}",
        f"brier: {outcome.brier}",
        f"ece: {outcome.ece}",
        "strengths:",
    ]
    lines += [f"  {k}: {v}" for k, v in outcome.strengths.items()]
    return "\n".join(lines) + "\n"


def next_version(directory: Path) -> int:
    """One more than the highest ``calibration-vN.yaml`` already in ``directory`` (else 1)."""
    if not directory.is_dir():
        return 1
    taken = [
        int(m.group(1))
        for p in directory.iterdir()
        if (m := _CALIBRATION_FILE.fullmatch(p.name)) is not None
    ]
    return max(taken, default=0) + 1


def write_calibration(outcome: CalibrationOutcome, directory: Path) -> Path:
    """Write ``calibration-vN.yaml`` at the next free N; an existing file is never replaced.

    The file is created exclusively, so a concurrent writer that took the same N makes this
    call move on to the next number rather than overwrite it.
    """
    if not outcome.fitted:
        raise CalibrationError(outcome.reason)
    directory.mkdir(parents=True, exist_ok=True)
    version = next_version(directory)
    for _ in range(100):
        path = directory / f"calibration-v{version}.yaml"
        try:
            with path.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(to_yaml(outcome, version))
        except FileExistsError:
            version += 1
            continue
        return path
    raise CalibrationError(f"could not find a free calibration-vN.yaml name in {directory}")
