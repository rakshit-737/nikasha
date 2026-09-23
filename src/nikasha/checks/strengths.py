# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The likelihood-ratio table checks score with (SPEC §12, §14.1).

``lr_defaults.yaml`` holds the initial priors. A calibrated table
(``calibration-vN.yaml``, SPEC §14.2) may replace it, and the version actually used is
recorded in every result so a verdict can always be reproduced.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from nikasha.errors import NikashaError

DEFAULTS_PATH = Path(__file__).with_name("lr_defaults.yaml")


class StrengthsError(NikashaError):
    """The strengths table is missing an entry or is malformed."""


@dataclass(frozen=True, slots=True)
class Strengths:
    """Per-(check, outcome) log-likelihood ratios."""

    version: str
    table: dict[str, dict[str, float]]

    def get(self, check_id: str, outcome: str) -> float:
        """The strength for one (check, outcome), raising if it is not in the table.

        Checks must never invent a number inline: every strength is auditable and
        calibratable, which is what makes `nikasha explain` a complete ledger (P6).
        """
        try:
            return self.table[check_id][outcome]
        except KeyError as exc:
            raise StrengthsError(f"no strength for {check_id}/{outcome}") from exc

    def outcomes(self, check_id: str) -> dict[str, float]:
        return dict(self.table.get(check_id, {}))


def _coerce(raw: object) -> dict[str, dict[str, float]]:
    checks = raw.get("checks") if isinstance(raw, dict) else None
    if not isinstance(checks, dict):
        raise StrengthsError("the strengths file has no 'checks' mapping")
    table: dict[str, dict[str, float]] = {}
    for check_id, outcomes in checks.items():
        if not isinstance(outcomes, dict):
            raise StrengthsError(f"{check_id}: outcomes must be a mapping")
        table[str(check_id)] = {str(k): float(v) for k, v in outcomes.items()}
    return table


def load_strengths(path: Path | None = None) -> Strengths:
    """Load a strengths table (the bundled defaults when ``path`` is ``None``)."""
    source = path or DEFAULTS_PATH
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StrengthsError(f"cannot read {source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise StrengthsError(f"cannot parse {source}: {exc}") from exc
    version = str(raw.get("version", "unknown")) if isinstance(raw, dict) else "unknown"
    label = "defaults-v" + version if path is None else source.stem
    return Strengths(version=label, table=_coerce(raw))


@lru_cache(maxsize=1)
def default_strengths() -> Strengths:
    """The bundled priors, loaded once."""
    return load_strengths()
