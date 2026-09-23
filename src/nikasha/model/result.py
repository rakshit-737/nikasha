# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The top-level result document (SPEC §7) and its deterministic serialization."""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from nikasha.model.base import Model
from nikasha.model.claims import Claim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Report
from nikasha.model.verdict import Verdict

SCHEMA_URL = "https://github.com/rakshit-737/nikasha/blob/main/schema/result-v1.json"


class ResolvedTarget(Model):
    """The repository and exact commit a report was checked against (SPEC §10)."""

    repo_url: str
    ref_name: str | None = None
    commit: str | None = None
    method: str
    confidence: Literal["low", "medium", "high"]
    alternatives: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class Environment(Model):
    mode: Literal["offline", "online"] = "offline"
    sandbox_engine: str | None = None
    llm: str | None = None
    fetched_urls: tuple[str, ...] = ()


class Result(Model):
    """Everything Nikasha concluded about one report.

    ``timings`` is the only field allowed to differ between two runs on the same input.
    """

    schema_url: str = Field(default=SCHEMA_URL, alias="schema")
    tool_version: str
    report: Report
    claims: tuple[Claim, ...] = ()
    target: ResolvedTarget | None = None
    evidence: tuple[Evidence, ...] = ()
    verdict: Verdict | None = None
    timings: dict[str, float] = Field(default_factory=dict)
    environment: Environment = Field(default_factory=Environment)

    def to_json(self, *, include_timings: bool = True) -> str:
        """Serialize with sorted keys and stable ordering (P2)."""
        data = self.model_dump(mode="json", by_alias=True)
        if not include_timings:
            data.pop("timings", None)
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
