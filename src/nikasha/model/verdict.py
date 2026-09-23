# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Verdicts and reporter questions (SPEC §7, §14). Populated from M3 onwards."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from nikasha.model.base import Model

VerdictLabel = Literal["REPRODUCED", "GROUNDED", "MIXED", "UNGROUNDED", "INSUFFICIENT", "ERROR"]


class Question(Model):
    text: str
    rationale: str
    evidence_ids: tuple[str, ...] = ()


class Verdict(Model):
    label: VerdictLabel
    score: int = Field(ge=0, le=100)
    confidence: Literal["low", "medium", "high"]
    key_evidence: tuple[str, ...] = ()
    questions: tuple[Question, ...] = ()
    notes: tuple[str, ...] = ()
    rule: str | None = None
