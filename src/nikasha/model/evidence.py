# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Evidence items produced by checks (SPEC §7, §12). Populated from M3 onwards."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from nikasha.model.base import Model

Outcome = Literal["SUPPORTS", "REFUTES", "NEUTRAL", "ERROR"]


class CodeLocation(Model):
    """A location in the repository at an exact commit, with an upstream permalink."""

    repo: str
    ref: str | None = None
    commit: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str | None = None
    permalink: str | None = None


class CommandRecord(Model):
    """An external command a check ran, recorded so anyone can re-run it (P6)."""

    argv: tuple[str, ...]
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    #: Measured wall-clock time, or ``None`` when the clock was not consulted (the default,
    #: so identical inputs serialize byte-identically, P2). Never a made-up figure (P6).
    duration_ms: int | None = Field(default=None, ge=0)
    truncated: bool = False


class Evidence(Model):
    id: str
    check_id: str
    claim_ids: tuple[str, ...]
    outcome: Outcome
    strength: float
    group: str
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    locations: tuple[CodeLocation, ...] = ()
    commands: tuple[CommandRecord, ...] = ()
    produced_by: Literal["deterministic", "llm"] = "deterministic"
