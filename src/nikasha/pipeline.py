# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The `nikasha check` pipeline: report in, evidence-backed :class:`Result` out.

Intake -> extraction -> target resolution -> indexing -> checks -> fusion -> verdict. Each
stage is already its own package; this module only sequences them and records how long
each took.

Timings are the **only** field allowed to differ between two runs on the same input
(P2), so they live in ``Result.timings`` and never touch a claim, an evidence item or the
verdict.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path

from nikasha.checks import load_checks
from nikasha.checks.base import CheckContext, CheckRun, run_checks
from nikasha.code.index import CodeIndex
from nikasha.errors import NikashaError
from nikasha.extract import extract_claims
from nikasha.fuse.scoring import Ledger, fuse
from nikasha.fuse.verdict import Decision, Thresholds, decide
from nikasha.ingest import InputFormat, load_report
from nikasha.model.claims import Claim
from nikasha.model.evidence import Evidence
from nikasha.model.report import Report
from nikasha.model.result import Environment, Result
from nikasha.model.verdict import Question, Verdict
from nikasha.resolve.target import Resolution, resolve_target
from nikasha.version import __version__


class CheckFailedError(NikashaError):
    """The pipeline could not produce a verdict at all."""


@dataclass
class _Timer:
    """Wall-clock stage timings, kept apart from everything the verdict depends on."""

    timings: dict[str, float] = field(default_factory=dict)

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.timings[name] = round(time.perf_counter() - started, 4)


@dataclass(frozen=True, slots=True)
class CheckReport:
    """Everything one `nikasha check` run produced."""

    result: Result
    ledger: Ledger
    decision: Decision
    runs: tuple[CheckRun, ...]
    resolution: Resolution

    @property
    def verdict(self) -> Verdict:
        if self.result.verdict is None:  # pragma: no cover - check_report always sets it
            raise CheckFailedError("the result carries no verdict")
        return self.result.verdict

    @property
    def evidence(self) -> tuple[Evidence, ...]:
        return self.result.evidence

    @property
    def claims(self) -> tuple[Claim, ...]:
        return self.result.claims


def build_verdict(
    decision: Decision,
    questions: Sequence[Question] = (),
) -> Verdict:
    """Turn a :class:`Decision` into the serialized :class:`Verdict` model."""
    return Verdict(
        label=decision.label,
        score=decision.score,
        confidence=decision.confidence,  # type: ignore[arg-type]
        key_evidence=tuple(decision.key_evidence),
        questions=tuple(questions),
        notes=tuple(decision.notes),
        rule=decision.rule,
    )


def check_report(
    report_path: str | Path,
    *,
    repo: str | None = None,
    ref: str | None = None,
    version: str | None = None,
    product: str | None = None,
    input_format: InputFormat = "auto",
    online: bool = False,
    prior: float = 0.0,
    thresholds: Thresholds | None = None,
    check_timeout: float = 10.0,
    index_path: Path | None = None,
) -> CheckReport:
    """Run the whole pipeline over one report and return its :class:`CheckReport`."""
    timer = _Timer()

    with timer.stage("ingest"):
        loaded = load_report(report_path, input_format=input_format)

    with timer.stage("extract"):
        extraction = extract_claims(loaded, product=product)
        claims = extraction.claims
        loaded = loaded.model_copy(update={"warnings": loaded.warnings + extraction.warnings})

    with timer.stage("resolve"):
        resolution = resolve_target(
            loaded,
            claims,
            repo=repo,
            ref=ref,
            version=version,
            product=product,
            online=online,
        )

    # A report that never says which version it means cannot be checked against code, but
    # that is an INSUFFICIENT verdict with a question, not a crash (SPEC §14.3 rule 2).
    # Refusing to answer here would turn the most common incomplete report into an error.
    commit = resolution.target.commit
    runs: tuple[CheckRun, ...] | list[CheckRun] = []
    unresolved = commit is None
    if commit is not None:
        with resolution.repo, CodeIndex(resolution.repo, index_path) as index:
            with timer.stage("index"):
                index.index_commit(commit)

            ctx = CheckContext(
                report=loaded,
                claims=claims,
                resolution=resolution,
                index=index,
                online=online,
            )
            with timer.stage("checks"):
                load_checks()
                runs = run_checks(ctx, timeout=check_timeout)

    evidence = tuple(sorted((e for run in runs for e in run.evidence), key=lambda e: e.id))

    with timer.stage("fuse"):
        ledger = fuse(evidence, prior=prior)
        decision = decide(ledger, evidence, claims, thresholds=thresholds)
        if unresolved:
            decision = replace(
                decision,
                rule="2: the report does not name a version that resolves to a commit",
                notes=(
                    *decision.notes,
                    "No version in the report resolves to a released tag or commit, so "
                    "nothing could be checked against the code.",
                ),
            )

    with timer.stage("questions"):
        questions = build_questions(decision, evidence, claims)

    for run in runs:
        timer.timings[f"check.{run.check_id}"] = run.seconds

    result = Result(
        tool_version=__version__,
        report=loaded,
        claims=claims,
        target=resolution.target,
        evidence=evidence,
        verdict=build_verdict(decision, questions),
        timings=timer.timings,
        environment=Environment(mode="online" if online else "offline"),
    )
    return CheckReport(
        result=result,
        ledger=ledger,
        decision=decision,
        runs=tuple(runs),
        resolution=resolution,
    )


def build_questions(
    decision: Decision,
    evidence: Sequence[Evidence],
    claims: Sequence[Claim],
) -> tuple[Question, ...]:
    """Questions for the reporter (SPEC §14.4). Implemented in :mod:`nikasha.fuse.questions`.

    Questions are the polish on top of a verdict, not part of it. A missing or broken
    template pack must never sink a run that already has its evidence, so the failure is
    swallowed here and the verdict stands on its own.
    """
    try:
        from nikasha.fuse.questions import questions_for  # noqa: PLC0415
    except ImportError:  # pragma: no cover - the template pack is optional
        return ()
    return questions_for(decision, evidence, claims)


def report_of(path: str | Path, *, input_format: InputFormat = "auto") -> Report:
    """Intake only, for callers that want the parsed report without checking it."""
    return load_report(path, input_format=input_format)


__all__ = ["CheckFailedError", "CheckReport", "build_verdict", "check_report", "report_of"]
