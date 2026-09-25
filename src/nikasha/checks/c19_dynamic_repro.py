# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C19 DYNAMIC_REPRO: did the sandboxed PoC crash the way the report says? (SPEC §12, §13.5)

This check never runs anything. The sandbox (``nikasha.repro``, only with ``--repro``)
attaches its result to the context as ``ctx.repro``; without one, C19 produces nothing.
``ctx.repro`` is either a :class:`~nikasha.repro.run.ReproRun` (the PoC ran) or a
:class:`~nikasha.repro.signature.ReproFailure` (build or infrastructure failure).

A ``ReproRun`` is read as follows. A timeout or exit status 0 is ``no_crash``; exit status
125-127 (the engine could not start the command) is an infrastructure ``ERROR``. Any other
status is a crash, and it is compared only if it can be attributed to the target:

1. only the *terminating* report on stderr counts: never stdout, never the best of several
   reports (a hostile PoC can print decoys), and never a report followed by more output
   (a sanitizer that aborts prints nothing after its report);
2. the exit status must be the one that report leaves (134, SIGABRT, for the ASan/UBSan
   builds every recipe makes). Otherwise the crash is ``crash_unattributed``;
3. the crashing frame must be project code with a source path, not the reporter's staged
   PoC under ``/poc`` (``crash_not_in_project``);
4. a ``c_harness`` run is never counted: the harness is the reporter's code running in the
   target's own process, so it can print a report that passes 1-3 and exit 134 itself.
   Its comparison is recorded as ``harness_unverified`` (NEUTRAL, flagged for review).

Outcomes and strengths (``lr_defaults.yaml``, row C19):

* ``signature_match`` (+6.0): forces REPRODUCED (verdict rule 1);
* ``different_signature`` (+0.5): it crashed, but not as described. Flagged prominently: a
  real but *different* bug may be present;
* ``no_crash`` (-0.5): weak and never decisive on its own. A clean run says nothing about
  the reporter's own PoC text (ADR 0003 never lets a ``reporter_artifact`` claim be
  refuted), so it cites only the refutable (project-attributed, non-negated) trace and
  core-symbol claims, which are what a non-crash weakens; with none, it is informational
  (NEUTRAL, strength withheld);
* build or infrastructure failure: ``ERROR``, no strength;
* ``crash_unparsed``, ``crash_uncompared``, ``crash_unattributed``,
  ``crash_not_in_project``, ``harness_unverified``: NEUTRAL, no strength.

Remaining forgery risk: attribution rests on the target not being scriptable. A recipe
whose target lets the input run commands or write arbitrary stderr and choose its exit
status (the sqlite shell's ``.shell``/``.output``/``.exit``) is as untrusted as a harness,
and ``ReproRun`` does not yet say which recipes those are.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, is_refutable, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.model.claims import (
    BehaviorClaim,
    Claim,
    ClaimBase,
    ClaimKind,
    ImpactClaim,
    SymbolClaim,
    TraceClaim,
    TraceData,
)
from nikasha.model.evidence import CommandRecord, Evidence, Outcome
from nikasha.repro.run import ReproRun
from nikasha.repro.signature import (
    MatchResult,
    ReproFailure,
    Signature,
    bug_class_of_cwe,
    bug_class_of_text,
    crash_in_project,
    exit_status_fits,
    match_locus,
    match_traces,
    signature,
    terminating_report,
)

CHECK_ID = "C19"
GROUP = "dynamic"

_PREDICATE_CLASSES: dict[str, str] = {
    "uses_freed": "use-after-free",
    "missing_null_check": "null-deref",
    "integer_overflow": "integer-overflow",
    "missing_bounds_check": "out-of-bounds",
}
_MAX_DETAIL = 200
#: Most trace claims compared; bounds the alignment work on hostile reports (P7).
_MAX_TRACE_CLAIMS = 8
#: Exit statuses meaning the engine could not start the command (docker/podman).
_ENGINE_FAILURES: frozenset[int] = frozenset({125, 126, 127})
#: Run kinds whose output the reporter's own code can write (in the target's process).
_UNATTESTED_KINDS: frozenset[str] = frozenset({"c_harness"})
#: Outcomes that carry a strength from lr_defaults.yaml; everything else scores 0.
_SCORED: frozenset[str] = frozenset({"signature_match", "different_signature", "no_crash"})

_Judgement = tuple[Outcome, str, str, list[ClaimBase]]


def _short(text: str) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= _MAX_DETAIL else flat[: _MAX_DETAIL - 1] + "…"


def claimed_class(claims: Sequence[Claim], title: str | None) -> str | None:
    """The bug class a report without a trace claims: CWE, then behavior, then title."""
    for claim in claims:
        if isinstance(claim, ImpactClaim) and not claim.negated:
            cls = bug_class_of_cwe(claim.cwe)
            if cls:
                return cls
    for claim in claims:
        if isinstance(claim, BehaviorClaim) and not claim.negated:
            mapped = _PREDICATE_CLASSES.get(claim.predicate)
            if mapped:
                return mapped
    return bug_class_of_text(title, prose=True)


def locus_function(claims: Sequence[Claim]) -> tuple[str | None, list[ClaimBase]]:
    """The core locus function: a core symbol, else a behavior subject, else any symbol."""
    symbols = [c for c in claims if isinstance(c, SymbolClaim) and not c.negated]
    for pick in (
        [c for c in symbols if c.role == "core" and not c.external],
        [c for c in claims if isinstance(c, BehaviorClaim) and not c.negated],
        [c for c in symbols if not c.external],
    ):
        if pick:
            first = pick[0]
            name = first.name if isinstance(first, SymbolClaim) else first.subject_symbol
            return name, [first]
    return None, []


@register
class DynamicRepro(BaseCheck):
    id = CHECK_ID
    name = "DYNAMIC_REPRO"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"trace", "symbol", "behavior", "impact", "poc"})
    runs_on_empty = True
    description = (
        "Compares the crash the sandboxed PoC produced with the crash the report describes"
        " (sanitizer, bug class, top application frames)."
    )

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        repro = ctx.repro
        if repro is None:
            return []
        commands: tuple[CommandRecord, ...] = ()
        if isinstance(repro, ReproRun):
            commands = (repro.record,)
        elif isinstance(repro, ReproFailure):
            commands = repro.commands
        cited: list[ClaimBase] = [c for c in claims if c.kind in ("trace", "poc")]
        details: dict[str, Any] = {}
        outcome, key, summary, cited = self._judge(ctx, repro, claims, cited, details)
        details["outcome"] = key
        strength = self.strengths.get(CHECK_ID, key) if key in _SCORED else 0.0
        return [
            make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=cited,
                outcome=outcome,
                strength=strength,
                summary=summary,
                details=details,
                commands=commands,
            )
        ]

    def _judge(
        self,
        ctx: CheckContext,
        repro: object,
        claims: Sequence[Claim],
        cited: list[ClaimBase],
        details: dict[str, Any],
    ) -> _Judgement:
        """Decide (outcome, strengths key, summary, cited claims); may extend ``details``."""
        if isinstance(repro, ReproFailure):
            label = repro.stage or "error"
            reason = f": {_short(repro.detail)}" if repro.detail else ""
            return "ERROR", label, f"the sandbox run did not complete ({label}){reason}", cited
        if not isinstance(repro, ReproRun):
            return "ERROR", "error", "the attached repro result has an unknown shape", cited
        details["run"] = {
            "kind": repro.kind,
            "exit_code": repro.exit_code,
            "timed_out": repro.timed_out,
            "truncated": repro.truncated,
        }
        if repro.timed_out or repro.exit_code == 0:
            return self._no_crash(repro, claims, details)
        if repro.exit_code in _ENGINE_FAILURES:
            return (
                "ERROR",
                "infra_error",
                f"the container engine could not run the PoC (exit status {repro.exit_code})",
                cited,
            )

        return self._crashed(ctx, repro, claims, cited, details)

    def _crashed(
        self,
        ctx: CheckContext,
        repro: ReproRun,
        claims: Sequence[Claim],
        cited: list[ClaimBase],
        details: dict[str, Any],
    ) -> _Judgement:
        """Compare the terminating crash with what the report claims."""
        report = terminating_report(repro.stderr)
        if report is None:
            return (
                "NEUTRAL",
                "crash_unparsed",
                f"the PoC exited with status {repro.exit_code}, but stderr carries no trace"
                " to compare",
                cited,
            )
        observed = report.trace
        sig = signature(observed)
        details["observed_signature"] = sig.as_dict()
        if not report.at_tail or not exit_status_fits(observed, repro.exit_code):
            details["flag"] = "crash_unattributed"
            why = (
                "more output follows it"
                if not report.at_tail
                else f"exit status {repro.exit_code} is not what a {observed.format} report"
                " that ends the process leaves"
            )
            return (
                "NEUTRAL",
                "crash_unattributed",
                f"REVIEW: stderr carries a {observed.format} report, but {why}, so it is not"
                " attributed to the target",
                cited,
            )
        if not crash_in_project(observed):
            details["flag"] = "crash_not_in_project"
            return (
                "NEUTRAL",
                "crash_not_in_project",
                "REVIEW: the PoC crashed, but the crashing frame is in the PoC itself or has"
                " no source path, so the crash is not attributed to the project",
                cited,
            )
        return self._compare(ctx, repro, observed, claims, cited=cited, details=details)

    def _compare(
        self,
        ctx: CheckContext,
        repro: ReproRun,
        observed: TraceData,
        claims: Sequence[Claim],
        *,
        cited: list[ClaimBase],
        details: dict[str, Any],
    ) -> _Judgement:
        """Compare an attributed crash with the quoted traces, or with class and locus."""
        traces = [c for c in claims if isinstance(c, TraceClaim) and not c.negated]
        results: list[MatchResult] = []
        if traces:
            if len(traces) > _MAX_TRACE_CLAIMS:
                details["trace_claims_total"] = len(traces)
                traces = traces[:_MAX_TRACE_CLAIMS]
            details["claimed_signatures"] = [signature(t).as_dict() for t in traces]
            for trace in traces:
                if ctx.expired():
                    return "ERROR", "timeout", "C19 ran out of time comparing traces", cited
                results.append(match_traces(trace, observed))
        else:
            cls = claimed_class(claims, ctx.report.title)
            locus, locus_claims = locus_function(claims)
            if cls is None and locus is None:
                return (
                    "NEUTRAL",
                    "crash_uncompared",
                    "the PoC crashed, but the report names no bug class or function to"
                    " compare the crash with",
                    cited,
                )
            details["claimed_class"] = cls
            details["claimed_locus"] = locus
            cited = [*cited, *locus_claims]
            results.append(match_locus(cls, locus, observed))

        # The observed crash is fixed (the terminating one), so picking the quoted trace it
        # fits best cannot be steered by what the PoC prints.
        result = max(results, key=lambda r: (r.matched, r.class_equivalent, r.alignment))
        details["match"] = {
            "mode": result.mode,
            "class_equivalent": result.class_equivalent,
            "alignment": result.alignment,
            "reason": result.reason,
        }
        return self._conclude(repro, signature(observed), result, cited, details)

    @staticmethod
    def _conclude(
        repro: ReproRun,
        sig: Signature,
        result: MatchResult,
        cited: list[ClaimBase],
        details: dict[str, Any],
    ) -> _Judgement:
        """Turn one comparison into the outcome, withholding it for an unattested kind."""
        where = ", ".join(sig.top_functions) or "no application frame"
        if repro.kind in _UNATTESTED_KINDS:
            details["flag"] = "unverified_harness"
            details["unverified_outcome"] = (
                "signature_match" if result.matched else "different_signature"
            )
            verb = "matches" if result.matched else "does not match"
            return (
                "NEUTRAL",
                "harness_unverified",
                f"REVIEW: the harness run {verb} the reported signature ({sig.bug_class} in"
                f" {where}), but a {repro.kind} PoC is the reporter's code in the target's"
                " own process and can print any report, so it is not counted as a"
                " reproduction",
                cited,
            )
        if result.matched:
            return (
                "SUPPORTS",
                "signature_match",
                f"reproduced: the PoC crashed with the reported signature"
                f" ({sig.bug_class}, in {where})",
                cited,
            )
        details["flag"] = "different_crash"
        return (
            "SUPPORTS",
            "different_signature",
            f"REVIEW: the PoC crashed with a different signature ({sig.bug_class} in"
            f" {where}); {result.reason}. There may be a real but different bug.",
            cited,
        )

    @staticmethod
    def _no_crash(repro: ReproRun, claims: Sequence[Claim], details: dict[str, Any]) -> _Judgement:
        refutable: list[ClaimBase] = [
            c
            for c in claims
            if is_refutable(c)
            and (c.kind == "trace" or (isinstance(c, SymbolClaim) and c.role == "core"))
        ]
        if not refutable:
            details["informational"] = "no refutable trace or core-symbol claim to weaken"
        how = "within the time limit" if repro.timed_out else "(exit status 0)"
        return (
            "REFUTES" if refutable else "NEUTRAL",
            "no_crash",
            f"the PoC ran in the sandbox without crashing {how}",
            refutable,
        )
