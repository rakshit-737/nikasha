# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C08 TRACE_FRAMES: does the stack trace fit the code at the claimed version? (SPEC §12)

Each application frame is asked the three questions C02, C03 and C05 ask of a hand-written
locus — does the file exist at the ref, is the named function there, and is the cited line
inside it — and the check scores the *share* of frames that fit, ``r``. One shifted frame in
a long trace is a line-number drift; every frame wrong is a trace that was never produced by
this code. The logic is implemented here rather than by calling those checks, so C08 keeps
working on frames that never become file, symbol or line claims.

Two exclusions carry the whole false-positive budget (P4, ADR 0003), because a trace is the
one artifact where a reporter necessarily quotes *other people's* code:

* **Frames that are not the project's.** Runtime frames (libc, the sanitizer, the loader)
  are dropped by :func:`~nikasha.code.trace_forensics.app_frames`; frames whose file is not
  in the tree *and* whose path or module says it belongs elsewhere — a system header, a
  vendored tree, a shared library — are skipped here. Counting a libc frame as fabricated is
  exactly the failure mode slopcheck showed. Generated and release-only files are skipped for
  the same reason (SPEC §11.5).
* **Frames in a file that did not parse cleanly.** ``parsed_ok=False`` means the function
  table is incomplete, so "the line is not in that function" is not knowable. Such a frame is
  *uncertain*, never inconsistent, and leaves the ratio.

With fewer than one frame left to check, the trace says nothing about the code and the
outcome is NEUTRAL. One evidence item is emitted per trace either way, so the ledger always
explains what happened to every frame (P6).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import HistoryTimeoutError
from nikasha.code.trace_forensics import FrameCheck, analyze_trace, app_frames, bare_function
from nikasha.model.claims import Claim, ClaimKind, Frame, TraceClaim
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence, Outcome

CHECK_ID = "C08"
GROUP = "trace"

#: Path and module fragments that place a file outside the repository: system headers and
#: sources, package-manager caches and the conventional names for vendored dependencies.
#: Only consulted for a frame whose path does *not* resolve in the tree, so a project that
#: really does ship ``vendor/`` is unaffected.
THIRD_PARTY_MARKERS: tuple[str, ...] = (
    "/.cargo/registry/",
    "/.m2/repository/",
    "/dist-packages/",
    "/external/",
    "/go/pkg/mod/",
    "/node_modules/",
    "/site-packages/",
    "/third_party/",
    "/thirdparty/",  # codespell:ignore - a directory name, not a misspelling
    "/usr/include/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/local/",
    "/usr/share/",
    "/usr/src/",
    "/vendor/",
)

#: Locations carried by one evidence item. A trace can have hundreds of frames; the details
#: keep every one of them, the permalinks stay readable.
MAX_LOCATIONS = 12

#: Frames of one trace that are analysed at all. The parsers cap the trace *text*, not the
#: frame count, so a hostile report could otherwise buy tens of thousands of lookups and an
#: evidence item that grows with the input. Frames past the cap are recorded as a count and
#: never judged, in either direction.
MAX_TRACE_FRAMES = 256

#: The bare name of a Go closure frame (``main.run.func1``, ``main.run.func1.2``).
_GO_CLOSURE_RE = re.compile(r"(?:func)?[0-9]{1,9}")

#: SPEC §11.5 wording, reused verbatim so C02, C04, C05 and C08 say the same thing.
GENERATED_NOTE = "generated/release-only file, not in source control"


def _shared_library(module: str) -> bool:
    """Whether a frame's module is a shared object rather than the program under test."""
    base = module.replace("\\", "/").rsplit("/", 1)[-1]
    return base.endswith((".so", ".dll", ".dylib")) or ".so." in base


def _marker(text: str) -> str | None:
    """The first :data:`THIRD_PARTY_MARKERS` fragment in ``text``, matched as a path."""
    probe = "/" + text.replace("\\", "/").lstrip("/")
    return next((marker for marker in THIRD_PARTY_MARKERS if marker in probe), None)


def _third_party_reason(frame: Frame) -> str | None:
    """Why this frame's missing file belongs to somebody else's code, if it does.

    Only the frame's own text is used: a missing file with nothing to say for itself is
    left to count as inconsistent, which is what makes an invented path detectable at all.
    """
    if frame.module is not None and _shared_library(frame.module):
        return f"the frame comes from the shared library {frame.module}"
    for text in (frame.path, frame.module):
        marker = _marker(text) if text else None
        if marker is not None:
            return f"the file is under {marker.strip('/')}, outside the repository"
    return None


def _synthetic(function: str | None) -> bool:
    """Whether a frame's function name is made by the runtime rather than written in the
    source: ``<module>``, ``run.<locals>.<lambda>``, Java ``<init>``, Node ``<anonymous>``,
    Rust ``main::{closure#0}``, Go ``main.run.func1``. No symbol table holds such a name, so
    the frame cannot honestly fail the "is the line inside that function" question (P4)."""
    if function is None:
        return False
    bare = bare_function(function)
    return not bare or bare.startswith("{") or _GO_CLOSURE_RE.fullmatch(bare) is not None


@dataclass(frozen=True, slots=True)
class _Unknown:
    """A history search that could not finish, and why."""

    reason: str


@dataclass
class _History:
    """Per-trace pickaxe answers by file name, and the commands that gave them (P6)."""

    first: dict[str, str | _Unknown | None] = field(default_factory=dict)
    commands: list[CommandRecord] = field(default_factory=list)


def _probe(ctx: CheckContext, name: str, records: list[CommandRecord]) -> str | _Unknown | None:
    """The first commit touching ``name`` in any history, ``None`` if none, or why unknown."""
    if ctx.expired():
        return _Unknown("the time budget ran out")  # the caller then returns _budget_spent
    repo = ctx.resolution.repo
    if repo.is_shallow():
        return _Unknown("the clone is shallow, so history cannot show the file never existed")
    try:
        return repo.pickaxe_first(name, timeout=ctx.history_timeout, record=records)
    except HistoryTimeoutError:
        return _Unknown(f"the history search timed out after {ctx.history_timeout:g}s")


def _score(consistent: int, checked: int) -> tuple[Outcome, str]:
    """Map the consistency ratio onto SPEC §12's four bands, in integers so the boundaries
    at r = 0.8 and r = 0.5 are exact for every frame count."""
    if consistent == checked:
        return "SUPPORTS", "all_consistent"
    if consistent * 10 >= checked * 8:
        return "SUPPORTS", "mostly_consistent"
    if consistent * 2 >= checked:
        return "REFUTES", "mixed"
    return "REFUTES", "inconsistent"


@register
class TraceFrames(BaseCheck):
    id = CHECK_ID
    name = "TRACE_FRAMES"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"trace"})
    description = "Scores how many of a stack trace's application frames fit the code at the ref."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        return [self._one(ctx, claim) for claim in claims if isinstance(claim, TraceClaim)]

    def _one(self, ctx: CheckContext, claim: TraceClaim) -> Evidence:
        judged = claim
        truncated = max(0, len(claim.frames) - MAX_TRACE_FRAMES)
        if truncated:
            judged = claim.model_copy(update={"frames": claim.frames[:MAX_TRACE_FRAMES]})
        if ctx.expired():
            return _budget_spent(claim)
        analysis = analyze_trace(ctx.index, ctx.commit, judged, project=ctx.resolution.project)
        frames = app_frames(judged)
        details: list[dict[str, Any]] = []
        locations: list[CodeLocation] = []
        tally = {"consistent": 0, "inconsistent": 0, "uncertain": 0, "undecided": 0, "skipped": 0}
        history = _History()
        for frame, check in zip(frames, analysis.frames, strict=True):
            if ctx.expired():
                return _budget_spent(claim)
            detail = _frame_detail(ctx, frame, check, history)
            details.append(detail)
            tally[str(detail["status"])] += 1
            location = _frame_location(ctx, frame, check, detail)
            if location is not None and len(locations) < MAX_LOCATIONS:
                locations.append(location)

        if ctx.expired():
            # Checked again after the loop, so every expiry yields the same evidence (P2).
            return _budget_spent(claim)
        checked = tally["consistent"] + tally["inconsistent"]
        where = ctx.ref_name or ctx.commit[:12]
        payload: dict[str, Any] = {
            "trace_format": claim.format,
            "trace_frames": len(claim.frames),
            "app_frames": len(frames),
            "checked_frames": checked,
            "consistent_frames": tally["consistent"],
            "uncertain_frames": tally["uncertain"],
            "undecided_frames": tally["undecided"],
            "truncated_frames": truncated,
            "skipped_frames": tally["skipped"],
            "frames": details,
        }
        if checked == 0:
            payload["outcome"] = "no_checkable_frames"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"no application frame in this trace can be checked against {where}",
                details=payload,
            )

        payload["ratio"] = round(tally["consistent"] / checked, 6)
        outcome, key = _score(tally["consistent"], checked)
        payload["outcome"] = key
        summary = (
            f"{tally['consistent']} of {checked} application frames fit the code at {where}"
            + _not_counted(tally)
        )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=self.strengths.get(CHECK_ID, key),
            summary=summary,
            details=payload,
            locations=locations,
            commands=history.commands,
        )


def _budget_spent(claim: TraceClaim) -> Evidence:
    """The one evidence item for a trace the time budget did not cover. Nothing in it depends
    on how far the check got, so identical inputs still give identical JSON (P2)."""
    return make_evidence(
        check_id=CHECK_ID,
        group=GROUP,
        claims=[claim],
        outcome="NEUTRAL",
        strength=0.0,
        summary="the check's time budget ran out before this trace could be judged",
        details={
            "outcome": "budget_expired",
            "trace_format": claim.format,
            "trace_frames": len(claim.frames),
        },
    )


def _not_counted(tally: dict[str, int]) -> str:
    """The tail of the summary naming the frames that stayed out of the ratio."""
    parts: list[str] = []
    if tally["skipped"]:
        parts.append(f"{tally['skipped']} outside the repository")
    if tally["uncertain"]:
        parts.append(f"{tally['uncertain']} in a file that did not parse cleanly")
    if tally["undecided"]:
        parts.append(f"{tally['undecided']} the tree alone cannot decide")
    return f" ({', '.join(parts)} not counted)" if parts else ""


def _frame_location(
    ctx: CheckContext, frame: Frame, check: FrameCheck, detail: dict[str, Any]
) -> CodeLocation | None:
    """A permalink for a frame that was counted, clamped to the file's real length."""
    if detail["status"] not in ("consistent", "inconsistent"):
        return None
    if check.resolved_path is None or frame.line is None:
        return None
    line = min(frame.line, check.n_lines) if check.n_lines else frame.line
    return ctx.location(check.resolved_path, line)


def _frame_detail(
    ctx: CheckContext, frame: Frame, check: FrameCheck, history: _History
) -> dict[str, Any]:
    """What the three questions said about one frame, as a child detail of the evidence."""
    detail: dict[str, Any] = {
        "index": frame.index,
        "function": frame.function,
        "claimed_path": frame.path,
        "line": frame.line,
        "resolved_path": check.resolved_path,
    }
    skipped = _skip_reason(ctx, frame, check)
    if skipped is not None:
        status, reason = skipped
        return {**detail, "status": status, "reason": reason}

    matched: list[str] = []
    mismatched: list[str] = []
    if check.file_exists:
        matched.append(f"{check.resolved_path} exists at this commit")
    else:
        mismatched.append(f"no file matching {frame.path} exists at this commit")
    if check.line_in_bounds is True:
        matched.append(f"line {frame.line} is inside the file ({check.n_lines} lines)")
    elif check.line_in_bounds is False:
        mismatched.append(f"{check.resolved_path} has {check.n_lines} lines")
    if check.function_matches is True:
        matched.append(f"line {frame.line} is inside {frame.function}")
    elif check.function_matches is False:
        mismatched.append(_function_mismatch(frame, check))
    detail["matched"] = matched
    detail["mismatched"] = mismatched
    detail["status"] = "consistent" if check.consistent else "inconsistent"
    if not check.consistent:
        undecided = _synthetic_reason(frame, check) or _missing_file_reason(
            ctx, frame, check, history
        )
        if undecided is not None:
            detail["status"] = "undecided"
            detail["reason"] = undecided
    return detail


def _synthetic_reason(frame: Frame, check: FrameCheck) -> str | None:
    """P4: a frame that only fails the function question, on a runtime-made name."""
    if (
        check.file_exists
        and check.line_in_bounds is not False
        and check.function_matches is False
        and _synthetic(frame.function)
    ):
        return f"{frame.function} is a runtime-made name, not a function in the source"
    return None


def _missing_file_reason(
    ctx: CheckContext, frame: Frame, check: FrameCheck, history: _History
) -> str | None:
    """P4: a missing file counts only once a complete history search on a full clone says
    the name never existed; otherwise the trace may come from another version."""
    if check.file_exists or frame.path is None:
        return None
    name = frame.path.replace("\\", "/").rsplit("/", 1)[-1]
    if not name or not name.isprintable():
        return "the file name cannot be searched for in history"
    if name not in history.first:
        history.first[name] = _probe(ctx, name, history.commands)
    first = history.first[name]
    if isinstance(first, _Unknown):
        return first.reason
    if first is not None:
        return f"{name} exists elsewhere in history, so the trace may be from another version"
    return None


def _skip_reason(ctx: CheckContext, frame: Frame, check: FrameCheck) -> tuple[str, str] | None:
    """``(status, reason)`` when a frame must stay out of the ratio, else ``None``.

    The order matters: a generated file is never judged even when it resolves, and a missing
    file is only forgiven when the frame itself says the code is somebody else's.
    """
    if check.generated is not None:
        return "skipped", f"{GENERATED_NOTE} ({check.generated.reason})"
    if frame.path is None:
        return "skipped", "the frame carries no file name"
    if check.resolved_path is None:
        reason = _third_party_reason(frame)
        return ("skipped", reason) if reason is not None else None
    facts = ctx.facts(check.resolved_path)
    if facts is not None and not facts.parsed_ok:
        # P4: a partial parse loses definitions, so a mismatch here is not a finding.
        return "uncertain", f"{check.resolved_path} did not parse cleanly at this commit"
    for candidate in check.candidates:
        # An unparsed namesake can never win the tie-break, yet may be the real file.
        if candidate == check.resolved_path:
            continue
        other = ctx.facts(candidate)
        if other is not None and not other.parsed_ok:
            return "uncertain", f"{candidate} did not parse cleanly at this commit"
    return None


def _function_mismatch(frame: Frame, check: FrameCheck) -> str:
    """Why the cited line is not inside the frame's function, as concretely as known."""
    if check.function_defined_elsewhere is not None:
        inside = (
            f"line {frame.line} is inside {check.actual_function}"
            if check.actual_function is not None
            else f"line {frame.line} is outside it"
        )
        return f"{frame.function} is defined at {check.function_defined_elsewhere}; {inside}"
    if check.actual_function is not None:
        return f"line {frame.line} is inside {check.actual_function}, not {frame.function}"
    return f"{frame.function} is not defined in {check.resolved_path}"
