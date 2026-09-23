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

from collections.abc import Sequence
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.trace_forensics import FrameCheck, analyze_trace, app_frames
from nikasha.model.claims import Claim, ClaimKind, Frame, TraceClaim
from nikasha.model.evidence import CodeLocation, Evidence, Outcome

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
        analysis = analyze_trace(ctx.index, ctx.commit, claim, project=ctx.resolution.project)
        frames = app_frames(claim)
        details: list[dict[str, Any]] = []
        locations: list[CodeLocation] = []
        tally = {"consistent": 0, "inconsistent": 0, "uncertain": 0, "skipped": 0}
        for frame, check in zip(frames, analysis.frames, strict=True):
            detail = _frame_detail(ctx, frame, check)
            details.append(detail)
            tally[str(detail["status"])] += 1
            location = _frame_location(ctx, frame, check, detail)
            if location is not None and len(locations) < MAX_LOCATIONS:
                locations.append(location)

        checked = tally["consistent"] + tally["inconsistent"]
        where = ctx.ref_name or ctx.commit[:12]
        payload: dict[str, Any] = {
            "trace_format": claim.format,
            "trace_frames": len(claim.frames),
            "app_frames": len(frames),
            "checked_frames": checked,
            "consistent_frames": tally["consistent"],
            "uncertain_frames": tally["uncertain"],
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
        )


def _not_counted(tally: dict[str, int]) -> str:
    """The tail of the summary naming the frames that stayed out of the ratio."""
    parts: list[str] = []
    if tally["skipped"]:
        parts.append(f"{tally['skipped']} outside the repository")
    if tally["uncertain"]:
        parts.append(f"{tally['uncertain']} in a file that did not parse cleanly")
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


def _frame_detail(ctx: CheckContext, frame: Frame, check: FrameCheck) -> dict[str, Any]:
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
    return detail


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
