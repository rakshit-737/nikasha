# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C11 SANITIZER_SANITY: does the sanitizer output contradict *itself*? (SPEC §12)

Every other trace check needs the repository. This one does not: a sanitizer report is a
machine-generated document whose parts must agree with each other, so a report that pastes
one can be judged with nothing but the text. That makes it the cheapest strong signal
Nikasha has — and the hardest one to fake, because a plausible-looking stack still has to
survive arithmetic.

The seven rules are SPEC §12's, in order. Each one is applied *only* when the trace carries
the data it needs; a field the reporter trimmed is "not checkable", never a violation (P4).

Two properties of real ASan output shape the implementation (ADR 0005):

* The **region wording changed**. Current ASan prints "0 bytes **after** 64-byte region",
  where older releases printed "0 bytes **to the right of**". Both mean ``addr - end == N``,
  and :mod:`nikasha.extract.traces.asan` normalizes them to the same ``relation``, so rule 4
  is spelling-independent by construction.
* The **SUMMARY usually names the interceptor**, not the application. A memcpy overflow
  summarises as ``… (hdrcat+0x4a44a1) in __asan_memcpy`` — a module and a runtime function,
  with no ``file:line`` at all. Rule 5 therefore accepts a SUMMARY that matches *either* the
  topmost frame (the modern, interceptor form) or the first application frame (the older
  form), and compares only the fields the SUMMARY actually carries.

Only the sanitizer formats are judged. valgrind prints ``==pid==`` markers and block
descriptions too, but its parser *derives* the block bounds from the faulting address and
numbers frames itself, so every valgrind trace would pass rules 1 to 4 tautologically; scoring
that as support would be measuring Nikasha, not the report.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any, NamedTuple

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.trace_forensics import bare_function
from nikasha.model.claims import Claim, ClaimKind, Frame, TraceClaim, TraceData
from nikasha.model.evidence import Evidence

CHECK_ID = "C11"
GROUP = "trace_meta"

#: Formats whose consistency the *tool* printed, so checking it judges the report.
SANITIZER_FORMATS: frozenset[str] = frozenset({"asan", "lsan", "msan", "tsan", "ubsan"})

_TOOL_NAMES: dict[str, str] = {
    "asan": "AddressSanitizer",
    "lsan": "LeakSanitizer",
    "msan": "MemorySanitizer",
    "tsan": "ThreadSanitizer",
    "ubsan": "UndefinedBehaviorSanitizer",
}

#: Bug types about a region that was allocated *and* released, so ASan prints both stacks.
#: ``heap-*`` covers the rest of the allocation side, and ``…use-after-free`` the free side.
#: Deliberately absent: ``attempting free on address which was not malloc()-ed``, which has
#: no allocation to describe, and the stack, global and leak reports, which have no chunk.
_RELEASED_REGION_BUGS: frozenset[str] = frozenset(
    {"double-free", "alloc-dealloc-mismatch", "new-delete-type-mismatch"}
)

#: Deliberately loose. ASan reports 1, 2, 4, 8 and 16 for instrumented loads and stores, but
#: ``__asan_report_load_n`` and the ``memcpy``/``strcpy`` interceptors report the real length
#: of the range, which is bounded only by the program. Anything a sanitizer can genuinely
#: print must pass (P4), so this rule catches only sizes no sanitizer ever emits.
MAX_ACCESS_SIZE = 1 << 31

#: Fewest addresses that can disagree with each other.
_MIN_ADDRESSES = 2

#: Longest run of frame numbers quoted in a message.
_MAX_SHOWN_INDICES = 6
#: Longest input-derived fragment quoted in a message (P7: the trace is attacker-controlled).
_MAX_QUOTED = 60


class Verdict(NamedTuple):
    """One rule's result: whether the trace carried the data, and what was wrong if so."""

    checked: bool
    detail: str = ""


NOT_CHECKABLE = Verdict(checked=False)
OK = Verdict(checked=True)


def broken(detail: str) -> Verdict:
    return Verdict(checked=True, detail=detail)


# --- formatting helpers ------------------------------------------------------------------


def _short(text: str) -> str:
    """Quote an input-derived fragment at a bounded length."""
    flat = " ".join(text.split())
    return flat if len(flat) <= _MAX_QUOTED else flat[: _MAX_QUOTED - 1] + "…"


def _hex(address: int) -> str:
    return f"0x{address:x}"


def _where(frame: Frame) -> str:
    """``util_copy_value at src/util.c:15``, with whatever parts the frame has."""
    name = _short(frame.function) if frame.function else f"frame #{frame.index}"
    if frame.path is None:
        return name
    line = f":{frame.line}" if frame.line is not None else ""
    return f"{name} at {_short(frame.path)}{line}"


def _summary_where(trace: TraceData) -> str:
    name = _short(trace.summary_function) if trace.summary_function else "no function"
    if trace.summary_path is None:
        return name
    line = f":{trace.summary_line}" if trace.summary_line is not None else ""
    return f"{name} at {_short(trace.summary_path)}{line}"


def _same_path(left: str, right: str) -> bool:
    """Whether two paths from the same trace name the same file, allowing a suffix match."""
    a, b = left.replace("\\", "/").strip("/"), right.replace("\\", "/").strip("/")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _named_stacks(trace: TraceData) -> list[tuple[str, tuple[Frame, ...]]]:
    """Every non-empty stack in the report, in the order a sanitizer prints them."""
    stacks: list[tuple[str, tuple[Frame, ...]]] = [
        ("crash", trace.frames),
        ("allocation", trace.alloc_frames),
        ("free", trace.free_frames),
    ]
    stacks += [(_short(stack.label), stack.frames) for stack in trace.other_stacks]
    return [(name, frames) for name, frames in stacks if frames]


# --- the seven rules ---------------------------------------------------------------------


def _pid_consistent(trace: TraceData) -> Verdict:
    """Rule 1: one report, one PID. Every ``==N==`` marker in it carries the same number."""
    if not trace.pids_seen:
        return NOT_CHECKABLE
    if len(trace.pids_seen) == 1:
        return OK
    seen = ", ".join(str(pid) for pid in trace.pids_seen)
    return broken(f"the report mixes process IDs {seen}, but one report carries one PID")


def _frame_indices(trace: TraceData) -> Verdict:
    """Rule 2: each stack is numbered ``#0, #1, #2, …`` with nothing missing."""
    stacks = _named_stacks(trace)
    if not stacks:
        return NOT_CHECKABLE
    bad: list[str] = []
    for name, frames in stacks:
        indices = [frame.index for frame in frames]
        if indices != list(range(len(indices))):
            shown = ", ".join(f"#{i}" for i in indices[:_MAX_SHOWN_INDICES])
            more = ", …" if len(indices) > _MAX_SHOWN_INDICES else ""
            bad.append(f"the {name} stack is numbered {shown}{more}")
    if not bad:
        return OK
    return broken(f"{'; '.join(bad)}, but a sanitizer numbers every stack from #0 upwards")


def _addresses_agree(trace: TraceData) -> Verdict:
    """Rule 3: the header, the access line and the region line name one address."""
    labelled = (
        ("the header", trace.address),
        ("the access line", trace.access_address),
        ("the region line", trace.region_address),
    )
    present = [(label, addr) for label, addr in labelled if addr is not None]
    if len(present) < _MIN_ADDRESSES:
        return NOT_CHECKABLE
    if len({addr for _, addr in present}) == 1:
        return OK
    disagreement = ", ".join(f"{label} says {_hex(addr)}" for label, addr in present)
    return broken(f"the faulting address is not the same everywhere: {disagreement}")


def _region_arithmetic(trace: TraceData) -> Verdict:
    """Rule 4: the region's bounds, size and the stated distance to the address agree.

    ``size == end - start`` always; then, depending on the relation the tool printed,
    ``addr - end`` ("after" / "to the right of"), ``start - addr`` ("before" / "to the left
    of") or ``addr - start`` ("inside of", which must also land within the region).
    """
    region = trace.region
    if region is None:
        return NOT_CHECKABLE
    problems: list[str] = []
    span = region.end - region.start
    if span != region.size:
        problems.append(
            f"the region [{_hex(region.start)},{_hex(region.end)}) spans {span} bytes,"
            f" not the stated {region.size}"
        )
    address = trace.region_address if trace.region_address is not None else trace.access_address
    if address is not None:
        if region.relation == "right":
            actual = address - region.end
            place = f"past the end of the region at {_hex(region.end)}"
        elif region.relation == "left":
            actual = region.start - address
            place = f"before the start of the region at {_hex(region.start)}"
        else:
            actual = address - region.start
            place = f"inside the region starting at {_hex(region.start)}"
        if actual != region.distance:
            problems.append(
                f"{_hex(address)} is {actual} bytes {place}, not the stated {region.distance}"
            )
        elif region.relation == "inside" and not 0 <= actual < region.size:
            problems.append(
                f"{_hex(address)} is {actual} bytes from the start of a {region.size}-byte"
                " region, so it is not inside it"
            )
    return broken("; ".join(problems)) if problems else OK


def _summary_matches_summary_frame(trace: TraceData, frame: Frame) -> bool | None:
    """Whether the SUMMARY agrees with ``frame`` on every field both of them carry.

    ``None`` means they share no field, so this frame says nothing either way.
    """
    agreements: list[bool] = []
    if trace.summary_function and frame.function:
        agreements.append(bare_function(trace.summary_function) == bare_function(frame.function))
    if trace.summary_path and frame.path:
        agreements.append(_same_path(trace.summary_path, frame.path))
    if trace.summary_line is not None and frame.line is not None:
        agreements.append(trace.summary_line == frame.line)
    return all(agreements) if agreements else None


def _summary_matches_frames(trace: TraceData) -> Verdict:
    """Rule 5: the SUMMARY names the frame the crash was attributed to.

    Current ASan attributes an intercepted copy to the interceptor and prints the module
    instead of a source location (``… (hdrcat+0x4a44a1) in __asan_memcpy``); older releases
    and UBSan print the application's ``file:line``. Both are correct output, so the SUMMARY
    may match the topmost frame or the first application frame.
    """
    if trace.summary is None or not trace.frames:
        return NOT_CHECKABLE
    top = trace.frames[0]
    app = next((f for f in trace.frames if not f.is_runtime and f.function), None)
    candidates = [top] if app is None or app is top else [top, app]
    compared = False
    for frame in candidates:
        agrees = _summary_matches_summary_frame(trace, frame)
        if agrees is None:
            continue
        if agrees:
            return OK
        compared = True
    if not compared:
        return NOT_CHECKABLE
    frames = " or ".join(_where(frame) for frame in candidates)
    return broken(f"SUMMARY points at {_summary_where(trace)}, but the crash is in {frames}")


def _expects_alloc_stack(bug_type: str) -> bool:
    return bug_type.startswith("heap-") or bug_type in _RELEASED_REGION_BUGS


def _expects_free_stack(bug_type: str) -> bool:
    return "use-after-free" in bug_type or bug_type in _RELEASED_REGION_BUGS


def _stacks_present(trace: TraceData) -> Verdict:
    """Rule 6: heap bugs carry an allocation stack, use-after-free also carries a free one.

    Gated on the trace reaching past where those stacks belong: a sanitizer prints them
    between the region line and the SUMMARY, so only a trace carrying *both* of those can be
    missing one. A reporter who trimmed the paste after the region line is not contradicting
    themselves (P4).
    """
    bug_type = (trace.bug_type or "").lower()
    wants_alloc = _expects_alloc_stack(bug_type)
    wants_free = _expects_free_stack(bug_type)
    if not (wants_alloc or wants_free):
        return NOT_CHECKABLE
    if trace.region_address is None or trace.summary is None:
        return NOT_CHECKABLE
    missing: list[str] = []
    if wants_alloc and not trace.alloc_frames:
        missing.append("an allocation stack")
    if wants_free and not trace.free_frames:
        missing.append("a free stack")
    if not missing:
        return OK
    tail = "neither" if len(missing) > 1 else "none"
    return broken(
        f"a {_short(bug_type)} report prints {' and '.join(missing)} between the region line"
        f" and the SUMMARY, and this one has {tail}"
    )


def _access_size(trace: TraceData) -> Verdict:
    """Rule 7: the access size is one a sanitizer can report at all."""
    access = trace.access
    if access is None or access.size is None:
        return NOT_CHECKABLE
    if 1 <= access.size <= MAX_ACCESS_SIZE:
        return OK
    return broken(
        f"{access.kind} of size {access.size} is not a size any sanitizer reports"
        " (a faulting access is at least one byte and never gigabytes wide)"
    )


#: The SPEC §12 rules in order, with the short name a summary uses for each.
RULES: tuple[tuple[str, str, Callable[[TraceData], Verdict]], ...] = (
    ("pid_consistent", "the process ID", _pid_consistent),
    ("frame_indices", "the frame numbering", _frame_indices),
    ("addresses_agree", "the faulting address", _addresses_agree),
    ("region_arithmetic", "the region arithmetic", _region_arithmetic),
    ("summary_matches_frames", "the SUMMARY line", _summary_matches_frames),
    ("stacks_present", "the allocation and free stacks", _stacks_present),
    ("access_size", "the access size", _access_size),
)


@register
class SanitizerSanity(BaseCheck):
    id = CHECK_ID
    name = "SANITIZER_SANITY"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"trace"})
    description = (
        "Checks a sanitizer trace against itself: PIDs, frame numbering, addresses,"
        " region arithmetic, the SUMMARY line, the alloc and free stacks, and the access size."
    )

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, TraceClaim) or claim.format not in SANITIZER_FORMATS:
                continue
            evidence = self._one(claim)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, claim: TraceClaim) -> Evidence | None:
        checked: list[str] = []
        violations: list[dict[str, str]] = []
        for key, label, rule in RULES:
            verdict = rule(claim)
            if not verdict.checked:
                continue
            checked.append(key)
            if verdict.detail:
                violations.append({"rule": key, "name": label, "detail": verdict.detail})
        if not checked:
            # Nothing in this trace is a claim about itself; C08 to C10 judge it instead.
            return None
        tool = _TOOL_NAMES.get(claim.format, claim.format)
        details: dict[str, Any] = {
            "format": claim.format,
            "bug_type": claim.bug_type,
            "rules_checked": checked,
            "rules_total": len(RULES),
            "violations": violations,
        }
        if not violations:
            details["outcome"] = "consistent"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, "consistent"),
                summary=f"the {tool} output is internally consistent"
                f" ({len(checked)} of {len(RULES)} consistency rules apply to it)",
                details=details,
            )
        # SPEC §12: each violated rule is one step, and the whole group is capped, so a
        # single self-contradicting trace cannot outvote the rest of the report on its own.
        strength = max(
            self.strengths.get(CHECK_ID, "violation_cap"),
            len(violations) * self.strengths.get(CHECK_ID, "violation"),
        )
        details["outcome"] = "violation"
        if len(violations) == 1:
            summary = f"the {tool} output contradicts itself: {violations[0]['detail']}"
        else:
            named = ", ".join(violation["name"] for violation in violations)
            summary = f"the {tool} output contradicts itself in {len(violations)} places: {named}"
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=strength,
            summary=summary,
            details=details,
        )
