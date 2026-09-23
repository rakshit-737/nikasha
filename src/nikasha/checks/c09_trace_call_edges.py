# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C09 TRACE_CALL_EDGES: can each consecutive pair of trace frames really call? (SPEC §12)

A stack trace asserts more than a list of locations: frame ``i+1`` called frame ``i``.
Those edges are the part of a pasted trace that is hardest to invent consistently, because
they have to agree with the call graph at the exact version — the demo fabrication's
``hdr_get -> util_copy_value`` is a call ``hdr_get`` has never made, in any release.

What this check refuses to do matters as much as what it does:

* **Edges into files outside the repository are skipped, never counted as missing.** Real
  traces cross into libc, the sanitizer runtime and third-party libraries constantly, and
  across such a boundary the frame above is usually not the caller of the frame below in
  any sense this repository can see. Counting that as a fabricated call edge is exactly
  the false-positive mode ADR 0003 exists to prevent.
* **Unknown is never missing (P4).** If either endpoint sits in a file that did not parse
  cleanly, in a generated file (SPEC §11.5), or names a function that is not defined at
  this commit at all, the edge is excluded and reported as unknown. A symbol that does not
  exist is C03's finding and a frame that does not fit its file is C08's; neither should be
  refuted a second time here.

Only the primary stack is walked: ASan's allocation and free stacks describe a different
moment in the program's life, and C11 owns their consistency.
"""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.callgraph import EdgeKind, edge
from nikasha.code.callgraph import Evidence as CallSite
from nikasha.code.facts import FileFacts
from nikasha.code.trace_forensics import app_frames, bare_function
from nikasha.model.claims import Claim, ClaimKind, Frame, TraceClaim
from nikasha.model.evidence import CodeLocation, Evidence, Outcome

CHECK_ID = "C09"
GROUP = "trace"

#: Edge kinds that mean "the call the trace shows can really happen at this commit".
REAL_KINDS: frozenset[str] = frozenset({"direct", "macro", "inlined_2hop"})

#: Caps that keep one evidence item's details bounded on a deep trace.
MAX_SITES = 5
MAX_CALLER_CALLS = 20
MAX_LOCATIONS = 10
MAX_NAMED = 3

#: Why one endpoint cannot take part in a checkable edge. ``outside_repo`` is a skip (the
#: trace left the repository); the rest are *unknown*, which never counts against a report.
EndpointStatus = Literal["checkable", "outside_repo", "generated", "unparsed", "undefined"]


def file_is_certain(facts: FileFacts | None) -> bool:
    """Whether ``facts`` can settle whether a call exists.

    A file with no facts at all (a Makefile, a README) and a file whose parse was cut short
    or hit an error tree both leave absence unproven, so neither may produce a missing edge
    (P4). :attr:`FileFacts.parsed_ok` is the parser's own verdict on that.
    """
    return facts is not None and facts.parsed_ok


def score_edges(
    kinds: Sequence[EdgeKind], strengths: Strengths, *, truncated: bool = False
) -> tuple[Outcome, float]:
    """Score the classified edges of one trace (SPEC §12, C09).

    Isolated from the walk so the arithmetic — in particular the ``missing_edge_cap``, which
    stops a long fabricated stack from dominating a verdict on its own — is auditable and
    directly testable. ``truncated`` means the budget ran out before every pair was looked
    at, which blocks the "every edge is real" support but leaves each classified missing
    edge standing on its own.
    """
    missing = sum(1 for kind in kinds if kind == "none")
    if missing:
        per_edge = strengths.get(CHECK_ID, "missing_edge")
        cap = strengths.get(CHECK_ID, "missing_edge_cap")
        return "REFUTES", max(cap, per_edge * missing)
    if kinds and not truncated and all(kind in REAL_KINDS for kind in kinds):
        return "SUPPORTS", strengths.get(CHECK_ID, "all_edges_real")
    return "NEUTRAL", strengths.get(CHECK_ID, "indirect_possible")


def edge_outcome_key(outcome: Outcome) -> str:
    """The strengths key :func:`score_edges` used to reach ``outcome``.

    Its three branches map one-to-one onto the three outcomes, so naming the key here keeps
    the evidence self-describing (SPEC §14.3 reads ``details['outcome']``) without repeating
    the arithmetic, which stays in the ``n_missing`` and ``n_checked`` details.
    """
    if outcome == "REFUTES":
        return "missing_edge"
    if outcome == "SUPPORTS":
        return "all_edges_real"
    return "indirect_possible"


@dataclass(frozen=True, slots=True)
class _Endpoint:
    """One application frame, resolved against the tree at the checked commit."""

    index: int
    display: str
    function: str
    path: str | None
    status: EndpointStatus
    reason: str = ""


@dataclass
class _Walk:
    """What walking one trace's app frames found, in stack order."""

    checked: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[dict[str, Any]] = field(default_factory=list)
    kinds: list[EdgeKind] = field(default_factory=list)
    locations: list[CodeLocation] = field(default_factory=list)
    pairs: int = 0
    truncated: bool = False


@register
class TraceCallEdges(BaseCheck):
    id = CHECK_ID
    name = "TRACE_CALL_EDGES"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"trace"})
    description = "Checks that each consecutive pair of trace frames is a call the code can make."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, TraceClaim):
                continue
            evidence = self._one(ctx, claim)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, ctx: CheckContext, claim: TraceClaim) -> Evidence | None:
        walk = _walk(ctx, claim)
        if walk.pairs == 0:
            # Fewer than two application frames: the trace asserts no call edge at all.
            return None
        outcome, strength = score_edges(walk.kinds, self.strengths, truncated=walk.truncated)
        details: dict[str, Any] = {
            "outcome": edge_outcome_key(outcome),
            "edges": walk.checked,
            "skipped": walk.skipped,
            "unknown": walk.unknown,
            "n_pairs": walk.pairs,
            "n_checked": len(walk.kinds),
            "n_missing": sum(1 for kind in walk.kinds if kind == "none"),
            "n_indirect": sum(1 for kind in walk.kinds if kind == "indirect_possible"),
            "trace_format": claim.format,
        }
        if walk.truncated:
            details["truncated"] = True
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome=outcome,
            strength=strength,
            summary=_summary(ctx, walk, outcome),
            details=details,
            locations=walk.locations[:MAX_LOCATIONS],
        )


def _walk(ctx: CheckContext, trace: TraceClaim) -> _Walk:
    """Classify every consecutive pair of application frames, innermost first."""
    walk = _Walk()
    endpoints = [_endpoint(ctx, frame) for frame in app_frames(trace)]
    walk.pairs = max(0, len(endpoints) - 1)
    # Stacks are innermost-first, so in each pair the caller is the *later* frame.
    for callee, caller in itertools.pairwise(endpoints):
        if ctx.expired():
            walk.truncated = True
            break
        blocked = [end for end in (caller, callee) if end.status != "checkable"]
        if blocked:
            record = _pair(caller, callee)
            record["reasons"] = [end.reason for end in blocked]
            left_repo = any(end.status == "outside_repo" for end in blocked)
            (walk.skipped if left_repo else walk.unknown).append(record)
            continue
        found = edge(ctx.index, ctx.commit, caller.function, callee.function)
        sites = sorted(f"{e.path}:{e.line} {e.note}" for e in found.evidence)
        record = _pair(caller, callee)
        record["kind"] = found.kind
        record["sites"] = sites[:MAX_SITES]
        if found.kind == "none":
            # "hdr_get calls hdr_casecmp, hdr_find_line, strncpy" is the useful half of a
            # missing edge: it shows the reporter what the function does do.
            record["caller_calls"] = found.caller_calls[:MAX_CALLER_CALLS]
        walk.checked.append(record)
        walk.kinds.append(found.kind)
        location = _location(ctx, caller, found.evidence[0] if found.evidence else None)
        if location is not None:
            walk.locations.append(location)
    return walk


def _pair(caller: _Endpoint, callee: _Endpoint) -> dict[str, Any]:
    return {
        "caller": caller.display,
        "callee": callee.display,
        "caller_frame": caller.index,
        "callee_frame": callee.index,
        "caller_path": caller.path,
        "callee_path": callee.path,
    }


def _endpoint(ctx: CheckContext, frame: Frame) -> _Endpoint:
    """Resolve one frame's file and function, and say whether an edge through it is judgeable."""
    name = bare_function(frame.function or "")
    display = frame.function or name
    ref = _ref(ctx)
    path = _resolve(ctx, frame, name)
    generated = ctx.generated(path if path is not None else frame.path or "")
    if generated is not None:
        reason = f"{generated.path} is {generated.kind} ({generated.reason}), so it is not judged"
        return _Endpoint(frame.index, display, name, path, "generated", reason)
    if path is None:
        where = frame.path or "a frame with no file"
        return _Endpoint(
            frame.index, display, name, None, "outside_repo", f"{where} is not in the tree at {ref}"
        )
    if not file_is_certain(ctx.facts(path)):
        reason = f"{path} did not parse cleanly at {ref}, so a missing call is not certain"
        return _Endpoint(frame.index, display, name, path, "unparsed", reason)
    if not _defined(ctx, name):
        reason = f"no function {name} is defined at {ref} (C03 owns that finding)"
        return _Endpoint(frame.index, display, name, path, "undefined", reason)
    return _Endpoint(frame.index, display, name, path, "checkable")


def _resolve(ctx: CheckContext, frame: Frame, name: str) -> str | None:
    """The one tree path this frame names, tie-broken by which candidate defines ``name``."""
    if frame.path is None:
        return None
    candidates = ctx.resolve_path(frame.path)
    if len(candidates) > 1:

        def defines(path: str) -> bool:
            facts = ctx.facts(path)
            return facts is not None and bool(facts.definitions(name))

        candidates = ctx.trie.disambiguate(frame.path, candidates, defines)
    return candidates[0] if candidates else None


def _defined(ctx: CheckContext, name: str) -> bool:
    return any(
        symbol.kind in ("function", "method")
        for _, symbol in ctx.index.definitions(ctx.commit, name)
    )


def _location(ctx: CheckContext, caller: _Endpoint, site: CallSite | None) -> CodeLocation | None:
    """The call site that justifies an edge, or the caller's body when there is none."""
    if site is not None:
        return ctx.location(site.path, site.line)
    if caller.path is None:
        return None
    facts = ctx.facts(caller.path)
    if facts is None:
        return None
    defined = facts.definitions(caller.function)
    if not defined:
        return None
    return ctx.location(caller.path, defined[0].start_line, defined[0].end_line)


def _ref(ctx: CheckContext) -> str:
    return ctx.ref_name or ctx.commit[:12]


def _arrow(record: dict[str, Any]) -> str:
    return f"{record['caller']} -> {record['callee']}"


def _join(records: Sequence[dict[str, Any]]) -> str:
    named = ", ".join(_arrow(r) for r in records[:MAX_NAMED])
    extra = len(records) - MAX_NAMED
    return f"{named} and {extra} more" if extra > 0 else named


def _summary(ctx: CheckContext, walk: _Walk, outcome: Outcome) -> str:
    ref = _ref(ctx)
    checked = walk.checked
    if outcome == "REFUTES":
        missing = [r for r in checked if r["kind"] == "none"]
        return (
            f"{_join(missing)}: no such call at {ref}"
            f" ({len(missing)} of {len(checked)} checked call edges in the trace)"
        )
    if outcome == "SUPPORTS":
        return f"all {len(checked)} call edges in the trace exist at {ref}: {_join(checked)}"
    if checked:
        indirect = [r for r in checked if r["kind"] == "indirect_possible"]
        return (
            f"{len(indirect)} of {len(checked)} checked call edges could only be indirect at"
            f" {ref} ({_join(indirect)}), so the trace is neither confirmed nor contradicted"
        )
    parts = []
    if walk.skipped:
        parts.append(f"{len(walk.skipped)} leave the repository")
    if walk.unknown:
        parts.append(f"{len(walk.unknown)} are unknown")
    if walk.truncated:
        parts.append("the check ran out of time")
    reason = "; ".join(parts) if parts else "nothing was checkable"
    return f"no call edge in the trace could be checked at {ref}: {reason}"
