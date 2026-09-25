# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C18 API_USAGE: does the subject function really call the API the report names? (SPEC §12)

"``hdr_parse_line()`` calls ``util_copy_value()``" is a claim about code that the call graph
can settle at the exact commit. A direct call, a call through a macro's replacement text, and
one hop through a small or ``static inline`` wrapper all count as "calls it": an optimizer
erases that middle frame, and reports describe the code as written (SPEC §11.4).

Only the ``calls_api`` predicate is decided here. The other four — a missing bounds check, a
missing NULL check, a use-after-free, an integer overflow — need dataflow that a name-based
call graph does not have, so they stay NEUTRAL in deterministic mode (C20 may look at them
when the LLM is enabled). They still produce evidence, because SPEC §12 asks for the locus to
be located and shown even when nothing is judged: that excerpt is what the HTML report puts
in front of the reader.

"It does not call that" is the one destructive answer this check can give, so absence is only
claimed when the code is in a state that could have shown the call (P4). A subject that is not
defined, a file that parsed only partially, a call through a function pointer, and a callee
whose address is taken each turn that refutation back into a NEUTRAL that says why.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.callgraph import Evidence as CallEvidence
from nikasha.code.callgraph import edge
from nikasha.code.facts import CallSite, FileFacts, SymbolDef
from nikasha.model.claims import BehaviorClaim, Claim, ClaimKind
from nikasha.model.evidence import CodeLocation, Evidence

CHECK_ID = "C18"
GROUP = "behavior"

#: Edge kinds that answer "yes, it calls it" (SPEC §12: directly, via a macro, or within 1 hop).
CALLING_EDGES = frozenset({"direct", "macro", "inlined_2hop"})

#: How many callee names a summary spells out before deferring to ``details['calls']``.
MAX_LISTED_CALLS = 12

#: How many justifications a supporting summary spells out.
MAX_LISTED_SITES = 3

#: What each predicate asserts, in the words a summary can use.
PREDICATE_PROSE = {
    "calls_api": "the claimed call",
    "missing_bounds_check": "a missing bounds check",
    "missing_null_check": "a missing NULL check",
    "uses_freed": "a use after free",
    "integer_overflow": "an integer overflow",
}


@dataclass(frozen=True, slots=True)
class Site:
    """One place the subject symbol is defined, with the facts of the file holding it."""

    path: str
    symbol: SymbolDef
    facts: FileFacts | None


def calls_inside(site: Site) -> list[CallSite]:
    """The calls the parser attributed to this definition.

    Languages where the parser records a qualified caller are matched by name; C, where a
    call at file scope carries ``caller_qname=None``, falls back to the definition's lines.
    """
    if site.facts is None:
        return []
    symbol = site.symbol
    return [
        call
        for call in site.facts.calls
        if call.caller_qname == symbol.qname
        or (call.caller_qname is None and symbol.start_line <= call.line <= symbol.end_line)
    ]


def absence_uncertainty(sites: Sequence[Site], api: str) -> str | None:
    """Why "it does not call that" cannot be said here, or ``None`` when it can (P4).

    Absence is evidence only when the code could have shown the call. A partially parsed file
    may be hiding it behind an error node; an indirect call may *be* it, since a function
    pointer names nothing the parser can resolve; and a callee whose address is taken can be
    reached without ever appearing as a callee. Each of those is a reason to say "uncertain",
    which is the answer P4 wants whenever the alternative is a false "fabricated".
    """
    if not sites:
        return "the function is not defined at this commit"
    for site in sites:
        if site.facts is None or not site.facts.parsed_ok:
            return f"{site.path} did not parse cleanly, so a call there could have been missed"
    for site in sites:
        indirect = next((c for c in calls_inside(site) if c.indirect), None)
        if indirect is not None:
            return (
                f"{site.path}:{indirect.line} calls through {indirect.callee},"
                " which could dispatch anywhere"
            )
    # The call graph matches the bare name (``Foo::bar`` and ``obj.bar`` both mean ``bar``),
    # so the address-taken test must too, or a qualified API name slips past it.
    bare = api.replace("::", ".").rsplit(".", 1)[-1]
    for site in sites:
        if site.facts is not None and bare in site.facts.addr_taken:
            return f"the address of {bare} is taken in {site.path}, so it can be called unnamed"
    return None


@register
class ApiUsage(BaseCheck):
    id = CHECK_ID
    name = "API_USAGE"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"behavior"})
    description = "Checks a claimed call from one function to an API against the call graph."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, BehaviorClaim):
                continue
            if ctx.expired():  # `edge` greps for address-taken callees; the budget is real
                break
            out.append(self._one(ctx, claim))
        return out

    def _one(self, ctx: CheckContext, claim: BehaviorClaim) -> Evidence:
        sites = _sites(ctx, claim.subject_symbol)
        locations = [ctx.location(s.path, s.symbol.start_line, s.symbol.end_line) for s in sites]
        generated = _generated_site(ctx, sites)
        if generated is not None:
            path, kind, reason = generated
            return self._undecided(
                claim,
                f"{claim.subject_symbol} is defined in {path}, which is {kind},"
                " so its calls are not judged",
                {"path": path, "generated": reason},
                locations,
            )
        if claim.predicate != "calls_api":
            return self._locus_only(ctx, claim, sites, locations)
        if claim.object is None:
            return self._undecided(
                claim,
                f"the report does not name the API {claim.subject_symbol} is said to call",
                {"paths": [s.path for s in sites]},
                locations,
            )
        return self._calls_api(ctx, claim, sites, locations, claim.object)

    def _calls_api(
        self,
        ctx: CheckContext,
        claim: BehaviorClaim,
        sites: Sequence[Site],
        locations: Sequence[CodeLocation],
        api: str,
    ) -> Evidence:
        link = edge(ctx.index, ctx.commit, claim.subject_symbol, api)
        details: dict[str, Any] = {
            "object": api,
            "edge": link.kind,
            "calls": list(link.caller_calls),
            "paths": [site.path for site in sites],
        }
        if link.kind in CALLING_EDGES:
            hits = sorted(link.evidence, key=lambda e: (e.path, e.line, e.note))
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, "calls_api"),
                summary=f"{claim.subject_symbol} calls {api} at {_at(ctx)}: {_notes(hits)}",
                details=details
                | {"outcome": "calls_api", "call_sites": [f"{e.path}:{e.line}" for e in hits]},
                locations=_dedupe([*locations, *(ctx.location(e.path, e.line) for e in hits)]),
            )
        uncertain = absence_uncertainty(sites, api)
        if uncertain is not None:
            return self._undecided(
                claim,
                f"whether {claim.subject_symbol} calls {api} at {_at(ctx)} cannot be"
                f" established: {uncertain}",
                details | {"uncertain": uncertain},
                locations,
            )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "does_not_call_api"),
            summary=f"{claim.subject_symbol} does not call {api} at {_at(ctx)};"
            f" it calls {_listed(link.caller_calls)}",
            details=details | {"outcome": "does_not_call_api"},
            locations=locations,
        )

    def _locus_only(
        self,
        ctx: CheckContext,
        claim: BehaviorClaim,
        sites: Sequence[Site],
        locations: Sequence[CodeLocation],
    ) -> Evidence:
        """NEUTRAL for a predicate the deterministic core cannot settle, with the code shown."""
        prose = PREDICATE_PROSE[claim.predicate]
        if not sites:
            return self._undecided(
                claim,
                f"{claim.subject_symbol} is not defined at {_at(ctx)}, so {prose} in it"
                " is not judged here",
                {"suggestions": ctx.suggest_symbols(claim.subject_symbol)},
                locations,
            )
        where = ", ".join(f"{s.path}:{s.symbol.start_line}" for s in sites)
        return self._undecided(
            claim,
            f"{prose} in {claim.subject_symbol} ({where}) needs dataflow analysis,"
            " which the deterministic core does not do",
            {"paths": [site.path for site in sites]},
            locations,
        )

    def _undecided(
        self,
        claim: BehaviorClaim,
        summary: str,
        details: dict[str, Any],
        locations: Sequence[CodeLocation],
    ) -> Evidence:
        """NEUTRAL evidence that still carries the locus: shown to the reader, scored at zero."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=self.strengths.get(CHECK_ID, "other_predicate"),
            summary=summary,
            details={
                "outcome": "other_predicate",
                "subject": claim.subject_symbol,
                "predicate": claim.predicate,
                **details,
            },
            locations=locations,
        )


def _sites(ctx: CheckContext, name: str) -> list[Site]:
    """Every function-like definition of ``name`` at the commit, ordered by path and line."""
    found = [
        Site(path, symbol, ctx.facts(path))
        for path, symbol in ctx.index.definitions(ctx.commit, name)
        if symbol.kind in ("function", "method")
    ]
    return sorted(found, key=lambda site: (site.path, site.symbol.start_line))


def _generated_site(ctx: CheckContext, sites: Sequence[Site]) -> tuple[str, str, str] | None:
    """The first generated or release-only file holding the subject; such code is never judged."""
    for site in sites:
        match = ctx.generated(site.path)
        if match is not None:
            return site.path, match.kind, match.reason
    return None


def _at(ctx: CheckContext) -> str:
    return ctx.ref_name or ctx.commit[:12]


def _notes(hits: Sequence[CallEvidence]) -> str:
    shown = [f"{hit.note} at {hit.path}:{hit.line}" for hit in hits[:MAX_LISTED_SITES]]
    return "; ".join(shown) if shown else "no call site recorded"


def _listed(names: Sequence[str]) -> str:
    """The callees, spelled out — SPEC §12 wants the refutation to say what it *does* call."""
    if not names:
        return "nothing"
    shown = ", ".join(names[:MAX_LISTED_CALLS])
    rest = len(names) - MAX_LISTED_CALLS
    return f"{shown}, and {rest} more" if rest > 0 else shown


def _dedupe(locations: Sequence[CodeLocation]) -> list[CodeLocation]:
    by_span = {(loc.path, loc.start_line, loc.end_line): loc for loc in locations}
    return [by_span[key] for key in sorted(by_span)]
