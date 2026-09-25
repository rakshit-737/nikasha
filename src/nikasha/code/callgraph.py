# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Name-based call graph (SPEC §11.4): can ``caller`` call ``callee`` at a commit?

``edge`` answers one of:

* ``direct``: the caller's body contains a direct call to the callee;
* ``macro``: the caller invokes a macro whose replacement text calls the callee;
* ``inlined_2hop``: the caller calls a small (≤30 lines) or ``static inline`` function that
  calls the callee directly (optimizers inline these, so traces skip the middle frame);
* ``indirect_possible``: the callee's address is taken somewhere, and the caller makes an
  indirect call (a function pointer or method dispatch could reach it);
* ``none``: none of the above.

This is approximate by design (name-based, no type resolution); the threat model says so.
Every answer carries the locations that justify it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from nikasha.code.facts import CallSite, MacroDef, SymbolDef
from nikasha.code.index import CodeIndex
from nikasha.errors import ExternalToolError

EdgeKind = Literal["direct", "macro", "inlined_2hop", "indirect_possible", "none"]
SMALL_FUNCTION_LINES = 30


@dataclass(frozen=True, slots=True)
class Evidence:
    path: str
    line: int
    note: str


@dataclass
class Edge:
    caller: str
    callee: str
    kind: EdgeKind
    evidence: list[Evidence] = field(default_factory=list)
    caller_found: bool = True
    #: The calls the caller actually makes (for "hdr_get calls: hdr_find_line, util_strip").
    caller_calls: list[str] = field(default_factory=list)


def _bare(name: str) -> str:
    return name.replace("::", ".").rsplit(".", 1)[-1]


def _calls_in(index: CodeIndex, commit: str, path: str, sym: SymbolDef) -> list[CallSite]:
    facts = index.facts_at(commit, path)
    if facts is None:
        return []

    def inside(call: CallSite) -> bool:
        if call.caller_qname is not None:
            return call.caller_qname == sym.qname
        return sym.start_line <= call.line <= sym.end_line

    return [c for c in facts.calls if inside(c)]


def _functions(index: CodeIndex, commit: str, name: str) -> list[tuple[str, SymbolDef]]:
    return [(p, s) for p, s in index.definitions(commit, name) if s.kind in ("function", "method")]


CallList = list[tuple[str, CallSite]]


def _direct(index: CodeIndex, commit: str, calls: CallList, target: str) -> list[Evidence]:
    return [
        Evidence(p, c.line, "direct call")
        for p, c in calls
        if c.callee == target and not c.indirect
    ]


def _via_macro(index: CodeIndex, commit: str, calls: CallList, target: str) -> list[Evidence]:
    hits: list[Evidence] = []
    for path, call in calls:
        for mpath, macro in _macros(index, commit, call.callee):
            if target in macro.calls:
                hits.append(
                    Evidence(path, call.line, f"via macro {macro.name} ({mpath}:{macro.line})")
                )
    return hits


def _two_hop(index: CodeIndex, commit: str, calls: CallList, target: str) -> list[Evidence]:
    hits: list[Evidence] = []
    for path, call in calls:
        if call.indirect or call.callee == target:
            continue
        for mpath, mid in _functions(index, commit, call.callee):
            small = (mid.end_line - mid.start_line + 1) <= SMALL_FUNCTION_LINES
            if not (small or "inline" in mid.flags):
                continue
            inner = _calls_in(index, commit, mpath, mid)
            if any(c.callee == target and not c.indirect for c in inner):
                hits.append(
                    Evidence(path, call.line, f"via {mid.qname} ({mpath}:{mid.start_line})")
                )
    return hits


def _indirect(index: CodeIndex, commit: str, calls: CallList, target: str) -> list[Evidence]:
    indirect_calls = [(p, c) for p, c in calls if c.indirect]
    if not indirect_calls:
        return []
    try:
        taken = _address_taken(index, commit, target)
    except ExternalToolError:
        # The search for the callee's address did not finish, so "cannot call" is unknown:
        # the edge stays possible rather than becoming ``none`` (P4).
        return [
            Evidence(
                p,
                c.line,
                f"indirect call via {c.callee} (where {target} is address-taken could not"
                " be searched, so the edge is not ruled out)",
            )
            for p, c in indirect_calls[:5]
        ]
    if not taken:
        return []
    return [Evidence(p, c.line, f"indirect call via {c.callee}") for p, c in indirect_calls[:5]]


_STEPS = (
    ("direct", _direct),
    ("macro", _via_macro),
    ("inlined_2hop", _two_hop),
    ("indirect_possible", _indirect),
)


def edge(index: CodeIndex, commit: str, caller: str, callee: str) -> Edge:
    """Classify the call edge ``caller → callee`` at ``commit`` (see module docstring).

    Raises :class:`~nikasha.errors.ExternalToolError` when git cannot finish a definition
    search (lazy index): the caller must treat the edge as not searched, never as ``none``.
    """
    target = _bare(callee)
    callers = _functions(index, commit, caller)
    if not callers:
        return Edge(caller, callee, "none", caller_found=False)
    calls: CallList = []
    for path, sym in callers:
        calls += [(path, c) for c in _calls_in(index, commit, path, sym)]
    names = sorted({c.callee for _, c in calls})
    for kind, step in _STEPS:
        evidence = step(index, commit, calls, target)
        if evidence:
            return Edge(caller, callee, kind, evidence, caller_calls=names)  # type: ignore[arg-type]
    return Edge(caller, callee, "none", caller_calls=names)


def _macros(index: CodeIndex, commit: str, name: str) -> list[tuple[str, MacroDef]]:
    out: list[tuple[str, MacroDef]] = []
    for path, sym in index.definitions(commit, name):
        if sym.kind != "macro":
            continue
        facts = index.facts_at(commit, path)
        if facts is not None:
            out += [(path, m) for m in facts.macros if m.name == name]
    return out


def _address_taken(index: CodeIndex, commit: str, name: str) -> bool:
    for hit in index.repo.grep(name, [commit], word=True, files_only=True, max_hits=200):
        facts = index.facts_at(commit, hit.path)
        if facts is not None and name in facts.addr_taken:
            return True
    return False
