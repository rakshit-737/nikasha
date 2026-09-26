# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C05 LINE_IN_FUNCTION: does the cited line fall inside the named function? (SPEC §12)

A report saying "the overflow is in ``util_copy_value()`` at ``src/util.c:30``" makes two
statements that must agree with each other. When they do not, the useful answer is not
"wrong" but *what is actually there*: naming the function that really contains line 30
turns a contradiction into something the reporter can act on, and it is the difference
between a refutation and an accusation (P1, P6).

The same question is asked of every application frame of a stack trace, where a frame
pairs a function with a line by construction. C08 aggregates those per-frame answers into
a consistency ratio; this check states each one.

Two softenings matter more than the refutation itself:

* **A near miss is usually a version mistake, not a fabrication.** If the line does fall
  inside that function in a neighbouring release, the report is most likely written
  against a different version, so the strength drops to ``fits_nearby_release`` and the
  details carry a ``version_fit_hint`` for C10 to pick up (SPEC §12 C05, C10).
* **P4.** Absence of the function, or a file that did not parse cleanly, is never evidence
  that the line is somewhere else: both are NEUTRAL here. A function that is missing
  altogether is C03's finding, and refuting it twice is exactly the double-counting group
  damping exists to stop (SPEC §14.1).
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.amalgamation import cached_amalgamation, resolve_source
from nikasha.code.facts import FileFacts, SymbolDef
from nikasha.code.trace_forensics import app_frames, same_function
from nikasha.errors import NikashaError
from nikasha.model.claims import Claim, ClaimKind, LineClaim, TraceClaim
from nikasha.model.evidence import CodeLocation, Evidence
from nikasha.resolve.refs import Release

CHECK_ID = "C05"
GROUP = "lines"

#: Final releases either side of the claimed one that are searched for a version fit.
#: C10 scores whole traces over ±15; one line needs only the immediate neighbourhood, and
#: each release costs a tree read plus a parse.
NEARBY_RADIUS = 3

#: Only definitions with a body can contain a line; a macro or a type cannot.
FUNCTION_KINDS = frozenset({"function", "method"})

#: A function name longer than this is not a name anybody wrote by hand; normalizing it
#: against every symbol of up to seven parsed files is attacker-sized work (P7).
MAX_FUNCTION_NAME = 1024

#: How far either side of a prose line reference the report is searched for the name of
#: the function that really encloses the line (``X() is called from Y() at f.c:30``).
HINT_WINDOW = 300


@dataclass(frozen=True, slots=True)
class _Site:
    """One (path, line, function) triple to judge: a line claim, or one trace frame."""

    path: str
    line: int
    function: str
    frame: int | None = None
    end_line: int | None = None
    #: The ``sqlite3.c`` path and line this site was mapped from (SPEC §11.5), if any.
    amalgamation: tuple[str, int] | None = None


@dataclass(frozen=True, slots=True)
class _Fit:
    """The claimed function *does* contain the line, but in another release."""

    release: str
    commit: str
    start_line: int
    end_line: int
    releases: tuple[str, ...]


def _function_defs(facts: FileFacts, name: str) -> list[SymbolDef]:
    """Definitions of ``name`` in this file that a line could be inside.

    Exact names first; the fallback normalizes what reports and traces actually write
    (``util_copy_value()``, ``ns::Class::method(int) const``) the same way the trace
    forensics do, so prose and frames are judged by one rule.
    """
    exact = [s for s in facts.definitions(name) if s.kind in FUNCTION_KINDS]
    if exact:
        return exact
    return [s for s in facts.symbols if s.kind in FUNCTION_KINDS and same_function(name, s)]


def _contains(defs: Sequence[SymbolDef], line: int) -> SymbolDef | None:
    """The first definition whose span covers ``line`` (overloads and ``#if`` twins)."""
    return next((s for s in defs if s.start_line <= line <= s.end_line), None)


def _span(sym: SymbolDef) -> list[int]:
    return [sym.start_line, sym.end_line]


@register
class LineInFunction(BaseCheck):
    id = CHECK_ID
    name = "LINE_IN_FUNCTION"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"line", "trace"})
    description = "Checks that a line said to be in a function really is inside its span."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            for site in _sites(claim):
                if ctx.expired():
                    # The budget is spent: say so, identically, instead of judging.
                    out.append(
                        self._neutral(
                            claim,
                            site,
                            summary=f"the time budget ran out before line {site.line}"
                            f" of {site.path} was judged",
                            details={"outcome": "budget_expired"},
                        )
                    )
                    continue
                evidence = self._one(ctx, claim, site)
                if evidence is not None:
                    out.append(evidence)
        return out

    def _one(self, ctx: CheckContext, claim: Claim, site: _Site) -> Evidence | None:  # noqa: PLR0911
        if len(site.function) > MAX_FUNCTION_NAME:
            return self._neutral(
                claim,
                site,
                summary=f"the function name at {site.path}:{site.line} is longer than"
                f" {MAX_FUNCTION_NAME} characters, so it is not judged",
                details={"outcome": "function_name_too_long"},
            )
        candidates = ctx.resolve_path(site.path)
        # A path that does not resolve may still be generated (an amalgamation is not in
        # the tree at all), and §11.5 says those are never judged.
        path = candidates[0] if len(candidates) == 1 else site.path
        generated = ctx.generated(path)
        if generated is not None:
            mapped = (
                _map_amalgamation(ctx, path, site) if generated.kind == "amalgamation" else None
            )
            if isinstance(mapped, _Site):
                evidence = self._one(ctx, claim, mapped)
                if evidence is None or evidence.outcome != "REFUTES":
                    return evidence
                # P4: an amalgamation line is only as good as the release it came from, and
                # one built from another version shifts every line; a mapped mismatch is
                # shown but never counts against the report.
                return self._neutral(
                    claim,
                    mapped,
                    summary=f"the line is not inside {mapped.function}() as mapped, but an"
                    " amalgamation from another release would shift every line, so this is"
                    " not judged",
                    details={"outcome": "amalgamation_mismatch", "mapped": evidence.summary},
                )
            extra = {"amalgamation": mapped} if isinstance(mapped, str) else {}
            return self._neutral(
                claim,
                site,
                summary=f"{path} is {generated.kind}, so its line numbers are not judged",
                details={
                    "outcome": "generated",
                    "path": path,
                    "generated": generated.reason,
                    **extra,
                },
            )
        if len(candidates) != 1:
            return None  # missing or ambiguous: C02 owns that finding
        facts = ctx.facts(path)
        if facts is None:
            return None  # no parser for this language: nothing to say about spans
        defs = _function_defs(facts, site.function)
        where = ctx.ref_name or ctx.commit[:12]
        inside = _contains(defs, site.line)
        if inside is not None:
            return self._supports(
                ctx, claim, site, path=path, inside=inside, where=where, parsed_ok=facts.parsed_ok
            )
        return self._negative(ctx, claim, site, path=path, facts=facts, defs=defs, where=where)

    def _negative(
        self,
        ctx: CheckContext,
        claim: Claim,
        site: _Site,
        *,
        path: str,
        facts: FileFacts,
        defs: Sequence[SymbolDef],
        where: str,
    ) -> Evidence:
        """The line is not in the function *as parsed here* — so P4 comes first."""
        if site.line > facts.n_lines:
            # C04 owns a line past the end of the file; refuting it here too would count
            # one wrong number twice in the same group (SPEC 14.1).
            return self._neutral(
                claim,
                site,
                summary=f"{path} has {facts.n_lines} lines at {where}, so line {site.line}"
                " is left to C04",
                details={"outcome": "line_past_end", "path": path, "n_lines": facts.n_lines},
            )
        overlap = _overlapping(defs, site)
        if overlap is not None:
            # A cited range that reaches into the function (from a doc comment above it,
            # say) is not a contradiction.
            return self._neutral(
                claim,
                site,
                summary=f"lines {site.line}-{site.end_line} of {path} overlap"
                f" {overlap.name}() (lines {overlap.start_line}-{overlap.end_line}) at {where}",
                details={
                    "outcome": "range_overlaps_function",
                    "path": path,
                    "function_span": _span(overlap),
                },
            )
        if not facts.parsed_ok:
            return self._neutral(
                claim,
                site,
                summary=f"{path} did not parse cleanly at {where}, so line {site.line}"
                f" cannot be placed outside {site.function}()",
                details={"outcome": "parse_incomplete", "path": path, "parsed_ok": False},
            )
        if not defs:
            # A function that is missing altogether is C03's finding, not a second
            # refutation from the lines group. The name may still be a macro or a type, so
            # the summary says only that no *function* of that name was found.
            return self._neutral(
                claim,
                site,
                summary=f"no function named {site.function}() is defined in {path} at {where},"
                f" so line {site.line} is not judged against it",
                details={
                    "outcome": "function_not_defined",
                    "path": path,
                    "function_defined": False,
                },
            )
        actual = facts.enclosing(site.line)
        if isinstance(claim, LineClaim) and actual is not None and _named_near(ctx, claim, actual):
            # A prose hint is only the first ``name()`` in the sentence; when the function
            # that really holds the line is named there too, the report may well say so.
            return self._neutral(
                claim,
                site,
                summary=f"{path}:{site.line} is inside {actual.name}(), which the report also"
                f" names next to this line, so {site.function}() is not taken as its container",
                details={
                    "outcome": "enclosing_function_named",
                    "path": path,
                    "actual_function": actual.qname,
                },
            )
        return self._refutes(ctx, claim, site, path=path, facts=facts, defs=defs, where=where)

    # --- outcomes -----------------------------------------------------------------------

    def _supports(
        self,
        ctx: CheckContext,
        claim: Claim,
        site: _Site,
        *,
        path: str,
        inside: SymbolDef,
        where: str,
        parsed_ok: bool,
    ) -> Evidence:
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="SUPPORTS",
            strength=self.strengths.get(CHECK_ID, "in_function"),
            summary=_say(
                site,
                f"{path}:{site.line} is inside {inside.name}()"
                f" (lines {inside.start_line}-{inside.end_line}) at {where}",
            ),
            details=_details(
                site,
                path=path,
                function_span=_span(inside),
                outcome="in_function",
                parsed_ok=parsed_ok,
            ),
            locations=[ctx.location(path, site.line)],
        )

    def _refutes(
        self,
        ctx: CheckContext,
        claim: Claim,
        site: _Site,
        *,
        path: str,
        facts: FileFacts,
        defs: Sequence[SymbolDef],
        where: str,
    ) -> Evidence:
        claimed = defs[0]
        actual = facts.enclosing(site.line)
        spans = ", ".join(f"{s.start_line}-{s.end_line}" for s in defs)
        if actual is not None:
            summary = (
                f"{path}:{site.line} is inside {actual.name}()"
                f" (lines {actual.start_line}-{actual.end_line}) at {where},"
                f" not {site.function}() (lines {spans})"
            )
        else:
            summary = (
                f"{path}:{site.line} is not inside any function at {where};"
                f" {site.function}() spans lines {spans}"
            )
        fit, searched_all = self._nearby_fit(ctx, path, site)
        if fit is None and not searched_all:
            # The neighbourhood was not fully examined (budget, or a neighbour that did not
            # parse cleanly): "it fits nowhere nearby" is not established (P4). The details
            # hold nothing that depends on how far the search got (P2).
            return self._neutral(
                claim,
                site,
                summary=f"{summary}; the neighbouring releases could not all be examined,"
                " so this is not judged",
                details={
                    "outcome": "nearby_search_incomplete",
                    "path": path,
                    "nearby_search_complete": False,
                },
            )
        details = _details(
            site,
            path=path,
            function_span=_span(claimed),
            actual_function=actual.qname if actual is not None else None,
            actual_span=_span(actual) if actual is not None else None,
            nearby_search_complete=searched_all,
        )
        locations: list[CodeLocation] = [
            ctx.location(path, site.line),
            ctx.location(path, claimed.start_line, claimed.end_line),
        ]
        if fit is None:
            details["outcome"] = "outside_function"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "outside_function"),
                summary=_say(site, summary),
                details=details,
                locations=locations,
            )
        # The report is self-consistent against another release: far likelier a version
        # mistake than an invention, so soften and hand C10 the release that does fit.
        details["outcome"] = "fits_nearby_release"
        details["version_fit_hint"] = {
            "release": fit.release,
            "commit": fit.commit,
            "releases": list(fit.releases),
            "path": path,
            "function": site.function,
            "line": site.line,
            "function_span": [fit.start_line, fit.end_line],
        }
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "fits_nearby_release"),
            summary=_say(
                site, f"{summary}; line {site.line} is inside {site.function}() in {fit.release}"
            ),
            details=details,
            locations=locations,
        )

    def _neutral(
        self,
        claim: Claim,
        site: _Site,
        *,
        summary: str,
        details: dict[str, Any],
    ) -> Evidence:
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=0.0,
            summary=_say(site, summary),
            details=_details(site, **details),
        )

    # --- the neighbouring releases ------------------------------------------------------

    def _nearby_fit(self, ctx: CheckContext, path: str, site: _Site) -> tuple[_Fit | None, bool]:
        """The nearest release where ``site.line`` *is* inside the function, if any.

        Returns the fit and whether the whole window was searched: a search cut short by
        the check's deadline, or a neighbour that did not parse cleanly, must not be reported
        as "it fits nowhere nearby" (P4). With no claimed release there is no neighbourhood
        to search (the target is a bare commit), which counts as complete. A claimed release
        that is absent from its own window (a prerelease or variant tag) was not searched
        around, which counts as incomplete.
        """
        claimed = ctx.resolution.release
        if claimed is None:
            return None, True
        window = ctx.resolution.releases.window(claimed, NEARBY_RADIUS)
        here = next((i for i, r in enumerate(window) if r.name == claimed.name), None)
        if here is None:
            # The claimed release is outside the main-line window (a prerelease or a variant
            # family tag), so no neighbour was searched: that is not "fits nowhere" (P4).
            return None, False
        complete = True
        found: list[tuple[int, int, Release, SymbolDef]] = []
        for i, release in enumerate(window):
            if ctx.expired():
                return _best(found), False
            if i == here:
                continue
            facts = ctx.index.facts_at(release.commit, path)
            if facts is None:
                continue
            inside = _contains(_function_defs(facts, site.function), site.line)
            if inside is not None:
                found.append((abs(i - here), i, release, inside))
            elif not facts.parsed_ok:
                complete = False
        return _best(found), complete


def _best(found: Sequence[tuple[int, int, Release, SymbolDef]]) -> _Fit | None:
    """The nearest fitting release, ties broken by version order (both deterministic)."""
    if not found:
        return None
    _, _, release, sym = min(found, key=lambda f: (f[0], f[1]))
    return _Fit(
        release=release.name,
        commit=release.commit,
        start_line=sym.start_line,
        end_line=sym.end_line,
        releases=tuple(r.name for _, _, r, _ in sorted(found, key=lambda f: f[1])),
    )


# --- what each claim kind contributes ---------------------------------------------------


def _sites(claim: Claim) -> list[_Site]:
    """The (path, line, function) triples a claim asserts, deduplicated in claim order.

    A recursive trace names the same site in several frames; judging it once keeps one
    fact from counting twice in fusion.
    """
    if isinstance(claim, LineClaim):
        if claim.path is None or claim.function_hint is None or claim.line < 1:
            return []
        end = claim.end_line if claim.end_line is not None and claim.end_line > claim.line else None
        return [_Site(claim.path, claim.line, claim.function_hint, end_line=end)]
    if not isinstance(claim, TraceClaim):
        return []
    sites: list[_Site] = []
    seen: set[tuple[str, int, str]] = set()
    for frame in app_frames(claim):
        if frame.path is None or frame.function is None or frame.line is None or frame.line < 1:
            continue
        key = (frame.path, frame.line, frame.function)
        if key in seen:
            continue
        seen.add(key)
        sites.append(_Site(frame.path, frame.line, frame.function, frame.index))
    return sites


def _overlapping(defs: Sequence[SymbolDef], site: _Site) -> SymbolDef | None:
    """For a cited range, the first definition the range reaches into."""
    end = site.end_line
    if end is None:
        return None
    return next((s for s in defs if s.start_line <= end and site.line <= s.end_line), None)


def _named_near(ctx: CheckContext, claim: LineClaim, actual: SymbolDef) -> bool:
    """Whether ``actual()`` is written within :data:`HINT_WINDOW` of the claim's text."""
    body = ctx.report.body
    needle = f"{actual.name}("
    for span in claim.spans:
        lo = max(0, span.start - HINT_WINDOW)
        hi = min(len(body), span.end + HINT_WINDOW)
        if body.find(needle, lo, hi) != -1:
            return True
    return False


def _say(site: _Site, text: str) -> str:
    """Name the frame a trace finding came from, so each piece of evidence stands alone."""
    if site.amalgamation is not None:
        amal_path, amal_line = site.amalgamation
        text = f"{amal_path}:{amal_line} is {site.path}:{site.line} in the release: {text}"
    return f"frame #{site.frame}: {text}" if site.frame is not None else text


def _details(site: _Site, **extra: object) -> dict[str, Any]:
    details: dict[str, Any] = {"path": site.path, "line": site.line, "function": site.function}
    if site.frame is not None:
        details["frame"] = site.frame
    if site.amalgamation is not None:
        details["amalgamation"] = {"path": site.amalgamation[0], "line": site.amalgamation[1]}
    details.update(extra)
    return details


def _map_amalgamation(  # noqa: PLR0911 - one return per unmappable case
    ctx: CheckContext, path: str, site: _Site
) -> _Site | str | None:
    """Map ``sqlite3.c:<line>`` to the source file and line at the resolved release (SPEC
    §11.5). Only with ``--online`` (P3, the zip is fetched once and cached) and only for a
    ``version-X.Y.Z`` release of SQLite. Returns the mapped site, a reason it could not be
    mapped (kept in the neutral evidence), or ``None`` when mapping does not apply."""
    project = ctx.resolution.project
    if project is None or project.name != "sqlite" or path.rsplit("/", 1)[-1] != "sqlite3.c":
        return None
    if site.amalgamation is not None:
        return None  # never map twice
    if not ctx.online:
        return "not mapped to its source file: the amalgamation is only fetched with --online"
    ref = ctx.ref_name or ""
    if not ref.startswith("version-"):
        return "not mapped: the target is not a SQLite version-X.Y.Z release tag"
    epoch = ctx.resolution.repo.commit_epoch(ctx.commit)
    if epoch is None:
        return "not mapped: the release date is unknown"
    year = time.gmtime(epoch).tm_year
    try:
        amal = cached_amalgamation(ref, (year, year + 1, year - 1), online=True)
    except NikashaError as exc:
        return f"not mapped: {exc}"
    hit = amal.lookup(site.line)
    if hit is None:
        return f"not mapped: line {site.line} is a banner or outside any inlined file"
    source = resolve_source(hit.file, ctx.tree_paths)
    if source is None:
        return f"line {site.line} is in {hit.file}, which is itself generated or not in git"
    return replace(site, path=source, line=hit.line, end_line=None, amalgamation=(path, site.line))
