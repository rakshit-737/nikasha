# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C03 SYMBOL_EXISTS: is a named symbol defined at the claimed version? (SPEC §12)

This is the one check that can call a genuine report fabricated, so most of it is about
not doing that. A missing definition has four very different explanations: the symbol is
defined somewhere the parser could not read; it is only *referenced* here (a libc call, a
symbol from a dependency); it moved between releases; or it never existed. Only the last
is a refutation worth -3.0, and it is reached only when every earlier layer came back
empty **and** the history search actually completed (P4).

Absence is therefore established in layers: the definition index at the exact commit, a
literal ``git grep -F -w`` when the index has nothing, the release timeline, and finally
``log -S`` over the whole history. Any gap in that chain — a shallow clone, a timed-out
pickaxe, a release that mentions the name in a file that did not parse cleanly — keeps
the finding but says plainly that history was incomplete, instead of claiming the symbol
never existed.

Where the symbol lives is not this check's business: a symbol defined in a different file
from the one the report names still *exists*, and C05 owns the location question.

This check emits no ``CommandRecord`` (ADR 0007 decision 4), because no git invocation of
its own reaches it as a :class:`~nikasha.code.gitio.GitResult`: the literal fallback is
:func:`~nikasha.code.literal.literal_search`, which surfaces only the equivalent command as
a string (kept in ``details['command']``), and the release sweep and the pickaxe belong to
:mod:`nikasha.code.timeline`, which reports what it found and not the commands it ran. An
exit code or output hash this check never saw would be an invention, and P6 asks for the
real record or none.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.facts import SymbolDef
from nikasha.code.generated import GeneratedMatch
from nikasha.code.literal import literal_search
from nikasha.code.timeline import Timeline
from nikasha.errors import ExternalToolError
from nikasha.model.claims import Claim, ClaimKind, SymbolClaim
from nikasha.model.evidence import CodeLocation, Evidence

CHECK_ID = "C03"
GROUP = "locus"

#: Definitions and references quoted in the evidence. A symbol defined in fifty places is
#: no more "existing" than one defined in three, and the locations are for a human to read.
MAX_LOCATIONS = 3

#: The separators the extractor's ``QUALIFIED`` grammar accepts (``Class::method``,
#: ``obj.method``, ``Class#method``). Parsers qualify differently (namespaces, nesting),
#: so a qualified spelling is also looked up, and searched for, by its last component.
_QUALIFIER_RE = re.compile(r"::|\.|#")

#: The fixed sentence for claims the budget did not reach. It carries no timing, so two
#: runs that are cut at different claims still say the same thing about each (P2).
BUDGET_SUMMARY = "{name} was not checked: the check's time budget ran out before it"


def _bare(name: str) -> str:
    """``Foo::bar`` / ``pkg.Foo.bar`` / ``Foo#bar`` -> ``bar``; a plain name unchanged."""
    return _QUALIFIER_RE.split(name)[-1] or name


def _where(ctx: CheckContext) -> str:
    """How to name the resolved target in a sentence."""
    return ctx.ref_name or ctx.commit[:12]


@register
class SymbolExists(BaseCheck):
    id = CHECK_ID
    name = "SYMBOL_EXISTS"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"symbol"})
    description = "Checks that a named symbol is defined in the repository at the resolved commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        out: list[Evidence] = []
        for claim in claims:
            if not isinstance(claim, SymbolClaim):
                continue
            # A timeline greps every release; stop rather than overrun the budget, but say
            # so for every claim left behind instead of dropping it silently (P6).
            if ctx.expired():
                evidence: Evidence | None = self._budget_spent(claim)
            else:
                try:
                    evidence = self._one(ctx, claim)
                except ExternalToolError as exc:
                    # A grep or pickaxe git could not finish is not "undefined": say so for
                    # this claim alone and keep judging the others (P4).
                    evidence = self._search_failed(claim, exc)
            if evidence is not None:
                out.append(evidence)
        return out

    def _one(self, ctx: CheckContext, claim: SymbolClaim) -> Evidence | None:
        name = claim.name.strip()
        if not name:
            return None
        if claim.external:
            # The reporter placed the symbol outside the project; there is nothing here to
            # confirm or contradict (ADR 0003).
            return self._neutral(
                claim,
                summary=f"{name} is attributed to code outside this repository,"
                " so it is not judged against it",
                details={"outcome": "referenced_only", "symbol": name, "external": True},
                strength=self.strengths.get(CHECK_ID, "referenced_only"),
            )
        definitions = self._definitions(ctx, claim, name)
        if definitions:
            # A definition found in git source stands even when the report's (heuristic)
            # context path is generated: where it lives is C05's question.
            return self._defined(ctx, claim, name, definitions)
        generated = self._generated_context(ctx, claim)
        if generated is not None:
            # SPEC §11.5: generated and release-only files are never judged (P4).
            return self._neutral(
                claim,
                summary=f"{name} is placed in {generated.path}, which is {generated.kind},"
                " so its symbols are not judged",
                details={
                    "outcome": "generated",
                    "symbol": name,
                    "path": generated.path,
                    "generated": generated.reason,
                },
            )
        referenced = self._referenced(ctx, claim, name)
        if referenced is not None:
            return referenced
        return self._absent(ctx, claim, name)

    # --- where the symbol is defined ----------------------------------------------------

    def _context_path(self, ctx: CheckContext, claim: SymbolClaim) -> str | None:
        """The file the report puts the symbol in, resolved when it resolves uniquely."""
        if claim.context_path is None:
            return None
        candidates = ctx.resolve_path(claim.context_path)
        return candidates[0] if len(candidates) == 1 else claim.context_path

    def _generated_context(self, ctx: CheckContext, claim: SymbolClaim) -> GeneratedMatch | None:
        path = self._context_path(ctx, claim)
        return ctx.generated(path) if path is not None else None

    def _definitions(
        self, ctx: CheckContext, claim: SymbolClaim, name: str
    ) -> list[tuple[str, SymbolDef]]:
        """Definitions of ``name`` at the resolved commit, the named file first."""
        path = self._context_path(ctx, claim)
        if path is not None:
            facts = ctx.facts(path)
            if facts is not None:
                found = [(path, symbol) for symbol in facts.definitions(name)]
                if not found and _bare(name) != name:
                    found = [(path, symbol) for symbol in facts.definitions(_bare(name))]
                if found:
                    return sorted(found, key=lambda item: (item[0], item[1].start_line))
        found = ctx.index.definitions(ctx.commit, name)
        if not found and _bare(name) != name:
            found = ctx.index.definitions(ctx.commit, _bare(name))
        return found

    def _defined(
        self,
        ctx: CheckContext,
        claim: SymbolClaim,
        name: str,
        definitions: list[tuple[str, SymbolDef]],
    ) -> Evidence:
        shown = definitions[:MAX_LOCATIONS]
        first_path, first = shown[0]
        more = len(definitions) - len(shown)
        key = "defined_core" if claim.role == "core" else "defined"
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="SUPPORTS",
            strength=self.strengths.get(CHECK_ID, key),
            summary=f"{name} is defined at {_where(ctx)} in {first_path}:{first.start_line}"
            + (f" (and {more} other place{'s' if more > 1 else ''})" if more else ""),
            details={
                "outcome": key,
                "symbol": name,
                "n_definitions": len(definitions),
                "definitions": [
                    {
                        "path": path,
                        "kind": symbol.kind,
                        "start_line": symbol.start_line,
                        "end_line": symbol.end_line,
                    }
                    for path, symbol in shown
                ],
            },
            locations=[
                ctx.location(path, symbol.start_line, symbol.end_line) for path, symbol in shown
            ],
        )

    def _referenced(self, ctx: CheckContext, claim: SymbolClaim, name: str) -> Evidence | None:
        """NEUTRAL evidence when the name is used but not defined here, else ``None``.

        This is the fallback the SPEC asks for when the index has nothing, and it is also a
        P4 safety net: a name that appears in a file the parser could not read reaches this
        branch, so an unparsed definition can never become an absence.
        """
        result = literal_search(ctx.resolution.repo, _bare(name), ctx.commit, word=True)
        if result is None or not result.hits:
            return None
        shown = result.hits[:MAX_LOCATIONS]
        return self._neutral(
            claim,
            summary=f"{name} is used at {_where(ctx)} (first in {shown[0].path}:{shown[0].line})"
            " but no definition of it was found in the files that could be parsed, so its"
            " definition is not judged here",
            details={
                "outcome": "referenced_only",
                "symbol": name,
                "n_references": len(result.hits),
                "references": [{"path": hit.path, "line": hit.line} for hit in shown],
                "truncated": result.truncated,
                # The re-runnable command as a string: ``literal_search`` hands back no
                # ``GitResult``, so there is no exit code or output hash to record (P6).
                "command": result.command,
            },
            strength=self.strengths.get(CHECK_ID, "referenced_only"),
            locations=[ctx.location(hit.path, hit.line) for hit in shown],
        )

    # --- absence, in decreasing order of certainty ---------------------------------------

    def _absent(self, ctx: CheckContext, claim: SymbolClaim, name: str) -> Evidence:
        # The bare component is what source text contains: ``log -S'Foo::bar'`` finds
        # nothing for a method written inside ``class Foo { ... bar() ... }`` (P4).
        timeline = ctx.timeline(_bare(name))
        sampled = [presence.release for presence in timeline.presence]
        details: dict[str, Any] = {"symbol": name, "releases_searched": sampled}

        if timeline.uncertain_releases:
            # The name *is* in those releases, in files tree-sitter could not read through
            # (about 0.4% of C definitions are lost to body-level `#if`, ADR 0004). Absence
            # is not established, so nothing is refuted (P4).
            return self._neutral(
                claim,
                summary=f"{name} is not defined at {_where(ctx)}, but it is mentioned in"
                f" {', '.join(timeline.uncertain_releases)} in files that did not parse"
                " cleanly, so its absence is not established",
                details=details
                | {
                    "outcome": "uncertain",
                    "uncertain_releases": timeline.uncertain_releases,
                    "defined_in": [p.release for p in timeline.presence if p.defined],
                },
            )

        if timeline.ever_defined:
            runs = [list(run) for run in timeline.runs]
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "absent_here_present_elsewhere"),
                summary=f"{name} is not defined at {_where(ctx)}; it is defined in"
                f" {_render_runs(timeline)}",
                details=details
                | {
                    "outcome": "absent_here_present_elsewhere",
                    "runs": runs,
                    "defined_in": [p.release for p in timeline.presence if p.defined],
                },
            )

        suggestions = ctx.suggest_symbols(name)
        details = details | {"suggestions": suggestions}
        if timeline.history_complete and timeline.never_in_history is False:
            # The pickaxe ran to completion and *found* the text in some commit: the name
            # did exist, just not as a definition in any sampled release. Neither "never
            # existed" nor "history incomplete" is true, and nothing is refuted (P4).
            return self._neutral(
                claim,
                summary=f"{name} is defined in none of the {len(sampled)} sampled releases,"
                f" but the name does appear in this repository's history (first in commit"
                f" {(timeline.first_commit_with_text or '')[:12]}), so its absence is not"
                " established" + _did_you_mean(suggestions),
                details=details
                | {
                    "outcome": "in_history_not_released",
                    "history_complete": True,
                    "never_in_history": False,
                    "first_commit_with_text": timeline.first_commit_with_text,
                },
            )
        gap = self._history_gap(ctx, timeline)
        if gap is None:
            key = "never_in_history_core" if claim.role == "core" else "never_in_history_supporting"
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, key),
                summary=f"{name} is defined in none of the {len(sampled)} sampled releases and"
                " never appears anywhere in this repository's history" + _did_you_mean(suggestions),
                details=details
                | {"outcome": key, "history_complete": True, "never_in_history": True},
            )

        # Everything below here is the P4 downgrade: the symbol is not in the releases we
        # sampled, but history could not be searched exhaustively, so "never existed" would
        # be a stronger statement than the evidence supports.
        details = details | {"history_complete": False, "history_gap": gap}
        summary = (
            f"{name} is defined in none of the {len(sampled)} sampled releases, but"
            f" history is incomplete ({gap}), so this is not evidence that it never existed"
            + _did_you_mean(suggestions)
        )
        if claim.role != "core":
            return self._neutral(
                claim, summary=summary, details=details | {"outcome": "history_incomplete"}
            )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "absent_in_sampled_core"),
            summary=summary,
            details=details | {"outcome": "absent_in_sampled_core"},
        )

    def _history_gap(self, ctx: CheckContext, timeline: Timeline) -> str | None:
        """Why "never existed" may not be said, or ``None`` when it may (SPEC §12 C03, P4).

        ``is_shallow`` is asked again here even though :mod:`nikasha.code.timeline` checks
        it: a timeline may have been built with another strategy, or served from the cache,
        and the cost of being wrong once is a false accusation.
        """
        if not timeline.history_complete:
            return "; ".join(timeline.notes) or "the history search did not complete"
        if timeline.never_in_history is not True:
            return "the history search did not run"
        if ctx.resolution.repo.is_shallow():
            return "the repository is a shallow clone"
        return None

    def _budget_spent(self, claim: SymbolClaim) -> Evidence | None:
        name = claim.name.strip()
        if not name:
            return None
        return self._neutral(
            claim,
            summary=BUDGET_SUMMARY.format(name=name),
            details={"outcome": "budget_expired", "symbol": name},
        )

    # --- helpers --------------------------------------------------------------------------

    def _search_failed(self, claim: SymbolClaim, exc: ExternalToolError) -> Evidence:
        name = claim.name.strip()
        return self._neutral(
            claim,
            summary=f"{name} could not be searched for: {exc}, so nothing is concluded",
            details={
                "symbol": name,
                "outcome": "search_failed",
                "incomplete": str(exc),
                "history_complete": False,
            },
        )

    def _neutral(
        self,
        claim: SymbolClaim,
        *,
        summary: str,
        details: dict[str, Any],
        strength: float = 0.0,
        locations: Sequence[CodeLocation] = (),
    ) -> Evidence:
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=strength,
            summary=summary,
            details=details,
            locations=locations,
        )


def _render_runs(timeline: Timeline) -> str:
    """``v1.0.0-v1.2.1, v1.3.0``: the releases that do define the symbol."""
    return ", ".join(first if first == last else f"{first}-{last}" for first, last in timeline.runs)


def _did_you_mean(suggestions: Sequence[str]) -> str:
    return f"; did you mean {', '.join(suggestions)}?" if suggestions else ""
