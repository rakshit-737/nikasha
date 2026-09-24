# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The check framework: context, registry, evidence construction and the refutation gate.

A check answers one factual question about a report's claims against the repository at the
resolved commit, and returns :class:`~nikasha.model.evidence.Evidence` (SPEC §12).

Three rules are enforced *here* rather than in each check, so no check can forget them:

1. **Refutation gating (ADR 0003).** Only ``project_attributed``, non-negated claims may be
   refuted. slopcheck's negative result traced most of its false contradictions to the
   reporter's own PoC code, third-party APIs and negated sentences. A ``REFUTES`` outcome
   whose claims are not all refutable is downgraded to ``NEUTRAL`` with a note, by
   :func:`make_evidence`.
2. **Determinism (P2).** Evidence IDs come from content, never from ordering or the clock,
   and :func:`run_checks` sorts its output. Durations are returned separately.
3. **Time bounds.** Each check gets a deadline (default 10 s). A check that overruns or
   raises yields ``ERROR`` evidence with strength 0, never a refutation (P4).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from nikasha.code.bktree import BKTree
from nikasha.code.generated import GeneratedMatch, generated_match
from nikasha.code.pathtrie import PathTrie
from nikasha.code.timeline import Timeline, build_timeline
from nikasha.model.claims import Claim, ClaimBase, ClaimKind
from nikasha.model.evidence import CodeLocation, CommandRecord, Evidence, Outcome
from nikasha.model.ids import stable_id

if TYPE_CHECKING:  # pragma: no cover - imports used only for annotations
    from nikasha.code.facts import FileFacts
    from nikasha.code.index import CodeIndex
    from nikasha.model.report import Report
    from nikasha.resolve.target import Resolution

#: Default wall-clock budget for one check (SPEC §12).
DEFAULT_CHECK_TIMEOUT_S = 10.0

#: Appended to a summary when a refutation is withheld because the claim is not attributed
#: to the project, or is negated (ADR 0003).
GATE_NOTE = "not attributed to the project, so this is reported without refuting the claim"


def is_refutable(claim: ClaimBase) -> bool:
    """Whether ``claim`` may ever be refuted (ADR 0003).

    A claim qualifies only when the reporter attributed it to the project and did not
    negate it. Everything else — their own PoC, a third-party API, "this is *not* a
    use-after-free" — may be *reported on*, never contradicted.
    """
    return claim.provenance == "project_attributed" and not claim.negated


class CheckError(Exception):
    """A check failed in a way that should become ``ERROR`` evidence, not a refutation."""


@dataclass
class CheckContext:
    """Everything a check may look at, built once per report and shared by every check.

    The cached helpers exist so twenty checks do not each re-read the tree, rebuild a
    :class:`~nikasha.code.pathtrie.PathTrie` or recompute a symbol timeline.
    """

    report: Report
    claims: tuple[Claim, ...]
    resolution: Resolution
    index: CodeIndex
    online: bool = False
    deadline: float | None = None
    history_timeout: float = 20.0
    #: An optional LLM provider (SPEC §16.6). ``None`` by default and in every offline run:
    #: only C20 reads it, and the framework never lets it be decisive (P2).
    llm: object | None = None
    _timelines: dict[str, Timeline] = field(default_factory=dict, repr=False)

    # --- the resolved target ------------------------------------------------------------

    @property
    def commit(self) -> str:
        """The exact commit every check measures against."""
        commit = self.resolution.target.commit
        if not commit:
            raise CheckError("the target has no resolved commit")
        return commit

    @property
    def ref_name(self) -> str | None:
        return self.resolution.target.ref_name

    @property
    def repo_url(self) -> str:
        return self.resolution.target.repo_url

    def expired(self) -> bool:
        """Whether this check's budget is spent. Long loops must poll this."""
        return self.deadline is not None and time.monotonic() >= self.deadline

    # --- the tree at the resolved commit ------------------------------------------------

    @cached_property
    def tree_paths(self) -> tuple[str, ...]:
        """Every path in the tree at :attr:`commit`, sorted."""
        return tuple(sorted(entry.path for entry in self.index.files(self.commit)))

    @cached_property
    def trie(self) -> PathTrie:
        """A suffix trie over the tree, for matching the partial paths reports use."""
        return PathTrie(self.tree_paths)

    @cached_property
    def path_set(self) -> frozenset[str]:
        return frozenset(self.tree_paths)

    def resolve_path(self, path: str) -> list[str]:
        """Candidate real paths for a path as written in the report (``src/x.c``, ``x.c``)."""
        if path in self.path_set:
            return [path]
        return self.trie.resolve(path)

    def facts(self, path: str) -> FileFacts | None:
        """Parsed facts for ``path`` at :attr:`commit`, or ``None`` if it is not source."""
        return self.index.facts_at(self.commit, path)

    def line_count(self, path: str) -> int | None:
        """The number of lines in ``path`` at :attr:`commit`."""
        entry = self.index.file_at(self.commit, path)
        if entry is None:
            return None
        facts = self.index.facts(entry.blob, path)
        if facts is not None:
            return facts.n_lines
        blob = self.resolution.repo.read_blob(entry.blob)
        if blob is None:
            return None
        return blob.count(b"\n") + (0 if blob.endswith(b"\n") or not blob else 1)

    # --- generated and release-only files (SPEC §11.5, critical for P4) -----------------

    def generated(self, path: str) -> GeneratedMatch | None:
        """Whether ``path`` is generated or release-only, and so must never be judged."""
        return generated_match(
            path,
            project=self.resolution.project,
            tree_paths=self.path_set,
            resolve=self.resolve_path,
        )

    # --- symbols ------------------------------------------------------------------------

    @cached_property
    def symbol_names(self) -> tuple[str, ...]:
        """Every symbol defined anywhere in the tree at :attr:`commit`, sorted."""
        names: set[str] = set()
        for entry in self.index.files(self.commit):
            facts = self.index.facts(entry.blob, entry.path)
            if facts is not None:
                names.update(symbol.name for symbol in facts.symbols)
        return tuple(sorted(names))

    @cached_property
    def symbol_tree(self) -> BKTree:
        """A BK-tree over the defined symbols, for "did you mean" suggestions."""
        return BKTree(self.symbol_names)

    def suggest_symbols(self, name: str, k: int = 3) -> list[str]:
        return self.symbol_tree.suggest(name, k)

    def timeline(self, name: str) -> Timeline:
        """The release timeline for symbol ``name``, computed once per report."""
        cached = self._timelines.get(name)
        if cached is None:
            cached = build_timeline(
                self.index,
                self.resolution.releases,
                name,
                history_timeout=self.history_timeout,
            )
            self._timelines[name] = cached
        return cached

    # --- evidence helpers ---------------------------------------------------------------

    def location(
        self,
        path: str,
        start_line: int,
        end_line: int | None = None,
        *,
        excerpt: str | None = None,
    ) -> CodeLocation:
        """A :class:`CodeLocation` at the resolved commit, with an upstream permalink."""
        end = end_line if end_line is not None else start_line
        return CodeLocation(
            repo=self.repo_url,
            ref=self.ref_name,
            commit=self.commit,
            path=path,
            start_line=max(1, start_line),
            end_line=max(1, end),
            excerpt=excerpt,
            permalink=permalink(self.repo_url, self.commit, path, start_line, end),
        )


def permalink(repo_url: str, commit: str, path: str, start: int, end: int) -> str | None:
    """An upstream blob URL pinning repo, commit, path and lines (SPEC §15.2)."""
    base = repo_url.removesuffix(".git")
    if not base.startswith(("https://github.com/", "https://gitlab.com/")):
        return None
    lines = f"#L{max(1, start)}" + (f"-L{end}" if end > start else "")
    if base.startswith("https://gitlab.com/"):
        lines = f"#L{max(1, start)}" + (f"-{end}" if end > start else "")
    return f"{base}/blob/{commit}/{path}{lines}"


def evidence_id(check_id: str, payload: object) -> str:
    return stable_id(f"evidence:{check_id}", payload)


def make_evidence(
    *,
    check_id: str,
    group: str,
    claims: Sequence[ClaimBase],
    outcome: Outcome,
    strength: float,
    summary: str,
    details: dict[str, Any] | None = None,
    locations: Sequence[CodeLocation] = (),
    commands: Sequence[CommandRecord] = (),
) -> Evidence:
    """Build one :class:`Evidence`, applying the ADR 0003 refutation gate.

    A ``REFUTES`` outcome survives only when **every** cited claim is refutable. Otherwise
    the outcome becomes ``NEUTRAL`` with strength 0 and the reason is recorded in
    ``details['gated']`` — the finding is still shown, it just cannot count against the
    report.
    """
    payload_details = dict(details or {})
    if outcome == "REFUTES" and not all(is_refutable(claim) for claim in claims):
        blocked = sorted(
            {
                "negated" if claim.negated else claim.provenance
                for claim in claims
                if not is_refutable(claim)
            }
        )
        payload_details["gated"] = blocked
        payload_details["withheld_strength"] = strength
        outcome, strength = "NEUTRAL", 0.0
        summary = f"{summary} ({GATE_NOTE}: {', '.join(blocked)})"
    if outcome == "NEUTRAL" and strength != 0.0:
        payload_details.setdefault("withheld_strength", strength)
        strength = 0.0
    claim_ids = tuple(sorted({claim.id for claim in claims}))
    identity = {
        "claim_ids": list(claim_ids),
        "outcome": outcome,
        "strength": round(strength, 6),
        "summary": summary,
        "details": payload_details,
        "locations": [location.model_dump(mode="json") for location in locations],
    }
    return Evidence(
        id=evidence_id(check_id, identity),
        check_id=check_id,
        claim_ids=claim_ids,
        outcome=outcome,
        strength=round(strength, 6),
        group=group,
        summary=summary,
        details=payload_details,
        locations=tuple(locations),
        commands=tuple(commands),
    )


# --- the registry -------------------------------------------------------------------------


@runtime_checkable
class Check(Protocol):
    """The interface every check implements (SPEC §12)."""

    id: str
    name: str
    group: str
    applies_to: frozenset[ClaimKind]
    runs_on_empty: bool

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]: ...


class BaseCheck:
    """Convenience base: class attributes plus claim filtering."""

    id: str = ""
    name: str = ""
    group: str = ""
    applies_to: frozenset[ClaimKind] = frozenset()
    description: str = ""
    #: Run even when the report produced no applicable claim. Only a check that reports on
    #: the *absence* of claims needs this (C21 hygiene drives the INSUFFICIENT verdict, and
    #: a report with nothing in it is exactly the case it exists to describe).
    runs_on_empty: bool = False

    def select(self, claims: Sequence[Claim]) -> list[Claim]:
        """The claims of a kind this check handles, in report order."""
        return [claim for claim in claims if claim.kind in self.applies_to]

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        raise NotImplementedError


CHECKS: dict[str, Check] = {}


def register(cls: type[BaseCheck]) -> type[BaseCheck]:
    """Register a check class (its ``id`` must be unique)."""
    instance = cls()
    if not instance.id:
        raise ValueError(f"{cls.__name__} has no id")
    if instance.id in CHECKS:
        raise ValueError(f"duplicate check {instance.id!r}")
    CHECKS[instance.id] = instance
    return cls


def all_checks() -> list[Check]:
    """Every registered check, ordered by ID so runs are reproducible."""
    return [CHECKS[key] for key in sorted(CHECKS)]


@dataclass(frozen=True, slots=True)
class CheckRun:
    """What one check produced, plus how long it took (kept out of the evidence)."""

    check_id: str
    evidence: tuple[Evidence, ...]
    seconds: float
    error: str | None = None


def run_checks(
    ctx: CheckContext,
    *,
    checks: Iterable[Check] | None = None,
    timeout: float = DEFAULT_CHECK_TIMEOUT_S,
    now: Callable[[], float] = time.monotonic,
) -> list[CheckRun]:
    """Run ``checks`` over ``ctx``, bounding each one and never letting one break the rest.

    Ordering is by check ID, and evidence within a check is sorted by ID, so two runs on
    the same input produce byte-identical output (P2).
    """
    selected = list(checks) if checks is not None else all_checks()
    runs: list[CheckRun] = []
    for check in sorted(selected, key=lambda c: c.id):
        applicable = [claim for claim in ctx.claims if claim.kind in check.applies_to]
        started = now()
        ctx.deadline = started + timeout
        error: str | None = None
        produced: list[Evidence] = []
        if applicable or getattr(check, "runs_on_empty", False):
            try:
                produced = check.run(ctx, applicable)
            except Exception as exc:  # one bad check must not stop the run
                error = f"{type(exc).__name__}: {exc}"
                produced = [
                    make_evidence(
                        check_id=check.id,
                        group=check.group,
                        claims=applicable,
                        outcome="ERROR",
                        strength=0.0,
                        summary=f"{check.id} could not run: {error}",
                        details={"error": error},
                    )
                ]
        ctx.deadline = None
        runs.append(
            CheckRun(
                check_id=check.id,
                evidence=tuple(sorted(produced, key=lambda e: e.id)),
                seconds=round(now() - started, 6),
                error=error,
            )
        )
    return runs
