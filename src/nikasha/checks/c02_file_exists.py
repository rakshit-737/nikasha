# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C02 FILE_EXISTS: is a cited path in the tree at the claimed version? (SPEC §12)

Paths come from file claims, line claims and the app frames of a trace, and are matched
after PathTrie normalization, so ``/home/build/libhdr/src/util.c`` from the reporter's
machine finds ``src/util.c`` here.

This check is where P4 is won or lost. "That file does not exist" is the most damaging
thing Nikasha can say about a genuine report, so a missing path only becomes *never
existed* when every sampled release lacks it (by path **or** basename, SPEC §12) *and* a
complete history search agrees. A shallow clone, a pickaxe that timed out and a release
scan cut short by the check's budget each downgrade the finding to "missing here" and say
in the summary that absence was not established. Generated and release-only files (SPEC
§11.5) are never judged at all: an amalgamation is absent from git by construction.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import HistoryTimeoutError
from nikasha.code.pathtrie import normalize_components
from nikasha.model.claims import Claim, ClaimKind, FileClaim, Frame, LineClaim, TraceClaim
from nikasha.model.evidence import Evidence

CHECK_ID = "C02"
GROUP = "locus"


def _ref(ctx: CheckContext) -> str:
    return ctx.ref_name or ctx.commit[:12]


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _frames(claim: TraceClaim) -> Iterator[Frame]:
    """Every frame the trace carries: the crash stack, then the allocation stacks.

    A fabricated path in an ASan "allocated by thread" stack is as checkable as one in the
    crash stack, and the reporter meant both to be believed.
    """
    yield from claim.frames
    yield from claim.alloc_frames
    yield from claim.free_frames
    for stack in claim.other_stacks:
        yield from stack.frames


def cited_paths(claim: Claim) -> list[str]:
    """The paths one claim puts on the record, in report order, as the report wrote them.

    Duplicates are dropped by *normalized* form, so a trace whose frames all live in
    ``/build/src/util.c`` yields one finding rather than eight. Runtime frames (libc,
    the interpreter) name files that are not in this repository, so they are skipped.
    """
    if isinstance(claim, FileClaim | LineClaim):
        raw: list[str | None] = [claim.path]
    elif isinstance(claim, TraceClaim):
        raw = [frame.path for frame in _frames(claim) if not frame.is_runtime]
    else:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for path in raw:
        if not path:
            continue
        normalized = "/".join(normalize_components(path))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(path)
    return out


@dataclass(frozen=True, slots=True)
class _History:
    """What ``log -S`` could establish about a file name across the whole history."""

    complete: bool
    first_commit: str | None = None
    reason: str | None = None

    @property
    def never_seen(self) -> bool:
        """Only ever ``True`` when the search actually finished (P4)."""
        return self.complete and self.first_commit is None


@dataclass(frozen=True, slots=True)
class _Scan:
    """Which sampled releases hold the path, and whether every one of them was looked at."""

    present: tuple[tuple[str, tuple[str, ...]], ...]
    sampled: int
    complete: bool


@dataclass
class _Trees:
    """Per-run caches, so twenty claims cost one tree listing and one pickaxe per name."""

    _basenames: dict[str, dict[str, tuple[str, ...]]] = field(default_factory=dict)
    _history: dict[str, _History] = field(default_factory=dict)
    _shallow: bool | None = None

    def matches(self, ctx: CheckContext, commit: str, path: str) -> tuple[str, ...]:
        """Files at ``commit`` sharing the basename of ``path`` (SPEC: path *or* basename)."""
        index = self._basenames.get(commit)
        if index is None:
            grouped: dict[str, list[str]] = {}
            for entry in ctx.index.files(commit):
                grouped.setdefault(_basename(entry.path), []).append(entry.path)
            index = {base: tuple(sorted(paths)) for base, paths in grouped.items()}
            self._basenames[commit] = index
        return index.get(_basename(path), ())

    def releases_with(self, ctx: CheckContext, path: str) -> _Scan:
        finals = ctx.resolution.releases.finals()
        present: list[tuple[str, tuple[str, ...]]] = []
        for release in finals:
            if ctx.expired():
                return _Scan(tuple(present), len(finals), complete=False)
            found = self.matches(ctx, release.commit, path)
            if found:
                present.append((release.name, found))
        return _Scan(tuple(present), len(finals), complete=True)

    def history(self, ctx: CheckContext, name: str) -> _History:
        cached = self._history.get(name)
        if cached is None:
            cached = self._probe(ctx, name)
            self._history[name] = cached
        return cached

    def _probe(self, ctx: CheckContext, name: str) -> _History:
        if not name.isprintable():
            return _History(False, reason="the file name cannot be searched for")
        if ctx.expired():
            return _History(False, reason="the check's time budget ran out")
        if self._shallow is None:
            self._shallow = ctx.resolution.repo.is_shallow()
        if self._shallow:
            return _History(False, reason="the clone is shallow")
        try:
            first = ctx.resolution.repo.pickaxe_first(name, timeout=ctx.history_timeout)
        except HistoryTimeoutError:
            return _History(
                False, reason=f"the history search timed out after {ctx.history_timeout:g}s"
            )
        return _History(True, first_commit=first)


@register
class FileExists(BaseCheck):
    id = CHECK_ID
    name = "FILE_EXISTS"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"file", "line", "trace"})
    description = "Checks that a cited path exists in the tree at the resolved commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        trees = _Trees()
        return [
            self._one(ctx, claim, path, trees)
            for claim in claims
            for path in cited_paths(claim)
        ]  # fmt: skip

    def _one(self, ctx: CheckContext, claim: Claim, path: str, trees: _Trees) -> Evidence:
        candidates = ctx.resolve_path(path)
        normalized = "/".join(normalize_components(path))
        generated = ctx.generated(candidates[0] if len(candidates) == 1 else normalized)
        if generated is not None:
            return self._generated(ctx, claim, normalized, generated.kind, generated.reason)
        if candidates:
            return self._exists(ctx, claim, path, normalized, candidates)
        return self._absent(ctx, claim, normalized, trees)

    def _generated(
        self, ctx: CheckContext, claim: Claim, path: str, kind: str, reason: str
    ) -> Evidence:
        """SPEC §11.5: a generated or release-only file is never judged, in either direction."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=self.strengths.get(CHECK_ID, "generated"),
            summary=f"{path} is a {kind} file, not in source control, so its presence at"
            f" {_ref(ctx)} is not judged",
            details={"outcome": "generated", "path": path, "generated": kind, "reason": reason},
        )

    def _exists(
        self,
        ctx: CheckContext,
        claim: Claim,
        cited: str,
        path: str,
        candidates: Sequence[str],
    ) -> Evidence:
        matched = candidates[0]
        ref = _ref(ctx)
        if len(candidates) > 1:
            summary = f"{path} matches {len(candidates)} files at {ref}, such as {matched}"
        elif matched == path:
            summary = f"{path} is in the tree at {ref}"
        else:
            summary = f"{path} resolves to {matched}, which is in the tree at {ref}"
        details: dict[str, Any] = {
            "outcome": "exists",
            "path": path,
            "matched": matched,
            "matched_components": ctx.trie.match_depth(path),
        }
        if cited != path:
            details["cited_as"] = cited
        if len(candidates) > 1:
            details["candidates"] = list(candidates)
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="SUPPORTS",
            strength=self.strengths.get(CHECK_ID, "exists"),
            summary=summary,
            details=details,
            locations=[ctx.location(matched, 1)],
        )

    def _absent(self, ctx: CheckContext, claim: Claim, path: str, trees: _Trees) -> Evidence:
        ref = _ref(ctx)
        scan = trees.releases_with(ctx, path)
        if scan.present:
            return self._elsewhere(ctx, claim, path, scan)

        history = trees.history(ctx, _basename(path))
        missing = (
            f"{path} is not in the tree at {ref} or in any of the {scan.sampled} sampled releases"
        )
        details: dict[str, Any] = {
            "path": path,
            "sampled_releases": scan.sampled,
            "history_complete": history.complete,
        }
        if scan.complete and history.never_seen:
            # The only place this check may say "never existed": every sampled release was
            # looked at, and log -S found the name in no commit on any ref.
            base = self.strengths.get(CHECK_ID, "never_in_history")
            core = claim.role == "core"
            if core:
                base *= self.strengths.get(CHECK_ID, "never_in_history_core_multiplier")
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=[claim],
                outcome="REFUTES",
                strength=base,
                summary=f"{missing}, and the name appears nowhere in history",
                details={
                    **details,
                    "outcome": "never_in_history",
                    "never_in_history": True,
                    "core_claim": core,
                },
            )

        # P4: absence is not established, so the strong outcome is withheld and the reason
        # is stated. The file is still genuinely missing at the ref, which is the -0.8.
        reasons: list[str] = []
        if not scan.complete:
            reasons.append("the release scan did not finish")
        if history.reason is not None:
            reasons.append(history.reason)
        if history.first_commit is not None:
            reasons.append(f"the name appears in history (commit {history.first_commit[:12]})")
            details["first_commit_with_name"] = history.first_commit
        note = "; ".join(reasons)
        details["history_note"] = note
        details["outcome"] = "missing_here_present_elsewhere"
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "missing_here_present_elsewhere"),
            summary=f"{missing}, but absence is not established: {note}",
            details=details,
        )

    def _elsewhere(self, ctx: CheckContext, claim: Claim, path: str, scan: _Scan) -> Evidence:
        names = [name for name, _ in scan.present]
        found = sorted({p for _, paths in scan.present for p in paths})
        note = (
            f"{path} exists in {', '.join(names)}: the report may be about one of those"
            " versions rather than " + _ref(ctx)
        )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "missing_here_present_elsewhere"),
            summary=f"{path} is not in the tree at {_ref(ctx)}, but it is in {', '.join(names)}",
            details={
                "outcome": "missing_here_present_elsewhere",
                "path": path,
                "present_in": names,
                "present_as": found,
                "sampled_releases": scan.sampled,
                "version_note": note,
            },
        )
