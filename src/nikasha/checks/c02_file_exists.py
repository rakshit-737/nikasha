# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C02 FILE_EXISTS: is a cited path in the tree at the claimed version? (SPEC §12)

Paths come from file claims, line claims and the app frames of a trace, and are matched
after PathTrie normalization, so ``/home/build/libhdr/src/util.c`` from the reporter's
machine finds ``src/util.c`` here.

This check is where P4 is won or lost. "That file does not exist" is the most damaging
thing Nikasha can say about a genuine report, so a missing path only becomes *never
existed* when every sampled release lacks it (by path **or** basename, SPEC §12) *and* a
complete history search agrees: no commit on any ref touched a file of that name, and no
diff ever spelled the name out. A shallow clone, a failed or timed-out search, an empty
release list and a budget that ran out each withhold the finding and say why. Generated
and release-only files (SPEC §11.5) are never judged at all, and neither are trace frames
in system headers or vendored code (C08's rule): those files are somebody else's.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.c08_trace_frames import _third_party_reason
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import GitTimeoutError, HistoryTimeoutError, HistoryUnavailableError
from nikasha.code.pathtrie import normalize_components
from nikasha.errors import ExternalToolError
from nikasha.model.claims import Claim, ClaimKind, FileClaim, Frame, LineClaim, TraceClaim
from nikasha.model.evidence import CommandRecord, Evidence

CHECK_ID = "C02"
GROUP = "locus"

#: Longest file name the history is searched for. No filesystem git runs on allows a
#: longer path component, and an unbounded one would reach the argv (E2BIG, WinError 206).
MAX_NAME_LEN = 255

#: NEUTRAL outcome labels. None is a strengths-table key: these findings carry no weight.
OUTSIDE_REPOSITORY = "outside_repository"
ABSENCE_NOT_ESTABLISHED = "absence_not_established"
BUDGET_EXPIRED = "budget_expired"


def _ref(ctx: CheckContext) -> str:
    return ctx.ref_name or ctx.commit[:12]


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _normalized(path: str) -> str:
    return "/".join(normalize_components(path))


def _glob_literal(name: str) -> str:
    """``name`` with git wildmatch metacharacters escaped, for a ``:(glob)`` pathspec."""
    return "".join("\\" + ch if ch in "\\*?[" else ch for ch in name)


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
        normalized = _normalized(path)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(path)
    return out


def _outside_reasons(claim: Claim) -> dict[str, str]:
    """Normalized trace paths whose every frame is somebody else's code, with the reason.

    A frame in ``/usr/include/``, a vendored tree or a shared library names a file this
    repository never had. C08 does not count such frames, and neither does this check.
    """
    if not isinstance(claim, TraceClaim):
        return {}
    reasons: dict[str, str | None] = {}
    for frame in _frames(claim):
        if not frame.path or frame.is_runtime:
            continue
        key = _normalized(frame.path)
        reason = _third_party_reason(frame)
        if key not in reasons:
            reasons[key] = reason
        elif reasons[key] is not None and reason is None:
            reasons[key] = None
    return {key: reason for key, reason in reasons.items() if reason is not None}


@dataclass
class _Cited:
    """One normalized path and everything that cites it."""

    path: str
    claims: list[Claim] = field(default_factory=list)
    #: Set only while every citation of the path is a third-party trace frame.
    outside: str | None = None
    has_own_citation: bool = False


@dataclass(frozen=True, slots=True)
class _History:
    """What the history search could establish about a file name across every ref."""

    complete: bool
    first_commit: str | None = None
    reason: str | None = None
    #: The searches that answered. A search that was refused or timed out records
    #: nothing: there is no exit code or output to hash (P6).
    commands: tuple[CommandRecord, ...] = ()

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
    """Per-run caches, so twenty claims cost one tree listing and one search per name."""

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
        if not finals:
            # Nothing was sampled, so "every sampled release lacks it" says nothing (P4).
            return _Scan((), 0, complete=False)
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
        if not name or not name.isprintable() or len(name) > MAX_NAME_LEN:
            return _History(False, reason="the file name cannot be searched for")
        if ctx.expired():
            return _History(False, reason="the check's time budget ran out")
        if self._shallow is None:
            self._shallow = ctx.resolution.repo.is_shallow()
        if self._shallow:
            return _History(False, reason="the clone is shallow")
        return _search(ctx, name)


def _why_unfinished(exc: ExternalToolError, timed_out: str, failed: str) -> str:
    """Only a real timeout is called one; any other failure keeps git's reason (P6)."""
    if isinstance(exc, GitTimeoutError) or (
        isinstance(exc, HistoryTimeoutError) and not isinstance(exc, HistoryUnavailableError)
    ):
        return timed_out
    return f"{failed}: {exc}"


def _search(ctx: CheckContext, name: str) -> _History:
    """Every ref's history, by file path and then by diff content, for one file name."""
    timed_out = f"the history search timed out after {ctx.history_timeout:g}s"
    failed = "the history search failed"
    records: list[CommandRecord] = []
    # By path first: a file whose name no tracked file ever spells out (a module found
    # by a build glob, a test file) is invisible to log -S, which reads contents only.
    pathspec = f":(glob)**/{_glob_literal(name)}"
    try:
        result = ctx.resolution.repo.run(
            ["log", "--all", "-1", "--format=%H", "--", pathspec],
            timeout=ctx.history_timeout,
            record=records,
        )
    except ExternalToolError as exc:
        return _History(False, reason=_why_unfinished(exc, timed_out, failed))
    if result.returncode != 0:
        return _History(False, reason=failed, commands=tuple(records))
    by_path = result.stdout.decode("ascii", "replace").strip()
    if by_path:
        return _History(True, first_commit=by_path, commands=tuple(records))
    try:
        first = ctx.resolution.repo.pickaxe_first(name, timeout=ctx.history_timeout, record=records)
    except HistoryTimeoutError as exc:
        return _History(
            False, reason=_why_unfinished(exc, timed_out, failed), commands=tuple(records)
        )
    if any(record.exit_code != 0 for record in records):
        # A failed log --all prints nothing, which is not "found nothing" (P4).
        return _History(False, reason=failed, commands=tuple(records))
    return _History(True, first_commit=first, commands=tuple(records))


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
        # One finding per path, citing every claim that names it: a file claim and a line
        # claim on the same missing file are one fact, not two refutations in one group.
        cited: dict[str, _Cited] = {}
        for claim in claims:
            outside = _outside_reasons(claim)
            for path in cited_paths(claim):
                key = _normalized(path)
                entry = cited.get(key)
                if entry is None:
                    entry = cited[key] = _Cited(path)
                if claim not in entry.claims:
                    entry.claims.append(claim)
                reason = outside.get(key)
                if reason is None:
                    entry.has_own_citation = True
                elif entry.outside is None:
                    entry.outside = reason
        trees = _Trees()
        return [
            self._one(
                ctx, entry.claims, entry.path, trees,
                None if entry.has_own_citation else entry.outside,
            )
            for entry in cited.values()
        ]  # fmt: skip

    def _one(
        self,
        ctx: CheckContext,
        claims: list[Claim],
        path: str,
        trees: _Trees,
        outside: str | None,
    ) -> Evidence:
        candidates = ctx.resolve_path(path)
        normalized = _normalized(path)
        generated = ctx.generated(candidates[0] if len(candidates) == 1 else normalized)
        if generated is not None:
            return self._generated(ctx, claims, normalized, generated.kind, generated.reason)
        if candidates:
            return self._exists(ctx, claims, path, normalized, candidates)
        if outside is not None:
            return self._outside(ctx, claims, normalized, outside)
        return self._absent(ctx, claims, normalized, trees)

    def _outside(self, ctx: CheckContext, claims: list[Claim], path: str, why: str) -> Evidence:
        """A frame in a system header or vendored code is not this repository's file."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="NEUTRAL",
            strength=0.0,
            summary=f"{path} is not in the tree at {_ref(ctx)} and is not judged: {why}",
            details={"outcome": OUTSIDE_REPOSITORY, "path": path, "reason": why},
        )

    def _generated(
        self, ctx: CheckContext, claims: list[Claim], path: str, kind: str, reason: str
    ) -> Evidence:
        """SPEC §11.5: a generated or release-only file is never judged, in either direction."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="NEUTRAL",
            strength=self.strengths.get(CHECK_ID, "generated"),
            summary=f"{path} is a {kind} file, not in source control, so its presence at"
            f" {_ref(ctx)} is not judged",
            details={"outcome": "generated", "path": path, "generated": kind, "reason": reason},
        )

    def _exists(
        self,
        ctx: CheckContext,
        claims: list[Claim],
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
            claims=claims,
            outcome="SUPPORTS",
            strength=self.strengths.get(CHECK_ID, "exists"),
            summary=summary,
            details=details,
            locations=[ctx.location(matched, 1)],
        )

    def _absent(self, ctx: CheckContext, claims: list[Claim], path: str, trees: _Trees) -> Evidence:
        ref = _ref(ctx)
        scan = trees.releases_with(ctx, path)
        if not scan.complete and scan.sampled:
            # How far the scan got depends on the clock, so nothing it saw is reported (P2).
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{path} is not in the tree at {ref}; the check's time budget ran out"
                " before the other releases were scanned, so it is not judged",
                details={"outcome": BUDGET_EXPIRED, "path": path, "release_scan_complete": False},
            )
        if scan.present:
            return self._elsewhere(ctx, claims, path, scan)

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
            # looked at, no commit on any ref touched a file of that name, and log -S found
            # the name in no diff.
            base = self.strengths.get(CHECK_ID, "never_in_history")
            core = any(claim.role == "core" for claim in claims)
            if core:
                base *= self.strengths.get(CHECK_ID, "never_in_history_core_multiplier")
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="REFUTES",
                strength=base,
                summary=f"{missing}, and the name appears nowhere in history",
                details={
                    **details,
                    "outcome": "never_in_history",
                    "never_in_history": True,
                    "core_claim": core,
                },
                commands=history.commands,
            )

        # P4: absence is not established, so the strong outcome is withheld and the reason
        # is stated. Only a history that *has* the name is "present elsewhere" (the -0.8);
        # an unfinished or impossible search establishes nothing, carries no weight, and
        # must not read as a version mismatch to the fusion rules.
        reasons: list[str] = []
        if not scan.complete:
            reasons.append("no release was available to sample")
        if history.reason is not None:
            reasons.append(history.reason)
        if history.first_commit is not None:
            reasons.append(f"the name appears in history (commit {history.first_commit[:12]})")
            details["first_commit_with_name"] = history.first_commit
        note = "; ".join(reasons)
        details["history_note"] = note
        in_history = history.first_commit is not None
        details["outcome"] = (
            "missing_here_present_elsewhere" if in_history else (ABSENCE_NOT_ESTABLISHED)
        )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="REFUTES" if in_history else "NEUTRAL",
            strength=(
                self.strengths.get(CHECK_ID, "missing_here_present_elsewhere")
                if in_history
                else 0.0
            ),
            summary=f"{missing}, but absence is not established: {note}",
            details=details,
            commands=history.commands,
        )

    def _elsewhere(
        self, ctx: CheckContext, claims: list[Claim], path: str, scan: _Scan
    ) -> Evidence:
        names = [name for name, _ in scan.present]
        found = sorted({p for _, paths in scan.present for p in paths})
        # Releases match by path *or* basename; only say "the path" when it was the path.
        what = path if path in found else f"a file named {_basename(path)}"
        note = (
            f"{what} exists in {', '.join(names)}: the report may be about one of those"
            " versions rather than " + _ref(ctx)
        )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "missing_here_present_elsewhere"),
            summary=f"{path} is not in the tree at {_ref(ctx)}, but {what} is in"
            f" {', '.join(names)}",
            details={
                "outcome": "missing_here_present_elsewhere",
                "path": path,
                "present_in": names,
                "present_as": found,
                "sampled_releases": scan.sampled,
                "version_note": note,
            },
        )
