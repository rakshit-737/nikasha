# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C13 FIX_STATUS: has the reported locus moved since the claimed version? (SPEC §12)

This check is for the maintainer reading the result, not against the reporter. A file that
has been touched since the tag the report names is the first place to look — the bug may
already be fixed upstream, and the reporter may simply be a release behind. It is never a
sign that the report is wrong: projects change their own files constantly. So the outcome
is always NEUTRAL and the strength is always 0 (P1, P4).

Only commits *after* the ref are listed. The range ``<commit>..<default branch>`` already
drops the ref's ancestors, and commits older than the ref's own committer date are dropped
too, because a tag cut from a maintenance branch would otherwise drag in work that
predates the release entirely.

A path that does not resolve, or resolves ambiguously, is left alone: that is C02's
finding, and repeating it here would only add noise to a section meant to be read quickly.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import safe_rev
from nikasha.errors import ExternalToolError
from nikasha.model.claims import Claim, ClaimKind, FileClaim, LineClaim, SymbolClaim
from nikasha.model.evidence import CommandRecord, Evidence

CHECK_ID = "C13"
GROUP = "info"

#: How many commits to name before the summary says "and N more".
MAX_COMMITS = 20

#: Per-path budget for the path log, well inside the 10 s a check gets.
LOG_TIMEOUT_S = 5.0

_SHA_HEX_LEN = 40

#: Claim kinds that carry a locus, i.e. something with a path in the tree.
_LOCUS_KINDS: frozenset[ClaimKind] = frozenset({"file", "line", "symbol"})


@register
class FixStatus(BaseCheck):
    id = CHECK_ID
    name = "FIX_STATUS"
    group = GROUP
    applies_to: frozenset[ClaimKind] = _LOCUS_KINDS
    description = "Lists commits after the claimed version that touch the reported locus."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        repo = ctx.resolution.repo
        branch = repo.default_branch()
        if branch is None:
            # A repository with a detached HEAD has no "since then" to report.
            return []
        ref_epoch = repo.commit_epoch(ctx.commit) or 0
        failed: list[Evidence] = []
        loci = self._loci(ctx, claims, failed)
        out: list[Evidence] = list(failed)
        for path in sorted(loci):
            if ctx.expired():
                break
            # One sink per path: the evidence for a file carries the log that produced it.
            records: list[CommandRecord] = []
            commits, capped = self._later_commits(ctx, branch, path, ref_epoch, records)
            if commits:
                out.append(
                    self._evidence(
                        ctx, path, branch, loci[path], commits, capped=capped, commands=records
                    )
                )
        return out

    # --- finding the locus --------------------------------------------------------------

    def _loci(
        self, ctx: CheckContext, claims: Sequence[Claim], failed: list[Evidence]
    ) -> dict[str, list[Claim]]:
        """Real paths in the tree to the claims that point at them.

        A claim whose locus git could not look up gets a NEUTRAL ``search_failed`` finding in
        ``failed`` and the other claims are still followed (P4).
        """
        loci: dict[str, list[Claim]] = {}
        for claim in claims:
            try:
                paths = self._paths(ctx, claim)
            except ExternalToolError as exc:
                failed.append(self._search_failed(claim, exc))
                continue
            for path in paths:
                loci.setdefault(path, []).append(claim)
        return loci

    def _paths(self, ctx: CheckContext, claim: Claim) -> list[str]:
        if isinstance(claim, FileClaim | LineClaim):
            if claim.path is None:
                return []
            candidates = ctx.resolve_path(claim.path)
            return candidates if len(candidates) == 1 else []
        if isinstance(claim, SymbolClaim):
            # A symbol's locus is wherever it is defined at the ref; if it is defined
            # nowhere, C03 says so and there is nothing here to follow.
            return sorted({path for path, _ in ctx.index.definitions(ctx.commit, claim.name)})
        return []

    # --- the path log ---------------------------------------------------------------------

    def _later_commits(
        self,
        ctx: CheckContext,
        branch: str,
        path: str,
        ref_epoch: int,
        records: list[CommandRecord],
    ) -> tuple[list[tuple[str, int]], bool]:
        """``(sha, committer epoch)`` for post-ref commits on ``branch`` touching ``path``.

        The flag is true when git stopped at ``--max-count``: more commits may exist even if
        the date filter below dropped some of the ones it printed, so the count is a floor.

        The log is appended to ``records`` when it ran at all, so the evidence can show the
        exact query and the hash of what it printed (P6).
        """
        argv = [
            "log",
            "--format=%H %ct",
            f"--max-count={MAX_COMMITS + 1}",
            "--end-of-options",
            f"{safe_rev(ctx.commit)}..{safe_rev(branch)}",
            "--",
            # A literal pathspec: a tree path may contain '*' or '[' and must not glob.
            f":(literal){path}",
        ]
        try:
            result = ctx.resolution.repo.run(argv, timeout=LOG_TIMEOUT_S, record=records)
        except ExternalToolError:
            # A history query that runs out of time yields no information, never a finding.
            return [], False
        if result.returncode != 0:
            return [], False
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        commits: list[tuple[str, int]] = []
        for line in lines:
            sha, _, epoch = line.partition(" ")
            if len(sha) == _SHA_HEX_LEN and epoch.isdigit() and int(epoch) > ref_epoch:
                commits.append((sha, int(epoch)))
        return commits, len(lines) > MAX_COMMITS

    # --- evidence ---------------------------------------------------------------------------

    def _search_failed(self, claim: Claim, exc: ExternalToolError) -> Evidence:
        name = claim.name if isinstance(claim, SymbolClaim) else getattr(claim, "path", claim.id)
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=[claim],
            outcome="NEUTRAL",
            strength=0.0,
            summary=f"where {name} is defined could not be searched for: {exc},"
            " so its later history is not listed",
            details={
                "outcome": "search_failed",
                "incomplete": str(exc),
                "history_complete": False,
            },
        )

    def _evidence(
        self,
        ctx: CheckContext,
        path: str,
        branch: str,
        claims: Sequence[Claim],
        commits: Sequence[tuple[str, int]],
        *,
        capped: bool = False,
        commands: Sequence[CommandRecord] = (),
    ) -> Evidence:
        listed = list(commits[:MAX_COMMITS])
        truncated = capped or len(commits) > MAX_COMMITS
        newest_sha, newest_epoch = listed[0]
        details: dict[str, Any] = {
            "outcome": "modified_after",
            "path": path,
            "branch": branch,
            "commits": [{"sha": sha, "date": _date(epoch)} for sha, epoch in listed],
            "n_commits": len(listed),
            "truncated": truncated,
        }
        generated = ctx.generated(path)
        if generated is not None:
            details["generated"] = generated.reason
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="NEUTRAL",
            strength=self.strengths.get(CHECK_ID, "modified_after"),
            summary=f"{path} was modified after the claimed version by {newest_sha[:12]}"
            f" ({_date(newest_epoch)}){_tail(len(listed) - 1, truncated, branch)},"
            " which may already be fixed",
            details=details,
            # The finding is about the file's history, so the location just pins the file
            # as it stood at the version the report names.
            locations=[ctx.location(path, 1)],
            commands=commands,
        )


def _date(epoch: int) -> str:
    """A commit's own committer date, in UTC, so the text never depends on the machine."""
    return datetime.fromtimestamp(epoch, tz=UTC).date().isoformat()


def _tail(extra: int, truncated: bool, branch: str) -> str:
    if extra <= 0:
        return f" and possibly more later commits on {branch}" if truncated else ""
    count = f"{extra} or more" if truncated else str(extra)
    plural = "" if extra == 1 and not truncated else "s"
    return f" and {count} later commit{plural} on {branch}"
