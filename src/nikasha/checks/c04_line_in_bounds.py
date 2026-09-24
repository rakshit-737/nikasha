# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C04 LINE_IN_BOUNDS: is a cited line inside the file at the claimed version? (SPEC §12)

A line past the end of the file is one of the few unambiguous signals: a report citing
``http.c:2143`` when that file has 1,944 lines at the claimed tag is wrong about something
concrete. The check says so with the real length, never more. It never refutes a length it did
not measure: a symlink or other non-regular entry, a permalink pinned to another ref or
repository, or a file that only shares the cited basename is left NEUTRAL or to C02.

Files the file-level checks already own are left alone: a path that does not resolve is
C02's finding, not a second refutation here (that double-counting is exactly what group
damping in SPEC §14.1 exists to stop, and this check avoids creating it at all).
"""

from __future__ import annotations

from collections.abc import Sequence

from nikasha.checks.base import BaseCheck, CheckContext, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.pathtrie import normalize_components
from nikasha.model.claims import Claim, ClaimKind, LineClaim
from nikasha.model.evidence import Evidence

CHECK_ID = "C04"
GROUP = "lines"

#: ``(resolved path, first line, cited line, permalink elsewhere or None)``.
_Key = tuple[str, int, int, str | None]


@register
class LineInBounds(BaseCheck):
    id = CHECK_ID
    name = "LINE_IN_BOUNDS"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"line"})
    description = "Checks that a cited line number exists in the file at the resolved commit."

    def __init__(self, strengths: Strengths | None = None) -> None:
        self.strengths = strengths or default_strengths()

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        # One fact, one evidence: the same resolved ``path:line`` cited twice (different
        # spelling, a function hint, a second sentence) is judged once for all its claims.
        grouped: dict[_Key, list[LineClaim]] = {}
        for claim in claims:
            if not isinstance(claim, LineClaim):
                continue
            key = self._key(ctx, claim)
            if key is not None:
                grouped.setdefault(key, []).append(claim)
        out: list[Evidence] = []
        for key, members in grouped.items():
            evidence = self._judge(ctx, key, members)
            if evidence is not None:
                out.append(evidence)
        return out

    def _key(self, ctx: CheckContext, claim: LineClaim) -> _Key | None:
        if claim.path is None or claim.line < 1:
            return None
        candidates = ctx.resolve_path(claim.path)
        if len(candidates) != 1:
            # Missing, or ambiguous: C02 owns that finding.
            return None
        path = candidates[0]
        if not _suffix_matches(path, claim.path):
            # The paths diverge above a shared suffix (often just the basename): this is
            # a different file, and whether the cited one exists is C02's finding.
            return None
        cited = claim.end_line if claim.end_line is not None else claim.line
        pin = _pin_mismatch(ctx, claim)
        return (path, claim.line, cited, pin)

    def _judge(self, ctx: CheckContext, key: _Key, members: list[LineClaim]) -> Evidence | None:
        path, first, cited, pin = key
        at = ctx.ref_name or ctx.commit[:12]
        if pin is not None:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=members,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"the report pins line {cited} of {path} to a permalink at {pin},"
                f" not {at}, so it is not judged here",
                details={
                    "outcome": "permalink_elsewhere",
                    "path": path,
                    "line": cited,
                    "permalink": pin,
                },
            )
        generated = ctx.generated(path)
        if generated is not None:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=members,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{path} is {generated.kind}, so its line numbers are not judged",
                details={"outcome": "generated", "path": path, "generated": generated.reason},
            )
        n_lines = ctx.line_count(path)
        if n_lines is None:
            return None
        if cited <= n_lines:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=members,
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, "in_bounds"),
                summary=f"{path} has {n_lines} lines at {at}; line {cited} is inside it",
                details={"outcome": "in_bounds", "path": path, "line": cited, "n_lines": n_lines},
                locations=[ctx.location(path, first, cited)],
            )
        mode = _mode(ctx, path)
        if mode not in _REGULAR_MODES:
            # A symlink's blob is its target text (one line); a submodule or an unknown
            # entry has no lines of its own. Never refute a length we did not measure.
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=members,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{path} is not a regular file at {at}, so its length is not judged",
                details={
                    "outcome": "not_regular_file",
                    "path": path,
                    "line": cited,
                    "mode": mode or "unknown",
                },
            )
        cited_as = sorted({m.path for m in members if m.path is not None})
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=members,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "past_end"),
            summary=f"{path} has {n_lines} lines at {at}; the report cites line {cited}",
            details={
                "outcome": "past_end",
                "path": path,
                "cited_as": cited_as,
                "line": cited,
                "n_lines": n_lines,
                "past_end_by": cited - n_lines,
            },
            locations=[ctx.location(path, max(1, n_lines))],
        )


_REGULAR_MODES = frozenset({"100644", "100755"})
#: Tree modes per commit, read once per process only when a refutation is on the table.
_MODES: dict[str, dict[str, str]] = {}


def _mode(ctx: CheckContext, path: str) -> str | None:
    """The tree mode of ``path`` at the target commit, or ``None`` if it cannot be read."""
    key = ctx.commit  # a commit SHA pins its tree, whichever clone holds it
    modes = _MODES.get(key)
    if modes is None:
        try:
            entries = ctx.resolution.repo.ls_tree(ctx.commit)
        except Exception:  # an unreadable tree means "unknown", never "regular"
            return None
        modes = {entry.path: entry.mode for entry in entries}
        if len(_MODES) > 8:  # noqa: PLR2004
            _MODES.clear()
        _MODES[key] = modes
    return modes.get(path)


def _suffix_matches(real: str, cited: str) -> bool:
    """Whether the cited path can name the real file rather than a different one.

    The two paths must share a non-empty suffix. They name different files only when both
    continue above that suffix and the next components differ (``tests/fuzz/util.c`` against
    ``src/util.c``). A cited path that is a suffix of the real one (``util.c``) matches, and
    so does a cited path that ends with the whole real path, since its extra leading
    components are a machine prefix (``/home/alice/libhdr/src/util.c``) or were consumed by
    ``..`` (``../../src/util.c``).
    """
    want = normalize_components(cited)
    have = normalize_components(real)
    shared = 0
    for a, b in zip(reversed(want), reversed(have), strict=False):
        if a != b:
            break
        shared += 1
    if shared == 0:
        return False
    return shared in (len(want), len(have))


def _pin_mismatch(ctx: CheckContext, claim: LineClaim) -> str | None:
    """The permalink's ``owner/repo@ref`` when it points somewhere other than the target."""
    link = claim.permalink
    if link is None:
        return None
    label = f"{link.owner}/{link.repo}@{link.ref}"
    target = ctx.repo_url.lower().rstrip("/").removesuffix(".git")
    if not target.endswith(f"/{link.owner.lower()}/{link.repo.lower()}"):
        return label
    if link.ref in (ctx.ref_name, ctx.commit):
        return None
    try:
        resolved = ctx.resolution.repo.rev_parse(link.ref)
    except Exception:  # an unsafe or unknown ref is not the target
        return label
    return None if resolved == ctx.commit else label
