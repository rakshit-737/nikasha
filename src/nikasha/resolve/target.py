# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Target resolution (SPEC §10): which repository, and which exact commit, a report is about.

Order of precedence for the repository: ``--repo``, then intake metadata (the report's
declared target), then claims (a product alias in ``known_projects.yaml``, or a repository
URL in a reference or permalink). For the version: ``--ref``/``--version``, then a permalink's
ref, then claimed versions (tested-on, then affected ranges, then fixed-in), then commit
claims, then branch refs (``master``/``HEAD``, resolved as of the report date).
**Never guess silently:** unresolvable targets fail with an actionable message; ambiguous
ones record alternatives and warnings.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, time

from nikasha.code.gitio import GitRepo
from nikasha.errors import NikashaError
from nikasha.extract.versions import parse_version
from nikasha.model.claims import (
    ClaimBase,
    LineClaim,
    ReferenceClaim,
    VersionClaim,
)
from nikasha.model.report import Report
from nikasha.model.result import ResolvedTarget
from nikasha.resolve.products import KnownProject, load_known_projects
from nikasha.resolve.refs import Release, ReleaseList
from nikasha.resolve.repo import acquire, canonical_url


class TargetNotFoundError(NikashaError):
    """No repository could be determined for a report."""


@dataclass
class Resolution:
    """Everything later stages need: the open repository, its releases and the target."""

    repo: GitRepo
    releases: ReleaseList
    target: ResolvedTarget
    project: KnownProject | None
    release: Release | None = None
    notes: list[str] = field(default_factory=list)


def _repo_from_claims(claims: Sequence[ClaimBase]) -> tuple[str, str] | None:
    """``(repo, method)`` from the report's own claims, or ``None``."""
    projects = load_known_projects()
    for claim in claims:
        if isinstance(claim, VersionClaim) and claim.product:
            project = projects.by_alias(claim.product)
            if project and project.repo:
                return project.repo, f"product {claim.product!r} in known_projects.yaml"
    for claim in claims:
        if isinstance(claim, LineClaim) and claim.permalink is not None:
            pl = claim.permalink
            return f"https://{pl.host}/{pl.owner}/{pl.repo}", "permalink in the report"
        if isinstance(claim, ReferenceClaim) and claim.repo_url:
            return claim.repo_url, f"{claim.ref_kind} URL in the report"
    return None


def _epoch_of(report: Report) -> int | None:
    if report.reported_at is None:
        return None
    return int(datetime.combine(report.reported_at, time.max, tzinfo=UTC).timestamp())


def _version_candidates(
    claims: Sequence[ClaimBase], product: str | None
) -> list[tuple[str, VersionClaim]]:
    """Version claims about this product, best evidence first."""
    about = [
        c for c in claims
        if isinstance(c, VersionClaim) and c.provenance != "third_party"
        and (c.product is None or product is None or c.product == product)
    ]  # fmt: skip
    ranked: list[tuple[int, str, VersionClaim]] = []
    for c in about:
        if c.relation == "tested_on" and c.parsed is not None:
            ranked.append((0, "tested-on version", c))
        elif c.relation == "affected_range" and c.upper is not None:
            ranked.append((1, "affected-range upper bound", c))
        elif c.relation == "fixed_in" and c.parsed is not None:
            ranked.append((2, "release before the claimed fix", c))
        elif c.commit:
            ranked.append((3, "claimed commit", c))
        elif c.special_ref:
            ranked.append((4, f"branch ref {c.special_ref!r}", c))
    ranked.sort(key=lambda t: (t[0], t[2].spans[0].start))
    return [(why, c) for _, why, c in ranked]


def _release_for(
    releases: ReleaseList, claim: VersionClaim, families: Sequence[str]
) -> Release | None:
    if claim.relation == "tested_on" and claim.parsed is not None:
        matches = releases.match(claim.parsed, preferred_families=families)
        return matches[0] if matches else None
    if claim.relation == "affected_range" and claim.upper is not None:
        if claim.upper_inclusive:
            matches = releases.match(claim.upper, preferred_families=families)
            return matches[0] if matches else None
        return releases.neighbours(claim.upper)[0]
    if claim.relation == "fixed_in" and claim.parsed is not None:
        return releases.neighbours(claim.parsed)[0]
    return None


@dataclass
class _Builder:
    git: GitRepo
    releases: ReleaseList
    project: KnownProject | None
    repo_url: str
    families: tuple[str, ...]
    method_parts: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def make(
        self,
        ref_name: str | None,
        commit: str | None,
        how: str,
        confidence: str,
        alts: Sequence[str] = (),
    ) -> Resolution:
        self.method_parts.append(how)
        target = ResolvedTarget(
            repo_url=self.repo_url,
            ref_name=ref_name,
            commit=commit,
            method="; ".join(self.method_parts),
            confidence=confidence,  # type: ignore[arg-type]
            alternatives=tuple(alts),
            warnings=tuple(self.warnings),
        )
        release = next((r for r in self.releases.releases if r.tag.raw == ref_name), None)
        return Resolution(self.git, self.releases, target, self.project, release)


def _choose_repo(report: Report, claims: Sequence[ClaimBase], repo: str | None) -> tuple[str, str]:
    if repo is not None:
        return repo, "--repo"
    if report.declared_target and report.declared_target.repo_url:
        return report.declared_target.repo_url, "intake metadata"
    found = _repo_from_claims(claims)
    if found is None:
        raise TargetNotFoundError(
            "could not tell which repository this report is about; pass --repo URL|PATH "
            "(and --version or --ref)"
        )
    return found


def _explicit(b: _Builder, ref: str | None, version: str | None) -> Resolution | None:
    if ref is not None:
        commit = b.git.rev_parse(ref)
        if commit is None:
            raise TargetNotFoundError(f"--ref {ref!r} does not exist in {b.repo_url}")
        return b.make(ref, commit, "ref from --ref", "high")
    if version is not None:
        spec = parse_version(version)
        matches = b.releases.match(spec, preferred_families=b.families) if spec else []
        if not matches:
            raise TargetNotFoundError(
                f"--version {version!r} matches no release tag in {b.repo_url}"
            )
        alts = [m.name for m in matches[1:]]
        return b.make(matches[0].name, matches[0].commit, "version from --version", "high", alts)
    return None


def _from_permalink(b: _Builder, claims: Sequence[ClaimBase]) -> Resolution | None:
    for claim in claims:
        if isinstance(claim, LineClaim) and claim.permalink is not None:
            commit = b.git.rev_parse(claim.permalink.ref)
            if commit is not None:
                return b.make(claim.permalink.ref, commit, "ref from a permalink", "high")
    return None


def _from_branch(b: _Builder, report: Report, claim: VersionClaim, why: str) -> Resolution:
    branch = b.git.default_branch() or "HEAD"
    epoch = _epoch_of(report)
    commit = b.git.tip_before(branch, epoch) if epoch else b.git.rev_parse(branch)
    when = " as of the report date" if epoch else " today (no report date)"
    b.warnings.append(f"{claim.special_ref!r} resolved to the tip of {branch}{when}")
    return b.make(branch, commit, why, "low")


def _from_claims(b: _Builder, report: Report, claims: Sequence[ClaimBase]) -> Resolution:
    chosen: tuple[Release, str] | None = None
    alternatives: list[str] = []
    for why, claim in _version_candidates(claims, b.project.name if b.project else None):
        if claim.commit:
            commit = b.git.rev_parse(claim.commit)
            if commit is None:
                b.warnings.append(
                    f"claimed commit {claim.commit} is not in this repository (a fork?)"
                )
            elif chosen is None:
                return b.make(claim.commit, commit, why, "high")
            continue
        if claim.special_ref:
            if chosen is None:
                return _from_branch(b, report, claim, why)
            continue
        release = _release_for(b.releases, claim, b.families)
        if release is None:
            b.warnings.append(f"claimed version {claim.raw!r} matches no release tag")
        elif chosen is None:
            chosen = (release, why)
        elif release.name != chosen[0].name and release.name not in alternatives:
            alternatives.append(release.name)
    if chosen is None:
        return b.make(None, None, "no version could be resolved", "low")
    if alternatives:
        b.warnings.append("the report names more than one version; using the first")
    confidence = "medium" if alternatives else "high"
    return b.make(chosen[0].name, chosen[0].commit, chosen[1], confidence, alternatives)


def resolve_target(
    report: Report,
    claims: Sequence[ClaimBase],
    *,
    repo: str | None = None,
    ref: str | None = None,
    version: str | None = None,
    product: str | None = None,
    online: bool = False,
) -> Resolution:
    """Resolve the repository and commit for ``report`` (see module docstring)."""
    repo_arg, how = _choose_repo(report, claims, repo)
    location = acquire(repo_arg, online=online)
    git = GitRepo(location.git_dir, online=online)
    known = load_known_projects()
    project = (known.by_repo(location.url) if location.url else None) or (
        known.by_alias(product) if product else None
    )
    families = project.tag_families if project else ()
    releases = ReleaseList.from_tags(git.tags(), families=families or None)
    builder = _Builder(git, releases, project, location.url or str(location.git_dir), families)
    builder.method_parts.append(f"repository from {how}")
    return (
        _explicit(builder, ref, version)
        or _from_permalink(builder, claims)
        or _from_claims(builder, report, claims)
    )


__all__ = ["Resolution", "TargetNotFoundError", "canonical_url", "resolve_target"]
