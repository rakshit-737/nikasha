# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C15 REFERENCES: do the commits, repo links, CVE records and CWE IDs check out? (SPEC §12)

The references around a report are cheap to verify and say a lot about how it was written.
A commit SHA either exists in this repository or it does not; a GitHub link either points
at this project or at a different one; a CWE either can or cannot describe the bug the
trace shows.

Three rules shape everything here:

* **A missing commit is not a lie.** It may come from a fork, a mirror or a
  security-embargo branch, so a SHA we cannot resolve is NEUTRAL with a question, never a
  refutation (SPEC §10, P4). Only *contradictions* — a foreign repository, a CVE for
  another product, an impossible CWE — carry negative strength.
* **CVE lookups are online only (P3).** Offline, the check says so and stops; it makes no
  network call of any kind. Online it fetches the CVE Program's own JSON 5.x record
  (SPEC §8) with stdlib ``urllib`` (ADR 0002: no httpx), under a timeout and a size cap,
  and records the URL, HTTP status and a hash of the response so the finding is
  reproducible (P6).
* **Unknown is not wrong.** A CWE the bundled table does not list, or a bug type it does
  not recognise, is NEUTRAL. ``cwe_compat.yaml`` exists to catch CWE-79 cited for a heap
  overflow in a C library, not to grade a reporter's taxonomy.

SPEC reads "+0.3 if the commit exists, +0.5 if it touches the claimed file" as one ladder,
so a commit that touches a claimed file yields a single ``commit_touches_file`` item
rather than two stacked ones: within a group, two items about the same fact would be
double-counted before group damping ever sees them (SPEC §14.1).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

import yaml

from nikasha.checks.base import BaseCheck, CheckContext, CheckError, make_evidence, register
from nikasha.checks.strengths import Strengths, default_strengths
from nikasha.code.gitio import CommandSink, GitRepo, safe_rev
from nikasha.errors import NikashaError
from nikasha.model.claims import (
    Claim,
    ClaimBase,
    ClaimKind,
    FileClaim,
    ImpactClaim,
    LineClaim,
    PatchClaim,
    ReferenceClaim,
    TraceClaim,
)
from nikasha.model.evidence import CommandRecord, Evidence
from nikasha.version import __version__

CHECK_ID = "C15"
GROUP = "refs"

#: The CVE Program's own record store (SPEC §8): ``cves/<year>/<n/1000>xxx/CVE-….json``.
CVE_LIST_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
CVE_TIMEOUT_S = 10.0
MAX_CVE_BYTES = 4 * 1024 * 1024
USER_AGENT = f"nikasha/{__version__}"
HTTP_OK = 200
HTTP_NOT_FOUND = 404

#: Affected-product placeholders that carry no information, so they cannot contradict one.
PLACEHOLDER_PRODUCTS = frozenset({"n/a", "n\\a", "na", "unknown", "unspecified", "all", "*", "-"})

#: How many touched paths, products or CWE suggestions a detail block may list.
MAX_LISTED = 8
#: Paths from one commit we are willing to compare against the claimed files.
MAX_TOUCHED_PATHS = 5000
_GIT_TIMEOUT_S = 10.0

_SHA_RE = re.compile(r"\A[0-9a-f]{7,40}\Z")
_CVE_RE = re.compile(r"\ACVE-(\d{4})-(\d{4,7})\Z", re.IGNORECASE)
_CWE_RE = re.compile(r"\A(?:CWE[-_ ]?)?(\d{1,5})\Z", re.IGNORECASE)
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]{1,64}")
_TOKEN_RE = re.compile(r"[a-z0-9]{1,64}")

_KeyT = TypeVar("_KeyT", int, str)
_ClaimT = TypeVar("_ClaimT", bound=ClaimBase)


def _slug(text: str) -> str:
    """``"Heap Buffer Overflow"`` and ``"heap-buffer-overflow"`` are the same key."""
    return _NON_ALNUM_RE.sub("-", text.strip().lower()).strip("-")


def _group(items: Iterable[tuple[_KeyT, _ClaimT]]) -> list[tuple[_KeyT, list[_ClaimT]]]:
    """Bucket claims by key, keys sorted and claims in report order (P2).

    One evidence item per distinct reference, however often the report repeats it: the
    same SHA quoted three times is one fact, not three.
    """
    buckets: dict[_KeyT, list[_ClaimT]] = {}
    for key, claim in items:
        buckets.setdefault(key, []).append(claim)
    return [(key, buckets[key]) for key in sorted(buckets)]


# --- the bundled CWE compatibility table ---------------------------------------------------

CWE_TABLE_PATH = Path(__file__).with_name("cwe_compat.yaml")


@dataclass(frozen=True, slots=True)
class CweCompat:
    """Which CWE IDs can describe which bug type, as loaded from ``cwe_compat.yaml``."""

    version: str
    titles: dict[int, str]
    families: dict[str, frozenset[int]]
    aliases: dict[str, str]

    def knows(self, cwe: int) -> bool:
        """Whether the table can say anything at all about this CWE."""
        return cwe in self.titles

    def family(self, bug_type: str) -> str | None:
        """The family a trace's ``bug_type`` belongs to, or ``None`` if it is unknown."""
        return self.aliases.get(_slug(bug_type))

    def compatible(self, family: str, cwe: int) -> bool:
        return cwe in self.families.get(family, frozenset())

    def expected(self, family: str) -> tuple[int, ...]:
        return tuple(sorted(self.families.get(family, frozenset())))


def load_cwe_compat(path: Path | None = None) -> CweCompat:
    """Load and validate the compatibility table.

    Every ``compatible`` ID must appear in ``cwes``: a typo there would silently turn a
    real CWE into an "incompatible" one, which is exactly the mistake P4 forbids.
    """
    source = path or CWE_TABLE_PATH
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CheckError(f"cannot read {source}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CheckError(f"cannot parse {source}: {exc}") from exc
    body = raw if isinstance(raw, dict) else {}
    titles_raw, families_raw = body.get("cwes"), body.get("bug_types")
    if not isinstance(titles_raw, dict) or not titles_raw:
        raise CheckError(f"{source}: no 'cwes' mapping")
    if not isinstance(families_raw, dict) or not families_raw:
        raise CheckError(f"{source}: no 'bug_types' mapping")
    titles = {int(key): str(value) for key, value in titles_raw.items()}
    families: dict[str, frozenset[int]] = {}
    aliases: dict[str, str] = {}
    for name, entry in families_raw.items():
        if not isinstance(entry, dict):
            raise CheckError(f"{source}: bug type {name} must be a mapping")
        ids = frozenset(int(cwe) for cwe in entry.get("compatible") or ())
        missing = sorted(ids - titles.keys())
        if missing:
            raise CheckError(f"{source}: {name} lists CWEs absent from 'cwes': {missing}")
        family = _slug(str(name))
        families[family] = ids
        aliases[family] = family
        for alias in entry.get("aliases") or ():
            aliases[_slug(str(alias))] = family
    return CweCompat(
        version=str(body.get("version", "unknown")),
        titles=titles,
        families=families,
        aliases=aliases,
    )


@lru_cache(maxsize=1)
def cwe_compat() -> CweCompat:
    """The bundled table, loaded once."""
    return load_cwe_compat()


def cwe_id(text: str) -> int | None:
    """``"CWE-79"``, ``"cwe_79"`` and ``"79"`` all mean 79; anything else is not a CWE."""
    match = _CWE_RE.match(text.strip())
    return int(match.group(1)) if match else None


# --- CVE records (online only) --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CveLookup:
    """One CVE record lookup. ``error`` means we learned nothing, which is never negative."""

    cve_id: str
    url: str
    status: int
    state: str | None = None
    products: tuple[str, ...] = ()
    body_sha256: str | None = None
    error: str | None = None


#: Injected in tests so the offline path can be proven to make no call at all.
CveFetcher = Callable[[str], CveLookup]


def cve_url(year: str, number: str) -> str:
    return f"{CVE_LIST_BASE}{year}/{int(number) // 1000}xxx/CVE-{year}-{number}.json"


def cve_state(data: dict[str, Any]) -> str | None:
    metadata = data.get("cveMetadata")
    state = metadata.get("state") if isinstance(metadata, dict) else None
    return state.upper() if isinstance(state, str) else None


def cve_products(data: dict[str, Any]) -> tuple[str, ...]:
    """Every vendor, product and package name the record names, minus the placeholders."""
    containers = data.get("containers")
    if not isinstance(containers, dict):
        return ()
    # The numbering-authority container, then the enrichment ones.  codespell:ignore cna
    blocks = [containers.get("cna"), *(containers.get("adp") or [])]  # codespell:ignore cna
    found: set[str] = set()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for entry in block.get("affected") or ():
            if not isinstance(entry, dict):
                continue
            for field in ("vendor", "product", "packageName"):
                value = entry.get(field)
                if isinstance(value, str) and value.strip().lower() not in PLACEHOLDER_PRODUCTS:
                    found.add(value.strip())
    return tuple(sorted(found))


def fetch_cve(cve_id: str, *, timeout: float = CVE_TIMEOUT_S) -> CveLookup:
    """GET one CVE 5.x record over HTTPS. Never raises: a failure is reported, not thrown."""
    match = _CVE_RE.match(cve_id)
    if match is None:
        return CveLookup(cve_id=cve_id, url="", status=0, error="not a CVE ID")
    url = cve_url(match.group(1), match.group(2))
    if not url.startswith("https://"):  # pragma: no cover - CVE_LIST_BASE is a constant
        raise CheckError(f"refusing a non-HTTPS CVE URL: {url!r}")
    request = urllib.request.Request(  # noqa: S310 - built from CVE_LIST_BASE, https-only
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body: bytes = response.read(MAX_CVE_BYTES + 1)
            status = int(response.status or HTTP_OK)
    except urllib.error.HTTPError as exc:
        return CveLookup(cve_id=cve_id, url=url, status=int(exc.code))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return CveLookup(cve_id=cve_id, url=url, status=0, error=f"{type(exc).__name__}: {exc}")
    return _read_cve(cve_id, url, status, body)


def _read_cve(cve_id: str, url: str, status: int, body: bytes) -> CveLookup:
    """Turn one fetched body into a lookup; anything unreadable becomes ``error``."""
    if len(body) > MAX_CVE_BYTES:
        return CveLookup(cve_id=cve_id, url=url, status=status, error="record exceeds the size cap")
    digest = sha256(body).hexdigest()
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return CveLookup(cve_id, url, status, body_sha256=digest, error=f"unreadable JSON: {exc}")
    if not isinstance(data, dict):
        return CveLookup(cve_id, url, status, body_sha256=digest, error="not a JSON object")
    return CveLookup(
        cve_id=cve_id,
        url=url,
        status=status,
        state=cve_state(data),
        products=cve_products(data),
        body_sha256=digest,
    )


# --- repository and path helpers -------------------------------------------------------------


def normalize_repo(url: str | None) -> str:
    """``https://GitHub.com/o/r.git/`` -> ``github.com/o/r``; ``""`` when it is not a URL.

    A local repository path has no upstream identity, so it normalizes to ``""`` and the
    foreign-repo comparison is simply not made (a link to the project's own GitHub page
    must never count against a report checked out from disk).
    """
    if not url:
        return ""
    parts = urlsplit(url.strip())
    host = parts.netloc.lower().removeprefix("www.")
    segments = [segment for segment in parts.path.split("/") if segment]
    if parts.scheme not in ("http", "https") or not host or len(segments) < 2:  # noqa: PLR2004
        return ""
    owner, name = segments[0].lower(), segments[1].lower().removesuffix(".git")
    return f"{host}/{owner}/{name}"


def _home_repos(ctx: CheckContext) -> frozenset[str]:
    """The repositories that *are* the target: the resolved one and the known project's."""
    names = {normalize_repo(ctx.repo_url)}
    project = ctx.resolution.project
    if project is not None and project.repo:
        names.add(normalize_repo(project.repo))
    return frozenset(name for name in names if name)


def _project_names(ctx: CheckContext) -> frozenset[str]:
    """Every name this project answers to, lower-cased: aliases, programs and repo names."""
    names: set[str] = set()
    project = ctx.resolution.project
    if project is not None:
        names.add(project.name.lower())
        names.update(alias.lower() for alias in project.aliases)
        names.update(program.lower() for program in project.programs)
    for repo in _home_repos(ctx):
        names.update(repo.split("/")[1:])
    return frozenset(name for name in names if name)


def _claimed_paths(ctx: CheckContext) -> tuple[str, ...]:
    """The files the report points at, as written. Not only the reference claims: "commit
    X touches the file I named" is a statement about the whole report."""
    raw: set[str] = set()
    for claim in ctx.claims:
        if isinstance(claim, PatchClaim):
            raw.update(claim.files)
        elif isinstance(claim, FileClaim | LineClaim) and claim.path:
            raw.add(claim.path)
    return tuple(sorted({path.strip().removeprefix("./") for path in raw if path.strip()}))


def _touched_matches(
    ctx: CheckContext, touched: Sequence[str], claimed: Sequence[str]
) -> list[str]:
    """Which touched paths are files the report claims, allowing the partial paths reports use."""
    hits: set[str] = set()
    for path in claimed:
        candidates = set(ctx.resolve_path(path)) | {path}
        suffix = "/" + path
        hits.update(name for name in touched if name in candidates or name.endswith(suffix))
    return sorted(hits)


def _touched_paths(
    repo: GitRepo, commit: str, record: CommandSink | None = None
) -> tuple[str, ...]:
    """The paths one commit changed (empty for a merge, or when git could not tell us).

    ``record`` collects the log for the evidence; a timeout adds nothing to it, because a
    command that never returned has no exit code or output to record honestly (P6).
    """
    try:
        result = repo.run(
            ["log", "-1", "--format=", "--name-only", "-z", "--end-of-options", safe_rev(commit)],
            timeout=_GIT_TIMEOUT_S,
            record=record,
        )
    except NikashaError:
        return ()  # a timeout tells us nothing about the commit, so we claim nothing (P4)
    if result.returncode != 0:
        return ()
    paths = [part for part in result.stdout.decode("utf-8", "replace").split("\0") if part]
    return tuple(sorted(set(paths))[:MAX_TOUCHED_PATHS])


def _matches_product(names: frozenset[str], products: Sequence[str]) -> list[str]:
    """The record entries that name this project; matching on whole tokens, never substrings."""
    matched: list[str] = []
    for product in products:
        tokens = set(_TOKEN_RE.findall(product.lower()))
        tokens.add(_NON_ALNUM_RE.sub("", product.lower()))
        if tokens & names:
            matched.append(product)
    return matched


@register
class References(BaseCheck):
    id = CHECK_ID
    name = "REFERENCES"
    group = GROUP
    applies_to: frozenset[ClaimKind] = frozenset({"reference", "impact"})
    description = "Checks cited commits, repository links, CVE records and CWE IDs."

    def __init__(
        self, strengths: Strengths | None = None, *, fetch: CveFetcher | None = None
    ) -> None:
        self.strengths = strengths or default_strengths()
        self.fetch = fetch or fetch_cve

    def run(self, ctx: CheckContext, claims: Sequence[Claim]) -> list[Evidence]:
        references = [claim for claim in claims if isinstance(claim, ReferenceClaim)]
        impacts = [claim for claim in claims if isinstance(claim, ImpactClaim)]
        out = self._commits(ctx, references)
        out += self._foreign_repos(ctx, references)
        out += self._cves(ctx, references)
        out += self._cwes(ctx, references, impacts)
        return out

    # --- commits ------------------------------------------------------------------------

    def _commits(self, ctx: CheckContext, references: Sequence[ReferenceClaim]) -> list[Evidence]:
        home = _home_repos(ctx)
        cited = _group(
            (claim.value.lower(), claim)
            for claim in references
            if claim.ref_kind == "commit"
            and _SHA_RE.match(claim.value.lower())
            # A SHA linked to another repository is that repository's business; the
            # foreign-repo finding below covers it, and "missing here" would be noise.
            and (claim.repo_url is None or not home or normalize_repo(claim.repo_url) in home)
        )
        repo = ctx.resolution.repo
        claimed = _claimed_paths(ctx)
        out: list[Evidence] = []
        for sha, group in cited:
            if ctx.expired():
                break
            # One sink per cited SHA: the rev-parse that looked for it, then the log
            # that listed what it touched.
            records: list[CommandRecord] = []
            resolved = repo.rev_parse(sha, record=records)
            if resolved is None:
                out.append(self._commit_missing(ctx, sha, group, records))
                continue
            touched = _touched_paths(repo, resolved, records)
            hits = _touched_matches(ctx, touched, claimed)
            out.append(
                self._commit_found(
                    ctx, sha, resolved, touched=touched, hits=hits, claims=group, commands=records
                )
            )
        return out

    def _commit_missing(
        self,
        ctx: CheckContext,
        sha: str,
        claims: Sequence[ReferenceClaim],
        commands: Sequence[CommandRecord] = (),
    ) -> Evidence:
        """SPEC §10: a SHA we cannot resolve is unresolved, not fabricated.

        ``commands`` carries the failed ``rev-parse``, which is the whole of the finding:
        exit 1 and no output is what "not in this repository" means here.
        """
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="NEUTRAL",
            strength=self.strengths.get(CHECK_ID, "commit_missing"),
            summary=f"commit {sha} is not in {ctx.repo_url}; it may come from a fork",
            details={
                "outcome": "commit_missing",
                "commit": sha,
                "repo": ctx.repo_url,
                "question": (
                    f"We could not find commit {sha} in {ctx.repo_url}. Is it from a fork or a "
                    "mirror? A link to the commit would let us confirm this quickly."
                ),
            },
            commands=commands,
        )

    def _commit_found(
        self,
        ctx: CheckContext,
        sha: str,
        resolved: str,
        *,
        touched: Sequence[str],
        hits: Sequence[str],
        claims: Sequence[ReferenceClaim],
        commands: Sequence[CommandRecord] = (),
    ) -> Evidence:
        key = "commit_touches_file" if hits else "commit_exists"
        details: dict[str, Any] = {
            "outcome": key,
            "commit": resolved,
            "cited": sha,
            "touches": list(touched[:MAX_LISTED]),
            "n_touched": len(touched),
        }
        if hits:
            details["claimed_paths_touched"] = list(hits[:MAX_LISTED])
            summary = f"commit {resolved[:12]} exists and touches {', '.join(hits[:3])}"
        else:
            summary = f"commit {resolved[:12]} exists in {ctx.repo_url}"
        located = [path for path in hits if path in ctx.path_set][:1]
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="SUPPORTS",
            strength=self.strengths.get(CHECK_ID, key),
            summary=summary,
            details=details,
            locations=[ctx.location(path, 1) for path in located],
            commands=commands,
        )

    # --- repository links ---------------------------------------------------------------

    def _foreign_repos(
        self, ctx: CheckContext, references: Sequence[ReferenceClaim]
    ) -> list[Evidence]:
        home = _home_repos(ctx)
        if not home:
            return []  # a local repository has no upstream identity to compare against
        names = _project_names(ctx)
        foreign = _group(
            (repo, claim)
            for claim in references
            if (repo := normalize_repo(claim.repo_url))
            and repo not in home
            # A mirror or a rename under the same project name is not a different project.
            and repo.rsplit("/", 1)[-1] not in names
        )
        return [
            make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "foreign_repo"),
                summary=f"the reference points at {repo}, not at {sorted(home)[0]}",
                details={
                    "outcome": "foreign_repo",
                    "repo": repo,
                    "expected": sorted(home),
                    "reference_kinds": sorted({claim.ref_kind for claim in claims}),
                },
            )
            for repo, claims in foreign
        ]

    # --- CVE records --------------------------------------------------------------------

    def _cves(self, ctx: CheckContext, references: Sequence[ReferenceClaim]) -> list[Evidence]:
        cited = _group(
            (claim.value.upper(), claim)
            for claim in references
            if claim.ref_kind == "cve" and _CVE_RE.match(claim.value)
        )
        out: list[Evidence] = []
        for cve, claims in cited:
            if ctx.expired():
                break
            if not ctx.online:
                out.append(self._cve_offline(cve, claims))
                continue
            out.append(self._cve_evidence(ctx, cve, claims, self.fetch(cve)))
        return out

    def _cve_offline(self, cve: str, claims: Sequence[ReferenceClaim]) -> Evidence:
        """P3: nothing is fetched without ``--online``, so nothing is claimed either."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="NEUTRAL",
            strength=0.0,
            summary=f"{cve} was not checked: CVE records are only fetched with --online",
            details={"cve": cve, "outcome": "offline"},
        )

    def _cve_evidence(
        self,
        ctx: CheckContext,
        cve: str,
        claims: Sequence[ReferenceClaim],
        lookup: CveLookup,
    ) -> Evidence:
        details: dict[str, Any] = {"cve": cve, "url": lookup.url, "http_status": lookup.status}
        if lookup.body_sha256 is not None:
            details["response_sha256"] = lookup.body_sha256
        unusable = self._cve_unusable(cve, claims, lookup, details)
        if unusable is not None:
            return unusable
        if lookup.state == "REJECTED":
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "cve_rejected"),
                summary=f"{cve} is a REJECTED record",
                details={**details, "outcome": "cve_rejected", "state": lookup.state},
            )
        return self._cve_product(ctx, cve, claims, lookup, details)

    def _cve_unusable(
        self,
        cve: str,
        claims: Sequence[ReferenceClaim],
        lookup: CveLookup,
        details: dict[str, Any],
    ) -> Evidence | None:
        """Everything that means "we could not read the record": never a refutation (P4)."""
        if lookup.error is not None:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{cve} could not be fetched ({lookup.error})",
                details={**details, "outcome": "fetch_failed", "error": lookup.error},
            )
        if lookup.status == HTTP_NOT_FOUND:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="REFUTES",
                strength=self.strengths.get(CHECK_ID, "cve_not_found"),
                summary=f"{cve} has no record in the CVE list",
                details={**details, "outcome": "cve_not_found"},
            )
        if lookup.status != HTTP_OK:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{cve} could not be read (HTTP {lookup.status})",
                details={**details, "outcome": "unexpected_status"},
            )
        return None

    def _cve_product(
        self,
        ctx: CheckContext,
        cve: str,
        claims: Sequence[ReferenceClaim],
        lookup: CveLookup,
        details: dict[str, Any],
    ) -> Evidence:
        listed = list(lookup.products)
        if not listed:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="NEUTRAL",
                strength=0.0,
                summary=f"{cve} exists but names no product we can compare",
                details={**details, "outcome": "no_product", "state": lookup.state},
            )
        matched = _matches_product(_project_names(ctx), listed)
        details = {**details, "products": listed[:MAX_LISTED], "n_products": len(listed)}
        if matched:
            return make_evidence(
                check_id=CHECK_ID,
                group=GROUP,
                claims=claims,
                outcome="SUPPORTS",
                strength=self.strengths.get(CHECK_ID, "cve_matches_product"),
                summary=f"{cve} is recorded against {matched[0]}",
                details={**details, "outcome": "cve_matches_product", "matched": matched[:3]},
            )
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "cve_other_product"),
            summary=f"{cve} is recorded against {listed[0]}, not this project",
            details={**details, "outcome": "cve_other_product"},
        )

    # --- CWE IDs ------------------------------------------------------------------------

    def _cwes(
        self,
        ctx: CheckContext,
        references: Sequence[ReferenceClaim],
        impacts: Sequence[ImpactClaim],
    ) -> list[Evidence]:
        table = cwe_compat()
        cited: list[tuple[int, ClaimBase]] = []
        for reference in references:
            if reference.ref_kind == "cwe" and (found := cwe_id(reference.value)) is not None:
                cited.append((found, reference))
        for impact in impacts:
            if impact.cwe and (found := cwe_id(impact.cwe)) is not None:
                cited.append((found, impact))
        if not cited:
            return []
        bugs = _bug_families(ctx, table)
        families = sorted({family for family, _ in bugs})
        reported = sorted({raw for _, raw in bugs})
        return [
            self._cwe_evidence(table, cwe, claims, families, reported)
            for cwe, claims in _group(cited)
        ]

    def _cwe_evidence(
        self,
        table: CweCompat,
        cwe: int,
        claims: Sequence[ClaimBase],
        families: Sequence[str],
        reported: Sequence[str],
    ) -> Evidence:
        details: dict[str, Any] = {"cwe": f"CWE-{cwe}", "table_version": table.version}
        if not families:
            return self._cwe_neutral(
                claims,
                f"CWE-{cwe} was not compared: the report shows no known bug type",
                {**details, "outcome": "no_bug_type"},
            )
        details |= {"bug_types": list(reported), "bug_families": list(families)}
        if not table.knows(cwe):
            return self._cwe_neutral(
                claims,
                f"CWE-{cwe} is not in the bundled compatibility table",
                {**details, "outcome": "unknown_cwe"},
            )
        title = table.titles[cwe]
        details["cwe_title"] = title
        if any(table.compatible(family, cwe) for family in families):
            return self._cwe_neutral(
                claims,
                f"CWE-{cwe} ({title}) fits the reported {reported[0]}",
                {**details, "outcome": "compatible"},
            )
        expected = sorted({f"CWE-{i}" for family in families for i in table.expected(family)})
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="REFUTES",
            strength=self.strengths.get(CHECK_ID, "cwe_incompatible"),
            summary=f"CWE-{cwe} ({title}) does not describe a {reported[0]}",
            details={
                **details,
                "outcome": "cwe_incompatible",
                "compatible": expected[:MAX_LISTED],
            },
        )

    def _cwe_neutral(
        self, claims: Sequence[ClaimBase], summary: str, details: dict[str, Any]
    ) -> Evidence:
        """Unknown, or simply consistent: either way the report is not judged on it (P4)."""
        return make_evidence(
            check_id=CHECK_ID,
            group=GROUP,
            claims=claims,
            outcome="NEUTRAL",
            strength=0.0,
            summary=summary,
            details=details,
        )


def _bug_families(ctx: CheckContext, table: CweCompat) -> tuple[tuple[str, str], ...]:
    """``(family, bug_type as the trace wrote it)`` for every trace the table recognises."""
    found: set[tuple[str, str]] = set()
    for claim in ctx.claims:
        if isinstance(claim, TraceClaim) and claim.bug_type:
            family = table.family(claim.bug_type)
            if family is not None:
                found.add((family, claim.bug_type))
    return tuple(sorted(found))
