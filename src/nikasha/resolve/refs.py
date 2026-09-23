# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Tag parsing, release ordering and version matching (SPEC §10, Appendix C).

A tag splits into a *family* (its alphabetic prefix, normalized: ``curl-8_5_0`` → ``curl``,
``OpenSSL_1_1_1w`` → ``openssl``, ``v2.4.58`` → ``v``), a numeric tuple (separated by ``.`` or
``_`` consistently) and a qualifier. Qualifier ranks order releases:
``dev < alpha < beta ≈ pre < rc < final < post`` (OpenSSL's letter releases such as
``1.1.1w`` are *post* releases of ``1.1.1``).

Tags that are not releases are ignored: dates (``nightly-2026-01-01``), branch-like names
(``stable/1.9.x``), CVE markers, and anything with an unrecognized qualifier
(``3.0-POST-CLANG-FORMAT-WEBKIT``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from nikasha.code.gitio import TagRef
from nikasha.model.claims import VersionSpec

QualifierKind = Literal["dev", "alpha", "beta", "pre", "rc", "final", "post"]

QUALIFIER_RANK: dict[QualifierKind, int] = {
    "dev": 0,
    "alpha": 1,
    "beta": 2,
    "pre": 2,
    "rc": 3,
    "final": 4,
    "post": 5,
}
_WORD_QUALIFIERS: dict[str, QualifierKind] = {
    "dev": "dev",
    "snapshot": "dev",
    "alpha": "alpha",
    "a": "alpha",
    "beta": "beta",
    "b": "beta",
    "pre": "pre",
    "preview": "pre",
    "rc": "rc",
    "cr": "rc",
    "candidate": "rc",
    "post": "post",
    "p": "post",
    "pl": "post",
    "patch": "post",
}
#: Tag families that are never releases.
IGNORED_FAMILIES = frozenset(
    {"cve", "stable", "nightly", "snapshot", "test", "tmp", "backup", "cvs", "svn", "branch", "wip"}
)

_TAG_RE = re.compile(
    r"^(?P<prefix>[A-Za-z][A-Za-z0-9+]{0,40}+(?:[-_ ][A-Za-z][A-Za-z0-9+]{0,40}+){0,4}+)?"
    r"[-_ /]?(?P<v>[vV])?"
    r"(?P<nums>\d{1,6}(?:(?P<sep>[._])\d{1,6}(?:(?P=sep)\d{1,6}){0,4})?)"
    r"(?P<rest>.{0,60})$"
)
_QUAL_TOKEN_RE = re.compile(r"[a-z]+|\d+")
_MIN_YEAR, _MAX_YEAR = 1970, 2100


@dataclass(frozen=True, slots=True, order=False)
class ParsedTag:
    raw: str
    family: str
    numbers: tuple[int, ...]
    kind: QualifierKind = "final"
    qual_num: int = 0
    qual_letter: str = ""

    @property
    def trimmed(self) -> tuple[int, ...]:
        """Numbers without trailing zeros, so ``8.5`` equals ``8.5.0`` (SPEC §10)."""
        nums = list(self.numbers)
        while len(nums) > 1 and nums[-1] == 0:
            nums.pop()
        return tuple(nums)

    @property
    def is_prerelease(self) -> bool:
        return QUALIFIER_RANK[self.kind] < QUALIFIER_RANK["final"]

    @property
    def sort_key(self) -> tuple[tuple[int, ...], int, int, str, str]:
        """A total order: version, qualifier rank, qualifier number and letter, raw name."""
        return (self.trimmed, QUALIFIER_RANK[self.kind], self.qual_num, self.qual_letter, self.raw)


def _normalize_family(prefix: str | None, has_v: bool) -> str:
    family = re.sub(r"[^a-z0-9+]", "", (prefix or "").lower())
    if not family and has_v:
        return "v"
    return family


def _parse_qualifier(rest: str) -> tuple[QualifierKind, int, str] | None:  # noqa: PLR0911
    """Interpret what follows the numbers; ``None`` means "not a release tag"."""
    text = rest.lower().strip("-_. ")
    if not text:
        return "final", 0, ""
    tokens = _QUAL_TOKEN_RE.findall(text)
    if not tokens or "".join(tokens) != re.sub(r"[-_. ]", "", text):
        return None
    head = tokens[0]
    if head.isalpha() and len(head) == 1 and len(tokens) == 1 and head not in ("a", "b", "p"):
        return "post", 0, head  # OpenSSL-style letter release: 1.1.1w
    if head.isalpha() and len(head) == 1 and head in ("a", "b") and len(tokens) == 1:
        return "post", 0, head  # 1.0.1a, 1.0.2b (letters without a number are post releases)
    kind = _WORD_QUALIFIERS.get(head)
    if kind is None:
        return None
    number = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 0
    # Allow a trailing "candidate" after rcN (httpd: 2.4.53-rc2-candidate); nothing else.
    extra = tokens[2:] if len(tokens) > 1 and tokens[1].isdigit() else tokens[1:]
    if any(tok not in ("candidate",) for tok in extra):
        return None
    return kind, number, ""


def parse_tag(name: str) -> ParsedTag | None:
    """Parse a tag name, or return ``None`` when it is not a release tag."""
    m = _TAG_RE.match(name.strip())
    if m is None:
        return None
    family = _normalize_family(m.group("prefix"), bool(m.group("v")))
    if family in IGNORED_FAMILIES or "/" in name:
        return None
    numbers = tuple(int(n) for n in re.split(r"[._]", m.group("nums")))
    qualifier = _parse_qualifier(m.group("rest"))
    if qualifier is None:
        return None
    kind, qual_num, letter = qualifier
    # Handle "candidate-2.4.52-rc1": the prefix itself is a qualifier word.
    if family == "candidate":
        family, kind = "", "rc" if kind == "final" else kind
    if _MIN_YEAR <= numbers[0] <= _MAX_YEAR and len(numbers) >= 3 and m.group("sep") != ".":  # noqa: PLR2004
        return None  # a date, not a version
    return ParsedTag(name, family, numbers, kind, qual_num, letter)


def spec_to_key(spec: VersionSpec) -> tuple[tuple[int, ...], QualifierKind, int, str]:
    """Interpret a claimed version's qualifier the same way tags are interpreted."""
    parsed = _parse_qualifier(spec.qualifier or "") or ("final", 0, "")
    nums = list(spec.numbers)
    while len(nums) > 1 and nums[-1] == 0:
        nums.pop()
    return tuple(nums), parsed[0], parsed[1], parsed[2]


@dataclass(frozen=True, slots=True)
class Release:
    tag: ParsedTag
    commit: str
    epoch: int

    @property
    def name(self) -> str:
        return self.tag.raw


#: Family tie-break order after the project's own pattern and product name (SPEC §10).
_GENERIC_FAMILY_ORDER = ("v", "version", "release", "")
#: A family joins the main line if at most this share of its versions collide with it.
_MAX_OVERLAP = 0.2


def main_line_families(releases: Sequence[Release]) -> frozenset[str]:
    """Guess the families of the project's main release line when none is configured.

    Start from the family with the most final releases; add each other family whose final
    versions mostly do *not* already exist on the line. That merges a renamed tag scheme
    (libxml2: ``LIBXML_2_4_2`` then ``v2.12.5``) but excludes a parallel product line that
    reuses the same numbers (curl's ``tiny-curl-8_4_0``). A family that extends the primary
    family's name (``OpenSSL-fips`` for ``openssl``) is a variant line and never joins.
    Anything subtler belongs in ``known_projects.yaml``.
    """
    by_family: dict[str, set[tuple[int, ...]]] = {}
    for r in releases:
        if not r.tag.is_prerelease:
            by_family.setdefault(r.tag.family, set()).add(r.tag.trimmed)
    if not by_family:
        return frozenset()
    ordered = sorted(by_family, key=lambda f: (-len(by_family[f]), f))
    primary = ordered[0]
    main = {primary}
    covered = set(by_family[primary])
    for family in ordered[1:]:
        versions = by_family[family]
        variant = primary not in _GENERIC_FAMILY_ORDER and primary in family
        if not variant and len(versions & covered) <= _MAX_OVERLAP * len(versions):
            main.add(family)
            covered |= versions
    return frozenset(main)


@dataclass
class ReleaseList:
    """Every release tag of a repository in version order (pre-releases included, flagged)."""

    releases: list[Release]
    ignored: list[str] = field(default_factory=list)
    #: Families forming the project's main release line (see :func:`main_line_families`).
    main_families: frozenset[str] = frozenset()

    @classmethod
    def from_tags(
        cls, tags: Iterable[TagRef], *, families: Sequence[str] | None = None
    ) -> ReleaseList:
        """Build from ``tags``. When ``families`` is given (from ``known_projects.yaml``),
        only those tag families count as releases."""
        releases: list[Release] = []
        ignored: list[str] = []
        for tag in tags:
            parsed = parse_tag(tag.name)
            if parsed is None or (families is not None and parsed.family not in families):
                ignored.append(tag.name)
                continue
            releases.append(Release(parsed, tag.commit, tag.epoch))
        releases.sort(key=lambda r: r.tag.sort_key)
        main = frozenset(families) if families is not None else main_line_families(releases)
        return cls(releases, sorted(ignored), main)

    def finals(self) -> list[Release]:
        """Final releases on the main line, in version order."""
        return [
            r
            for r in self.releases
            if not r.tag.is_prerelease
            and (not self.main_families or r.tag.family in self.main_families)
        ]

    def family_rank(self, family: str, *, preferred: Sequence[str] = ()) -> int:
        order = [*preferred, *_GENERIC_FAMILY_ORDER]
        return order.index(family) if family in order else len(order)

    def match(self, spec: VersionSpec, *, preferred_families: Sequence[str] = ()) -> list[Release]:
        """Releases matching ``spec`` (trailing zeros ignored), best family first.

        Pre-releases only match when the claim names a qualifier.
        """
        nums, kind, qual_num, letter = spec_to_key(spec)
        found = [
            r
            for r in self.releases
            if r.tag.trimmed == nums
            and r.tag.kind == kind
            and (kind == "final" or r.tag.qual_num == qual_num)
            and r.tag.qual_letter == letter
        ]
        return sorted(
            found,
            key=lambda r: (self.family_rank(r.tag.family, preferred=preferred_families), r.tag.raw),
        )

    def latest_before(self, epoch: int) -> Release | None:
        """The highest final release tagged at or before ``epoch``."""
        candidates = [r for r in self.finals() if r.epoch <= epoch]
        return max(candidates, key=lambda r: r.tag.sort_key) if candidates else None

    def neighbours(self, spec: VersionSpec) -> tuple[Release | None, Release | None]:
        """The closest final releases below and above ``spec``."""
        nums = spec_to_key(spec)[0]
        below = [r for r in self.finals() if r.tag.trimmed < nums]
        above = [r for r in self.finals() if r.tag.trimmed > nums]
        return (below[-1] if below else None, above[0] if above else None)

    def window(self, release: Release, radius: int) -> list[Release]:
        """``radius`` final releases either side of ``release`` (SPEC §12 C10)."""
        finals = self.finals()
        try:
            i = next(k for k, r in enumerate(finals) if r.tag.raw == release.tag.raw)
        except StopIteration:
            return []
        return finals[max(0, i - radius) : i + radius + 1]
