# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Bench manifests: IDs, URLs and labels only (SPEC §17.2).

A manifest never carries report text. ``extra="forbid"`` makes a stray ``text:`` or
``body:`` key a load error rather than a quiet leak into the repository. Local fixtures are
named by a repository-relative ``path``; remote sources by an ``https`` URL whose content is
fetched at runtime into a gitignored cache (not in this module, and never before the
source's terms have been checked, ADR 0003).
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from nikasha.errors import NikashaError

#: Where the committed manifests live, relative to the repository root.
MANIFEST_DIR = Path("bench") / "manifests"

Label = Literal["genuine", "fabricated", "insufficient"]
Expected = Literal["REPRODUCED", "GROUNDED", "MIXED", "UNGROUNDED", "INSUFFICIENT"]
Split = Literal["real", "synthetic"]

#: Manifest sources and the split each one belongs to (S5 and S6 are synthetic/hermetic).
SOURCES: dict[str, Split] = {
    "S1": "real",
    "S2": "real",
    "S3": "real",
    "S4": "real",
    "S5": "synthetic",
    "S6": "synthetic",
}

_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,79}")
_URL = re.compile(r"https://[A-Za-z0-9.-]{1,253}(?:/[^\s]{0,2000})?")
NOTES_MAX = 200
_MUTATION = re.compile(r"M[1-7]")


class ManifestError(NikashaError):
    """A manifest is malformed or refers to something it must not."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Entry(_Frozen):
    """One labelled report. Exactly one of ``path`` (local fixture) or ``url`` is set."""

    id: str
    label: Label
    expected: Expected | None = None
    path: str | None = None
    url: str | None = None
    repo: str | None = None
    version: str | None = None
    #: Optional ``bench run --repro`` inputs: a repository-relative PoC file or directory and
    #: the recipe id to build with. Both are needed (with ``version``) for a case to join
    #: the repro subset; without them the case runs the static checks only.
    poc: str | None = None
    recipe: str | None = None
    notes: str = ""

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError(f"bad entry id {value!r}")
        return value

    @field_validator("path", "poc")
    @classmethod
    def _check_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        pure = PurePosixPath(value)
        if not value.strip() or not pure.parts or pure.parts == (".",):
            raise ValueError("path must name a file, not be empty or '.'")
        if pure.is_absolute() or ".." in pure.parts or "\\" in value or ":" in value:
            raise ValueError(f"path must be repository-relative without '..': {value!r}")
        return value

    @field_validator("notes")
    @classmethod
    def _check_notes(cls, value: str) -> str:
        # A short single-line label note, never a place to paste report text.
        if len(value) > NOTES_MAX or "\n" in value or "\r" in value:
            raise ValueError(f"notes must be one line of at most {NOTES_MAX} characters")
        return value

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str | None) -> str | None:
        if value is not None and not _URL.fullmatch(value):
            raise ValueError(f"url must be https: {value!r}")
        return value

    @field_validator("recipe")
    @classmethod
    def _check_recipe(cls, value: str | None) -> str | None:
        if value is not None and not _ID.fullmatch(value):
            raise ValueError(f"bad recipe id {value!r}")
        return value

    @model_validator(mode="after")
    def _one_locator(self) -> Entry:
        if (self.path is None) == (self.url is None):
            raise ValueError(f"{self.id}: set exactly one of 'path' or 'url'")
        if (self.poc is None) != (self.recipe is None):
            raise ValueError(f"{self.id}: 'poc' and 'recipe' go together")
        if self.poc is not None and self.version is None:
            raise ValueError(f"{self.id}: a 'poc' needs the 'version' to build")
        return self


class Exclusion(_Frozen):
    """A source item deliberately left out, with a one-line reason (SPEC §17.2).

    For example a REJECTED CVE record whose content has been blanked: the spec says to
    exclude it and document the exclusion, so the manifest records the ID and why.
    """

    id: str
    reason: str

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError(f"bad excluded id {value!r}")
        return value

    @field_validator("reason")
    @classmethod
    def _check_reason(cls, value: str) -> str:
        if not value.strip() or len(value) > NOTES_MAX or "\n" in value or "\r" in value:
            raise ValueError(f"reason must be one non-empty line of at most {NOTES_MAX} chars")
        return value


class Generator(_Frozen):
    """S5 only: which S6 entries to mutate, with which mutations and seeds."""

    bases: tuple[str, ...]
    mutations: tuple[str, ...]
    seeds: tuple[int, ...] = Field(min_length=1)

    @field_validator("mutations")
    @classmethod
    def _check_mutations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        bad = [m for m in value if not _MUTATION.fullmatch(m)]
        if bad:
            raise ValueError(f"unknown mutations {bad}")
        return value


class Manifest(_Frozen):
    """A whole source: its entries, or (S5) the generator that derives them."""

    source: str
    title: str
    terms_checked: bool = False
    entries: tuple[Entry, ...] = ()
    #: Source items left out on purpose, each with its reason (never counted as cases).
    excluded: tuple[Exclusion, ...] = ()
    generator: Generator | None = None

    @field_validator("source")
    @classmethod
    def _check_source(cls, value: str) -> str:
        if value not in SOURCES:
            raise ValueError(f"unknown source {value!r}")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Manifest:
        ids = [e.id for e in self.entries] + [x.id for x in self.excluded]
        if len(ids) != len(set(ids)):
            raise ValueError(f"{self.source}: duplicate entry or excluded ids")
        remote = [e.id for e in self.entries if e.url is not None]
        if remote and not self.terms_checked:
            raise ValueError(
                f"{self.source}: remote entries {remote[:3]} need terms_checked: true first"
            )
        return self

    @property
    def split(self) -> Split:
        return SOURCES[self.source]


def load_manifest(path: Path) -> Manifest:
    """Parse and validate one manifest file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError(f"{path}: a manifest is a mapping")
    try:
        return Manifest.model_validate(data)
    except ValueError as exc:
        raise ManifestError(f"{path}: {exc}") from exc


def load_manifests(directory: Path) -> tuple[Manifest, ...]:
    """Every ``*.yaml`` manifest in ``directory``, ordered by source."""
    if not directory.is_dir():
        raise ManifestError(f"no manifest directory at {directory}")
    manifests = [load_manifest(p) for p in sorted(directory.glob("*.yaml"))]
    sources = [m.source for m in manifests]
    if len(sources) != len(set(sources)):
        raise ManifestError(f"{directory}: two manifests claim the same source")
    return tuple(sorted(manifests, key=lambda m: m.source))


def for_split(manifests: tuple[Manifest, ...], split: str) -> tuple[Manifest, ...]:
    """The manifests in ``split`` (``real``, ``synthetic`` or ``all``)."""
    if split not in ("real", "synthetic", "all"):
        raise ManifestError(f"unknown split {split!r}; use real, synthetic or all")
    return tuple(m for m in manifests if split in ("all", m.split))
