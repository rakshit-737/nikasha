# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Known projects (SPEC §10, §11.5), loaded from ``nikasha/data/known_projects.yaml``.

The file ships inside the package (so an installed tool can read it). A project's own
``nikasha.toml`` can add or override entries (M7). ``yaml.safe_load`` only: the file is data.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Literal

import yaml

from nikasha.errors import NikashaError

GeneratedKind = Literal["amalgamation", "generated", "release_artifact"]
_KINDS = frozenset({"amalgamation", "generated", "release_artifact"})


@dataclass(frozen=True, slots=True)
class GeneratedEntry:
    path_glob: str
    kind: GeneratedKind
    source_markers: str | None = None
    artifact_url_template: str | None = None


@dataclass(frozen=True, slots=True)
class KnownProject:
    name: str
    aliases: tuple[str, ...]
    repo: str | None
    tag_families: tuple[str, ...]
    programs: tuple[str, ...] = ()
    constant_prefixes: tuple[str, ...] = ()
    recipe: str | None = None
    generated: tuple[GeneratedEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class KnownProjects:
    projects: tuple[KnownProject, ...]
    generic_generated: tuple[GeneratedEntry, ...]

    def by_alias(self, alias: str) -> KnownProject | None:
        low = alias.strip().lower()
        for project in self.projects:
            if low == project.name.lower() or low in (a.lower() for a in project.aliases):
                return project
        return None

    def by_repo(self, url: str) -> KnownProject | None:
        norm = _normalize_url(url)
        for project in self.projects:
            if project.repo and _normalize_url(project.repo) == norm:
                return project
        return None


def _normalize_url(url: str) -> str:
    return url.strip().lower().removesuffix("/").removesuffix(".git").split("://", 1)[-1]


def _entries(raw: object, where: str) -> tuple[GeneratedEntry, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise NikashaError(f"{where}: generated must be a list")
    out: list[GeneratedEntry] = []
    for item in raw:
        if not isinstance(item, dict) or "path_glob" not in item:
            raise NikashaError(f"{where}: each generated entry needs path_glob")
        kind = str(item.get("kind", "generated"))
        if kind not in _KINDS:
            raise NikashaError(f"{where}: unknown generated kind {kind!r}")
        out.append(
            GeneratedEntry(
                path_glob=str(item["path_glob"]),
                kind=kind,  # type: ignore[arg-type]
                source_markers=item.get("source_markers"),
                artifact_url_template=item.get("artifact_url_template"),
            )
        )
    return tuple(out)


def _strings(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise NikashaError("expected a list of strings")
    return tuple(str(x) for x in raw)


def parse_known_projects(text: str) -> KnownProjects:
    """Parse and validate the YAML document."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise NikashaError(f"known_projects: invalid YAML ({exc.__class__.__name__})") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise NikashaError("known_projects: expected a mapping with version: 1")
    projects: list[KnownProject] = []
    for raw in data.get("projects") or []:
        if not isinstance(raw, dict) or not raw.get("name"):
            raise NikashaError("known_projects: every project needs a name")
        name = str(raw["name"])
        projects.append(
            KnownProject(
                name=name,
                aliases=_strings(raw.get("aliases")) or (name,),
                repo=raw.get("repo"),
                tag_families=_strings(raw.get("tag_families")),
                programs=_strings(raw.get("programs")),
                constant_prefixes=_strings(raw.get("constant_prefixes")),
                recipe=raw.get("recipe"),
                generated=_entries(raw.get("generated"), name),
            )
        )
    return KnownProjects(tuple(projects), _entries(data.get("generic_generated"), "generic"))


@cache
def load_known_projects() -> KnownProjects:
    """The built-in table (cached)."""
    text = resources.files("nikasha.data").joinpath("known_projects.yaml").read_text("utf-8")
    return parse_known_projects(text)
