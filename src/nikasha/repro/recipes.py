# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Reproduction recipes (SPEC §13.2): how to build a project and run a PoC against it.

A recipe is YAML validated against ``schema/recipe-v1.json``. The schema is the published
contract; the pydantic models below enforce the same shape (a unit test keeps the two in
step) plus the rules a JSON schema cannot say: output basenames are unique, placeholders
are only ``{args}`` (a whole argument) and ``{file}``, and no path escapes its root.
No JSON-schema library is needed.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from nikasha.errors import NikashaError
from nikasha.model.base import Model

SCHEMA_VERSION = 1
MAX_RECIPE_BYTES = 64 * 1024

#: Placeholders a run command may use.
ARGS_PLACEHOLDER = "{args}"
FILE_PLACEHOLDER = "{file}"

_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./+@")
_SIZE_RE = re.compile(r"[0-9]{1,15}[kmgKMG]?")

Identifier = Annotated[str, Field(min_length=1, max_length=64)]


class RecipeError(NikashaError):
    """A recipe is missing, unreadable or invalid."""


def _check_id(value: str) -> str:
    if not set(value) <= _ID_CHARS or value[0] in "-_":
        raise ValueError(f"{value!r} must be lowercase letters, digits, '-' or '_'")
    return value


def _check_rel_path(value: str) -> str:
    """A relative POSIX path with no ``..``, no absolute root and a small alphabet."""
    if not value or not set(value) <= _PATH_CHARS or value.startswith(("/", "-")):
        raise ValueError(f"unsafe path {value!r}")
    if ".." in PurePosixPath(value).parts:
        raise ValueError(f"unsafe path {value!r}")
    return value


def _check_size(value: str) -> str:
    if _SIZE_RE.fullmatch(value) is None:
        raise ValueError(f"invalid size {value!r} (e.g. 2g, 256m)")
    return value


def _check_env(env: dict[str, str]) -> dict[str, str]:
    for key, value in env.items():
        if not key or not (key[0].isalpha() or key[0] == "_"):
            raise ValueError(f"invalid environment variable name {key!r}")
        if not all(c.isalnum() or c == "_" for c in key) or "\0" in value:
            raise ValueError(f"invalid environment variable {key!r}")
    return env


class RecipeMatch(Model):
    products: tuple[Identifier, ...] = Field(min_length=1)
    tag_pattern: str = Field(min_length=1, max_length=128)


class RecipeImage(Model):
    dockerfile: str
    tag: str = Field(min_length=1, max_length=128)

    @field_validator("dockerfile")
    @classmethod
    def _dockerfile(cls, value: str) -> str:
        _check_rel_path(value)
        if not value.startswith("docker/recipes/") or not value.endswith(".Dockerfile"):
            raise ValueError("dockerfile must be docker/recipes/<name>.Dockerfile")
        return value

    @field_validator("tag")
    @classmethod
    def _tag(cls, value: str) -> str:
        if value.startswith("-") or any(c.isspace() for c in value):
            raise ValueError(f"invalid image tag {value!r}")
        return value


class RecipeBuild(Model):
    env: dict[str, str] = Field(default_factory=dict)
    steps: tuple[Annotated[str, Field(min_length=1, max_length=4096)], ...] = Field(min_length=1)
    outputs: tuple[str, ...] = Field(min_length=1)
    timeout_s: int = Field(default=600, ge=1, le=6 * 3600)
    work_size: str = "2g"

    @field_validator("env")
    @classmethod
    def _env_ok(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_env(value)

    @field_validator("work_size")
    @classmethod
    def _size_ok(cls, value: str) -> str:
        return _check_size(value)

    @field_validator("outputs")
    @classmethod
    def _outputs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        names = [PurePosixPath(_check_rel_path(v)).name for v in value]
        if len(set(names)) != len(names):
            raise ValueError("outputs must have unique basenames (each lands at /build/<name>)")
        return value


class RunKind(Model):
    compile: tuple[str, ...] | None = None
    cmd: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _placeholders(self) -> RunKind:
        for part in (*(self.compile or ()), *self.cmd):
            if ARGS_PLACEHOLDER in part and part != ARGS_PLACEHOLDER:
                raise ValueError("{args} must be a whole argument")
            rest = part.replace(ARGS_PLACEHOLDER, "").replace(FILE_PLACEHOLDER, "")
            if "{" in rest or "}" in rest:
                raise ValueError(f"unknown placeholder in {part!r}")
        return self


class RecipeRun(Model):
    kinds: dict[Identifier, RunKind] = Field(min_length=1)
    env: dict[str, str] = Field(default_factory=dict)
    timeout_s: int = Field(default=30, ge=1, le=3600)

    @field_validator("env")
    @classmethod
    def _env_ok(cls, value: dict[str, str]) -> dict[str, str]:
        return _check_env(value)

    @field_validator("kinds")
    @classmethod
    def _kinds(cls, value: dict[str, RunKind]) -> dict[str, RunKind]:
        for name in value:
            _check_id(name)
        return value


class RecipeLimits(Model):
    cpus: float = Field(default=2, gt=0, le=64)
    memory: str = "2g"
    pids: int = Field(default=256, ge=16, le=4096)
    output_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)

    @field_validator("memory")
    @classmethod
    def _size_ok(cls, value: str) -> str:
        return _check_size(value)


class Recipe(Model):
    id: Identifier
    title: str = Field(min_length=1, max_length=200)
    match: RecipeMatch
    image: RecipeImage
    build: RecipeBuild
    run: RecipeRun
    limits: RecipeLimits = RecipeLimits()

    @field_validator("id")
    @classmethod
    def _id_ok(cls, value: str) -> str:
        return _check_id(value)


@dataclass(frozen=True, slots=True)
class LoadedRecipe:
    """A validated recipe plus where it came from and the hash that keys its build cache."""

    recipe: Recipe
    path: Path
    sha256: str

    @property
    def root(self) -> Path:
        """The checkout root the recipe's ``dockerfile`` path is relative to."""
        return self.path.resolve().parent.parent

    @property
    def dockerfile(self) -> Path:
        return self.root / self.recipe.image.dockerfile


def _format_error(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:5]:
        where = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"{where}: {err['msg']}")
    return "; ".join(parts)


def parse_recipe(data: bytes, *, source: str = "<recipe>") -> Recipe:
    """Validate recipe YAML bytes; raise :class:`RecipeError` with a readable message."""
    if len(data) > MAX_RECIPE_BYTES:
        raise RecipeError(f"{source}: recipe is larger than {MAX_RECIPE_BYTES} bytes")
    try:
        raw: Any = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RecipeError(f"{source}: not valid UTF-8 YAML ({type(exc).__name__})") from exc
    if not isinstance(raw, dict):
        raise RecipeError(f"{source}: a recipe is a YAML mapping")
    try:
        return Recipe.model_validate(raw)
    except ValidationError as exc:
        raise RecipeError(f"{source}: {_format_error(exc)}") from exc


def load_recipe(path: Path) -> LoadedRecipe:
    """Read and validate one recipe file."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RecipeError(f"cannot read recipe {path.name}: {type(exc).__name__}") from exc
    recipe = parse_recipe(data, source=path.name)
    if recipe.id != path.stem:
        raise RecipeError(f"{path.name}: id {recipe.id!r} must match the file name")
    return LoadedRecipe(recipe, path, hashlib.sha256(data).hexdigest())


def default_recipes_dir() -> Path:
    """``recipes/`` of the checkout this package runs from."""
    return Path(__file__).resolve().parents[3] / "recipes"


def list_recipes(recipes_dir: Path | None = None) -> list[Path]:
    """Every ``*.yaml`` in the recipes directory, sorted by name."""
    root = recipes_dir or default_recipes_dir()
    if not root.is_dir():
        raise RecipeError(f"no recipes directory at {root.name!r}")
    return sorted(root.glob("*.yaml"))


def find_recipe(name: str, recipes_dir: Path | None = None) -> LoadedRecipe:
    """Resolve ``--recipe``: a path to a ``.yaml`` file, or a recipe id."""
    if name.endswith((".yaml", ".yml")):
        return load_recipe(Path(name))
    try:
        _check_id(name)
    except ValueError as exc:
        raise RecipeError(str(exc)) from exc
    path = (recipes_dir or default_recipes_dir()) / f"{name}.yaml"
    if not path.is_file():
        raise RecipeError(f"no recipe named {name!r}; see `nikasha recipes list`")
    return load_recipe(path)


def recipe_for_product(product: str, recipes_dir: Path | None = None) -> LoadedRecipe | None:
    """The first recipe (by id) whose ``match.products`` names ``product``."""
    for path in list_recipes(recipes_dir):
        loaded = load_recipe(path)
        if product in loaded.recipe.match.products:
            return loaded
    return None


__all__ = [
    "ARGS_PLACEHOLDER",
    "FILE_PLACEHOLDER",
    "LoadedRecipe",
    "Recipe",
    "RecipeError",
    "RunKind",
    "default_recipes_dir",
    "find_recipe",
    "list_recipes",
    "load_recipe",
    "parse_recipe",
    "recipe_for_product",
]
