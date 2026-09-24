# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha.toml``: project and user configuration (SPEC §16.1).

Three layers, lowest precedence first: the user-level file under
:func:`nikasha.config.config_dir`, the nearest ``nikasha.toml`` found by walking up from the
working directory (stopping at the first ``.git`` boundary), and the file named with
``--config``. Later layers override earlier ones key by key, so a project can pin its
thresholds while a user keeps a local LLM setting.

The file is data, not trust (P7):

* it is parsed with :mod:`tomllib`, capped in size, and refused when it is not UTF-8 or
  nests deeper than the parser can follow;
* every key is validated against a frozen schema with ``extra="forbid"``, so a typo is an
  error that names the file and the key rather than a silently ignored setting;
* no value is ever taken from a process variable. ``llm.allow_cloud`` in particular can
  only be turned on by writing ``true`` into a file the user controls (P3);
* only the working directory's ancestors, the user directory and ``--config`` are ever
  consulted. The search always starts from a *directory*, never from a report file, so a
  ``nikasha.toml`` unpacked next to a report, or inside a repository that Nikasha cloned to
  check a report, is never read: both are chosen by the report;
* a ``[questions]`` override is compiled in a sandboxed template environment
  (:func:`override_environment`) and may not reach into Python internals.

The values that feed a verdict (``[thresholds]``, ``[scoring]``) are recorded in every
result through the ledger's prior and calibration label, so a run stays reproducible from
its JSON alone (P2, P6).
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from jinja2 import StrictUndefined, TemplateSyntaxError, nodes
from jinja2.exceptions import SecurityError
from jinja2.sandbox import ImmutableSandboxedEnvironment
from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_core import ErrorDetails

from nikasha.checks.strengths import Strengths, default_strengths, load_strengths
from nikasha.config import config_dir
from nikasha.errors import NikashaError
from nikasha.fuse.questions import known_templates, listed, ranged, short, template_name
from nikasha.fuse.scoring import DEFAULT_PRIOR
from nikasha.fuse.verdict import Thresholds
from nikasha.model.base import Model
from nikasha.resolve.products import KnownProject

#: The file name looked for at every level.
CONFIG_NAME = "nikasha.toml"

#: The top-level tables a file may contain, in the order the documentation lists them.
SECTIONS = ("project", "thresholds", "scoring", "questions", "ignore", "llm", "hackerone")

#: A configuration file larger than this is refused unread. Real files are a few hundred
#: bytes; a megabyte of TOML is a mistake or an attack, and either way not worth parsing.
MAX_CONFIG_BYTES = 1 << 20

#: Directory levels walked up from the start directory before giving up.
MAX_WALK = 256

MAX_ALIASES = 64
MAX_IGNORE_GLOBS = 512
MAX_QUESTION_OVERRIDES = 256
MAX_TEMPLATE_CHARS = 2000

#: ``llm.provider`` names. The cloud ones additionally need ``llm.allow_cloud = true``.
PROVIDERS = ("none", "ollama", "anthropic", "openai")
CLOUD_PROVIDERS = frozenset({"anthropic", "openai"})

#: URL schemes ``project.repo`` may use. ``file://`` and git's ``<helper>::`` transports
#: are refused here so a bad value is a configuration error naming the key, not a clone
#: error later; :mod:`nikasha.code.gitio` refuses them again at the git boundary.
ALLOWED_REPO_SCHEMES = frozenset({"https", "http", "ssh", "git+ssh"})

#: Tables are merged this many levels deep; anything deeper is replaced wholesale. The
#: schema is two levels deep, so this is a bound on hostile input, not a feature.
_MERGE_DEPTH = 4

#: How many problems one error message lists before saying "and N more".
_MAX_ERRORS = 8

#: Characters no free-text value may contain: C0 and C1 controls, DEL, and the invisible
#: or direction-changing code points (zero-width joiners, bidi embeddings, overrides and
#: isolates, line and paragraph separators, the BOM) that can visually reorder text in a
#: question sent to a reporter or a rendered report.
_HIDDEN = (
    r"\x00-\x1f\x7f-\x9f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff"
)

# Every pattern is linear-time: bounded quantifiers, single character classes, no nested
# repetition. ``tests/unit/test_settings.py`` times each one against adversarial input.
_PRINTABLE = re.compile(rf"\A[^{_HIDDEN}]{{1,100}}\Z")
_REPO = re.compile(rf"\A[^\s{_HIDDEN}]{{1,512}}\Z")
_GLOB = re.compile(rf"\A[^{_HIDDEN}]{{1,256}}\Z")
_SCHEME = re.compile(r"\A([A-Za-z][A-Za-z0-9+.-]{0,31})://")
_DRIVE = re.compile(r"\A[A-Za-z]:(?:[/\\]|\Z)")
_RECIPE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_HANDLE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_MODEL = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_PROVIDER = re.compile(
    r"\A(none|ollama|anthropic|openai)(?::([A-Za-z0-9][A-Za-z0-9._:/-]{0,127}))?\Z"
)
_CHECK_ID = re.compile(r"\AC[0-9]{2}\Z")

#: Words that must not reach a reporter (P1). The same list guards the bundled templates in
#: ``tests/unit/fuse``; an override lives under the same rule as the text it replaces.
_TONE_WORDS = ("ai", "llm", "chatgpt", "generated", "fabricated", "fake", "lying", "slop", "bogus")
_TONE = re.compile(r"\b(?:" + "|".join(_TONE_WORDS) + r")\b", re.IGNORECASE)

#: Template statements an override may not use: an override is one self-contained string,
#: and the sandbox it runs in has no loader to satisfy them anyway.
_NOT_SELF_CONTAINED = (nodes.Include, nodes.Extends, nodes.Import, nodes.FromImport)

_REPO_FORMS = (
    "repo must be an https://, ssh:// or git+ssh:// URL, an scp-style user@host:path, "
    "or a local path"
)

_THRESHOLD_DEFAULTS = Thresholds()

Score = Annotated[int, Field(ge=0, le=100)]
Groups = Annotated[int, Field(ge=1, le=100)]
Count = Annotated[int, Field(ge=0, le=1000)]
Refutation = Annotated[float, Field(ge=-50.0, le=0.0, allow_inf_nan=False)]
Weight = Annotated[float, Field(ge=0.0, le=1000.0, allow_inf_nan=False)]
Prior = Annotated[float, Field(ge=-10.0, le=10.0, allow_inf_nan=False)]


class SettingsError(NikashaError):
    """A configuration file could not be read, parsed or validated. Names the file and key."""


def _printable(value: str, what: str) -> str:
    text = value.strip()
    if not _PRINTABLE.match(text):
        raise ValueError(f"{what} must be 1 to 100 printable characters")
    return text


# --- sections ------------------------------------------------------------------------------------


class ProjectSettings(Model):
    """``[project]``: what the repository this file lives in is called and where it is."""

    name: str | None = None
    repo: str | None = None
    aliases: tuple[str, ...] = ()
    recipe: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        return None if value is None else _printable(value, "name")

    @field_validator("repo")
    @classmethod
    def _repo(cls, value: str | None) -> str | None:
        if value is None:
            return None
        repo = value.strip()
        if not _REPO.match(repo):
            raise ValueError("repo must be a URL or a path without whitespace (512 characters)")
        if repo.startswith("-"):
            raise ValueError("repo must not start with '-'")
        scheme = _SCHEME.match(repo)
        if scheme is not None:
            if scheme.group(1).lower() not in ALLOWED_REPO_SCHEMES:
                raise ValueError(_REPO_FORMS)
            return repo
        # No scheme: a local path (``/srv/x``, ``C:\x``, ``./x``) or scp-style ``user@host:x``.
        # A ``::`` before the first slash is a git transport helper (``ext::``, ``fd::``);
        # a lone ``:`` without a user part is neither of the documented forms.
        head = repo.split("/", 1)[0]
        if "::" in head or (":" in head and "@" not in head and not _DRIVE.match(repo)):
            raise ValueError(_REPO_FORMS)
        return repo

    @field_validator("aliases")
    @classmethod
    def _aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_ALIASES:
            raise ValueError(f"at most {MAX_ALIASES} aliases")
        return tuple(_printable(alias, f"entry {i}") for i, alias in enumerate(value))

    @field_validator("recipe")
    @classmethod
    def _recipe(cls, value: str | None) -> str | None:
        if value is not None and not _RECIPE.match(value):
            raise ValueError("recipe must be an identifier (letters, digits, '.', '_', '-')")
        return value


class ThresholdSettings(Model):
    """``[thresholds]``: every number the verdict ladder makes configurable (SPEC §14.3).

    The defaults are read from :class:`nikasha.fuse.verdict.Thresholds` itself, so the two
    cannot drift apart. Raising the ``ungrounded_*`` scores makes the hardest verdict easier
    to reach: the bench numbers behind P4 hold for the defaults, not for a loosened file.
    """

    ungrounded_score: Score = _THRESHOLD_DEFAULTS.ungrounded_score
    ungrounded_score_strict: Score = _THRESHOLD_DEFAULTS.ungrounded_score_strict
    ungrounded_core_strength: Refutation = _THRESHOLD_DEFAULTS.ungrounded_core_strength
    ungrounded_core_groups: Groups = _THRESHOLD_DEFAULTS.ungrounded_core_groups
    ungrounded_strong_strength: Refutation = _THRESHOLD_DEFAULTS.ungrounded_strong_strength
    ungrounded_strong_groups: Groups = _THRESHOLD_DEFAULTS.ungrounded_strong_groups
    grounded_score: Score = _THRESHOLD_DEFAULTS.grounded_score
    grounded_max_refutation: Refutation = _THRESHOLD_DEFAULTS.grounded_max_refutation
    min_checkable_claims: Count = _THRESHOLD_DEFAULTS.min_checkable_claims
    insufficient_total: Weight = _THRESHOLD_DEFAULTS.insufficient_total

    @model_validator(mode="after")
    def _ladder_is_ordered(self) -> ThresholdSettings:
        if self.ungrounded_score_strict > self.ungrounded_score:
            raise ValueError("ungrounded_score_strict must not exceed ungrounded_score")
        if self.grounded_score <= self.ungrounded_score:
            raise ValueError("grounded_score must be above ungrounded_score")
        return self

    def to_thresholds(self) -> Thresholds:
        """The dataclass :func:`nikasha.fuse.verdict.decide` takes."""
        return Thresholds(**self.model_dump())


class ScoringSettings(Model):
    """``[scoring]``: the prior log-odds and an optional calibrated strengths table."""

    prior: Prior = DEFAULT_PRIOR
    calibration: Path | None = None

    @field_validator("calibration", mode="before")
    @classmethod
    def _names_a_file(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            raise ValueError("calibration must name a file")
        return value


class IgnoreSettings(Model):
    """``[ignore]``: repository paths that are never judged, as globs."""

    paths: tuple[str, ...] = ()

    @field_validator("paths")
    @classmethod
    def _globs(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_IGNORE_GLOBS:
            raise ValueError(f"at most {MAX_IGNORE_GLOBS} globs")
        out: list[str] = []
        for i, raw in enumerate(value):
            glob = raw.strip()
            if "\\" in glob:
                raise ValueError(f"entry {i}: use forward slashes in globs")
            if not _GLOB.match(glob):
                raise ValueError(f"entry {i}: a glob is 1 to 256 printable characters")
            out.append(glob.removeprefix("./").lstrip("/"))
        return tuple(out)


class LLMSettings(Model):
    """``[llm]``: the optional assistant (SPEC §16.6). Off unless a provider is named.

    ``allow_cloud`` is a strict boolean: only a TOML ``true`` in a file switches it on. It is
    never read from a process variable or a flag, because a cloud call can leak an
    embargoed report (P3).
    """

    provider: str = "none"
    allow_cloud: Annotated[bool, Field(strict=True)] = False
    model: str | None = None

    @field_validator("provider")
    @classmethod
    def _provider(cls, value: str) -> str:
        spec = value.strip()
        if not _PROVIDER.match(spec):
            names = ", ".join(PROVIDERS)
            raise ValueError(f"provider must be one of {names}, optionally followed by :MODEL")
        return spec

    @field_validator("model")
    @classmethod
    def _model(cls, value: str | None) -> str | None:
        if value is not None and not _MODEL.match(value):
            raise ValueError("model must be a model identifier (letters, digits, '.', ':', '/')")
        return value

    @property
    def provider_name(self) -> str:
        """``"ollama"`` for ``"ollama:llama3.1:8b"``."""
        return self.provider.partition(":")[0]

    @property
    def model_name(self) -> str | None:
        """``model`` when set, else the part of ``provider`` after the first colon."""
        if self.model is not None:
            return self.model
        return self.provider.partition(":")[2] or None

    @property
    def enabled(self) -> bool:
        return self.provider_name != "none"

    @property
    def is_cloud(self) -> bool:
        """True for the providers that send text off the machine."""
        return self.provider_name in CLOUD_PROVIDERS


class HackerOneSettings(Model):
    """``[hackerone]``: the program whose reports ``nikasha h1`` fetches."""

    program: str | None = None

    @field_validator("program")
    @classmethod
    def _program(cls, value: str | None) -> str | None:
        if value is not None and not _HANDLE.match(value):
            raise ValueError("program must be a handle (letters, digits, '_', '-')")
        return value


# --- the whole file ----------------------------------------------------------------------------


class Settings(Model):
    """Everything ``nikasha.toml`` can say, with the defaults the tool runs on without one.

    The ``[thresholds]`` table is stored as :attr:`limits` (an alias), because
    :meth:`thresholds` is the helper that returns the dataclass the fusion layer takes.
    ``model_dump(by_alias=True)`` gives the file's own key names back.

    ``[questions]`` is stored as a tuple of ``(key, template)`` pairs sorted by key, which
    keeps the model hashable (as every frozen :class:`~nikasha.model.base.Model` is) and
    makes the order independent of the order in the file; :meth:`question_overrides` gives
    it back as a dictionary.
    """

    project: ProjectSettings = Field(default_factory=ProjectSettings)
    limits: ThresholdSettings = Field(default_factory=ThresholdSettings, alias="thresholds")
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    questions: tuple[tuple[str, str], ...] = ()
    ignore: IgnoreSettings = Field(default_factory=IgnoreSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    hackerone: HackerOneSettings = Field(default_factory=HackerOneSettings)

    @field_validator("questions", mode="before")
    @classmethod
    def _overrides(cls, value: object) -> object:
        """Fold the TOML table into sorted ``(key, template)`` pairs, validating each one.

        Both ``"C03.outcome" = "..."`` and a ``[questions.C03]`` sub-table are accepted (an
        unquoted dotted key in TOML is a nested table, which is the most natural thing to
        type); both spellings of one key in one file is an error, because TOML treats them
        as different keys and would otherwise let the last one win silently. A sequence of
        pairs (a dumped model) is accepted too. Anything else is left for pydantic to name.
        """
        pairs: list[tuple[str, object]] | None
        if isinstance(value, Mapping):
            pairs = _flatten(value)
        elif isinstance(value, (list, tuple)):
            pairs = _pairs(value)
        else:
            pairs = None
        if pairs is None:
            return value
        if len(pairs) > MAX_QUESTION_OVERRIDES:
            raise ValueError(f"at most {MAX_QUESTION_OVERRIDES} question overrides")
        validated: dict[str, str] = {}
        for key, text in pairs:
            if key in validated:
                raise ValueError(f"{key} is given twice")
            if not isinstance(text, str):
                raise ValueError(f"{key}: the template must be text, not {type(text).__name__}")
            validated[key] = _template(key, text)
        return tuple(sorted(validated.items()))

    # -- helpers for the rest of the tool ----------------------------------------------------

    def thresholds(self) -> Thresholds:
        """The ``[thresholds]`` table as :func:`nikasha.fuse.verdict.decide` takes it."""
        return self.limits.to_thresholds()

    def prior(self) -> float:
        """``scoring.prior``, the log-odds :func:`nikasha.fuse.scoring.fuse` starts from."""
        return self.scoring.prior

    def strengths(self) -> Strengths:
        """The strengths table: the bundled defaults, or ``scoring.calibration`` when set."""
        if self.scoring.calibration is None:
            return default_strengths()
        return load_strengths(self.scoring.calibration)

    def question_overrides(self) -> dict[str, str]:
        """``[questions]`` as ``{"C03.never_in_history_core": template}``, sorted by key.

        Every template here was compiled in :func:`override_environment` and must be
        rendered in it too: the sandbox refuses attribute access into Python internals at
        render time, and the plain environment the bundled templates use does not.
        """
        return dict(self.questions)

    def project_entry(self) -> KnownProject | None:
        """``[project]`` as a :class:`~nikasha.resolve.products.KnownProject`, or ``None``.

        Lets a repository describe itself the way ``known_projects.yaml`` describes the
        well-known ones: name, aliases, clone URL, recipe and HackerOne program.
        """
        name = self.project.name
        if name is None:
            return None
        aliases: list[str] = []
        seen: set[str] = set()
        for alias in (name, *self.project.aliases):
            if alias.lower() not in seen:
                seen.add(alias.lower())
                aliases.append(alias)
        program = self.hackerone.program
        return KnownProject(
            name=name,
            aliases=tuple(aliases),
            repo=self.project.repo,
            tag_families=(),
            programs=(program,) if program else (),
            recipe=self.project.recipe,
        )

    def is_ignored(self, path: str) -> bool:
        """Whether a repo-relative path matches an ``[ignore]`` glob.

        Same dialect as ``known_projects.yaml``: ``*`` stays within a component, ``**``
        crosses them, and a glob without a slash matches the basename anywhere.
        """
        return any(ignore_match(glob, path) for glob in self.ignore.paths)


# --- a linear-time glob matcher -------------------------------------------------------------------

# Token kinds. ``code.generated.glob_match`` compiles a glob to a backtracking regex, which
# is fine for the bundled, reviewed globs but not for a file a repository controls:
# ``*a*a*a...b`` or ``**/**/**/...x`` takes exponential or high-polynomial time there. This
# matcher speaks the same dialect and simulates the automaton over a set of states, so it
# costs O(len(glob) * len(path)) whatever the input.
_LIT, _ONE, _STAR, _DSTAR, _DSTAR_SLASH = range(5)


@lru_cache(maxsize=1024)
def _glob_tokens(glob: str) -> tuple[tuple[int, str], ...]:
    out: list[tuple[int, str]] = []
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append((_DSTAR_SLASH, ""))
            i += 3
        elif glob.startswith("**", i):
            out.append((_DSTAR, ""))
            i += 2
        elif glob[i] == "*":
            out.append((_STAR, ""))
            i += 1
        elif glob[i] == "?":
            out.append((_ONE, ""))
            i += 1
        else:
            out.append((_LIT, glob[i]))
            i += 1
    return tuple(out)


def _closure(tokens: tuple[tuple[int, str], ...], states: set[tuple[int, bool]]) -> None:
    """Add the epsilon moves: every star may match nothing (not mid-component for ``**/``)."""
    stack = list(states)
    while stack:
        index, inside = stack.pop()
        if inside or index >= len(tokens) or tokens[index][0] in (_LIT, _ONE):
            continue
        nxt = (index + 1, False)
        if nxt not in states:
            states.add(nxt)
            stack.append(nxt)


def _step(
    token: tuple[int, str], index: int, inside: bool, char: str, moved: set[tuple[int, bool]]
) -> None:
    """The states one character leads to from ``(index, inside)``."""
    kind, lit = token
    if kind == _LIT:
        if char == lit:
            moved.add((index + 1, False))
    elif kind == _DSTAR:
        moved.add((index, False))
    elif char != "/":
        if kind == _ONE:
            moved.add((index + 1, False))
        else:  # ``*`` stays put; ``**/`` is now inside a component
            moved.add((index, kind == _DSTAR_SLASH))
    elif kind == _DSTAR_SLASH and inside:
        moved.add((index, False))


def ignore_match(glob: str, path: str) -> bool:
    """:func:`nikasha.code.generated.glob_match`'s dialect, in linear time.

    States are ``(token index, inside)``; ``inside`` is only used by ``**/`` (the regex
    ``(?:[^/]+/)*``) and means "one or more non-slash characters of this component seen".
    """
    target = path.lstrip("/")
    if "/" not in glob:
        target = target.rsplit("/", 1)[-1]
    tokens = _glob_tokens(glob)
    states: set[tuple[int, bool]] = {(0, False)}
    _closure(tokens, states)
    for char in target:
        moved: set[tuple[int, bool]] = set()
        for index, inside in states:
            if index < len(tokens):
                _step(tokens[index], index, inside, char, moved)
        if not moved:
            return False
        _closure(tokens, moved)
        states = moved
    return (len(tokens), False) in states


def _flatten(table: Mapping[Any, Any]) -> list[tuple[str, object]]:
    """``{"C03": {"x": t}}`` and ``{"C03.x": t}`` both become ``[("C03.x", t)]``.

    Two levels only; deeper nesting is an error rather than a recursion. A key spelled
    both ways in one table is an error (see :meth:`Settings._overrides`).
    """
    flat: dict[str, object] = {}
    for key, item in table.items():
        if not isinstance(item, Mapping):
            name = str(key)
            if name in flat:
                raise ValueError(f"{name} is given twice (quoted key and sub-table)")
            flat[name] = item
            continue
        for sub, subitem in item.items():
            if isinstance(subitem, Mapping):
                raise ValueError(f'{key}.{sub} is nested too deeply; write "{key}.{sub}" = "..."')
            name = f"{key}.{sub}"
            if name in flat:
                raise ValueError(f"{name} is given twice (quoted key and sub-table)")
            flat[name] = subitem
    return list(flat.items())


def _pairs(items: list[Any] | tuple[Any, ...]) -> list[tuple[str, object]] | None:
    """A sequence of ``(key, template)`` pairs, or ``None`` when it is not shaped like one."""
    pairs: list[tuple[str, object]] = []
    for item in items:
        if not isinstance(item, (list, tuple)):
            return None
        try:
            key, text = item
        except ValueError:
            return None
        if not isinstance(key, str):
            return None
        pairs.append((key, text))
    return pairs


@lru_cache(maxsize=1)
def override_environment() -> ImmutableSandboxedEnvironment:
    """The sandboxed template environment every ``[questions]`` override runs in.

    Configured like :func:`nikasha.fuse.questions.environment` (the same ``ranged``,
    ``listed`` and ``short`` filters, :class:`~jinja2.StrictUndefined`, no autoescape, the
    same block trimming) with two differences that are the point: it is an
    :class:`~jinja2.sandbox.ImmutableSandboxedEnvironment`, which refuses attribute access
    into Python internals and mutation of its inputs with
    :class:`~jinja2.exceptions.SecurityError` when a template is *rendered*, and it has no
    loader, so an override cannot pull in other files. The bundled ``.j2`` templates ship
    with the code and keep the plain environment; an override is text a repository
    controls, so it gets this one, at load time and at render time alike.
    """
    env = ImmutableSandboxedEnvironment(
        undefined=StrictUndefined,
        autoescape=False,  # plain text out; the HTML and Markdown renderers escape (SPEC §15.2)
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=False,
    )
    env.filters["ranged"] = ranged
    env.filters["listed"] = listed
    env.filters["short"] = short
    return env


def _template(key: str, text: str) -> str:
    """Validate one question override: a well-formed key, a compilable template, P1 wording.

    The sandbox catches unsafe attribute access only when a template is rendered, which
    happens later, with a context this function does not have. The load-time defence is
    therefore literal: no ``__`` anywhere in the template (every route from a string or a
    global to ``os`` goes through a dunder attribute), and no ``include``, ``extends`` or
    ``import`` statement (an override is one self-contained string).
    """
    check, _, outcome = key.partition(".")
    name = template_name(check, outcome) if _CHECK_ID.match(check) else None
    if name is None:
        raise ValueError(f'{key}: keys look like "C03.never_in_history_core"')
    if name not in known_templates():
        # A typo in an outcome would otherwise be an override that silently never applies.
        raise ValueError(f"{key}: no bundled question has this name")
    body = text.strip()
    if not body:
        raise ValueError(f"{key}: the template is empty")
    if len(body) > MAX_TEMPLATE_CHARS:
        raise ValueError(f"{key}: the template is longer than {MAX_TEMPLATE_CHARS} characters")
    if "__" in body:
        raise ValueError(f"{key}: template uses a restricted attribute ('__')")
    found = _TONE.search(body)
    if found:
        raise ValueError(f"{key}: the word {found.group(0)!r} is not used in a question (P1)")
    env = override_environment()
    try:
        tree = env.parse(body)
        env.compile(tree)
    except TemplateSyntaxError as exc:
        raise ValueError(f"{key}: template syntax: {exc.message}") from exc
    except SecurityError as exc:
        raise ValueError(f"{key}: template uses a restricted attribute") from exc
    if any(True for _ in tree.find_all(_NOT_SELF_CONTAINED)):
        raise ValueError(f"{key}: the template must be self-contained (no include or extends)")
    return body


# --- reading files -------------------------------------------------------------------------------


def user_config_path() -> Path:
    """The user-level file: ``config_dir()/nikasha.toml`` (it need not exist)."""
    return config_dir() / CONFIG_NAME


def repo_config_path(start: Path | None = None) -> Path | None:
    """The nearest ``nikasha.toml`` at or above the directory ``start``, or ``None``.

    The walk stops at the first directory that contains ``.git`` (a directory or, for
    worktrees, a file), after checking that directory itself. That is what keeps a file in
    a parent checkout, or in the home directory, from applying to an unrelated repository.

    ``start`` must be an existing directory (the working directory when omitted). It is
    never a report file: a report is hostile input (P7) and must not choose the
    configuration that judges it.
    """
    if start is None:
        try:
            start = Path.cwd()
        except OSError as exc:
            raise SettingsError(f"working directory: cannot read ({exc.strerror or exc})") from exc
    try:
        if not start.is_dir():
            raise SettingsError(f"{start}: the configuration search starts from a directory")
        current = start.resolve()
        for _ in range(MAX_WALK):
            candidate = current / CONFIG_NAME
            if candidate.is_file():
                return candidate
            if (current / ".git").exists() or current.parent == current:
                return None
            current = current.parent
    except OSError as exc:
        raise SettingsError(f"{start}: cannot read ({exc.strerror or exc})") from exc
    return None


def _same(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError as exc:
        raise SettingsError(f"{path}: cannot read ({exc.strerror or exc})") from exc


def config_files(start: Path | None = None, explicit: Path | None = None) -> tuple[Path, ...]:
    """The files :func:`load_settings` would read, lowest precedence first.

    ``explicit`` must exist: the user named it. The other two are optional.
    """
    found: list[Path] = []
    user = user_config_path()
    if _is_file(user):
        found.append(user)
    repo = repo_config_path(start)
    if repo is not None and not any(_same(repo, seen) for seen in found):
        found.append(repo)
    if explicit is not None:
        if not _is_file(explicit):
            raise SettingsError(f"{explicit}: no such configuration file")
        if not any(_same(explicit, seen) for seen in found):
            found.append(explicit)
    return tuple(found)


def _read_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SettingsError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    if size > MAX_CONFIG_BYTES:
        raise SettingsError(f"{path}: {size} bytes is over the {MAX_CONFIG_BYTES}-byte limit")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SettingsError(f"{path}: cannot read ({exc.strerror or exc})") from exc
    if len(data) > MAX_CONFIG_BYTES:
        raise SettingsError(f"{path}: over the {MAX_CONFIG_BYTES}-byte limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SettingsError(f"{path}: not valid UTF-8 (byte {exc.start})") from exc
    return text.removeprefix("\ufeff")


def _parse(text: str, path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(text)
    except ValueError as exc:  # TOMLDecodeError is a ValueError
        raise SettingsError(f"{path}: invalid TOML: {exc}") from exc
    except RecursionError as exc:
        raise SettingsError(f"{path}: nested too deeply to parse") from exc


def _anchor_calibration(raw: dict[str, Any], path: Path) -> None:
    """Make ``scoring.calibration`` absolute relative to the file that set it, and check it."""
    scoring = raw.get("scoring")
    if not isinstance(scoring, dict):
        return
    calibration = scoring.get("calibration")
    if not isinstance(calibration, str) or not calibration.strip():
        return
    target = Path(calibration.strip()).expanduser()
    if not target.is_absolute():
        target = path.parent / target
    try:
        if not target.is_file():
            raise SettingsError(f"{path}: scoring.calibration: no such file {target}")
        scoring["calibration"] = str(target.resolve())
    except OSError as exc:
        raise SettingsError(
            f"{path}: scoring.calibration: cannot read {target} ({exc.strerror or exc})"
        ) from exc


def _loc(parts: tuple[int | str, ...]) -> str:
    text = ""
    for part in parts:
        if isinstance(part, int):
            text += f"[{part}]"
        else:
            text = f"{text}.{part}" if text else str(part)
    return text


def _describe(error: ErrorDetails) -> str:
    loc = _loc(error["loc"])
    if error["type"] == "extra_forbidden":
        hint = "" if "." in loc else f" (sections: {', '.join(SECTIONS)})"
        return f"unknown key {loc}{hint}"
    msg = error["msg"].removeprefix("Value error, ")
    return f"{loc}: {msg}" if loc else msg


def _validate(raw: Mapping[str, Any], where: str) -> Settings:
    try:
        return Settings.model_validate(dict(raw))
    except ValidationError as exc:
        errors = exc.errors()
        problems = [_describe(error) for error in errors[:_MAX_ERRORS]]
        if len(errors) > _MAX_ERRORS:
            problems.append(f"and {len(errors) - _MAX_ERRORS} more")
        raise SettingsError(f"{where}: {'; '.join(problems)}") from exc


def read_config(path: Path) -> dict[str, Any]:
    """Read, parse and validate one file on its own; return its raw tables for merging.

    Validating each file alone is what lets an error name the file it came from.
    """
    raw = _parse(_read_text(path), path)
    _anchor_calibration(raw, path)
    _validate(raw, str(path))
    return raw


def _merge(base: Mapping[str, Any], override: Mapping[str, Any], depth: int = 0) -> dict[str, Any]:
    """Key-wise merge, tables recursively (to a bound), everything else replaced."""
    out: dict[str, Any] = dict(base)
    for key, value in override.items():
        current = out.get(key)
        if depth < _MERGE_DEPTH and isinstance(current, Mapping) and isinstance(value, Mapping):
            out[key] = _merge(current, value, depth + 1)
        else:
            out[key] = value
    return out


def load_settings(start: Path | None = None, explicit: Path | None = None) -> Settings:
    """The effective settings: user-level, then repo-level, then ``explicit``, merged.

    ``start`` is the directory the repo-level search begins in: ``None`` means the working
    directory, which is what the CLI passes. It is never the report being checked or its
    directory (see :func:`repo_config_path`). ``explicit`` is the ``--config`` file and must
    exist. With no file at all the defaults apply, which is a complete, working
    configuration.

    Every failure is a :class:`SettingsError` naming the file and the key. A conflict that
    only appears once files are combined (each valid alone) names every file involved.
    """
    files = config_files(start, explicit)
    if not files:
        return Settings()
    merged: dict[str, Any] = {}
    for path in files:
        merged = _merge(merged, read_config(path))
    return _validate(merged, " + ".join(str(path) for path in files))


__all__ = [
    "ALLOWED_REPO_SCHEMES",
    "CLOUD_PROVIDERS",
    "CONFIG_NAME",
    "MAX_CONFIG_BYTES",
    "PROVIDERS",
    "SECTIONS",
    "HackerOneSettings",
    "IgnoreSettings",
    "LLMSettings",
    "ProjectSettings",
    "ScoringSettings",
    "Settings",
    "SettingsError",
    "ThresholdSettings",
    "config_files",
    "ignore_match",
    "load_settings",
    "override_environment",
    "read_config",
    "repo_config_path",
    "user_config_path",
]
