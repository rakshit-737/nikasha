# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha.toml`` loading (SPEC §16.1).

Every test that touches the loader runs inside ``isolated``: a temporary tree with a
``.git`` boundary at its root and a fake user configuration directory, so nothing on the
developer's machine (a real ``~/.config/nikasha/nikasha.toml``, a checkout above the temp
directory) can leak into a result.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from jinja2.exceptions import SecurityError
from jinja2.sandbox import ImmutableSandboxedEnvironment

from nikasha import settings as settings_module
from nikasha.checks.strengths import default_strengths
from nikasha.code.generated import glob_match
from nikasha.errors import NikashaError
from nikasha.fuse.questions import environment as plain_environment
from nikasha.fuse.scoring import DEFAULT_PRIOR
from nikasha.fuse.verdict import Thresholds
from nikasha.settings import (
    MAX_CONFIG_BYTES,
    SECTIONS,
    HackerOneSettings,
    IgnoreSettings,
    LLMSettings,
    ProjectSettings,
    ScoringSettings,
    Settings,
    SettingsError,
    ThresholdSettings,
    config_files,
    ignore_match,
    load_settings,
    override_environment,
    repo_config_path,
)

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs" / "configuration.md"
_KEY = "C03.never_in_history_core"
EXAMPLE = ROOT / "examples" / "nikasha.toml"

SECTION_MODELS = {
    "project": ProjectSettings,
    "thresholds": ThresholdSettings,
    "scoring": ScoringSettings,
    "ignore": IgnoreSettings,
    "llm": LLMSettings,
    "hackerone": HackerOneSettings,
}

#: The right-to-left override, the character that makes "x\u202ey" render as "xy" reversed.
RLO = "\u202e"

FULL = """
[project]
name = "libhdr"
repo = "https://example.invalid/libhdr/libhdr.git"
aliases = ["hdr", "libhdr-c"]
recipe = "libhdr-asan"

[thresholds]
ungrounded_score = 12
ungrounded_score_strict = 8
ungrounded_core_strength = -2.5
ungrounded_core_groups = 3
ungrounded_strong_strength = -1.8
ungrounded_strong_groups = 4
grounded_score = 80
grounded_max_refutation = -1.0
min_checkable_claims = 3
insufficient_total = 2.0

[scoring]
prior = -0.5

[questions]
"C03.never_in_history_core" = "Which commit added {{ symbol }} in {{ where }}?"

[ignore]
paths = ["vendor/**", "third_party/*", "config.h"]

[llm]
provider = "ollama:llama3.1:8b"
allow_cloud = false
model = "llama3.1:70b"

[hackerone]
program = "libhdr"
"""


@pytest.fixture
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """A repository root with a ``.git`` boundary, plus an empty user config directory."""
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    userdir = tmp_path / "userdir"
    userdir.mkdir()
    monkeypatch.setattr(settings_module, "config_dir", lambda: userdir)
    return SimpleNamespace(root=root, userdir=userdir, user_file=userdir / "nikasha.toml")


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --- defaults -------------------------------------------------------------------------------------


def test_defaults_match_the_fusion_layer() -> None:
    plain = Settings()
    assert plain.thresholds() == Thresholds()
    assert plain.prior() == DEFAULT_PRIOR
    assert plain.strengths() is default_strengths()


def test_threshold_settings_mirror_the_dataclass_field_for_field() -> None:
    dataclass_fields = {f.name: f.default for f in dataclasses.fields(Thresholds)}
    model_fields = {name: field.default for name, field in ThresholdSettings.model_fields.items()}
    assert model_fields == dataclass_fields


@pytest.mark.parametrize("section", [s for s in SECTIONS if s != "questions"])
def test_every_section_has_a_complete_default(section: str) -> None:
    plain = Settings()
    attribute = "limits" if section == "thresholds" else section
    assert getattr(plain, attribute) == SECTION_MODELS[section]()


def test_section_defaults_in_detail() -> None:
    plain = Settings()
    assert plain.project == ProjectSettings(name=None, repo=None, aliases=(), recipe=None)
    assert plain.scoring.prior == 0.0
    assert plain.scoring.calibration is None
    assert plain.questions == ()
    assert plain.question_overrides() == {}
    assert plain.ignore.paths == ()
    assert plain.llm.provider == "none"
    assert plain.llm.allow_cloud is False
    assert plain.llm.model is None
    assert plain.llm.enabled is False
    assert plain.llm.is_cloud is False
    assert plain.hackerone.program is None
    assert plain.project_entry() is None
    assert plain.is_ignored("src/anything.c") is False


def test_no_file_at_all_is_the_defaults(isolated: SimpleNamespace) -> None:
    assert config_files(isolated.root) == ()
    assert load_settings(isolated.root) == Settings()


def test_empty_file_is_the_defaults(isolated: SimpleNamespace) -> None:
    path = write(isolated.root / "nikasha.toml", "")
    assert config_files(isolated.root) == (path,)
    assert load_settings(isolated.root) == Settings()


def test_dump_uses_the_file_key_names() -> None:
    assert tuple(Settings().model_dump(by_alias=True)) == SECTIONS


# --- a full file ----------------------------------------------------------------------------------


def test_full_file_round_trip(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", FULL)
    loaded = load_settings(isolated.root)

    assert loaded.project.name == "libhdr"
    assert loaded.project.aliases == ("hdr", "libhdr-c")
    assert loaded.project.recipe == "libhdr-asan"
    assert loaded.thresholds() == Thresholds(
        ungrounded_score=12,
        ungrounded_score_strict=8,
        ungrounded_core_strength=-2.5,
        ungrounded_core_groups=3,
        ungrounded_strong_strength=-1.8,
        ungrounded_strong_groups=4,
        grounded_score=80,
        grounded_max_refutation=-1.0,
        min_checkable_claims=3,
        insufficient_total=2.0,
    )
    assert loaded.prior() == -0.5
    assert loaded.question_overrides() == {
        "C03.never_in_history_core": "Which commit added {{ symbol }} in {{ where }}?"
    }
    assert loaded.ignore.paths == ("vendor/**", "third_party/*", "config.h")
    assert loaded.llm.provider_name == "ollama"
    assert loaded.llm.model_name == "llama3.1:70b"  # the explicit model wins over the suffix
    assert loaded.llm.enabled is True
    assert loaded.llm.is_cloud is False
    assert loaded.hackerone.program == "libhdr"

    entry = loaded.project_entry()
    assert entry is not None
    assert entry.name == "libhdr"
    assert entry.aliases == ("libhdr", "hdr", "libhdr-c")
    assert entry.repo == "https://example.invalid/libhdr/libhdr.git"
    assert entry.programs == ("libhdr",)
    assert entry.recipe == "libhdr-asan"


def test_settings_are_frozen() -> None:
    loaded = Settings()
    with pytest.raises(Exception, match="frozen"):
        loaded.scoring = ScoringSettings(prior=1.0)  # type: ignore[misc]


def test_settings_are_hashable(isolated: SimpleNamespace) -> None:
    """The ``Model`` contract: frozen instances are hashable, ``[questions]`` included."""
    write(isolated.root / "nikasha.toml", FULL)
    loaded = load_settings(isolated.root)
    assert hash(Settings()) == hash(Settings())
    assert hash(loaded) == hash(load_settings(isolated.root))
    assert hash(loaded) != hash(Settings())


def test_a_dumped_model_validates_again(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", FULL)
    loaded = load_settings(isolated.root)
    assert Settings.model_validate(loaded.model_dump(by_alias=True)) == loaded


# --- unknown keys and bad values name the file and the key -------------------------------------


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("name = 'x'\n", "unknown key name"),
        ("[projekt]\nname = 'x'\n", "unknown key projekt"),
        ("[thresholds]\ngrounded = 80\n", "unknown key thresholds.grounded"),
        ("[llm]\nallow_clowd = true\n", "unknown key llm.allow_clowd"),
        ("[scoring]\nprior = 0.1\nextra = 1\n", "unknown key scoring.extra"),
    ],
)
def test_unknown_keys_are_errors(isolated: SimpleNamespace, text: str, key: str) -> None:
    path = write(isolated.root / "nikasha.toml", text)
    with pytest.raises(SettingsError) as excinfo:
        load_settings(isolated.root)
    message = str(excinfo.value)
    assert str(path) in message
    assert key in message


def test_top_level_unknown_key_lists_the_sections(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", "prior = 0.5\n")
    with pytest.raises(SettingsError, match="sections: project, thresholds"):
        load_settings(isolated.root)


@pytest.mark.parametrize(
    ("text", "key"),
    [
        ("[thresholds]\ngrounded_score = 'high'\n", "thresholds.grounded_score"),
        ("[thresholds]\ngrounded_score = 101\n", "thresholds.grounded_score"),
        ("[thresholds]\nungrounded_core_groups = 0\n", "thresholds.ungrounded_core_groups"),
        ("[thresholds]\ngrounded_max_refutation = 0.5\n", "thresholds.grounded_max_refutation"),
        ("[thresholds]\ninsufficient_total = nan\n", "thresholds.insufficient_total"),
        ("[scoring]\nprior = nan\n", "scoring.prior"),
        ("[scoring]\nprior = inf\n", "scoring.prior"),
        ("[scoring]\nprior = 11\n", "scoring.prior"),
        ("[scoring]\ncalibration = ''\n", "scoring.calibration"),
        ("[project]\nname = ''\n", "project.name"),
        ('[project]\nname = "x\\u202Ey"\n', "project.name"),  # bidi override
        ('[project]\nname = "x\\u200By"\n', "project.name"),  # zero-width space
        ('[project]\nname = "x\\u0085y"\n', "project.name"),  # C1 control
        ("[project]\nrepo = '-oops'\n", "project.repo"),
        ("[project]\nrepo = 'has space'\n", "project.repo"),
        ('[project]\nrepo = "x\\u202Ey"\n', "project.repo"),
        ("[project]\nrepo = 'ext::sh$IFS-c$IFSid'\n", "project.repo"),
        ("[project]\nrepo = 'fd::3'\n", "project.repo"),
        ("[project]\nrepo = 'file:///etc'\n", "project.repo"),
        ("[project]\nrepo = 'git://example.invalid/x.git'\n", "project.repo"),
        ("[project]\nrepo = 'ftp://example.invalid/x.git'\n", "project.repo"),
        ("[project]\nrepo = 'user@ext::cmd'\n", "project.repo"),
        ("[project]\nrepo = 'host:path'\n", "project.repo"),
        ("[project]\nrecipe = 'no spaces'\n", "project.recipe"),
        ("[project]\naliases = ['ok', '']\n", "project.aliases"),
        ('[project]\naliases = ["x\\u202Ey"]\n', "project.aliases"),
        ("[ignore]\npaths = ['']\n", "ignore.paths"),
        ("[ignore]\npaths = ['vendor\\\\**']\n", "ignore.paths"),
        ('[ignore]\npaths = ["src/\\u202E*"]\n', "ignore.paths"),
        ("[llm]\nprovider = 'gpt5'\n", "llm.provider"),
        ("[llm]\nprovider = 'ollama:'\n", "llm.provider"),
        ("[llm]\nmodel = 'a model'\n", "llm.model"),
        ("[hackerone]\nprogram = 'not a handle'\n", "hackerone.program"),
    ],
)
def test_bad_values_name_the_key(isolated: SimpleNamespace, text: str, key: str) -> None:
    path = write(isolated.root / "nikasha.toml", text)
    with pytest.raises(SettingsError) as excinfo:
        load_settings(isolated.root)
    assert str(path) in str(excinfo.value)
    assert key in str(excinfo.value)


@pytest.mark.parametrize(
    "repo",
    [
        "https://github.com/curl/curl.git",
        "HTTPS://github.com/curl/curl",
        "http://git.example.invalid/x.git",
        "ssh://git@github.com/curl/curl.git",
        "ssh://[::1]/srv/x.git",
        "git+ssh://git@example.invalid/x.git",
        "git@github.com:curl/curl.git",
        "/srv/git/curl.git",
        "./vendor/curl",
        "curl",
        "C:/repos/curl",
        "C:\\repos\\curl",
        "c:",
    ],
)
def test_repo_accepts_the_documented_forms(repo: str) -> None:
    assert ProjectSettings(repo=repo).repo == repo


def test_bidi_and_zero_width_characters_are_refused_in_free_text() -> None:
    """A right-to-left override in a name would visually reorder a question to a reporter."""
    for hidden in (RLO, "\u200b", "\u200e", "\u2066", "\u2028", "\ufeff", "\u061c", "\x85"):
        with pytest.raises(ValueError, match="printable"):
            ProjectSettings(name=f"x{hidden}y")
        with pytest.raises(ValueError, match="printable"):
            IgnoreSettings(paths=(f"src/{hidden}*",))
        with pytest.raises(ValueError, match="repo must"):
            ProjectSettings(repo=f"https://example.invalid/{hidden}x")
    assert ProjectSettings(name="café ünïcode 名前").name == "café ünïcode 名前"


def test_errors_are_nikasha_errors() -> None:
    assert issubclass(SettingsError, NikashaError)


def test_invalid_toml_names_the_file(isolated: SimpleNamespace) -> None:
    path = write(isolated.root / "nikasha.toml", "[project\nname = 'x'\n")
    with pytest.raises(SettingsError, match="invalid TOML") as excinfo:
        load_settings(isolated.root)
    assert str(path) in str(excinfo.value)


def test_duplicate_keys_are_invalid_toml(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", "[scoring]\nprior = 1.0\nprior = 2.0\n")
    with pytest.raises(SettingsError, match="invalid TOML"):
        load_settings(isolated.root)


def test_ladder_order_is_enforced(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", "[thresholds]\nungrounded_score_strict = 20\n")
    with pytest.raises(SettingsError, match="ungrounded_score_strict must not exceed"):
        load_settings(isolated.root)
    write(isolated.root / "nikasha.toml", "[thresholds]\ngrounded_score = 15\n")
    with pytest.raises(SettingsError, match="grounded_score must be above"):
        load_settings(isolated.root)


def test_many_problems_are_capped(isolated: SimpleNamespace) -> None:
    body = "\n".join(f"key{i} = {i}" for i in range(30))
    write(isolated.root / "nikasha.toml", body + "\n")
    with pytest.raises(SettingsError, match=r"and \d+ more"):
        load_settings(isolated.root)


# --- [questions] ----------------------------------------------------------------------------------


def test_question_override_accepts_quoted_and_nested_keys() -> None:
    quoted = Settings.model_validate({"questions": {"C03.never_in_history_core": "Which one?"}})
    nested = Settings.model_validate(
        {"questions": {"C03": {"never_in_history_core": "Which one?"}}}
    )
    assert quoted == nested
    assert quoted.question_overrides() == {"C03.never_in_history_core": "Which one?"}
    assert quoted.questions == (("C03.never_in_history_core", "Which one?"),)


def test_question_override_given_as_both_spellings_is_an_error() -> None:
    """TOML sees ``"C03.a"`` and ``[questions.C03] a`` as different keys; we do not."""
    with pytest.raises(SettingsError, match=r"C03\.a is given twice"):
        settings_module._validate(
            {"questions": {"C03.a": "Which one?", "C03": {"a": "Which other?"}}}, "f"
        )
    with pytest.raises(SettingsError, match=r"C03\.a is given twice"):
        settings_module._validate(
            {"questions": {"C03": {"a": "Which other?"}, "C03.a": "Which one?"}}, "f"
        )


def test_question_override_given_as_both_spellings_in_a_file(isolated: SimpleNamespace) -> None:
    path = write(
        isolated.root / "nikasha.toml",
        '[questions]\n"C03.a" = "Which one?"\n[questions.C03]\nb = "Which two?"\na = "Again?"\n',
    )
    with pytest.raises(SettingsError, match="given twice") as excinfo:
        load_settings(isolated.root)
    assert str(path) in str(excinfo.value)


def test_question_overrides_are_sorted_by_key_not_file_order() -> None:
    loaded = Settings.model_validate(
        {
            "questions": {
                "C03.never_in_history_core": "Which patch?",
                "C02.never_in_history": "Which commit?",
                "C03.absent_in_sampled_core": "Which file?",
            }
        }
    )
    assert loaded.questions == (
        ("C02.never_in_history", "Which commit?"),
        ("C03.absent_in_sampled_core", "Which file?"),
        ("C03.never_in_history_core", "Which patch?"),
    )
    assert list(loaded.question_overrides()) == [
        "C02.never_in_history",
        "C03.absent_in_sampled_core",
        "C03.never_in_history_core",
    ]


@pytest.mark.parametrize("key", ["C18.unknown_call", "C03.never_in_histroy_core"])
def test_question_override_must_name_a_bundled_question(key: str) -> None:
    """A typo in the outcome would be an override that silently never applies."""
    with pytest.raises(SettingsError, match=f"{re.escape(key)}: no bundled question"):
        settings_module._validate({"questions": {key: "Which call site?"}}, "f")


@pytest.mark.parametrize(
    ("key", "text", "reason"),
    [
        ("c03.never_in_history_core", "Which one?", "keys look like"),
        ("C3.never_in_history_core", "Which one?", "keys look like"),
        ("C03.never in history", "Which one?", "keys look like"),
        ("C03", "Which one?", "keys look like"),
        (_KEY, "   ", "empty"),
        (_KEY, "x" * 2001, "longer than"),
        (_KEY, "{{ where", "template syntax"),
        (_KEY, "{{ where | no_such_filter }}", "template syntax"),
        (
            "C03.never_in_history_core",
            "{% include 'C03.never_in_history_core.j2' %}",
            "self-contained",
        ),
        (
            "C03.never_in_history_core",
            "{% extends 'C03.never_in_history_core.j2' %}",
            "self-contained",
        ),
        (_KEY, "{% import 'x' as y %}{{ where }}", "self-contained"),
        ("C03.never_in_history_core", "{% from 'x' import y %}{{ where }}", "self-contained"),
    ],
)
def test_question_override_rejections(key: str, text: str, reason: str) -> None:
    with pytest.raises(SettingsError, match=reason):
        settings_module._validate({"questions": {key: text}}, "f.toml")


@pytest.mark.parametrize(
    "text",
    [
        '{{ "".__class__.__mro__ }}',
        "{{ cycler.__init__.__globals__ }}",
        "{{ self._TemplateReference__context }}",
        '{{ "".__class__.__mro__[1].__subclasses__()|length }} which commit?',
        "{{ cycler.__init__.__globals__.os.getcwd() }} which commit?",
        "{{ where.__doc__ }}",
        "{% set x = '__' %}{{ where }}",  # a literal is enough to refuse
    ],
)
def test_question_override_refuses_template_injection(text: str) -> None:
    """A repository's file may not turn into code execution through a question template."""
    with pytest.raises(SettingsError, match="restricted attribute"):
        settings_module._validate({"questions": {"C03.never_in_history_core": text}}, "f")


def test_override_environment_is_a_sandbox() -> None:
    """What refuses the attribute walk at render time, for the consumer of the overrides."""
    env = override_environment()
    assert isinstance(env, ImmutableSandboxedEnvironment)
    assert env is override_environment()  # built once
    assert env.loader is None  # an override cannot pull in other files
    for source in (
        "{{ x.__class__ }}",
        "{{ x.__class__.__mro__[1].__subclasses__() }}",
        "{{ items.append(1) }}",
        "{{ x.format.__globals__ }}",
    ):
        with pytest.raises(SecurityError):
            env.from_string(source).render(x="", items=[])


def test_override_environment_matches_the_plain_one_for_honest_templates() -> None:
    """Same filters, same undefined behaviour, same trimming as the bundled templates get."""
    source = (
        "{% if releases %}Which of {{ releases | listed }} ({{ releases | ranged }}) "
        "at {{ commit | short }}?{% endif %}"
    )
    context = {"releases": ["1.0", "1.1", "1.2", "1.3"], "commit": "0123456789abcdef"}
    sandboxed = override_environment().from_string(source).render(context)
    plain = plain_environment().from_string(source).render(context)
    assert sandboxed == plain
    assert "and 1 others" in sandboxed
    assert "0123456789ab?" in sandboxed
    with pytest.raises(Exception, match="undefined"):
        override_environment().from_string("{{ nope }}").render()


@pytest.mark.parametrize(
    "text",
    [
        "This looks fake, which commit?",
        "Was this generated by AI?",
        "Which LLM wrote {{ path }}?",
        "The trace is bogus; which commit?",
    ],
)
def test_question_override_must_keep_the_tone_rules(text: str) -> None:
    """P1: an override is sent to a reporter under the same rules as the bundled text."""
    with pytest.raises(SettingsError, match=r"\(P1\)"):
        settings_module._validate({"questions": {"C03.never_in_history_core": text}}, "f")


def test_question_override_tone_rule_matches_whole_words_only() -> None:
    loaded = Settings.model_validate(
        {"questions": {_KEY: "Could you explain in detail which commit added {{ symbol }}?"}}
    )
    assert loaded.question_overrides()[_KEY].startswith("Could you explain")


def test_question_override_nested_too_deep_is_an_error() -> None:
    with pytest.raises(SettingsError, match="nested too deeply"):
        settings_module._validate({"questions": {"C03": {"x": {"y": "z"}}}}, "f")


def test_question_override_value_must_be_text() -> None:
    with pytest.raises(SettingsError, match=r"questions.*C03\.x.*must be text"):
        settings_module._validate({"questions": {"C03.x": 1}}, "f")


def test_question_overrides_of_the_wrong_shape_are_named() -> None:
    with pytest.raises(SettingsError, match="questions"):
        settings_module._validate({"questions": 5}, "f")
    with pytest.raises(SettingsError, match="questions"):
        settings_module._validate({"questions": ["C03.x"]}, "f")


def test_too_many_question_overrides() -> None:
    many = {f"C03.o{i}": "Which one?" for i in range(300)}
    with pytest.raises(SettingsError, match="at most"):
        settings_module._validate({"questions": many}, "f")


# --- [ignore] -------------------------------------------------------------------------------------


def test_ignore_globs_use_the_known_projects_dialect() -> None:
    loaded = Settings.model_validate(
        {"ignore": {"paths": ["vendor/**", "./third_party/*", "/build/*.c", "config.h"]}}
    )
    assert loaded.ignore.paths == ("vendor/**", "third_party/*", "build/*.c", "config.h")
    assert loaded.is_ignored("vendor/zlib/inflate.c")
    assert loaded.is_ignored("third_party/x.c")
    assert not loaded.is_ignored("third_party/deep/x.c")
    assert loaded.is_ignored("build/gen.c")
    assert loaded.is_ignored("src/config.h")  # a bare name matches the basename anywhere
    assert not loaded.is_ignored("src/hdr.c")


_GLOB_CASES = [
    "vendor/**",
    "**/x.c",
    "a/**/b",
    "**",
    "*.c",
    "src/*/x?.c",
    "a**b",
    "**/**/x",
    "config.h",
    "x/*",
]
_PATH_CASES = [
    "vendor/zlib/inflate.c",
    "x.c",
    "a/x.c",
    "a/b",
    "a/c/d/b",
    "ab",
    "a/b/b",
    "src/k/x1.c",
    "src/k/x12.c",
    "x/y/z",
    "x/y",
    "config.h",
    "q/config.h",
    "",
    "a//b",
]


@pytest.mark.parametrize("glob", _GLOB_CASES)
def test_ignore_matcher_agrees_with_the_known_projects_dialect(glob: str) -> None:
    for path in _PATH_CASES:
        assert ignore_match(glob, path) == glob_match(glob, path), (glob, path)


@pytest.mark.parametrize(
    ("glob", "path"),
    [
        ("*a" * 60 + "b", "a" * 5000),
        ("**/" * 60 + "x", "a/" * 3000 + "y"),
        ("**a" * 60, "a" * 5000),
    ],
)
@pytest.mark.no_cover  # the budget measures the matcher, not coverage.py's tracer (~5x)
def test_a_hostile_ignore_glob_is_matched_in_linear_time(glob: str, path: str) -> None:
    # The regex translation takes exponential time on these; the file is repository-controlled.
    loaded = Settings.model_validate({"ignore": {"paths": [glob]}})
    began = time.perf_counter()
    loaded.is_ignored(path)
    assert time.perf_counter() - began < 2.0


# --- [llm] ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("provider", "name", "model", "cloud"),
    [
        ("none", "none", None, False),
        ("ollama", "ollama", None, False),
        ("ollama:llama3.1:8b", "ollama", "llama3.1:8b", False),
        ("anthropic:some-model", "anthropic", "some-model", True),
        ("openai", "openai", None, True),
    ],
)
def test_llm_provider_spec(provider: str, name: str, model: str | None, cloud: bool) -> None:
    llm = LLMSettings(provider=provider)
    assert llm.provider_name == name
    assert llm.model_name == model
    assert llm.is_cloud is cloud
    assert llm.enabled is (name != "none")


@pytest.mark.parametrize("value", ['"true"', "1", '"yes"', "[true]"])
def test_allow_cloud_is_a_strict_boolean(isolated: SimpleNamespace, value: str) -> None:
    write(isolated.root / "nikasha.toml", f"[llm]\nallow_cloud = {value}\n")
    with pytest.raises(SettingsError, match=r"llm.allow_cloud"):
        load_settings(isolated.root)


def test_allow_cloud_true_needs_a_file(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", "[llm]\nprovider = 'anthropic'\nallow_cloud = true\n")
    loaded = load_settings(isolated.root)
    assert loaded.llm.allow_cloud is True
    assert loaded.llm.is_cloud is True


def test_allow_cloud_cannot_come_from_the_process_environment(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """P3: cloud LLMs are opt-in by file only. No variable name, however plausible, counts."""
    for name in (
        "NIKASHA_LLM_ALLOW_CLOUD",
        "NIKASHA_ALLOW_CLOUD",
        "NIKASHA_LLM__ALLOW_CLOUD",
        "LLM_ALLOW_CLOUD",
        "ALLOW_CLOUD",
        "NIKASHA_LLM",
        "NIKASHA_LLM_PROVIDER",
    ):
        monkeypatch.setenv(name, "true")
    monkeypatch.setenv("NIKASHA_LLM_PROVIDER", "anthropic:x")

    assert load_settings(isolated.root).llm.allow_cloud is False
    write(isolated.root / "nikasha.toml", "[llm]\nprovider = 'anthropic'\nallow_cloud = false\n")
    loaded = load_settings(isolated.root)
    assert loaded.llm.allow_cloud is False
    assert loaded.llm.provider == "anthropic"


def test_settings_module_never_reads_process_variables() -> None:
    """The static half of the P3 guarantee: no ``os.environ``/``getenv`` anywhere in it."""
    source = inspect.getsource(settings_module)
    assert "os.environ" not in source
    assert "getenv" not in source
    assert re.search(r"^\s*(import os\b|from os\b)", source, re.MULTILINE) is None


# --- discovery -----------------------------------------------------------------------------


def test_nearest_file_wins_walking_up(isolated: SimpleNamespace) -> None:
    top = write(isolated.root / "nikasha.toml", "[scoring]\nprior = 1.0\n")
    deep = isolated.root / "a" / "b" / "c"
    deep.mkdir(parents=True)
    assert repo_config_path(deep) == top
    assert load_settings(deep).prior() == 1.0

    nearer = write(isolated.root / "a" / "nikasha.toml", "[scoring]\nprior = 2.0\n")
    assert repo_config_path(deep) == nearer
    assert load_settings(deep).prior() == 2.0


def test_a_file_beside_a_report_is_never_loaded(isolated: SimpleNamespace, tmp_path: Path) -> None:
    """A report is hostile input (P7): the directory it was unpacked into chooses nothing.

    Without a ``.git`` anywhere near it, a ``nikasha.toml`` next to the report used to be
    found by walking up from the report's own directory, which would let an attachment
    archive enable a cloud LLM (P3) or loosen the UNGROUNDED ladder (P4).
    """
    unzipped = tmp_path / "unzipped"
    write(
        unzipped / "nikasha.toml",
        "[llm]\nallow_cloud = true\n[thresholds]\nungrounded_score = 90\n",
    )
    report = write(unzipped / "report.md", "# report\n")
    assert not any(p.name == ".git" for p in unzipped.iterdir())

    loaded = load_settings(isolated.root)  # start is the working directory, elsewhere
    assert loaded.llm.allow_cloud is False
    assert loaded.limits.ungrounded_score == Thresholds().ungrounded_score
    with pytest.raises(SettingsError, match="starts from a directory"):
        load_settings(report)  # and the report itself is refused as a start


def test_start_must_be_an_existing_directory(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", "[scoring]\nprior = 1.0\n")
    report = write(isolated.root / "reports" / "r.md", "# report\n")
    with pytest.raises(SettingsError, match="starts from a directory") as excinfo:
        repo_config_path(report)
    assert str(report) in str(excinfo.value)
    with pytest.raises(SettingsError, match="starts from a directory"):
        repo_config_path(isolated.root / "missing")
    with pytest.raises(SettingsError, match="starts from a directory"):
        config_files(report)


def test_git_directory_is_a_boundary(isolated: SimpleNamespace, tmp_path: Path) -> None:
    """A file above the repository must not apply to it."""
    outside = write(tmp_path / "nikasha.toml", "[scoring]\nprior = 9.0\n")
    assert outside.is_file()
    inner = isolated.root / "src"
    inner.mkdir()
    assert repo_config_path(inner) is None
    assert load_settings(inner).prior() == 0.0


def test_git_file_is_a_boundary_too(isolated: SimpleNamespace, tmp_path: Path) -> None:
    """Worktrees have a ``.git`` file, not a directory."""
    write(tmp_path / "nikasha.toml", "[scoring]\nprior = 9.0\n")
    worktree = tmp_path / "wt"
    write(worktree / ".git", "gitdir: /somewhere/else\n")
    (worktree / "src").mkdir()
    assert repo_config_path(worktree / "src") is None


def test_the_boundary_directory_itself_is_searched(isolated: SimpleNamespace) -> None:
    here = write(isolated.root / "nikasha.toml", "")
    assert repo_config_path(isolated.root) == here


def test_walk_is_capped(
    isolated: SimpleNamespace, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk visits at most ``MAX_WALK`` directories, whatever lies above them."""
    deep = tmp_path / "walk" / "a" / "b" / "c"
    deep.mkdir(parents=True)
    monkeypatch.setattr(settings_module, "MAX_WALK", 2)
    started = time.perf_counter()
    assert repo_config_path(deep) is None  # c and b only: no .git, no file, and it stops
    assert time.perf_counter() - started < 1.0

    found = write(tmp_path / "walk" / "a" / "nikasha.toml", "")
    monkeypatch.setattr(settings_module, "MAX_WALK", 1)
    assert repo_config_path(deep) is None  # the cap is honoured: only c is looked at
    monkeypatch.setattr(settings_module, "MAX_WALK", 2)
    assert repo_config_path(deep) is None  # c and b
    monkeypatch.setattr(settings_module, "MAX_WALK", 3)
    assert repo_config_path(deep) == found  # c, b, a


def test_default_start_is_the_working_directory(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    here = write(isolated.root / "nikasha.toml", "[scoring]\nprior = 3.0\n")
    monkeypatch.chdir(isolated.root)
    assert repo_config_path() == here
    assert load_settings().prior() == 3.0


def test_filesystem_errors_become_settings_errors(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Permission denied (or ELOOP, or an invalid path) is a message, not a traceback."""
    real_is_file = Path.is_file

    def denied(self: Path, *args: object, **kwargs: object) -> bool:
        if self.name == "nikasha.toml":
            raise PermissionError(13, "Permission denied")
        return real_is_file(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_file", denied)
    with pytest.raises(SettingsError, match="cannot read") as excinfo:
        repo_config_path(isolated.root)
    assert "Permission denied" in str(excinfo.value)
    with pytest.raises(SettingsError, match="cannot read"):
        config_files(isolated.root)
    with pytest.raises(SettingsError, match="cannot read"):
        load_settings(isolated.root, isolated.root / "nikasha.toml")


def test_calibration_filesystem_errors_name_the_key(
    isolated: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(isolated.root / "nikasha.toml", "[scoring]\ncalibration = 'cal.yaml'\n")
    real_is_file = Path.is_file

    def denied(self: Path, *args: object, **kwargs: object) -> bool:
        if self.name == "cal.yaml":
            raise PermissionError(13, "Permission denied")
        return real_is_file(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_file", denied)
    with pytest.raises(SettingsError, match=r"scoring\.calibration: cannot read"):
        load_settings(isolated.root)


# --- precedence ----------------------------------------------------------------------------


def test_precedence_user_then_repo_then_explicit(isolated: SimpleNamespace, tmp_path: Path) -> None:
    user = write(
        isolated.user_file,
        "[thresholds]\ngrounded_score = 80\n[llm]\nprovider = 'ollama:llama3'\n",
    )
    repo = write(
        isolated.root / "nikasha.toml",
        "[thresholds]\ngrounded_score = 85\n[project]\nname = 'libhdr'\n",
    )
    explicit = write(tmp_path / "custom.toml", "[thresholds]\ngrounded_score = 90\n")

    assert config_files(isolated.root, explicit) == (user, repo, explicit)
    loaded = load_settings(isolated.root, explicit)
    assert loaded.limits.grounded_score == 90  # explicit beats repo beats user
    assert loaded.llm.provider == "ollama:llama3"  # untouched user key survives (deep merge)
    assert loaded.project.name == "libhdr"  # untouched repo key survives
    assert loaded.limits.ungrounded_score == 15  # nothing set it: the default


def test_user_level_alone(isolated: SimpleNamespace) -> None:
    write(isolated.user_file, "[llm]\nprovider = 'ollama'\n")
    assert config_files(isolated.root) == (isolated.user_file,)
    assert load_settings(isolated.root).llm.provider == "ollama"


def test_explicit_alone_and_missing(isolated: SimpleNamespace, tmp_path: Path) -> None:
    explicit = write(tmp_path / "x.toml", "[scoring]\nprior = 0.25\n")
    assert load_settings(isolated.root, explicit).prior() == 0.25
    with pytest.raises(SettingsError, match="no such configuration file"):
        load_settings(isolated.root, tmp_path / "missing.toml")


def test_the_same_file_is_read_once(isolated: SimpleNamespace) -> None:
    repo = write(isolated.root / "nikasha.toml", "[scoring]\nprior = 0.25\n")
    assert config_files(isolated.root, repo) == (repo,)


def test_arrays_replace_rather_than_append(isolated: SimpleNamespace) -> None:
    write(isolated.user_file, "[ignore]\npaths = ['a/**']\n")
    write(isolated.root / "nikasha.toml", "[ignore]\npaths = ['b/**']\n")
    assert load_settings(isolated.root).ignore.paths == ("b/**",)


def test_question_overrides_from_both_layers_are_kept(isolated: SimpleNamespace) -> None:
    write(isolated.user_file, '[questions]\n"C03.never_in_history_core" = "Which path?"\n')
    write(isolated.root / "nikasha.toml", '[questions]\n"C02.never_in_history" = "Which?"\n')
    loaded = load_settings(isolated.root)
    assert loaded.question_overrides() == {
        "C02.never_in_history": "Which?",
        "C03.never_in_history_core": "Which path?",
    }
    assert loaded.questions[0][0] == "C02.never_in_history"  # sorted, not in layer order


def test_question_override_in_a_later_layer_replaces_the_same_key(
    isolated: SimpleNamespace,
) -> None:
    write(isolated.user_file, '[questions]\n"C03.never_in_history_core" = "Which path?"\n')
    write(isolated.root / "nikasha.toml", '[questions]\n"C03.never_in_history_core" = "Which?"\n')
    assert load_settings(isolated.root).question_overrides() == {
        "C03.never_in_history_core": "Which?"
    }


def test_conflict_that_only_appears_when_merged_names_both_files(
    isolated: SimpleNamespace,
) -> None:
    user = write(isolated.user_file, "[thresholds]\nungrounded_score = 40\n")  # valid alone
    repo = write(isolated.root / "nikasha.toml", "[thresholds]\ngrounded_score = 30\n")  # valid
    with pytest.raises(SettingsError, match="grounded_score must be above") as excinfo:
        load_settings(isolated.root)
    assert str(user) in str(excinfo.value)
    assert str(repo) in str(excinfo.value)


def test_the_first_bad_file_is_named_even_when_a_later_one_is_fine(
    isolated: SimpleNamespace,
) -> None:
    user = write(isolated.user_file, "[llm]\nprovider = 'nope'\n")
    write(isolated.root / "nikasha.toml", "")
    with pytest.raises(SettingsError) as excinfo:
        load_settings(isolated.root)
    assert str(user) in str(excinfo.value)
    assert "llm.provider" in str(excinfo.value)


# --- [scoring] calibration ------------------------------------------------------------------------


def test_calibration_is_relative_to_the_file_that_names_it(isolated: SimpleNamespace) -> None:
    table = write(
        isolated.root / "calibration" / "calibration-v2.yaml",
        "version: 2\nchecks:\n  C03:\n    never_in_history_core: -2.5\n",
    )
    write(
        isolated.root / "nikasha.toml",
        "[scoring]\ncalibration = 'calibration/calibration-v2.yaml'\n",
    )
    sub = isolated.root / "deep"
    sub.mkdir()
    loaded = load_settings(sub)
    assert loaded.scoring.calibration == table.resolve()
    strengths = loaded.strengths()
    assert strengths.version == "calibration-v2"
    assert strengths.get("C03", "never_in_history_core") == -2.5


def test_missing_calibration_file_names_file_and_key(isolated: SimpleNamespace) -> None:
    path = write(isolated.root / "nikasha.toml", "[scoring]\ncalibration = 'nope.yaml'\n")
    with pytest.raises(SettingsError, match=r"scoring.calibration") as excinfo:
        load_settings(isolated.root)
    assert str(path) in str(excinfo.value)


# --- hostile files fail cleanly -------------------------------------------------------------------


def test_huge_file_is_refused_unread(isolated: SimpleNamespace) -> None:
    path = isolated.root / "nikasha.toml"
    path.write_bytes(b"# " + b"x" * (MAX_CONFIG_BYTES + 1) + b"\n")
    with pytest.raises(SettingsError, match="limit") as excinfo:
        load_settings(isolated.root)
    assert str(path) in str(excinfo.value)


def test_deeply_nested_inline_tables_fail_cleanly(isolated: SimpleNamespace) -> None:
    depth = 5000
    write(isolated.root / "nikasha.toml", "deep = " + "{a = " * depth + "1" + "}" * depth + "\n")
    with pytest.raises(NikashaError):
        load_settings(isolated.root)


def test_deeply_nested_headers_fail_cleanly(isolated: SimpleNamespace) -> None:
    write(isolated.root / "nikasha.toml", "[questions" + ".a" * 500 + "]\nk = 'v'\n")
    with pytest.raises(NikashaError, match="nested too deeply"):
        load_settings(isolated.root)
    write(isolated.root / "nikasha.toml", "[project" + ".a" * 500 + "]\nk = 'v'\n")
    with pytest.raises(NikashaError, match=r"unknown key project.a"):
        load_settings(isolated.root)


def test_non_utf8_is_refused(isolated: SimpleNamespace) -> None:
    path = isolated.root / "nikasha.toml"
    path.write_bytes(b"[project]\nname = 'caf\xe9'\n")
    with pytest.raises(SettingsError, match="UTF-8") as excinfo:
        load_settings(isolated.root)
    assert str(path) in str(excinfo.value)


def test_utf8_bom_is_tolerated(isolated: SimpleNamespace) -> None:
    path = isolated.root / "nikasha.toml"
    path.write_bytes(b"\xef\xbb\xbf[scoring]\nprior = 0.5\n")
    assert load_settings(isolated.root).prior() == 0.5


def test_control_characters_are_invalid_toml(isolated: SimpleNamespace) -> None:
    path = isolated.root / "nikasha.toml"
    path.write_bytes(b"[project]\nname = 'a\x00b'\n")
    with pytest.raises(SettingsError, match="invalid TOML"):
        load_settings(isolated.root)


def test_explicit_path_that_is_a_directory(isolated: SimpleNamespace, tmp_path: Path) -> None:
    folder = tmp_path / "nikasha.toml"
    folder.mkdir()
    with pytest.raises(SettingsError, match="no such configuration file"):
        load_settings(isolated.root, folder)


def test_a_directory_named_like_the_file_is_skipped_in_discovery(
    isolated: SimpleNamespace,
) -> None:
    (isolated.root / "nikasha.toml").mkdir()
    assert repo_config_path(isolated.root) is None


def _module_patterns() -> list[tuple[str, re.Pattern[str]]]:
    return sorted(
        (name, value)
        for name, value in vars(settings_module).items()
        if isinstance(value, re.Pattern)
    )


@pytest.mark.parametrize(("name", "pattern"), _module_patterns(), ids=lambda p: str(p)[:12])
def test_every_module_pattern_is_linear_time(name: str, pattern: re.Pattern[str]) -> None:
    """The extract-layer ReDoS suite does not walk this module, so it is timed here."""
    hostile = ["a" * 40_000, "a:" * 20_000, ":" * 40_000, "-" * 40_000, "ai " * 13_000]
    hostile.append(("x" * 39_999) + "\x00")
    hostile.append("C" + "0" * 39_999)
    started = time.perf_counter()
    for text in hostile:
        pattern.match(text)
        pattern.search(text)
    assert time.perf_counter() - started < 1.0, name


# --- documentation and the example stay honest ----------------------------------------------------


def _documented_keys() -> list[str]:
    keys = ["questions"]
    for section, model in SECTION_MODELS.items():
        keys.extend(f"{section}.{name}" for name in model.model_fields)
    return keys


@pytest.mark.parametrize("key", _documented_keys())
def test_docs_mention_every_key(key: str) -> None:
    text = DOCS.read_text(encoding="utf-8")
    section, _, name = key.partition(".")
    assert f"[{section}]" in text
    if name:
        assert f"`{name}`" in text, f"docs/configuration.md does not document {key}"


def test_docs_state_the_trust_model_and_the_sandbox() -> None:
    text = DOCS.read_text(encoding="utf-8")
    assert "## Trust model" in text
    assert "never taken from report input" in text
    assert "sandbox" in text
    assert "question_overrides()" in text
    assert "XDG_CONFIG_HOME" in text
    assert "given twice" in text or "both spellings" in text


@pytest.mark.parametrize("key", _documented_keys())
def test_example_mentions_every_key(key: str) -> None:
    text = EXAMPLE.read_text(encoding="utf-8")
    section, _, name = key.partition(".")
    assert f"[{section}]" in text
    if name:
        assert re.search(rf"^#?\s*{re.escape(name)}\s*=", text, re.MULTILINE), key


def test_example_file_loads(isolated: SimpleNamespace) -> None:
    loaded = load_settings(isolated.root, EXAMPLE)
    assert loaded.project.name
    assert loaded.llm.allow_cloud is False
    assert loaded.thresholds() == Thresholds()  # the example keeps the calibrated defaults
    assert loaded.question_overrides()


def test_docs_and_example_carry_spdx_headers() -> None:
    # Assembled at run time so the REUSE linter does not read these literals as real tags.
    tag = "SPDX-License" + "-Identifier: "
    assert tag + "CC-BY-4.0" in DOCS.read_text(encoding="utf-8")
    assert tag + "Apache-2.0" in EXAMPLE.read_text(encoding="utf-8")
