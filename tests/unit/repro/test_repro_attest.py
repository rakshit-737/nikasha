# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Attested run kinds, sanitizer abort options, output caps, /poc paths and image IDs."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from nikasha.model.claims import Frame
from nikasha.model.evidence import CommandRecord
from nikasha.repro import build, sandbox
from nikasha.repro.recipes import RecipeError, list_recipes, load_recipe, parse_recipe
from nikasha.repro.run import ReproRun
from nikasha.repro.sandbox import EngineInfo
from nikasha.repro.signature import is_poc_frame

ROOT = Path(__file__).resolve().parents[3]
VULNLAB = (ROOT / "recipes" / "vulnlab.yaml").read_bytes()
DOCKER = EngineInfo("docker", True, "27.3.1", False, "v2")


def _vulnlab() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(VULNLAB)
    return data


def _parse(data: dict[str, Any]) -> Any:
    return parse_recipe(yaml.safe_dump(data).encode())


# --- attested_output --------------------------------------------------------------------


def test_only_vulnlab_file_input_is_attested() -> None:
    attested = {
        (path.stem, name)
        for path in list_recipes()
        for name, kind in load_recipe(path).recipe.run.kinds.items()
        if kind.attested_output
    }
    assert attested == {("vulnlab", "file_input")}


def test_every_shipped_kind_states_attested_output_explicitly() -> None:
    for path in list_recipes():
        raw = yaml.safe_load(path.read_bytes())
        for name, kind in raw["run"]["kinds"].items():
            assert "attested_output" in kind, f"{path.name}: {name}"


def test_attested_output_defaults_to_false() -> None:
    data = _vulnlab()
    del data["run"]["kinds"]["file_input"]["attested_output"]
    assert _parse(data).run.kinds["file_input"].attested_output is False


def test_reprorun_attested_defaults_to_false() -> None:
    record = CommandRecord(argv=("x",), exit_code=0, stdout_sha256="0" * 64, stderr_sha256="0" * 64)
    assert ReproRun("file_input", 0, False, False, "", "", record).attested is False


# --- sanitizer options ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("var", "value", "needs"),
    [
        ("ASAN_OPTIONS", "detect_leaks=0:symbolize=1", "abort_on_error=1"),
        ("ASAN_OPTIONS", "abort_on_error=1:abort_on_error=0", "abort_on_error=1"),
        ("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1", "abort_on_error=1"),
        ("UBSAN_OPTIONS", "abort_on_error=1", "halt_on_error=1"),
    ],
)
def test_sanitizer_recipes_must_abort(var: str, value: str, needs: str) -> None:
    data = _vulnlab()
    data["run"]["env"][var] = value
    with pytest.raises(RecipeError, match=needs):
        _parse(data)


def test_missing_sanitizer_options_variable_is_refused() -> None:
    data = _vulnlab()
    del data["run"]["env"]["ASAN_OPTIONS"]
    with pytest.raises(RecipeError, match="ASAN_OPTIONS"):
        _parse(data)


def test_msan_is_checked_too() -> None:
    data = _vulnlab()
    data["build"]["env"]["CFLAGS"] += " -fsanitize=memory"
    with pytest.raises(RecipeError, match="MSAN_OPTIONS"):
        _parse(data)
    data["run"]["env"]["MSAN_OPTIONS"] = "abort_on_error=1"
    _parse(data)


def test_sanitizer_in_compile_argv_is_checked() -> None:
    data = _vulnlab()
    data["build"]["env"] = {"CC": "clang"}
    del data["run"]["env"]["UBSAN_OPTIONS"]
    with pytest.raises(RecipeError, match="UBSAN_OPTIONS"):
        _parse(data)  # c_harness compiles with -fsanitize=address,undefined


def test_recipe_without_sanitizers_needs_no_options() -> None:
    data = _vulnlab()
    data["build"]["env"] = {"CC": "clang"}
    del data["run"]["kinds"]["c_harness"]
    data["run"]["env"] = {}
    _parse(data)


# --- copy_outputs caps ------------------------------------------------------------------


def test_copy_outputs_refuses_too_many_bytes(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "a").write_bytes(b"x" * 600)
    (out / "b").write_bytes(b"x" * 600)
    with pytest.raises(build.BuildFailedError, match="exceed"):
        build.copy_outputs(out, tmp_path / "dest", max_bytes=1000)
    build.copy_outputs(out, tmp_path / "ok", max_bytes=1200)
    assert (tmp_path / "ok" / "b").read_bytes() == b"x" * 600


def test_copy_outputs_refuses_too_many_entries(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "d").mkdir(parents=True)
    for i in range(5):
        (out / "d" / f"f{i}").write_bytes(b"")
    with pytest.raises(build.BuildFailedError, match="exceed"):
        build.copy_outputs(out, tmp_path / "dest", max_entries=5)
    build.copy_outputs(out, tmp_path / "ok", max_entries=6)


def test_copy_budget_catches_a_file_that_grew(tmp_path: Path) -> None:
    src = tmp_path / "f"
    src.write_bytes(b"y" * 100)
    with pytest.raises(build.BuildFailedError):
        build._copy_regular(src, tmp_path / "g", 99)
    assert build._copy_regular(src, tmp_path / "h", 100) == 100


def test_default_caps_are_sensible() -> None:
    assert build.MAX_OUTPUT_BYTES == 1024**3
    assert build.MAX_OUTPUT_ENTRIES == 10_000


# --- /poc paths -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "under"),
    [
        ("/poc/poc.c", True),
        ("/poc", True),
        ("/work/../poc/poc.c", True),
        ("//poc/poc.c", True),
        ("/poc/./x/../poc.c", True),
        ("\\poc\\poc.c", True),
        ("/poc/../work/src/a.c", False),
        ("/pocket/a.c", False),
        ("/work/poc/a.c", False),
    ],
)
def test_poc_paths_are_normalised(path: str, under: bool) -> None:
    assert is_poc_frame(Frame(index=0, function="f", path=path, raw="#0")) is under


# --- image_id ---------------------------------------------------------------------------


def _fake_run(stdout: bytes, code: int = 0) -> Any:
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        assert kwargs.get("timeout") and "shell" not in kwargs
        return subprocess.CompletedProcess(argv, code, stdout, b"")

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_image_id_reads_inspect_format(monkeypatch: pytest.MonkeyPatch) -> None:
    ident = "sha256:" + "ab" * 32
    fake = _fake_run(ident.encode() + b"\n")
    monkeypatch.setattr(sandbox, "engine_executable", lambda e: "/usr/bin/docker")
    monkeypatch.setattr(sandbox.subprocess, "run", fake)  # type: ignore[attr-defined]
    assert sandbox.image_id(DOCKER, "nikasha/recipe-c:1") == ident
    assert fake.calls == [
        ["/usr/bin/docker", "image", "inspect", "--format", "{{.Id}}", "nikasha/recipe-c:1"]
    ]


@pytest.mark.parametrize(("stdout", "code"), [(b"", 1), (b"garbage\n", 0), (b"sha256:zz", 0)])
def test_image_id_unknown(monkeypatch: pytest.MonkeyPatch, stdout: bytes, code: int) -> None:
    monkeypatch.setattr(sandbox, "engine_executable", lambda e: "/usr/bin/docker")
    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run(stdout, code))  # type: ignore[attr-defined]
    assert sandbox.image_id(DOCKER, "nikasha/recipe-c:1") is None


def test_image_id_refuses_option_like_tags() -> None:
    with pytest.raises(sandbox.SandboxError):
        sandbox.image_id(DOCKER, "--help")
