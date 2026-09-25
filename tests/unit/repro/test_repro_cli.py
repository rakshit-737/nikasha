# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha repro`` and ``nikasha recipes`` through a Typer app that registers them."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from nikasha.repro.cli import register, terminal_safe

ROOT = Path(__file__).resolve().parents[3]
runner = CliRunner()


def _app() -> typer.Typer:
    app = typer.Typer()

    @app.command()
    def version() -> None:  # a second command, so Typer keeps sub-command names
        typer.echo("x")

    register(app)
    return app


APP = _app()


def test_repro_refuses_without_an_engine(tmp_path, monkeypatch):
    """The real refusal path: an empty PATH means no podman or docker can be found."""
    monkeypatch.setenv("PATH", str(tmp_path))
    poc = tmp_path / "crash.bin"
    poc.write_bytes(b"x")
    result = runner.invoke(
        APP,
        [
            *("repro", "--repo", str(tmp_path), "--ref", "v1.2.0"),
            *("--recipe", "vulnlab", "--poc", str(poc)),
        ],
    )
    assert result.exit_code == 1
    assert "no container engine is available" in result.output
    assert "never run on the host" in result.output


def test_repro_refuses_a_named_engine_that_is_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    result = runner.invoke(
        APP,
        [
            *("repro", "--repo", ".", "--ref", "x", "--recipe", "vulnlab"),
            *("--poc", "p", "--sandbox", "docker"),
        ],
    )
    assert result.exit_code == 1
    assert "--sandbox docker" in result.output


def test_recipes_list() -> None:
    result = runner.invoke(APP, ["recipes", "list"])
    assert result.exit_code == 0
    ids = [line.split("\t")[0] for line in result.output.splitlines()]
    assert ids == ["curl", "libxml2", "sqlite", "vulnlab"]


def test_recipes_show_is_json_with_sha() -> None:
    result = runner.invoke(APP, ["recipes", "show", "vulnlab"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["recipe"]["id"] == "vulnlab"
    assert len(payload["sha256"]) == 64


def test_recipes_show_unknown_fails() -> None:
    result = runner.invoke(APP, ["recipes", "show", "nope"])
    assert result.exit_code == 1
    assert "no recipe named" in result.output


def test_recipes_validate_all_shipped() -> None:
    result = runner.invoke(APP, ["recipes", "validate"])
    assert result.exit_code == 0, result.output
    assert result.output.count("ok\t") == 4


def test_recipes_validate_reports_bad_files(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: bad\ntitle: x\n", encoding="utf-8")
    result = runner.invoke(APP, ["recipes", "validate", str(bad)])
    assert result.exit_code == 1
    assert "invalid\tbad.yaml" in result.output


@pytest.mark.parametrize("value", ["0", "-5", "3601", "nan", "inf"])
def test_repro_rejects_out_of_range_timeouts(tmp_path, value):
    result = runner.invoke(
        APP,
        [
            *("repro", "--repo", ".", "--ref", "x", "--recipe", "vulnlab"),
            *("--poc", "p", "--timeout", value),
        ],
    )
    assert result.exit_code == 1
    assert "--timeout must be" in result.output


def test_terminal_safe_neutralizes_escape_sequences() -> None:
    hostile = "a\x1b[2Jb\x1b]0;title\x07c\x1b]52;c;ZXZpbA==\x07\x9b31m\x7fd\te\nf"
    safe = terminal_safe(hostile)
    assert not any(ord(ch) < 0x20 and ch not in "\t\n" for ch in safe)
    assert not any(0x7F <= ord(ch) < 0xA0 for ch in safe)
    assert "\\x1b[2J" in safe and "\\x9b" in safe
    assert safe.endswith("d\te\nf")


def test_terminal_safe_escapes_bidi_overrides() -> None:
    assert terminal_safe("a\u202eb\u2066c") == "a\\u202eb\\u2066c"


HOSTILE = (
    "boom\x1b[2J\x1b]0;pwned\x07\x1b]52;c;ZXZpbA==\x07"
    "\x1b]8;;http://x\x07link\x9b1m :smile: [red]x[/]"
)


def _fake_pipeline(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    """Every stage of ``repro`` replaced by a stand-in; the run's stderr is hostile."""
    from nikasha.model.evidence import CommandRecord  # noqa: PLC0415
    from nikasha.repro import build, run, sandbox  # noqa: PLC0415
    from nikasha.resolve import repo as resolve_repo  # noqa: PLC0415

    engine = sandbox.EngineInfo("docker", True, version="t", rootless=False)
    record = CommandRecord(
        argv=("docker", "run"), exit_code=1, stdout_sha256="0" * 64, stderr_sha256="0" * 64
    )

    class _Repo:
        def __enter__(self):  # type: ignore[no-untyped-def]
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def rev_parse(self, ref: str) -> str:
            return "a" * 40

    monkeypatch.setattr(sandbox, "select_engine", lambda choice: engine)
    monkeypatch.setattr(sandbox, "image_exists", lambda e, tag: True)
    monkeypatch.setattr(resolve_repo, "open_repo", lambda repo, online: _Repo())
    monkeypatch.setattr(
        build,
        "build",
        lambda *a, **k: build.BuildResult(tmp_path, cached=True, log="", record=record),
    )
    monkeypatch.setattr(
        run,
        "run_poc",
        lambda *a, **k: run.ReproRun("file_input", 1, False, False, HOSTILE, HOSTILE, record),
    )


def test_repro_output_never_passes_terminal_controls(tmp_path, monkeypatch):
    _fake_pipeline(monkeypatch, tmp_path)
    poc = tmp_path / "crash.bin"
    poc.write_bytes(b"x")
    args = ["repro", "--repo", ".", "--ref", "v1", "--recipe", "vulnlab", "--poc", str(poc)]
    result = runner.invoke(APP, args)
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "\x9b" not in result.output
    assert "\\x1b[2J" in result.output  # shown, but inert
    assert ":smile: [red]x[/]" in result.output  # verbatim: no emoji or markup rendering
    as_json = runner.invoke(APP, [*args, "--json"])
    assert as_json.exit_code == 0
    assert "\x1b" not in as_json.output  # JSON escapes controls as \\u001b
    assert json.loads(as_json.output)["run"]["stderr"] == HOSTILE


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows file names cannot hold control characters"
)
def test_recipes_validate_escapes_hostile_file_names(tmp_path):
    bad = tmp_path / "x\x1b]0;t\x07.yaml"
    bad.write_text("id: [unclosed\n", encoding="utf-8")
    result = runner.invoke(APP, ["recipes", "validate", str(bad)])
    assert result.exit_code == 1
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "\\x1b]0;t\\x07.yaml" in result.output
