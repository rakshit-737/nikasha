# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha repro`` and ``nikasha recipes`` through a Typer app that registers them."""

from __future__ import annotations

import json
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


def test_recipes_list():
    result = runner.invoke(APP, ["recipes", "list"])
    assert result.exit_code == 0
    ids = [line.split("\t")[0] for line in result.output.splitlines()]
    assert ids == ["curl", "libxml2", "sqlite", "vulnlab"]


def test_recipes_show_is_json_with_sha():
    result = runner.invoke(APP, ["recipes", "show", "vulnlab"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["recipe"]["id"] == "vulnlab"
    assert len(payload["sha256"]) == 64


def test_recipes_show_unknown_fails():
    result = runner.invoke(APP, ["recipes", "show", "nope"])
    assert result.exit_code == 1
    assert "no recipe named" in result.output


def test_recipes_validate_all_shipped():
    result = runner.invoke(APP, ["recipes", "validate"])
    assert result.exit_code == 0, result.output
    assert result.output.count("ok\t") == 4


def test_recipes_validate_reports_bad_files(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: bad\ntitle: x\n", encoding="utf-8")
    result = runner.invoke(APP, ["recipes", "validate", str(bad)])
    assert result.exit_code == 1
    assert "invalid\tbad.yaml" in result.output


@pytest.mark.parametrize("value", ["0", "-5", "3601"])
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


def test_terminal_safe_neutralizes_escape_sequences():
    hostile = "a\x1b[2Jb\x1b]0;title\x07c\x1b]52;c;ZXZpbA==\x07\x9b31m\x7fd\te\nf"
    safe = terminal_safe(hostile)
    assert not any(ord(ch) < 0x20 and ch not in "\t\n" for ch in safe)
    assert not any(0x7F <= ord(ch) < 0xA0 for ch in safe)
    assert "\\x1b[2J" in safe and "\\x9b" in safe
    assert safe.endswith("d\te\nf")
