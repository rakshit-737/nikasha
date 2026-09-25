# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import json

import pytest
from typer.testing import CliRunner

from nikasha import __version__
from nikasha.cli import INTEGRATIONS, MISSING_INTEGRATIONS, app, status_symbols
from nikasha.code import gitio

runner = CliRunner()


def test_version_prints_single_sourced_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert "doctor" in result.output
    assert "version" in result.output


def test_doctor_json_is_well_formed(tmp_path, monkeypatch):
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.stdout)
    names = [c["name"] for c in payload["checks"]]
    assert {"python", "git", "cache", "podman", "docker", "network"} <= set(names)
    assert all(c["status"] in {"ok", "warn", "fail"} for c in payload["checks"])
    assert result.exit_code == (0 if payload["ok"] else 1)


def test_doctor_fails_without_git(tmp_path, monkeypatch):
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(gitio, "git_version", lambda: None)
    result = runner.invoke(app, ["doctor", "--json"])
    payload = json.loads(result.stdout)
    assert result.exit_code == 1
    assert payload["ok"] is False
    git = next(c for c in payload["checks"] if c["name"] == "git")
    assert git["status"] == "fail"


@pytest.mark.parametrize("args", [["doctor"], ["doctor", "--json"]])
def test_doctor_table_and_json_agree_on_exit_code(tmp_path, monkeypatch, args):
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    json_code = runner.invoke(app, ["doctor", "--json"]).exit_code
    assert runner.invoke(app, args).exit_code == json_code


@pytest.mark.parametrize("encoding", ["cp1252", "ascii", "latin-1", "no-such-codec"])
def test_legacy_encodings_fall_back_to_ascii(encoding):
    symbols = status_symbols(encoding)
    assert all(ch.isascii() for ch in "".join(symbols.values()))


@pytest.mark.parametrize("encoding", ["utf-8", "UTF-8", None])
def test_utf8_uses_check_marks(encoding):
    assert status_symbols(encoding)["ok"] == "✓"


def test_ascii_flag_forces_ascii():
    assert status_symbols("utf-8", force_ascii=True)["ok"] == "+"


def test_doctor_table_survives_cp1252_stdout(tmp_path, monkeypatch):
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "cache"))
    result = CliRunner(charset="cp1252").invoke(app, ["doctor"])
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "doctor" in result.output


# --- integration hooks (SPEC §16) --------------------------------------------------------


def test_every_integration_registered_itself() -> None:
    """A missing integration module is a packaging fault, not a shorter CLI (SPEC §16).

    `cli.py` tolerates an absent or half-written module while a milestone is in flight so
    the rest of the CLI keeps working; this test is what makes that tolerance safe.
    """
    assert MISSING_INTEGRATIONS == (), f"not registered: {MISSING_INTEGRATIONS}"
    assert len(INTEGRATIONS) == 8


@pytest.mark.parametrize(
    "command", ["lint", "cve", "h1", "gh-advisories", "mcp", "serve", "repro", "recipes", "bench"]
)
def test_integration_commands_have_help(command: str) -> None:
    result = CliRunner().invoke(app, [command, "--help"])
    assert result.exit_code == 0, result.output
    assert "Example" in result.output or "Usage" in result.output
