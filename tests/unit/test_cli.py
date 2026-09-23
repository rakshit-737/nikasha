# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import json

import pytest
from typer.testing import CliRunner

from nikasha import __version__
from nikasha.cli import app
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
