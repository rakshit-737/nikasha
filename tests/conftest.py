# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures."""

from __future__ import annotations

import importlib.util
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_forced_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI sets FORCE_COLOR for readable logs; tests assert on plain CLI text."""
    monkeypatch.delenv("FORCE_COLOR", raising=False)


@pytest.fixture(scope="session")
def vulnlab_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The deterministic vulnlab history, built once per test session (a bare repo)."""
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    spec = importlib.util.spec_from_file_location(
        "build_vulnlab", ROOT / "scripts" / "build_vulnlab.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dest = tmp_path_factory.mktemp("vulnlab") / "libhdr.git"
    module.build_vulnlab(dest)
    return dest
