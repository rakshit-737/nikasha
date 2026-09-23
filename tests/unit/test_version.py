# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import importlib.metadata
import tomllib
from pathlib import Path

from packaging.version import Version

import nikasha
from nikasha.version import __version__

ROOT = Path(__file__).resolve().parents[2]


def test_version_is_pep440():
    Version(__version__)


def test_package_exports_same_version():
    assert nikasha.__version__ == __version__


def test_pyproject_reads_version_from_version_module():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" in pyproject["project"]["dynamic"]
    assert "version" not in pyproject["project"]
    assert pyproject["tool"]["hatch"]["version"]["path"] == "src/nikasha/version.py"


def test_installed_metadata_matches():
    assert Version(importlib.metadata.version("nikasha")) == Version(__version__)
