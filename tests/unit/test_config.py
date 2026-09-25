# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import os
import stat
from pathlib import Path

import pytest

from nikasha import config


def test_cache_dir_env_override(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NIKASHA_CACHE_DIR", str(tmp_path / "c"))
    assert config.cache_dir() == tmp_path / "c"


def test_cache_dir_default_mentions_app(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NIKASHA_CACHE_DIR", raising=False)
    assert "nikasha" in str(config.cache_dir()).lower()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_private_dir_is_owner_only(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b"
    config.ensure_private_dir(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_private_dir_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "x"
    config.ensure_private_dir(target)
    config.ensure_private_dir(target)
    assert target.is_dir()
