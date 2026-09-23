# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Filesystem locations for caches and user configuration.

Caches may hold embargoed report text, so they are created with owner-only permissions
(0700 for directories) wherever the platform supports POSIX modes (P3).
"""

from __future__ import annotations

import os
from pathlib import Path

import platformdirs

APP_NAME = "nikasha"
CACHE_DIR_MODE = 0o700


def cache_dir() -> Path:
    """Return the user cache directory, honouring ``NIKASHA_CACHE_DIR`` when set."""
    override = os.environ.get("NIKASHA_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return platformdirs.user_cache_path(APP_NAME, appauthor=False)


def config_dir() -> Path:
    """Return the user configuration directory."""
    return platformdirs.user_config_path(APP_NAME, appauthor=False)


def ensure_private_dir(path: Path) -> Path:
    """Create ``path`` (and parents) if needed and restrict it to the owner where supported."""
    path.mkdir(parents=True, exist_ok=True, mode=CACHE_DIR_MODE)
    if os.name == "posix":
        path.chmod(CACHE_DIR_MODE)
    return path
