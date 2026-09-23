# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The checks catalogue (SPEC §12).

Every module named ``cNN_*.py`` in this package is imported on first use, in sorted order,
so a check registers itself simply by existing. ``docs/checks.md`` is generated from the
registry by ``scripts/gen_checks_doc.py``.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import threading

from nikasha.checks.base import (
    CHECKS,
    BaseCheck,
    Check,
    CheckContext,
    CheckError,
    CheckRun,
    all_checks,
    is_refutable,
    make_evidence,
    permalink,
    register,
    run_checks,
)
from nikasha.checks.strengths import Strengths, default_strengths, load_strengths

__all__ = [
    "CHECKS",
    "BaseCheck",
    "Check",
    "CheckContext",
    "CheckError",
    "CheckRun",
    "Strengths",
    "all_checks",
    "default_strengths",
    "is_refutable",
    "load_checks",
    "load_strengths",
    "make_evidence",
    "permalink",
    "register",
    "run_checks",
]

_MODULE_RE = re.compile(r"^c\d{2}_[a-z0-9_]+$")
_loaded = False
_lock = threading.Lock()


def load_checks() -> dict[str, Check]:
    """Import every ``cNN_*`` module once, then return the registry."""
    global _loaded  # noqa: PLW0603 - a module-level import-once latch
    if not _loaded:
        with _lock:
            if not _loaded:
                names = sorted(
                    info.name
                    for info in pkgutil.iter_modules(__path__)
                    if _MODULE_RE.match(info.name)
                )
                for name in names:
                    importlib.import_module(f"{__name__}.{name}")
                _loaded = True
    return dict(CHECKS)
