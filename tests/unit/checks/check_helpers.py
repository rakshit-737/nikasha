# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the checks suite (constants, the context factory type, claim()).

This module has a name of its own, unlike ``conftest``: pytest imports every
``conftest.py`` as the bare module ``conftest``, so two directories that each do
``from conftest import ...`` resolve to whichever one was loaded first. The fixtures stay
in ``conftest.py``; everything a test imports by name lives here.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

from nikasha.checks.base import CheckContext
from nikasha.extract.registry import make_claim
from nikasha.model.claims import ClaimBase
from nikasha.model.report import Span

ROOT = Path(__file__).resolve().parents[3]
REPORTS = ROOT / "examples" / "reports"
REPO_URL = "https://github.com/nikasha-demo/libhdr"

#: The vulnlab releases, oldest first.
TAGS = ("v1.0.0", "v1.1.0", "v1.2.0", "v1.2.1", "v1.3.0")
#: The release most fixtures target: the one the demo bug is reported against.
DEFAULT_TAG = "v1.2.0"

ClaimT = TypeVar("ClaimT", bound=ClaimBase)

#: The ``make_ctx`` fixture's type: build a CheckContext at a tag with the given claims.
MakeContext = Callable[..., CheckContext]


def claim(cls: type[ClaimT], /, text: str = "x", **fields: Any) -> ClaimT:
    """Build a claim with a content-derived ID, attributed to the project by default.

    ``provenance`` defaults to ``project_attributed`` and ``negated`` to ``False`` so a
    test that does not say otherwise exercises the *refutable* path. Tests for the ADR
    0003 gate pass ``provenance=...`` or ``negated=True`` explicitly.
    """
    fields.setdefault("role", "supporting")
    fields.setdefault("provenance", "project_attributed")
    return make_claim(
        cls,
        spans=[Span(start=0, end=len(text), text=text)],
        extractor="test",
        confidence=1.0,
        **fields,
    )
