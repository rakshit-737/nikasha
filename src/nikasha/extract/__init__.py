# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Deterministic claim extraction (SPEC §9; ADR 0003).

Importing this package registers every extractor; :func:`extract_claims` runs them all.
"""

from __future__ import annotations

# Extractor modules register themselves on import (order does not matter: the pipeline runs
# them sorted by name).
from nikasha.extract import (  # noqa: F401
    behavior,
    impact,
    options,
    patches,
    paths,
    pocs,
    references,
    snippets,
    symbols,
    trace_claims,
    versions,
)
from nikasha.extract.pipeline import MAX_CLAIMS, Extraction, extract_claims

__all__ = ["MAX_CLAIMS", "Extraction", "extract_claims"]
