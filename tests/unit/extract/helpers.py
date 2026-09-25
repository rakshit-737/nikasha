# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the extraction tests."""

from __future__ import annotations

from typing import Any

from nikasha.extract import extract_claims
from nikasha.ingest import ingest_string


def claims(
    text: str, kind: str | None = None, *, fmt: str = "markdown", product: str | None = None
) -> list[Any]:
    report = ingest_string(text, input_format=fmt)  # type: ignore[arg-type]
    extraction = extract_claims(report, product=product)
    found = [c for c in extraction.claims if kind is None or c.kind == kind]
    return found


def one(text: str, kind: str, **kwargs: Any) -> Any:
    found = claims(text, kind, **kwargs)
    assert len(found) == 1, found
    return found[0]
