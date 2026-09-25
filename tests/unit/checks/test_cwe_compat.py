# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The bundled CWE table follows the CWE hierarchy and keeps real contradictions (P4)."""

from __future__ import annotations

import pytest

from nikasha.checks.c15_references import cwe_compat


@pytest.mark.parametrize(
    ("bug_type", "cwe"),
    [
        ("heap-buffer-overflow", 121),
        ("stack-buffer-overflow", 122),
        ("buffer-overflow", 122),
        ("global-buffer-overflow", 121),
        ("global-buffer-overflow", 122),
        ("stack-overflow", 121),
        ("heap-use-after-free", 825),
        ("heap-use-after-free", 672),
        ("heap-use-after-free", 787),
        ("double-free", 825),
        ("use-of-uninitialized-value", 665),
        ("implicit-conversion", 197),
    ],
)
def test_parents_and_siblings_in_the_cwe_hierarchy_are_compatible(bug_type: str, cwe: int) -> None:
    table = cwe_compat()
    family = table.family(bug_type)
    assert family is not None
    assert table.knows(cwe)
    assert table.compatible(family, cwe)


@pytest.mark.parametrize(
    ("bug_type", "cwe"),
    [
        ("heap-buffer-overflow", 79),
        ("heap-use-after-free", 89),
        ("xss", 787),
        ("heap-buffer-overflow", 401),
        ("sql-injection", 416),
    ],
)
def test_category_errors_stay_incompatible(bug_type: str, cwe: int) -> None:
    table = cwe_compat()
    family = table.family(bug_type)
    assert family is not None
    assert table.knows(cwe)
    assert not table.compatible(family, cwe)
