# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Every regex that reads report or repository text must run in linear time on hostile input
(SPEC §9, §19.2).

Each compiled pattern (text or bytes) in the extraction, ingest, code-intelligence and
resolution modules is fed adversarial strings: a
short seed of "interesting" characters repeated to ~40k characters, the classic shape that
triggers catastrophic backtracking. A pattern that backtracks exponentially or
quadratically blows through the time budget.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import nikasha.code
import nikasha.extract
import nikasha.extract.traces
import nikasha.ingest
import nikasha.resolve

BUDGET_S = 0.5
TARGET_LEN = 40_000
ALPHABET = "aA_0 .:/-`'\"()[]{}<>#*@$=,;\n\t" + "xX1lL"


_PACKAGES = (
    nikasha.extract, nikasha.extract.traces, nikasha.ingest, nikasha.code, nikasha.resolve
)  # fmt: skip


def _patterns() -> list[tuple[str, re.Pattern[Any]]]:
    found: dict[str, re.Pattern[Any]] = {}
    for package in _PACKAGES:
        for info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            module = importlib.import_module(info.name)
            for name, value in vars(module).items():
                if isinstance(value, re.Pattern):
                    found[f"{info.name}.{name}"] = value
    return sorted(found.items())


PATTERNS = _patterns()


def _time(pattern: re.Pattern[Any], text: str) -> float:
    subject: str | bytes = text.encode() if isinstance(pattern.pattern, bytes) else text
    started = time.perf_counter()
    for _ in pattern.finditer(subject):
        pass
    pattern.match(subject)
    return time.perf_counter() - started


def test_patterns_were_collected():
    assert len(PATTERNS) > 40


@pytest.mark.parametrize(("name", "pattern"), PATTERNS, ids=[n for n, _ in PATTERNS])
@given(seed=st.text(alphabet=ALPHABET, min_size=1, max_size=12))
@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_regex_is_linear_on_repetitive_input(name, pattern, seed):
    text = seed * (TARGET_LEN // len(seed))
    elapsed = _time(pattern, text)
    assert elapsed < BUDGET_S, f"{name} took {elapsed:.3f}s on {seed!r} x {len(text)}"


@pytest.mark.parametrize(("name", "pattern"), PATTERNS, ids=[n for n, _ in PATTERNS])
@pytest.mark.parametrize(
    "text",
    [
        "a" * TARGET_LEN,
        "1." * (TARGET_LEN // 2),
        "a/" * (TARGET_LEN // 2),
        "`" + "a" * TARGET_LEN,
        "--" + "a-" * (TARGET_LEN // 2),
        "CVSS:3.1" + "/AV:N" * (TARGET_LEN // 5),
        "@@ -1 +1 @@\n" * (TARGET_LEN // 12),
        "    at " * (TARGET_LEN // 7),
    ],
    ids=["letters", "dotted", "slashes", "tick", "dashes", "cvss", "hunks", "at"],
)
def test_regex_on_known_hostile_shapes(name, pattern, text):
    elapsed = _time(pattern, text)
    assert elapsed < BUDGET_S, f"{name} took {elapsed:.3f}s"
