# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The generated checks catalogue lists every outcome a check can record, scored or not."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

from nikasha.checks.strengths import default_strengths

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def gen() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_checks_doc", ROOT / "scripts" / "gen_checks_doc.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("gen_checks_doc", module)
    spec.loader.exec_module(module)
    return module


def _section(doc: str, check_id: str) -> str:
    start = doc.index(f"\n## {check_id}\n")
    end = doc.find("\n## ", start + 1)
    return doc[start : end if end != -1 else len(doc)]


@pytest.mark.parametrize(
    ("check_id", "key"),
    [
        ("C02", "outside_repository"),
        ("C12", "file_missing"),
        ("C14", "name_only"),
        ("C15", "universal_cwe"),
        ("C15", "crash_signal"),
        ("C15", "unknown_project"),
        ("C16", "previous_release_not_ancestor"),
        ("C19", "crash_unattributed"),
        ("C19", "harness_unverified"),
        ("C20", "skipped"),
    ],
)
def test_neutral_outcomes_are_listed_as_not_scored(
    gen: ModuleType, check_id: str, key: str
) -> None:
    section = _section(gen.build(), check_id)
    assert f"| `{key}` | — (not scored) |" in section


def test_scored_outcomes_keep_their_strength(gen: ModuleType) -> None:
    doc = gen.build()
    table = default_strengths()
    for key, value in table.outcomes("C03").items():
        assert f"| `{key}` | {value:+.2f} |" in _section(doc, "C03")


def test_static_extraction_recognises_every_recording_form(gen: ModuleType) -> None:
    source = """
KEY = "from_constant"
TABLE = {"from_table": ("NEUTRAL", None), "scored": ("REFUTES", "k")}
def f(d, flag):
    d["outcome"] = "from_subscript" if flag else KEY
    g(details={"outcome": "from_dict"}, label="from_label")
    return ("NEUTRAL", "from_tuple", "why")
"""
    assert gen.emitted_outcomes(source) == {
        "from_constant",
        "from_table",
        "from_subscript",
        "from_dict",
        "from_label",
        "from_tuple",
        "k",
    }


def test_committed_catalogue_is_up_to_date(gen: ModuleType) -> None:
    assert (ROOT / "docs" / "checks.md").read_text(encoding="utf-8") == gen.build()
