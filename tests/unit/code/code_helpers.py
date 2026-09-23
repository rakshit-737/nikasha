# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Helpers shared by the parser tests: fixture loading and compact views of FileFacts."""

from __future__ import annotations

from pathlib import Path

from nikasha.code.facts import FileFacts
from nikasha.code.languages import Lang
from nikasha.code.parser import parse_file

ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests" / "fixtures" / "code"
VULNLAB = ROOT / "examples" / "vulnlab" / "src"


def parse_fixture(lang: Lang, relpath: str) -> FileFacts:
    return parse_file(lang, (FIXTURES / relpath).read_bytes())


def symbols(facts: FileFacts) -> list[tuple[str, str, str, int, int]]:
    """``(kind, name, qname, start_line, end_line)`` in source order."""
    return [(s.kind, s.name, s.qname, s.start_line, s.end_line) for s in facts.symbols]


def calls(facts: FileFacts) -> list[tuple[str | None, str, int, bool]]:
    """``(caller_qname, callee, line, indirect)`` in source order."""
    return [(c.caller_qname, c.callee, c.line, c.indirect) for c in facts.calls]


def callees(facts: FileFacts, caller: str) -> list[str]:
    return [c.callee for c in facts.calls if c.caller_qname == caller]


def flags(facts: FileFacts, qname: str) -> frozenset[str]:
    (sym,) = [s for s in facts.symbols if s.qname == qname]
    return sym.flags


def assert_clean(facts: FileFacts) -> None:
    assert facts.parsed_ok, facts.notes
    assert facts.error_nodes == 0
    assert facts.notes == ()
