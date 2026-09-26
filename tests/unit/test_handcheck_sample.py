# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "handcheck_sample.py"
_spec = importlib.util.spec_from_file_location("handcheck_sample", _PATH)
assert _spec is not None and _spec.loader is not None
hs = importlib.util.module_from_spec(_spec)
sys.modules["handcheck_sample"] = hs  # dataclasses look the module up
_spec.loader.exec_module(hs)


def _record(rid: str, label: str, outcomes: list[str]) -> str:
    ev = [
        {"check": f"C0{i + 1}", "group": "locus", "outcome": o, "strength": -1.5}
        for i, o in enumerate(outcomes)
    ]
    return json.dumps({"id": rid, "label": label, "evidence": ev})


def _lines(k: int) -> list[str]:
    return [_record(f"h1-{1000 + i}", "slop", ["REFUTES", "SUPPORTS"]) for i in range(k)]


def test_only_refutes_are_loaded_in_stable_order() -> None:
    lines = [_record("h1-2", "genuine", ["SUPPORTS", "REFUTES"]), "", _record("h1-1", "slop", [])]
    got = hs.load_refutes(lines)
    assert [(f.report_id, f.index, f.check) for f in got] == [("h1-2", 1, "C02")]
    assert got[0].claim == hs.MISSING


def test_sample_is_deterministic_and_seed_dependent() -> None:
    findings = hs.load_refutes(_lines(100))
    a = hs.sample(findings, 40, 7)
    assert a == hs.sample(findings, 40, 7)
    assert len(a) == 40 and len(set(a)) == 40
    assert a != hs.sample(findings, 40, 8)
    assert a == sorted(a, key=lambda f: (f.report_id, f.index))


def test_fewer_than_n_includes_all_and_says_so(tmp_path: Path) -> None:
    src = tmp_path / "results.jsonl"
    src.write_text("\n".join(_lines(3)), encoding="utf-8")
    out = tmp_path / "cache" / "w.md"
    assert hs.main([str(src), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "Fewer than 40 exist, so all 3 are included." in text
    assert text.count("https://hackerone.com/reports/") == 3
    assert "slop" not in text.lower().replace("genuine/slop", "")


def test_cells_are_escaped() -> None:
    f = hs.Finding("x|y", 0, "C02", "locus", -2.0, "a|b\nc", "s", "p")
    text = hs.render([f], 1, 40, 1, "r.jsonl")
    row = text.splitlines()[-1]
    assert r"a\|b c" in row and r"x\|y" in row
    assert hs.report_url("x|y") == ""
