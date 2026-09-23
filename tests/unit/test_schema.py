# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The committed JSON Schema must match the models (SPEC §7: CI fails on drift)."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("gen_schema", ROOT / "scripts" / "gen_schema.py")
assert _spec is not None
assert _spec.loader is not None
gen_schema = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen_schema)


def test_committed_schema_is_current():
    assert gen_schema.main(["gen_schema.py", "--check"]) == 0, (
        "schema/result-v1.json drifted from the models; run `uv run python scripts/gen_schema.py`"
    )


def test_schema_describes_every_claim_kind():
    schema = json.loads((ROOT / "schema" / "result-v1.json").read_text(encoding="utf-8"))
    defs = schema["$defs"]
    for name in ("SymbolClaim", "TraceClaim", "PatchClaim", "VersionClaim", "Evidence", "Verdict"):
        assert name in defs
    assert defs["SymbolClaim"]["additionalProperties"] is False
