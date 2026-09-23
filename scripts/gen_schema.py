# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Generate ``schema/result-v1.json`` from the pydantic models (SPEC §7).

The committed schema must always match the models; ``--check`` exits non-zero on drift and is
run by the test suite.

Usage:
    python scripts/gen_schema.py            # write schema/result-v1.json
    python scripts/gen_schema.py --check    # verify it is current
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from nikasha.model.result import SCHEMA_URL, Result

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "result-v1.json"


def render() -> str:
    schema = Result.model_json_schema(by_alias=True, mode="serialization")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_URL,
        **schema,
    }
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    expected = render()
    if argv[1:] == ["--check"]:
        current = SCHEMA_PATH.read_text(encoding="utf-8") if SCHEMA_PATH.exists() else ""
        if current != expected:
            print(f"{SCHEMA_PATH.relative_to(ROOT)} is out of date; run scripts/gen_schema.py")
            return 1
        return 0
    SCHEMA_PATH.parent.mkdir(parents=True, exist_ok=True)
    SCHEMA_PATH.write_text(expected, encoding="utf-8")
    print(f"wrote {SCHEMA_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
