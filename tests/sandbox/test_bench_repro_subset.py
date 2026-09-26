# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``bench run --repro`` on the committed S6 manifest, against a real container engine.

The S6 entries that name a ``poc``, ``recipe`` and ``version`` form the repro subset
(SPEC §17.3). This test runs exactly what the manifest says, through the same
:func:`run_bench` the CLI uses: the genuine report's PoC crashes v1.2.0, so its verdict
becomes REPRODUCED, and the same PoC at the fixed v1.3.0 must not crash, so the
already-fixed report is never REPRODUCED. Marked ``sandbox``: the default run skips it and
the ubuntu sandbox CI job runs it.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

from nikasha.bench.manifests import MANIFEST_DIR, load_manifests
from nikasha.bench.repro import NOT_IN_SUBSET, RAN, Reproducer
from nikasha.bench.runner import collect_cases, run_bench
from nikasha.repro import recipes, sandbox
from nikasha.repro.sandbox import EngineInfo, NoEngineError

pytestmark = pytest.mark.sandbox

ROOT = Path(__file__).resolve().parents[2]
VULNLAB = recipes.find_recipe("vulnlab")


@pytest.fixture(scope="module")
def engine() -> EngineInfo:
    try:
        chosen = sandbox.select_engine(os.environ.get("NIKASHA_TEST_SANDBOX", "auto"))
    except NoEngineError as exc:  # a sandbox run without an engine is a failure, not a skip
        pytest.fail(f"the sandbox suite needs a container engine: {exc}")
    tag = VULNLAB.recipe.image.tag
    if not sandbox.image_exists(chosen, tag):
        sandbox.build_image(chosen, VULNLAB.dockerfile, VULNLAB.dockerfile.parent, tag, online=True)
    return chosen


def test_s6_repro_subset_reproduces_the_genuine_report_only(
    engine: EngineInfo, tmp_path: Path
) -> None:
    spec = importlib.util.spec_from_file_location("bv", ROOT / "scripts" / "build_vulnlab.py")
    assert spec is not None and spec.loader is not None
    bv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bv)
    repo = tmp_path / "libhdr.git"
    bv.build_vulnlab(repo)

    s6 = tuple(m for m in load_manifests(ROOT / MANIFEST_DIR) if m.source == "S6")
    cases, skipped = collect_cases(s6, ROOT)
    assert skipped == ()
    subset = {c.id for c in cases if c.poc is not None}
    assert subset == {"vulnlab-genuine", "vulnlab-already-fixed"}

    metrics = run_bench(
        cases,
        repo=repo,
        out_dir=tmp_path / "results",
        date="2026-09-26",
        split="synthetic",
        commit="sandbox-test",
        repro=Reproducer(engine),
    )
    lines = (tmp_path / "results" / "2026-09-26" / "results.jsonl").read_text(encoding="utf-8")
    records = {r["id"]: r for r in map(json.loads, lines.splitlines())}

    assert metrics["repro"] == {RAN: 2, NOT_IN_SUBSET: 3}
    assert records["vulnlab-genuine"]["repro"] == RAN
    assert records["vulnlab-genuine"]["verdict"] == "REPRODUCED"
    assert records["vulnlab-already-fixed"]["repro"] == RAN
    assert records["vulnlab-already-fixed"]["verdict"] not in ("REPRODUCED", "ERROR")
    for rid in ("vulnlab-mixed-wrong-version", "vulnlab-fabricated", "vulnlab-vague"):
        assert records[rid]["repro"] == NOT_IN_SUBSET
    # P4 holds with reproduction on: no genuine report is called UNGROUNDED.
    assert metrics["false_ungrounded_on_genuine"]["count"] == 0
