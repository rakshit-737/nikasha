# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""C19 against real sandboxed PoC runs of the vulnlab recipe (SPEC §13.5, §21: M5).

``@pytest.mark.sandbox``: the default run excludes these; the ubuntu CI job runs them with
``-m sandbox``, where a missing engine is a failure, not a skip. Each run is a real build
and a real container: the genuine report must come out REPRODUCED through
``pipeline.check_report(repro=...)``, and every hostile PoC below must not.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest

from nikasha.checks.base import CheckContext
from nikasha.checks.c19_dynamic_repro import DynamicRepro
from nikasha.code.gitio import GitRepo
from nikasha.extract.pipeline import extract_claims
from nikasha.ingest import ingest_string
from nikasha.model.evidence import Evidence
from nikasha.pipeline import check_report
from nikasha.repro import build, recipes, run, sandbox
from nikasha.repro.sandbox import EngineInfo, NoEngineError
from nikasha.repro.signature import ABORT_STATUS

pytestmark = pytest.mark.sandbox

ROOT = Path(__file__).resolve().parents[3]
REPORTS = ROOT / "examples" / "reports"
ASAN_RUN = (ROOT / "tests/fixtures/traces/asan/01-vulnlab-heap-overflow-v1.2.0.txt").read_text(
    encoding="utf-8"
)
VULNLAB = recipes.find_recipe("vulnlab")
OVERFLOW = "Host: example.test\nX-Overflow: " + "A" * 96 + "\n"


def _c_string(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


#: A harness that prints a copy of a real report on stderr and then exits as a sanitizer
#: would, without any bug in the project.
FORGED_ABORT = (
    "#include <stdio.h>\n#include <stdlib.h>\n"
    f"int main(void) {{ fputs({_c_string(ASAN_RUN)}, stderr); abort(); }}\n"
)
FORGED_EXIT1 = (
    f"#include <stdio.h>\nint main(void) {{ fputs({_c_string(ASAN_RUN)}, stderr); return 1; }}\n"
)
#: A real heap overflow, but in the harness's own code.
HARNESS_OWN_BUG = (
    "#include <stdlib.h>\n#include <string.h>\n"
    "int main(void) { char *p = malloc(8); memset(p, 1, 32); return p[0]; }\n"
)
#: The genuine bug, driven through the library API.
HARNESS_GENUINE = (
    '#include "hdr.h"\n#include <string.h>\n'
    "int main(void) { hdr_list l; char b[200]; hdr_list_init(&l); memset(b, 0, sizeof b);"
    ' strcpy(b, "X-Overflow: "); memset(b + 12, 65, 96); return hdr_parse_line(&l, b); }\n'
)


@pytest.fixture(scope="module")
def engine() -> EngineInfo:
    try:
        chosen = sandbox.select_engine(os.environ.get("NIKASHA_TEST_SANDBOX", "auto"))
    except NoEngineError as exc:
        pytest.fail(f"the sandbox suite needs a container engine: {exc}")
    tag = VULNLAB.recipe.image.tag
    if not sandbox.image_exists(chosen, tag):
        sandbox.build_image(chosen, VULNLAB.dockerfile, VULNLAB.dockerfile.parent, tag, online=True)
    return chosen


@pytest.fixture(scope="module")
def outputs(
    engine: EngineInfo, vulnlab_repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> tuple[Path, Path]:
    """The sanitizer build of v1.2.0, and the cache root it lives under."""
    cache = tmp_path_factory.mktemp("repro-cache")
    with GitRepo(vulnlab_repo) as repo:
        commit = repo.rev_parse("v1.2.0")
        assert commit is not None
        built = build.build(repo, commit, VULNLAB, engine, cache_root=cache)
    return built.outputs_dir, cache


def _run(
    engine: EngineInfo, outputs: tuple[Path, Path], tmp_path: Path, name: str, text: str
) -> run.ReproRun:
    poc = tmp_path / name
    poc.write_text(text, encoding="utf-8")
    return run.run_poc(engine, VULNLAB.recipe, outputs[0], poc, cache_root=outputs[1])


def _c19(name: str, repro: run.ReproRun) -> Evidence:
    report = ingest_string((REPORTS / name).read_text(encoding="utf-8"), uri=name)
    claims = extract_claims(report).claims
    ctx = CheckContext(
        report=report,
        claims=claims,
        resolution=cast(Any, None),
        index=cast(Any, None),
        repro=repro,
    )
    check = DynamicRepro()
    (evidence,) = check.run(ctx, check.select(claims))
    return evidence


def _c19_of(result: Any) -> Evidence:
    (evidence,) = [e for e in result.evidence if e.check_id == "C19"]
    return cast(Evidence, evidence)


def test_genuine_report_is_reproduced_through_the_pipeline(
    engine: EngineInfo, outputs: tuple[Path, Path], vulnlab_repo: Path, tmp_path: Path
) -> None:
    repro = _run(engine, outputs, tmp_path, "poc.txt", OVERFLOW)
    assert repro.kind == "file_input"
    assert repro.exit_code == ABORT_STATUS  # the measured status the gate relies on
    result = check_report(
        REPORTS / "genuine_hdr_overflow.md",
        repo=str(vulnlab_repo),
        index_path=tmp_path / "index.sqlite",
        repro=repro,
    )
    assert _c19_of(result).details["outcome"] == "signature_match"
    assert result.verdict.label == "REPRODUCED"
    without = check_report(
        REPORTS / "genuine_hdr_overflow.md",
        repo=str(vulnlab_repo),
        index_path=tmp_path / "index.sqlite",
    )
    assert not [e for e in without.evidence if e.check_id == "C19"]
    assert without.verdict.label == "GROUNDED"


def test_fabricated_report_is_not_reproduced(
    engine: EngineInfo, outputs: tuple[Path, Path], vulnlab_repo: Path, tmp_path: Path
) -> None:
    repro = _run(engine, outputs, tmp_path, "poc.txt", OVERFLOW)
    result = check_report(
        REPORTS / "fabricated_hdr_overflow.md",
        repo=str(vulnlab_repo),
        index_path=tmp_path / "index.sqlite",
        repro=repro,
    )
    assert _c19_of(result).details["outcome"] == "different_signature"
    assert result.verdict.label != "REPRODUCED"


def test_benign_input_is_no_crash(
    engine: EngineInfo, outputs: tuple[Path, Path], tmp_path: Path
) -> None:
    repro = _run(engine, outputs, tmp_path, "poc.txt", "Host: example.test\n")
    assert repro.exit_code == 0
    assert _c19("genuine_hdr_overflow.md", repro).details["outcome"] == "no_crash"


@pytest.mark.parametrize(
    ("source", "outcome"),
    [
        (FORGED_ABORT, "harness_unverified"),
        (FORGED_EXIT1, "crash_unattributed"),
        (HARNESS_OWN_BUG, "crash_not_in_project"),
        (HARNESS_GENUINE, "harness_unverified"),
    ],
    ids=["forged-abort", "forged-exit-1", "bug-in-harness", "genuine-harness"],
)
def test_harness_runs_are_never_a_reproduction(
    engine: EngineInfo, outputs: tuple[Path, Path], tmp_path: Path, source: str, outcome: str
) -> None:
    repro = _run(engine, outputs, tmp_path, "poc.c", source)
    assert repro.kind == "c_harness"
    evidence = _c19("genuine_hdr_overflow.md", repro)
    assert evidence.details["outcome"] == outcome, evidence.summary
    assert evidence.outcome == "NEUTRAL" and evidence.strength == 0.0
