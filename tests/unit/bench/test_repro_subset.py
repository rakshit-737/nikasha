# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``bench run --repro``: the subset, the no-engine skip, and no container without the flag."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

import nikasha.bench.cli as bench_cli
from nikasha.bench import repro as bench_repro
from nikasha.bench.manifests import Entry, Manifest
from nikasha.bench.runner import Case, collect_cases, repro_summary, run_case
from nikasha.errors import NikashaError

ROOT = Path(__file__).resolve().parents[3]
MANIFESTS = ROOT / "bench" / "manifests"


def _app() -> typer.Typer:
    app = typer.Typer()
    bench_cli.register(app)

    @app.command()
    def other() -> None:
        """Placeholder."""

    return app


def test_entry_poc_needs_recipe_and_version() -> None:
    with pytest.raises(ValueError, match="go together"):
        Entry(id="x", label="genuine", path="r.md", poc="p.bin")
    with pytest.raises(ValueError, match="version"):
        Entry(id="x", label="genuine", path="r.md", poc="p.bin", recipe="vulnlab")
    with pytest.raises(ValueError, match="relative"):
        Entry(id="x", label="genuine", path="r.md", poc="../p", recipe="v", version="v1")
    ok = Entry(id="x", label="genuine", path="r.md", poc="p.bin", recipe="vulnlab", version="v1")
    assert ok.poc == "p.bin"


def test_collect_cases_carries_repro_inputs(tmp_path: Path) -> None:
    (tmp_path / "r.md").write_text("report", encoding="utf-8")
    entry = Entry(
        id="x", label="genuine", path="r.md", poc="p.bin", recipe="vulnlab", version="v1.2.0"
    )
    cases, _ = collect_cases((Manifest(source="S6", title="t", entries=(entry,)),), tmp_path)
    assert cases[0].poc == tmp_path / "p.bin"
    assert (cases[0].recipe, cases[0].version) == ("vulnlab", "v1.2.0")


def test_static_run_never_probes_for_an_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nikasha.repro import sandbox  # noqa: PLC0415

    def forbidden(*_a: object, **_k: object) -> None:
        raise AssertionError("a static bench run touched the container engine")

    monkeypatch.setattr(sandbox, "select_engine", forbidden)
    monkeypatch.setattr(sandbox, "run_container", forbidden)
    monkeypatch.setattr(bench_repro, "select_engine", forbidden)
    result = CliRunner().invoke(
        _app(),
        [
            "bench", "run", "--date", "2026-01-01", "--repo", str(tmp_path / "none.git"),
            "--manifests", str(MANIFESTS), "--root", str(ROOT), "--out", str(tmp_path),
        ],
    )  # fmt: skip
    assert not isinstance(result.exception, AssertionError)


def test_repro_without_an_engine_skips_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nikasha.repro import sandbox  # noqa: PLC0415

    def none(*_a: object, **_k: object) -> None:
        raise sandbox.NoEngineError("no engine")

    monkeypatch.setattr(sandbox, "select_engine", none)
    assert bench_repro.select_engine("auto") is None
    seen: dict[str, Any] = {}

    def fake_run_bench(cases: object, **kw: Any) -> dict[str, Any]:
        seen.update(kw)
        (tmp_path / "2026-01-01").mkdir(exist_ok=True)
        return {"cases": 0, "false_ungrounded_on_genuine": {"count": 0, "of": 0}, "mismatches": []}

    monkeypatch.setattr(bench_cli, "run_bench", fake_run_bench)
    result = CliRunner().invoke(
        _app(),
        [
            "bench", "run", "--date", "2026-01-01", "--repro", "--manifests", str(MANIFESTS),
            "--root", str(ROOT), "--out", str(tmp_path),
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "repro skipped" in result.output
    assert seen["repro"] is None


def _case(**kw: Any) -> Case:
    return Case("c", "S6", "genuine", "GROUNDED", "text", **kw)


def test_reproducer_statuses(tmp_path: Path) -> None:
    from nikasha.repro.signature import ReproFailure  # noqa: PLC0415

    calls: list[str] = []

    def ok(case: Case, repo: Path, engine: object, recipes: Path | None) -> Any:
        calls.append(case.id)
        return "RUN"

    def build_fails(*_a: object) -> Any:
        class BuildFailedError(NikashaError):
            pass

        raise BuildFailedError(f"make failed in {tmp_path}")

    engine: Any = object()
    assert bench_repro.Reproducer(engine, attempt_fn=ok).attempt(_case(), tmp_path) == (
        "not_in_subset",
        None,
    )
    assert calls == []
    subset = _case(poc=tmp_path / "p", recipe="vulnlab", version="v1.2.0")
    assert bench_repro.Reproducer(engine, attempt_fn=ok).attempt(subset, tmp_path) == ("ran", "RUN")
    status, failure = bench_repro.Reproducer(engine, attempt_fn=build_fails).attempt(
        subset, tmp_path
    )
    assert status == "failed"
    assert failure == ReproFailure("build_failed", "BuildFailedError")


def test_run_case_passes_repro_to_the_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nikasha.pipeline  # noqa: PLC0415

    seen: dict[str, Any] = {}

    def fake_check(*_a: object, **kw: Any) -> None:
        seen.update(kw)
        raise NikashaError("stop here")

    monkeypatch.setattr(nikasha.pipeline, "check_report", fake_check)
    reproducer = bench_repro.Reproducer(object(), attempt_fn=lambda *_a: "RUN")  # type: ignore[arg-type]
    subset = _case(poc=tmp_path / "p", recipe="vulnlab", version="v1")
    record = run_case(
        subset, repo=tmp_path, workdir=tmp_path, index_path=tmp_path / "i", repro=reproducer
    )
    assert seen["repro"] == "RUN"
    assert record["repro"] == "ran"
    static = run_case(_case(), repo=tmp_path, workdir=tmp_path, index_path=tmp_path / "i")
    assert "repro" not in static
    assert seen["repro"] is None
    assert repro_summary([record, static, {"repro": "ran"}]) == {"ran": 2}
    json.dumps(record)
