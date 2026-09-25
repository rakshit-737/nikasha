# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The bench runner: case collection, output files and the CLI surface."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from nikasha.bench.cli import register
from nikasha.bench.manifests import load_manifests
from nikasha.bench.metrics import compute
from nikasha.bench.runner import (
    BenchError,
    Case,
    check_date,
    collect_cases,
    run_bench,
    run_case,
    write_outputs,
)

ROOT = Path(__file__).resolve().parents[3]
MANIFESTS = ROOT / "bench" / "manifests"


def test_committed_manifests_give_47_offline_cases() -> None:
    cases, skipped = collect_cases(load_manifests(MANIFESTS), ROOT)
    assert skipped == ()
    assert len(cases) == 5 + 2 * 7 * 3
    ids = [c.id for c in cases]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    assert sum(c.source == "S5" for c in cases) == 42


@pytest.mark.parametrize("date", ["2026-9-1", "today", "2026-09-01/../x", ""])
def test_dates_are_validated(date: str) -> None:
    with pytest.raises(BenchError):
        check_date(date)


def test_missing_repo_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(BenchError, match="build_vulnlab"):
        run_bench(
            [], repo=tmp_path / "nope.git", out_dir=tmp_path, date="2026-01-01", split="synthetic"
        )


def test_outputs_are_byte_stable(tmp_path: Path) -> None:
    records = [
        {"id": "b", "source": "S6", "label": "genuine", "verdict": "GROUNDED", "score": 90,
         "expected": "GROUNDED", "rule": "5", "timing": {"seconds": 1.0}},
        {"id": "a", "source": "S6", "label": "fabricated", "verdict": "UNGROUNDED", "score": 2,
         "expected": "UNGROUNDED", "rule": "3a", "timing": {"seconds": 2.0}},
    ]  # fmt: skip
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        write_outputs(
            records, compute(records), tmp_path / name, date="2026-01-01", split="all", commit="c"
        )
    for file in ("results.jsonl", "metrics.json", "RESULTS.md"):
        assert (tmp_path / "one" / file).read_bytes() == (tmp_path / "two" / file).read_bytes()
    first = json.loads((tmp_path / "one" / "results.jsonl").read_text().splitlines()[0])
    assert list(first) == sorted(first)


def test_cli_registers_bench_and_refuses_without_a_repo(tmp_path: Path) -> None:
    app = typer.Typer()
    register(app)

    @app.command()
    def other() -> None:  # a second command keeps `bench` a sub-group
        """Placeholder."""

    runner = CliRunner()
    result = runner.invoke(app, ["bench", "--help"])
    assert result.exit_code == 0
    assert "run" in result.output
    assert "calibrate" in result.output
    result = runner.invoke(
        app,
        [
            "bench", "run", "--date", "2026-01-01", "--repo", str(tmp_path / "none.git"),
            "--manifests", str(MANIFESTS), "--root", str(ROOT), "--out", str(tmp_path),
        ],
    )  # fmt: skip
    assert result.exit_code != 0
    assert isinstance(result.exception, BenchError)


def test_calibrate_command_keeps_defaults(tmp_path: Path) -> None:
    app = typer.Typer()
    register(app)

    @app.command()
    def other() -> None:
        """Placeholder."""

    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps({"label": "genuine", "source": "S6", "verdict": "GROUNDED"}))
    result = CliRunner().invoke(app, ["bench", "calibrate", str(results)])
    assert result.exit_code == 0
    assert "kept defaults" in result.output


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_run_case_against_vulnlab(vulnlab_repo: Path, tmp_path: Path) -> None:
    text = (ROOT / "examples" / "reports" / "fabricated_hdr_overflow.md").read_text("utf-8")
    case = Case("vulnlab-fabricated", "S6", "fabricated", "UNGROUNDED", text)
    record = run_case(case, repo=vulnlab_repo, workdir=tmp_path, index_path=tmp_path / "i.db")
    assert record["verdict"] == "UNGROUNDED"
    assert record["error"] is None
    assert record["ablation"]
    assert set(record["timing"]) == {"seconds"}
    assert not (tmp_path / "vulnlab-fabricated.md").exists()


def test_unreadable_fixture_is_a_bench_error(tmp_path: Path) -> None:
    from nikasha.bench.manifests import Entry, Manifest  # noqa: PLC0415

    manifest = Manifest(
        source="S6", title="t", entries=(Entry(id="x", label="genuine", path="missing.md"),)
    )
    with pytest.raises(BenchError, match=r"cannot read missing\.md"):
        collect_cases((manifest,), tmp_path)


def test_errors_record_only_the_exception_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import nikasha.pipeline  # noqa: PLC0415

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError(f"secret report text at {tmp_path}")

    monkeypatch.setattr(nikasha.pipeline, "check_report", boom)
    case = Case("c", "S6", "genuine", "GROUNDED", "text")
    record = run_case(case, repo=tmp_path, workdir=tmp_path, index_path=tmp_path / "i.db")
    assert record["verdict"] == "ERROR"
    assert record["error"] == "unexpected: RuntimeError"
    assert not (tmp_path / "c.md").exists()


def test_calibrate_writes_a_file_only_when_fitted(tmp_path: Path) -> None:
    app = typer.Typer()
    register(app)

    @app.command()
    def other() -> None:
        """Placeholder."""

    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps({"label": "genuine", "source": "S2", "verdict": "GROUNDED"}))
    out = tmp_path / "cal"
    result = CliRunner().invoke(app, ["bench", "calibrate", str(results), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "No calibration file written" in result.output
    assert not out.exists()


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_same_case_twice_gives_the_same_record(vulnlab_repo: Path, tmp_path: Path) -> None:
    """Records minus timing are equal across runs."""
    text = (ROOT / "examples" / "reports" / "genuine_hdr_overflow.md").read_text("utf-8")
    case = Case("vulnlab-genuine", "S6", "genuine", "GROUNDED", text)
    records = []
    for n in range(2):
        work = tmp_path / str(n)
        work.mkdir()
        record = run_case(case, repo=vulnlab_repo, workdir=work, index_path=work / "i.db")
        record.pop("timing")
        records.append(record)
    assert records[0] == records[1]


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_c10_budget_expiring_after_the_last_release_keeps_the_scan_complete(
    vulnlab_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: C10 evidence IDs used to flip when the clock ran out right after the
    last release was scored (the bench's s5-vulnlab-genuine-m1-* records differed run to run).
    """
    import nikasha.checks.c10_trace_version_fit as c10  # noqa: PLC0415
    from nikasha.bench.mutations import mutate  # noqa: PLC0415
    from nikasha.checks.base import CheckContext  # noqa: PLC0415
    from nikasha.pipeline import check_report  # noqa: PLC0415

    genuine = (ROOT / "examples" / "reports" / "genuine_hdr_overflow.md").read_text("utf-8")
    text = mutate(genuine, "M1", base="vulnlab-genuine", seed=0)

    def c10_evidence(run: str) -> list[tuple[str, bool]]:
        work = tmp_path / run
        work.mkdir()
        report = work / "r.md"
        report.write_text(text, encoding="utf-8")
        checked = check_report(report, repo=str(vulnlab_repo), index_path=work / "i.db")
        return [(e.id, e.details["scan_complete"]) for e in checked.evidence if e.check_id == "C10"]

    baseline = c10_evidence("clock-ok")
    assert baseline
    assert all(complete for _, complete in baseline)

    scored = {"n": 0}
    real = c10.analyze_trace

    def counting(*args: object, **kwargs: object) -> object:
        scored["n"] += 1
        return real(*args, **kwargs)  # type: ignore[arg-type]

    # vulnlab has five final releases: the budget is spent the moment the fifth is scored.
    monkeypatch.setattr(c10, "analyze_trace", counting)
    monkeypatch.setattr(CheckContext, "expired", lambda self: scored["n"] >= 5)
    assert c10_evidence("clock-late") == baseline
