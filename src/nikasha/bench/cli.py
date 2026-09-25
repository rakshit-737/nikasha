# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha bench run`` and ``nikasha bench calibrate`` (SPEC §17.3, §14.2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from nikasha.bench.calibrate import calibrate, to_yaml
from nikasha.bench.charts import ChartsUnavailableError, render_charts
from nikasha.bench.manifests import MANIFEST_DIR, for_split, load_manifests
from nikasha.bench.runner import check_date, collect_cases, run_bench
from nikasha.config import cache_dir

bench_app = typer.Typer(help="NikashaBench: measure verdicts against labelled reports.")


def default_repo() -> Path:
    """Where the hermetic vulnlab repository is expected (built by scripts/build_vulnlab.py)."""
    return cache_dir() / "vulnlab" / "libhdr.git"


@bench_app.command("run")
def run(
    *,
    date: Annotated[str, typer.Option(help="Results directory name, YYYY-MM-DD.")],
    split: Annotated[str, typer.Option(help="real, synthetic or all.")] = "synthetic",
    repo: Annotated[Path | None, typer.Option(help="Repository to check against.")] = None,
    manifests: Annotated[Path, typer.Option(help="Manifest directory.")] = MANIFEST_DIR,
    root: Annotated[Path, typer.Option(help="Root that manifest paths are relative to.")] = Path(),
    out: Annotated[Path, typer.Option(help="Results root.")] = Path("bench") / "results",
    commit: Annotated[str, typer.Option(help="Nikasha commit recorded in RESULTS.md.")] = "unknown",
    charts: Annotated[bool, typer.Option(help="Also write SVG charts ([bench] extra).")] = False,
) -> None:
    """Run the static checks over a split and write results, metrics and RESULTS.md."""
    check_date(date)
    selected = for_split(load_manifests(manifests), split)
    cases, skipped = collect_cases(selected, root)
    metrics = run_bench(
        cases,
        repo=repo or default_repo(),
        out_dir=out,
        date=date,
        split=split,
        commit=commit,
        skipped=skipped,
    )
    target = out / date
    if charts:
        records = [
            json.loads(line)
            for line in (target / "results.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        try:
            render_charts(records, metrics, target)
        except ChartsUnavailableError as exc:
            typer.echo(f"charts skipped: {exc}", err=True)
    fu = metrics["false_ungrounded_on_genuine"]
    typer.echo(
        f"{metrics['cases']} cases; false-UNGROUNDED on genuine {fu['count']}/{fu['of']}; "
        f"{len(metrics['mismatches'])} differed from the expected verdict; "
        f"{len(skipped)} remote entries skipped (offline). Wrote {target}."
    )


@bench_app.command("calibrate")
def calibrate_command(
    results: Annotated[Path, typer.Argument(help="A results.jsonl from `nikasha bench run`.")],
    out: Annotated[
        Path | None,
        typer.Option(help="Directory to write calibration-v<N>.yaml to, if a fit happens."),
    ] = None,
    version: Annotated[int, typer.Option(min=1, help="N in calibration-v<N>.yaml.")] = 1,
) -> None:
    """Fit strengths if there is enough labelled data, else keep the defaults (SPEC §14.2)."""
    records = [
        json.loads(line) for line in results.read_text(encoding="utf-8").splitlines() if line
    ]
    outcome = calibrate(records)
    typer.echo(outcome.reason)
    if outcome.fitted:
        typer.echo(f"Brier {outcome.brier} · ECE {outcome.ece}")
        if out is not None:
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"calibration-v{version}.yaml"
            path.write_text(to_yaml(outcome, version), encoding="utf-8", newline="\n")
            typer.echo(f"Wrote {path}.")
    elif out is not None:
        typer.echo("No calibration file written: the defaults stay in force.")


def register(app: typer.Typer) -> None:
    """Attach ``nikasha bench`` to the main CLI."""
    app.add_typer(bench_app, name="bench")
