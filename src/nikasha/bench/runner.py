# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Run the pipeline over a bench split and write the results (SPEC §17.3).

Outputs, under ``<out>/<date>/``:

* ``results.jsonl``: one record per case, sorted by id, keys sorted, evidence sorted by
  (check, outcome, group, strength). Everything except ``timing`` is meant to be a pure
  function of the inputs, with one known limit: C10 stops at a wall-clock scan budget, so
  a machine too slow to score every release in time gets different C10 evidence (and in
  principle a verdict). A finished scan no longer flips on timing (fixed in C10).
* ``metrics.json``: :func:`nikasha.bench.metrics.compute`.
* ``RESULTS.md``: the neutral summary table.

The date and commit are passed in; nothing here reads the wall clock except the latency
stopwatch, whose output lives in ``timing``. Offline, remote manifest entries (S1 to S3)
are listed as skipped instead of being fetched.
"""

from __future__ import annotations

import json
import re
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nikasha.bench import metrics as bench_metrics
from nikasha.bench.h1corpus import load_cached, report_id_from_url
from nikasha.bench.manifests import Manifest
from nikasha.bench.mutations import generate
from nikasha.bench.repro import Reproducer
from nikasha.errors import NikashaError
from nikasha.fuse.scoring import fuse
from nikasha.fuse.verdict import decide

_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class BenchError(NikashaError):
    """The bench cannot run as asked."""


@dataclass(frozen=True, slots=True)
class Case:
    """One report to check, with its label. ``text`` is held in memory only."""

    id: str
    source: str
    label: str
    expected: str | None
    text: str
    mutation: str | None = None
    base: str | None = None
    poc: Path | None = None
    recipe: str | None = None
    version: str | None = None


def collect_cases(
    manifests: Sequence[Manifest], root: Path, *, h1_cache: Path | None = None
) -> tuple[tuple[Case, ...], tuple[str, ...]]:
    """Cases for every local entry and generator; the ids of skipped remote entries.

    A remote HackerOne entry becomes a case only when ``h1_cache`` is given and holds its
    text (fetched earlier by ``nikasha bench fetch-h1 --online``, ADR 0011); otherwise it
    is skipped. Nothing is fetched here.
    """
    cases: list[Case] = []
    skipped: list[str] = []
    local: dict[str, str] = {}
    for manifest in manifests:
        for entry in manifest.entries:
            if entry.path is None:
                rid = None if entry.url is None else report_id_from_url(entry.url)
                cached = None
                if h1_cache is not None and rid is not None:
                    cached = load_cached(h1_cache, rid)
                if cached is None:
                    skipped.append(entry.id)
                    continue
                text = cached
            else:
                try:
                    text = (root / entry.path).read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    raise BenchError(
                        f"{manifest.source}/{entry.id}: cannot read {entry.path} "
                        f"({type(exc).__name__})"
                    ) from exc
            local[entry.id] = text
            cases.append(
                Case(
                    entry.id,
                    manifest.source,
                    entry.label,
                    entry.expected,
                    text,
                    poc=None if entry.poc is None else root / entry.poc,
                    recipe=entry.recipe,
                    version=entry.version,
                )
            )
    for manifest in manifests:
        if manifest.generator is None:
            continue
        gen = manifest.generator
        missing = [b for b in gen.bases if b not in local]
        if missing:
            raise BenchError(f"{manifest.source}: base entries {missing} are not loaded")
        bases = {b: local[b] for b in gen.bases}
        for synthetic in generate(bases, gen.mutations, gen.seeds):
            cases.append(
                Case(
                    synthetic.id,
                    manifest.source,
                    synthetic.label,
                    synthetic.expected,
                    synthetic.text,
                    synthetic.mutation,
                    synthetic.base,
                )
            )
    return tuple(sorted(cases, key=lambda c: c.id)), tuple(sorted(skipped))


def run_case(
    case: Case,
    *,
    repo: Path,
    workdir: Path,
    index_path: Path,
    repro: Reproducer | None = None,
) -> dict[str, Any]:
    """Check one case and return its results record.

    ``repro`` is set only by ``bench run --repro``; without it no container is ever started
    and the record has no ``repro`` key, so static runs keep their exact shape.
    """
    from nikasha.pipeline import check_report  # noqa: PLC0415 - keeps `bench --help` light

    report_path = workdir / f"{case.id}.md"
    report_path.write_text(case.text, encoding="utf-8")
    record: dict[str, Any] = {
        "id": case.id,
        "source": case.source,
        "label": case.label,
        "expected": case.expected,
        "mutation": case.mutation,
        "base": case.base,
    }
    started = time.perf_counter()
    dynamic = None
    if repro is not None:
        status, dynamic = repro.attempt(case, repo)
        record["repro"] = status
    try:
        checked = check_report(
            report_path,
            repo=str(repo),
            index_path=index_path,
            repro=dynamic,
        )
    except Exception as exc:  # one bad case must not lose the whole run
        # Only the class name is recorded: exception messages can echo report text or
        # local paths, and results are meant to be shareable.
        kind = "expected" if isinstance(exc, NikashaError) else "unexpected"
        record.update(
            verdict="ERROR",
            score=None,
            rule="",
            error=f"{kind}: {type(exc).__name__}",
            evidence=[],
            ablation={},
        )
    else:
        verdict = checked.verdict
        evidence = list(checked.evidence)
        ablated: dict[str, str] = {}
        for check in sorted({e.check_id for e in evidence}):
            kept = [e for e in evidence if e.check_id != check]
            ablated[check] = decide(fuse(kept), kept, checked.claims).label
        record.update(
            verdict=verdict.label,
            score=verdict.score,
            rule=verdict.rule,
            error=None,
            evidence=sorted(
                (
                    {
                        "check": e.check_id,
                        "outcome": e.outcome,
                        "strength": e.strength,
                        "group": e.group,
                    }
                    for e in evidence
                ),
                key=_evidence_key,
            ),
            ablation=ablated,
        )
    finally:
        report_path.unlink(missing_ok=True)
    record["timing"] = {"seconds": round(time.perf_counter() - started, 4)}
    return record


def _evidence_key(item: dict[str, Any]) -> tuple[str, str, str, float]:
    return (str(item["check"]), str(item["outcome"]), str(item["group"]), float(item["strength"]))


def check_date(date: str) -> str:
    """The results directory name must be an ISO date, passed in (never the wall clock)."""
    if not _DATE.fullmatch(date):
        raise BenchError(f"--date must look like YYYY-MM-DD, got {date!r}")
    return date


def run_bench(
    cases: Sequence[Case],
    *,
    repo: Path,
    out_dir: Path,
    date: str,
    split: str,
    commit: str = "unknown",
    skipped: Sequence[str] = (),
    repro: Reproducer | None = None,
) -> dict[str, Any]:
    """Run every case, write the three output files and return the metrics."""
    check_date(date)
    if not repo.exists():
        raise BenchError(
            f"no repository at {repo}; build the hermetic one with "
            f"`python scripts/build_vulnlab.py {repo}`"
        )
    target = out_dir / date
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="nikasha-bench-") as tmp:
        work = Path(tmp)
        index_path = work / "index.sqlite"
        records = [
            run_case(case, repo=repo, workdir=work, index_path=index_path, repro=repro)
            for case in cases
        ]
    records.sort(key=lambda r: str(r["id"]))
    computed = bench_metrics.compute(records)
    computed["skipped_remote"] = list(skipped)
    if repro is not None:
        computed["repro"] = repro_summary(records)
    write_outputs(records, computed, target, date=date, split=split, commit=commit)
    return computed


def write_outputs(
    records: Sequence[dict[str, Any]],
    computed: dict[str, Any],
    target: Path,
    *,
    date: str,
    split: str,
    commit: str,
) -> None:
    """results.jsonl, metrics.json and RESULTS.md, byte-stable for identical inputs."""
    lines = [json.dumps(r, sort_keys=True, ensure_ascii=False) for r in records]
    (target / "results.jsonl").write_text(
        "".join(line + "\n" for line in lines), encoding="utf-8", newline="\n"
    )
    (target / "metrics.json").write_text(
        json.dumps(computed, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    (target / "RESULTS.md").write_text(
        bench_metrics.render_markdown(computed, date=date, split=split, commit=commit),
        encoding="utf-8",
        newline="\n",
    )


def repro_summary(records: Sequence[dict[str, Any]]) -> dict[str, int]:
    """How many cases ended in each ``repro`` status (only for ``--repro`` runs)."""
    counts: dict[str, int] = {}
    for r in records:
        status = r.get("repro")
        if status is not None:
            counts[str(status)] = counts.get(str(status), 0) + 1
    return dict(sorted(counts.items()))
