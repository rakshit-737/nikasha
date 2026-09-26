# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Sample REFUTES findings from a bench ``results.jsonl`` into a hand-check worksheet.

ADR 0003 asks for the per-finding precision of 40 random refutations, checked by a human.
This script picks them deterministically (a seeded ``random.Random`` over a sorted list)
and writes a Markdown table with a blank "correct? y/n" column. The worksheet is *blind*:
it never shows the genuine/slop label. It may contain report-derived text, so write it
only under the gitignored ``bench/cache/``.

    uv run python scripts/handcheck_sample.py bench/results/2026-09-26/results.jsonl \
        --out bench/cache/handcheck-2026-09-26.md
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_N = 40
DEFAULT_SEED = 20260926
MISSING = "n/a"


@dataclass(frozen=True)
class Finding:
    report_id: str
    index: int
    check: str
    group: str
    strength: float
    claim: str
    summary: str
    location: str


def report_url(report_id: str) -> str:
    """Return the public URL for a bench case ID (``h1-<n>`` is a HackerOne report)."""
    if report_id.startswith("h1-") and report_id[3:].isdigit():
        return f"https://hackerone.com/reports/{report_id[3:]}"
    return ""


def _text(value: object) -> str:
    if value is None or value == "":
        return MISSING
    if isinstance(value, dict):
        return ", ".join(f"{k}={value[k]}" for k in sorted(value))
    return str(value)


def load_refutes(lines: list[str]) -> list[Finding]:
    """Every REFUTES evidence item, in (report ID, position) order."""
    found: list[Finding] = []
    for line in lines:
        if not line.strip():
            continue
        record = json.loads(line)
        rid = str(record.get("id", ""))
        for i, ev in enumerate(record.get("evidence") or []):
            if ev.get("outcome") != "REFUTES":
                continue
            found.append(
                Finding(
                    report_id=rid,
                    index=i,
                    check=str(ev.get("check", "")),
                    group=str(ev.get("group", "")),
                    strength=float(ev.get("strength", 0.0)),
                    claim=_text(ev.get("claim")),
                    summary=_text(ev.get("summary")),
                    location=_text(ev.get("locator") or ev.get("location")),
                )
            )
    found.sort(key=lambda f: (f.report_id, f.index))
    return found


def sample(findings: list[Finding], n: int, seed: int) -> list[Finding]:
    """``n`` findings chosen with ``seed`` (all of them if fewer), in stable order."""
    if len(findings) <= n:
        return list(findings)
    picked = random.Random(seed).sample(range(len(findings)), n)  # noqa: S311 (not crypto)
    return [findings[i] for i in sorted(picked)]


def _cell(text: str) -> str:
    one_line = " ".join(text.split())
    return one_line.replace("\\", "\\\\").replace("|", r"\|")


def render(picked: list[Finding], total: int, n: int, seed: int, source: str) -> str:
    out = [
        "# Hand-check worksheet: REFUTES findings",
        "",
        f"Source: `{source}`. Seed {seed}. {total} REFUTES findings in the run.",
    ]
    if total < n:
        out.append(f"Fewer than {n} exist, so all {total} are included.")
    else:
        out.append(f"{len(picked)} sampled.")
    out += [
        "",
        "Blind: the genuine/slop label is not shown. Mark a finding correct (y) when the",
        "refutation is right about the code at the version the report names.",
        f"`{MISSING}` means the run did not store that field: re-run `nikasha check` on the",
        "report at the named version to see the claim, summary and evidence location.",
        "",
        "| # | report | URL | check | group | strength | claim | summary | evidence location"
        " | correct? y/n |",
        "|--:|---|---|---|---|--:|---|---|---|---|",
    ]
    for k, f in enumerate(picked, 1):
        cells = [
            str(k),
            f"{f.report_id} (evidence #{f.index})",
            report_url(f.report_id),
            f.check,
            f.group,
            f"{f.strength:g}",
            f.claim,
            f.summary,
            f.location,
            "",
        ]
        out.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    ap.add_argument("results", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("-n", type=int, default=DEFAULT_N)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = ap.parse_args(argv)
    findings = load_refutes(args.results.read_text(encoding="utf-8").splitlines())
    picked = sample(findings, args.n, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    text = render(picked, len(findings), args.n, args.seed, args.results.as_posix())
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(picked)} of {len(findings)} REFUTES findings -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
