<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# NikashaBench

Labelled reports used to measure Nikasha's verdicts (SPEC §17). See
[DATASET_CARD.md](DATASET_CARD.md) for what is in the benchmark and why.

## Run it offline (S5 and S6)

```sh
# 1. Build the hermetic vulnlab repository into the cache (once).
python scripts/build_vulnlab.py "$(python -c 'from nikasha.bench.cli import default_repo; print(default_repo())')"

# 2. Run the synthetic split. The date names the results directory; nothing reads the clock.
nikasha bench run --split synthetic --date 2026-09-24 --commit "$(git rev-parse --short HEAD)"

# 3. Optional: SVG charts and calibration need the bench extra (numpy, scikit-learn, matplotlib).
nikasha bench run --split synthetic --date 2026-09-24 --charts
nikasha bench calibrate bench/results/2026-09-24/results.jsonl --out bench/calibration
```

`bench calibrate` fits only when there are at least 50 labelled real (S1 to S4), non-ERROR
reports per class. Otherwise it prints `kept defaults: ...` followed by `Kept the defaults
(lr_defaults.yaml)` and writes nothing. Offline that is always what happens. When it fits and
`--out DIR` is given, it writes `calibration-v<N>.yaml`, where N is one more than the highest
existing `calibration-v*.yaml` in DIR (1 if there is none). The file is created exclusively,
so an existing file is never overwritten. The content is deterministic: the version, Brier,
ECE and the sorted per-(check, outcome) strengths, with a fixed cross-validation seed. When
it fits without `--out`, it prints the scores and writes nothing. For a local trial run,
point `--out` at a scratch directory rather than the repository.

The outputs go to `bench/results/<date>/`:

- `results.jsonl` has one record per case, sorted by ID with sorted keys and with evidence
  sorted by (check, outcome, group, strength). Everything except `timing` is meant to
  depend on the inputs only. Two back-to-back runs of the synthetic split on the same
  machine gave identical records once `timing` was removed. The flip seen in review (C10
  marking a finished scan "stopped" when its budget ran out just after the last release)
  is fixed in C10 itself. **Remaining limit:** C10 still has a wall-clock budget (SPEC
  §12), so a machine too slow to score every release in time gets different C10 evidence
  (and in principle a different verdict). On vulnlab's five releases that takes seconds.
- An error in one case becomes an `ERROR` record whose `error` field holds only
  `expected: <class>` or `unexpected: <class>`, never the message (messages can echo report
  text or local paths). The run carries on.
- `metrics.json` holds the SPEC §17.4 metrics. Latency sits under `timing`.
- `RESULTS.md` is a neutral summary table. It lists every verdict that differed from the
  expected one and the drop-one ablation. Latency sits in a separate "Timing
  (non-deterministic)" section at the end.
- `confusion.svg`, `scores.svg`, `reliability.svg`, `ablation.svg` and `latency.svg` are
  written with `--charts`. `reliability.svg` is the reliability diagram: mean predicted
  P(genuine) (score / 100) per bin against the observed fraction of genuine reports, with
  the diagonal for reference. Every SVG uses a fixed `svg.hashsalt` and no date metadata,
  so identical inputs give identical files.

## The `--repro` subset (SPEC §17.3)

`nikasha bench run --repro [--sandbox auto|podman|docker]` also reproduces the cases whose
manifest entry names a `poc` (repository-relative PoC file or directory), a `recipe` (recipe
id) and a `version` (the ref to build). `poc` and `recipe` must be given together, and
`poc` needs `version`. For each such case the project is built at `version` with the recipe
and the PoC runs once in a fresh container through `nikasha.repro`. Image builds happen
offline. The result goes to C19 alongside the static checks.

- Without `--repro`, nothing probes for a container engine or starts a container.
- With `--repro` and no usable engine, the run prints `repro skipped: no usable container
  engine; static checks only.` and carries on like a static run.
- With `--repro` and an engine, every record gets a `repro` field: `not_in_subset`, `ran`
  or `failed`. A failure keeps only the exception class, as C19 `ERROR` evidence with
  stage `build_failed` or `infra_error`. `metrics.json` gets a `repro` count per status.
- S6 has a two-case subset: `vulnlab-genuine` (the project's own PoC,
  `examples/vulnlab/pocs/hdr_overflow.txt`, at v1.2.0, where it crashes, so the verdict
  becomes REPRODUCED) and `vulnlab-already-fixed` (the same PoC at the fixed v1.3.0, which
  must not crash, so the verdict stays MIXED). Every other case is `not_in_subset`. With
  `--repro`, `vulnlab-genuine` differs from its static `expected: GROUNDED`, and RESULTS.md
  lists that difference. `tests/sandbox/test_bench_repro_subset.py` runs this subset in
  the sandbox CI job.

## Layout

| Path | What |
|---|---|
| `manifests/s1_*.yaml` … `s3_*.yaml` | Real-world sources. These are empty stubs until the terms check. |
| `manifests/s5_mutations.yaml` | Generator settings for the seeded mutations: bases, mutations and seeds. |
| `manifests/s6_vulnlab.yaml` | The vulnlab fixtures with their labels and expected verdicts. |
| `results/` | Generated outputs; `bench/results/*/` is gitignored and nothing under it is committed. Publish numbers by copying them into docs. |

The `real` split contains S1–S3 and the `synthetic` split contains S5 and S6. Without
network access and an accepted terms check, `real` has no cases.
