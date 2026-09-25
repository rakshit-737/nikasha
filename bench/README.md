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

`bench calibrate --out DIR` writes `calibration-v<N>.yaml` only when it fits (at least 50
labelled real S1 to S4 reports per class). Offline that never happens, and the defaults stay.
For a local trial run, point `--out` at a scratch directory rather than the repository.

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
  written with `--charts`.

Not done yet: the SPEC §17.3 `--repro` subset (dynamic reproduction of the bench cases in
the sandbox). `bench run` runs the static checks only.

## Layout

| Path | What |
|---|---|
| `manifests/s1_*.yaml` … `s3_*.yaml` | Real-world sources. These are empty stubs until the terms check. |
| `manifests/s5_mutations.yaml` | Generator settings for the seeded mutations: bases, mutations and seeds. |
| `manifests/s6_vulnlab.yaml` | The vulnlab fixtures with their labels and expected verdicts. |
| `results/` | Generated outputs; `bench/results/*/` is gitignored and nothing under it is committed. Publish numbers by copying them into docs. |

The `real` split contains S1–S3 and the `synthetic` split contains S5 and S6. Without
network access and an accepted terms check, `real` has no cases.
