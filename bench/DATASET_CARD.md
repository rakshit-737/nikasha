<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# NikashaBench dataset card

A datasheet for NikashaBench (SPEC §17.5). NikashaBench measures how Nikasha's verdicts
line up with labelled vulnerability reports. It does not measure people, and nothing here
says who wrote a report.

## Motivation

- **Why it exists.** Nikasha must not call a genuine report UNGROUNDED (P4: at most 1%,
  aiming for 0). The bench measures that rate, how many fabricated reports are detected,
  coverage, how much each check contributes, and speed (SPEC §17.1).
- **Who maintains it.** The Nikasha authors.

## Composition

| Source | What | Label | Status in this repository |
|---|---|---|---|
| S1 | curl's public list of AI-generated security reports (HackerOne links) | fabricated | 49 HackerOne IDs and labels (via the slopcheck curl index, ADR 0011); text fetched at runtime into the gitignored cache. |
| S2 | curl's genuine CVE reports (`curl.se/docs/vuln.json`, HackerOne issue URLs) | genuine | 126 HackerOne IDs of reports curl confirmed (ADR 0011). All 124 `vuln.json` records with a HackerOne issue URL are among them (checked 2026-09-26). |
| S3 | Fabricated CVE records from JFrog's analysis, content from cvelistV5 | fabricated | No cases: all six SQLite CVEs the post names are REJECTED with blanked records (checked 2026-09-26), so they are listed as exclusions (SPEC §17.2). |
| S4 | Linux-kernel false-positive dataset | n/a | Not included: the repository declares no license (checked 2026-09-26). |
| S5 | Seeded mutations M1–M7 of the S6 genuine and wrong-version fixtures | per mutation | 2 bases × 7 mutations × 3 seeds = 42 cases, generated in memory. |
| S6 | The vulnlab fixtures in `examples/reports/` (fictional `libhdr`) | genuine / fabricated / insufficient | 5 cases. |
| S7 | LLM-written fabricated reports | synthetic | Not included. Never mixed into real-world metrics. |

Labels are `genuine`, `fabricated` or `insufficient`. An entry may also carry the verdict
it is expected to get (`expected`). For S5, the expected verdicts come from the SPEC §17.1
table: M3 (a version where the code differs) should give MIXED, and every other mutation
should give UNGROUNDED.

## Collection

- The manifests in `bench/manifests/` hold **IDs, URLs, labels and derived annotations only**.
  The loader rejects any other field, so report text cannot be committed by accident.
- Remote entries (S1–S3) are fetched at runtime into a gitignored cache, and only after the
  terms of that source have been checked (`terms_checked: true` in the manifest; ADR 0003).
  Until then those manifests are empty and the bench runs offline.
- S6 is written by the Nikasha authors against their own demo library. The sanitizer output in
  it was captured by really running the proof of concept.

## Preprocessing

- S5 mutations are deterministic. The random generator is seeded from
  `"<base>:<mutation>:<seed>"`, so every machine produces the same text. Mutated text lives only
  in memory, plus a temporary file for the length of one check.
- The bench outputs contain no report text at all: only IDs, labels, verdicts, scores,
  rules, evidence metadata (check, outcome, strength, group) and, for a failed case, the
  exception class name. Manifest `notes` are capped at one line of 200 characters.
- There is no fetch cache yet. Stripping reporter handles and names from cached text will
  be built together with the S1 to S3 fetcher, after the terms check.

## Uses

- Measuring the false-UNGROUNDED rate, recall, coverage, calibration (Brier and ECE) and
  latency of Nikasha releases, plus a drop-one ablation for each check.
- Calibrating check strengths (`nikasha bench calibrate`). This happens only when there are at
  least 50 labelled real reports per class. Only the real split (S1 to S4) counts: synthetic
  S5 mutations and the project's own S6 vulnlab fixtures never do. A fit is written as a new
  `calibration-v<N>.yaml` and never overwrites an earlier one.
- Dynamic reproduction (`nikasha bench run --repro`) of entries that name a `poc`, a `recipe`
  and a `version`. No committed entry names a PoC yet.
- **Not for** judging, ranking or naming reporters, and not as training data for classifiers
  that detect AI-written text.

## Distribution

- The manifests and this card are in the repository: code under Apache-2.0, documentation
  under CC-BY-4.0.
- Third-party report text is never redistributed unless its license allows it.
- `bench/results/<date>/` holds generated outputs. Results are published as summary tables
  worded neutrally.

## Maintenance and takedown

- New sources arrive as manifest changes with a terms check recorded in the pull request.
- **Takedown.** If you are the author of a report listed in a manifest, or hold rights to it,
  open an issue or email the maintainers listed in `SECURITY.md` and ask for removal. We remove
  the entry, delete any cached copy, and drop it from the next results run. You do not have to
  give a reason.
