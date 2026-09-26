<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0011: Fetching publicly disclosed HackerOne reports for NikashaBench

- **Status:** accepted
- **Date:** 2026-09-26
- **Decides:** the open terms question of ADR 0003 ("Before fetching, we must check
  HackerOne's terms for the disclosed-report `.json` endpoint") and SPEC §8/§17.2

## Context

The M3.5 gate (ADR 0003) needs the text of the curl reports in slopcheck's corpus index:
126 reports curl confirmed (`resolved`) and 49 from curl's published AI-slop list. The text
is only on HackerOne, as publicly disclosed reports with a public `.json` rendering at
`https://hackerone.com/reports/<id>.json`.

Checked on 2026-09-26:

- `https://hackerone.com/terms/general` has no clause on scraping or automated access.
- `https://hackerone.com/robots.txt` lists a sitemap and no `Disallow` rule.

## Decision

The maintainer allows the access, conservatively, under these conditions. They are
enforced in code (`src/nikasha/bench/h1corpus.py`) where code can enforce them:

1. **Publicly disclosed reports only**, through the public report `.json` endpoint. No
   authentication, no other endpoint. A payload without `disclosed_at`, or marked not
   public, is dropped and not written.
2. **Polite:** at least 2 s between the starts of consecutive requests (a lower delay is
   refused), one connection at a time, and an honest `User-Agent` naming Nikasha and the
   repository URL. Nothing is requested without `--online` (P3). Responses are capped.
3. **Cache only under the gitignored `bench/cache/`** (directory 0700, files 0600), and
   only the title and the report body. The reporter, comments and other fields are not
   stored. The cache is resumable, so a report is fetched once.
4. **Manifests hold IDs, URLs and labels only** (enforced by `extra="forbid"` in
   `bench/manifests.py`). No report text is ever committed.
5. **Stop and purge on any objection** from HackerOne, curl or a reporter:
   `nikasha.bench.h1corpus.purge` deletes the cache, and the fetch is not rerun.
6. **Re-check the terms and robots.txt before each corpus refresh**, and record the date
   in `PROGRESS.md`.

The corpus index and labels are reused from slopcheck (MIT) with attribution in the
manifest headers.

## Consequences

- `nikasha bench fetch-h1 --online` fills `bench/cache/h1/`, and `nikasha bench run
  --split real --h1-cache bench/cache/h1` checks the cached reports. Without the cache the
  remote entries are skipped, as before.
- `nikasha bench gate results.jsonl` computes the ADR 0003 gate numbers.
- If HackerOne's terms change to forbid this, this ADR is superseded and the cache purged.
