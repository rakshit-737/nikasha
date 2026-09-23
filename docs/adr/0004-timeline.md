<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0004: Symbol timelines: lazy by default

- **Status:** accepted
- **Date:** 2026-09-23

## Context

SPEC §11.4 asks in which releases a symbol is *defined* (not merely mentioned), and asks for
two strategies to be benchmarked on curl and SQLite before choosing a default:

- **lazy:** one batched `git grep -F -w -l <name>` across every final release tree, then
  parse only the matching files (each blob once, cached by SHA) to confirm a definition;
- **full:** index every final release tree (`nikasha index --history`), then answer from
  SQLite.

Both end with a time-bounded `git log --all -S<name>` when no release defines the symbol, so
that "never existed anywhere in history" is only said when git confirms it.

## Method

`scripts/bench_timeline.py <repo> <symbols…>` runs each strategy on a fresh index database,
cold (empty index) and then warm (the same query again), on the cached full clones. For each
repository it picks four symbols: one removed during history, one added during history, one
mentioned in hundreds of files in every release, and one invented.

- **Machine:** Fedora 44, Linux 7.1.8, 16 CPUs (x86_64), 15 GiB RAM; Python 3.12.14;
  git 2.55.0. The clones live in `~/.cache/nikasha` on btrfs (the NTFS working tree is not
  involved). Single-threaded; only brief, light commands ran alongside the final runs.
- **Correctness cross-check:** the boundaries were confirmed with plain `git grep` on the
  neighbouring tags (for example, `Curl_http_readwrite_headers` is defined in `lib/http.c`
  at `curl-7_20_0` and `curl-8_5_0`, and absent at `curl-7_19_7` and `curl-8_6_0`).

## Results

Seconds per query. *Cold* is the first query on an empty index, *warm* the same query
again. The full strategy's first cold query includes indexing every release.

**curl** (206 final releases; whole run 7 min 39 s, peak memory 1.2 GB)

| Strategy | Symbol | Cold | Warm | Defined in |
|---|---|---:|---:|---|
| lazy | `Curl_http_readwrite_headers` (removed) | 12.6 | 4.4 | 7.20.0 … 8.5.0 |
| lazy | `Curl_sasl_decode_mech` (added) | 8.4 | 4.3 | 7.41.0 … 8.22.0 |
| lazy | `curl_easy_perform` (everywhere) | 32.5 | 13.7 | 7.1.1 … 8.22.0 |
| lazy | `Curl_nonexistent_chunk_decoder` (invented) | 9.9 | 10.0 | never; absent from all history |
| full | `Curl_http_readwrite_headers` | 312.3 | 5.6 | 7.20.0 … 8.5.0 |
| full | `Curl_sasl_decode_mech` | 5.0 | 4.9 | 7.41.0 … 8.22.0 |
| full | `curl_easy_perform` | 4.2 | 3.8 | 7.1.1 … 8.22.0 |
| full | `Curl_nonexistent_chunk_decoder` | 13.3 | 13.0 | never; absent from all history |

**SQLite** (375 final releases, 2.x and 3.x; whole run 9 min 0 s, peak memory 2.3 GB)

| Strategy | Symbol | Cold | Warm | Defined in |
|---|---|---:|---:|---|
| lazy | `sqlite3BtreeFactory` (removed) | 22.4 | 14.1 | 3.0.0 … 3.7.2 |
| lazy | `sqlite3_prepare_v3` (added) | 34.7 | 14.1 | 3.20.0 … 3.53.4 |
| lazy | `sqlite3VdbeExec` (everywhere) | 30.7 | 13.7 | 3.0.0 … 3.53.4 |
| lazy | `sqlite3VdbeFabricatedDecoder` (invented) | 27.7 | 28.1 | never; absent from all history |
| full | `sqlite3BtreeFactory` | 259.5 | 15.3 | 3.0.0 … 3.7.2 |
| full | `sqlite3_prepare_v3` | 6.3 | 6.2 | 3.20.0 … 3.53.4 |
| full | `sqlite3VdbeExec` | 3.1 | 3.2 | 3.0.0 … 3.53.4 |
| full | `sqlite3VdbeFabricatedDecoder` | 30.1 | 30.2 | never; absent from all history |

Both strategies give identical answers for all eight symbols. Boundaries checked with plain
`git grep`: `sqlite3BtreeFactory` is in `src/main.c` at `version-3.0.0` and `version-3.7.2`
and gone at `version-3.7.3`.

**The history search is the fixed cost of "never existed".** For an invented name, the
timeline adds a `git log --all -S` over the whole history, measured on its own at 5.0 s for
curl and 13.6 s for SQLite, against a 20 s budget. On a machine about 1.5× slower,
SQLite's search would time out, and the timeline would say "history incomplete" instead of
"never existed". That is the conservative direction (P4), but caching search results per
repository state is a worthwhile follow-up.

### Indexing one tree (SPEC target: curl HEAD under 30 s)

| Repository | Files | Source files | Parsed cleanly | Symbols | Calls | Cold | Warm | DB size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| curl `4c67658f95` | 4,546 | 1,100 | 851 | 11,864 | 51,729 | 2.6 s | 0.01 s | 11 MB |
| SQLite `b943fa1288` | 2,224 | 457 | 253 | 19,345 | 85,707 | 4.3 s | 0.01 s | 17 MB |
| libxml2 `16d4a7c21e` | 3,890 | 218 | 102 | 6,033 | 29,268 | 1.7 s | 0.01 s | 7 MB |

### Parser recall on real C

"Parsed cleanly" is low for macro-heavy C because tree-sitter does not run the
preprocessor. What matters is whether definitions are lost, so each `.c` file at HEAD was
compared with an independent baseline: every file-scope function whose header starts at
column 0 and whose `{` opens at column 0 within 12 lines, before any `;`.

| Repository | Baseline definitions | Found | Missed in clean files | Missed in files with errors |
|---|---:|---:|---:|---:|
| curl | 5,742 | 99.6% | 3 | 19 |
| SQLite | 773 | 99.9% | 0 | 1 |
| libxml2 (before `preproc.py`) | 1,564 | 95.8% | 0 | 66 |
| libxml2 (after) | 1,564 | 99.6% | 0 | 6 |

libxml2's losses came from attribute macros between the type and the name
(`static void LIBXML_ATTR_FORMAT(3,0) xmlErrValid(...)`), which tree-sitter read as the
function's name. That produced a false definition and misattributed calls, which would have
failed genuine trace frames. `code/preproc.py` fixes this pattern. The remaining misses are
mostly `#if` blocks inside function bodies. They are covered by the uncertainty rule below
rather than guessed at.

## A bug the benchmark found

The first curl run spent minutes on `curl_easy_perform`. Profiling 20 releases showed 58 of
70 seconds in `CodeIndex.file_at`, which re-read the whole tree listing from SQLite for
every single file lookup: quadratic in tree size. Listings are now recorded once per tree
and looked up by primary key, and parse results are kept in a bounded in-memory LRU
(including "not a source file"). The same 20-release query dropped to 8.5 s, dominated by
parsing. `tests/integration/test_code_intel.py::TestIndex::test_lookups_do_not_reread_trees_or_facts`
guards it.

## Decision

- **Lazy is the default** for `nikasha timeline` and for the checks (C03 and friends). A
  report asks about a handful of symbols; lazy answers each in seconds with no up-front
  cost, while full pays several minutes of indexing before its first answer.
- **Full stays available** (`--strategy full`, and `nikasha index --history` to pre-build)
  for repeated work on one repository, such as a benchmark run over many reports.
- Warm full queries still revisit every release (`index_commit` re-checks each tree's
  blobs; 15 s per query on SQLite's 375 releases). Skipping trees already marked indexed is
  a cheap follow-up, deferred until M6 needs it.
- **Uncertainty is part of the answer (P4).** A release where the name appears only in
  files that did not parse cleanly is reported as *uncertain*, never as absent
  (`Timeline.uncertain_releases`), and a timed-out or shallow history search marks the
  timeline incomplete.

## Consequences

- On curl and SQLite, a timeline costs 8–35 s cold and 4–14 s warm, plus the history
  search when a symbol is never found. That is acceptable for a per-report check, and the
  index database makes repeat queries on a repository cheaper.
- Parse results kept in memory are bounded (an LRU of 8,192 entries). Peak RSS over a whole
  benchmark run (both strategies, four symbols) was 1.2 GB for curl and 2.3 GB for SQLite;
  where that memory goes has not been profiled yet.
- Parser gaps turn into "uncertain", not into false refutations.
