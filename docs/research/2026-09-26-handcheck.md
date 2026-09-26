<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# M3.5 hand-check of 40 REFUTES findings (2026-09-26)

> **Model-judged by an AI agent (Claude), not human-verified.** A maintainer should
> spot-check these judgements before any of the numbers are quoted as ADR 0003 results.

ADR 0003 asks for the per-finding precision of 40 randomly sampled refutations. The sample
comes from `bench/results/2026-09-26/results.jsonl` (59 REFUTES findings, seed 20260926,
`scripts/handcheck_sample.py`). For each finding the agent re-ran `check_report` on the
cached report against the same local curl clone and read the claim, the summary and the
evidence. It then inspected the curl tree at the ref the check used, and at the version
the report names. The re-runs used a shared warm index with a 900 s check budget for the
first 7 reports and 60 s for the rest.

A refutation is **correct** when the claim really contradicts curl's code at the version
the report names. It is **incorrect** when it does not, including when the "claim" is not
a claim about curl at all, such as a reporter's PoC file. It is **undecidable** when the
report names two versions that disagree. The judged worksheet, which contains
report-derived text, is `bench/cache/handcheck-2026-09-26-judged.md` (gitignored).

## Precision

Precision is correct / (correct + incorrect), with a Wilson 95% interval.

| slice | n | correct | incorrect | undecidable | precision [Wilson 95%] |
|---|--:|--:|--:|--:|---|
| all | 40 | 3 | 35 | 2 | 0.08 [0.03, 0.21] |
| C01 | 1 | 1 | 0 | 0 | 1.00 [0.21, 1.00] |
| C02 | 22 | 0 | 22 | 0 | 0.00 [0.00, 0.15] |
| C03 | 11 | 1 | 8 | 2 | 0.11 [0.02, 0.44] |
| C04 | 1 | 1 | 0 | 0 | 1.00 [0.21, 1.00] |
| C11 | 1 | 0 | 1 | 0 | 0.00 [0.00, 0.79] |
| C12 | 1 | 0 | 1 | 0 | 0.00 [0.00, 0.79] |
| C14 | 3 | 0 | 3 | 0 | 0.00 [0.00, 0.56] |
| label fabricated | 12 | 2 | 8 | 2 | 0.20 [0.06, 0.51] |
| label genuine | 28 | 1 | 27 | 0 | 0.04 [0.01, 0.18] |

The findings are not independent: 40 findings come from 28 reports, so the intervals are
optimistic.

## Why the incorrect refutations are wrong

| cause | findings | what happened |
|---|--:|---|
| scoping | 14 | A reporter's PoC file or script, a system header from a PoC `#include`, a helper function in `poc.py`, or a libssh permalink was treated as a `project_attributed` curl claim |
| moving-ref | 11 | The report pinned `master` (or tested master) when a file, symbol or option still existed there (NSS was removed 2023-07, SMB on 2026-09-12). The check resolved `master` to today's tip |
| extraction | 5 | Git commit hashes cited in prose were extracted as symbols (3), and a Markdown escape `exploit\_server.py` was cut to `_server.py` (2) |
| wrong-version | 3 | A historical commit the report cites ("introduced in", "dates to", "the earlier fix") was taken as the tested version |
| polarity | 1 | The report says a function does *not* exist and proposes adding it |
| trace-parse | 1 | The free and allocation stacks were present but hand-reformatted; C11 said they were missing |

## Per-finding results

| # | report | check | label | judgement | cause |
|--:|---|---|---|---|---|
| 1 | h1-1234760 | C02 | genuine | incorrect | moving-ref |
| 2 | h1-1555441 | C02 | genuine | incorrect | moving-ref |
| 3 | h1-1555441 | C02 | genuine | incorrect | moving-ref |
| 4 | h1-1555441 | C14 | genuine | incorrect | moving-ref |
| 5 | h1-1573634 | C14 | genuine | incorrect | wrong-version |
| 6 | h1-2072338 | C02 | genuine | incorrect | scoping |
| 7 | h1-2823554 | C02 | fabricated | incorrect | scoping |
| 8 | h1-2823554 | C02 | fabricated | incorrect | scoping |
| 9 | h1-3125832 | C02 | fabricated | incorrect | extraction |
| 10 | h1-3125832 | C02 | fabricated | incorrect | extraction |
| 11 | h1-3249936 | C03 | fabricated | undecidable | ambiguous version |
| 12 | h1-3249936 | C03 | fabricated | undecidable | ambiguous version |
| 13 | h1-3294999 | C02 | genuine | incorrect | scoping |
| 14 | h1-3335085 | C03 | fabricated | incorrect | scoping |
| 15 | h1-3392174 | C04 | fabricated | correct | |
| 16 | h1-3459417 | C03 | genuine | correct | |
| 17 | h1-3466883 | C01 | fabricated | correct | |
| 18 | h1-3470095 | C02 | fabricated | incorrect | moving-ref |
| 19 | h1-3470095 | C03 | fabricated | incorrect | moving-ref |
| 20 | h1-3473182 | C02 | fabricated | incorrect | scoping |
| 21 | h1-3477116 | C02 | genuine | incorrect | scoping |
| 22 | h1-3477116 | C02 | genuine | incorrect | scoping |
| 23 | h1-3480925 | C02 | genuine | incorrect | scoping |
| 24 | h1-3583983 | C03 | genuine | incorrect | extraction |
| 25 | h1-3591944 | C02 | genuine | incorrect | moving-ref |
| 26 | h1-3591944 | C02 | genuine | incorrect | moving-ref |
| 27 | h1-3591944 | C03 | genuine | incorrect | moving-ref |
| 28 | h1-3591944 | C03 | genuine | incorrect | moving-ref |
| 29 | h1-3591944 | C14 | genuine | incorrect | moving-ref |
| 30 | h1-3650689 | C03 | genuine | incorrect | polarity |
| 31 | h1-3671818 | C02 | genuine | incorrect | scoping |
| 32 | h1-3677759 | C02 | genuine | incorrect | scoping |
| 33 | h1-3694390 | C03 | genuine | incorrect | extraction |
| 34 | h1-3733910 | C02 | genuine | incorrect | wrong-version |
| 35 | h1-3750295 | C02 | genuine | incorrect | scoping |
| 36 | h1-3750295 | C03 | genuine | incorrect | extraction |
| 37 | h1-3751697 | C11 | genuine | incorrect | trace-parse |
| 38 | h1-3751712 | C12 | genuine | incorrect | wrong-version |
| 39 | h1-3793260 | C02 | genuine | incorrect | scoping |
| 40 | h1-3822248 | C02 | genuine | incorrect | scoping |

## Reproducibility notes

- 31 of the 40 findings were reproduced exactly (same check, outcome and strength at the
  same position). For 8 of the other 9, the evidence order had shifted, so the first
  REFUTES from the same check in the same report was judged. It may not be the identical
  item.
- In finding 6, the re-run's C02 history search timed out (20 s), so the check withheld
  the finding. A plain `nikasha check` with the default 10 s budget withheld finding 1 the
  same way. Findings depend on wall-clock budgets beyond C10.
- Two reports whose bench verdict was MIXED came out **UNGROUNDED** on re-run
  (h1-3335085, h1-3466883; both labelled fabricated). This is not a P4 problem, but the
  bench verdicts are not reproducible across machine load.
