<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0012: Reposition around supporting evidence and reproduction after M3.5

- **Status:** accepted
- **Date:** 2026-09-26
- **Decides:** the maintainer decision that ADR 0003 requires after the M3.5 gate

## Context

ADR 0003 made M3.5 an early real-world gate: run the static pipeline on slopcheck's curl
corpus and then decide between continuing, repositioning around reproduction and dossiers,
or stopping. The gate ran on 2026-09-26 (ADR 0011 for corpus access) on all 175 labelled
reports (126 genuine, 49 slop), each checked at the version it names. Numbers from
`bench/results/2026-09-26/gate.json` (not committed), as recorded in `PROGRESS.md`:

| metric | Nikasha | slopcheck |
|---|--:|--:|
| flag rate (>=1 REFUTES) genuine / slop | 20.6% / 20.4% | 29.4% / 28.6% |
| J of that flag | -0.002 | about -0.008 |
| false UNGROUNDED on genuine | 0/126 (Wilson 95% upper 2.96%) | n/a |
| recall UNGROUNDED on slop | 0/49 | n/a |
| recall UNGROUNDED or MIXED on slop | 20.4% (10/49) | n/a |
| MIXED or UNGROUNDED on genuine | 22.2% (28/126) | n/a |
| J (UNGROUNDED or MIXED) | -0.018 | n/a |
| best J, score threshold sweep | 0.249 | 0.083 |
| median best J, seeded random score | 0.103 | 0.092 |

Verdicts: genuine GROUNDED 32, MIXED 28, INSUFFICIENT 66; slop GROUNDED 5, MIXED 10,
INSUFFICIENT 34.

What this shows:

- **P4 held** (no genuine report was called UNGROUNDED), but n=126 cannot yet show the
  rate is under 1%.
- **Refutations do not separate** slop from genuine reports (J about 0), no better than
  slopcheck.
- The only signal is **support**: GROUNDED is more common on genuine reports (25%) than on
  slop (10%). The best-threshold J (0.249, against 0.103 for a random score) is picked
  after the fact and is therefore optimistic.
- The hand-checked precision of 40 random REFUTES findings is still open.

## Decision

The maintainer chose option **(b): reposition**.

1. **Primary value: grounding and reproduction.** Nikasha shows which claims the code
   supports, at which version, with the evidence (repository, commit, path, lines,
   command). Sandboxed reproduction (C19, REPRODUCED) is the strongest evidence it offers.
2. **Refutations stay, gated and conservative, as leads.** The ADR 0003 gating is
   unchanged. Refutations are presented as questions for the reporter and leads for the
   triager, never as a fabrication or "slop" detector.
3. **UNGROUNDED stays only as the existing strict rule** (ladder rule 3). It is not
   loosened, widened or promoted.
4. **No scoring change.** Strengths, thresholds and fusion stay as they are until they can
   be calibrated on more data (M6). Nothing is tuned on the M3.5 corpus.

## Consequences

- README, `docs/index.md` and `docs/concepts.md` lead with grounding and reproduction and
  publish the M3.5 numbers with their caveats.
- **M6 (NikashaBench) should measure next:**
  - *supporting-evidence recall*: the share of genuine reports' checkable project claims
    that receive SUPPORTS evidence at the named version;
  - *reproduction rate*: the share of reports with a PoC that reach REPRODUCED with the
    shipped recipes (curl, sqlite, libxml2 first);
  - *precision of refutations*, starting from the 40-finding hand-check
    (`scripts/handcheck_sample.py`), then on larger samples;
  - false UNGROUNDED on a genuine set large enough for the Wilson upper bound to fall
    under 1% (about 381 or more genuine reports with no false UNGROUNDED).
- **M9** may explore dossier features (supporting-evidence views, version-fit reports)
  rather than new refutation checks.
- Any later scoring change needs a new ADR with calibration data that was not used to
  choose it.
