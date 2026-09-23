<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0003: Positioning after slopcheck's negative result, and the M3.5 gate

- **Status:** accepted
- **Date:** 2026-09-23

## Context

SPEC §0.2 claimed that no open-source, maintainer-facing tool mechanically verifies a
report's claims against source code. The M0 check found that this is no longer true.

[**slopcheck**](https://github.com/GaganGanesh98/SlopCheck) (MIT, created 2026-09-05,
tag `v1.0-negative-result`) is deterministic and read-only. It checks a report against a
source tree at `--ref` with six checks: `file_exists`, `line_in_range`, `symbol_exists`,
`snippet_present`, `commit_exists` and `version_tagged`. Its author evaluated it on **557
publicly disclosed curl HackerOne reports** (126 confirmed, 49 from curl's published
AI-slop list, 382 unlabelled) and published a careful **negative result**:

- 29.4% of confirmed, genuine reports received at least one contradiction, against 28.6%
  of slop reports.
- The best Youden J over any threshold sweep was 0.083, while a random feature swept the
  same way reached a median of 0.092.
- Only 4 of 40 randomly sampled contradictions were correct (10%).
- **Its diagnosis:** "the tool cannot tell which parts of a report are claims about the
  project". The wrong findings came from:
  - the reporter's own PoC or build artefacts and prose nouns (35%);
  - third-party APIs (20%);
  - a stale ref (15%);
  - a bare "line N" bound to the wrong path (10%);
  - path shape (5%);
  - negated statements ("there is no `X` equivalent") treated as existence claims.
- `snippet_present` was found "unsound by construction", because honest reporters quote
  their own PoCs, illustrations and signatures that have since changed.
- **Its own caveat:** every report was scored against **HEAD**, not the version it
  named.

Other tools found: SlopGate (a student capstone), SlopGuard (early, static plus LLM),
and GitHub's *announced but unshipped* "codebase inconsistency" detection for private
vulnerability reports. None of them does line-in-function, trace ↔ call-graph, trace
version-fit, sanitizer-arithmetic or patch-application checks, or sandboxed reproduction.

## Decision

The maintainer chose to **differentiate, and gate early**.

1. **Messaging.** Nikasha is presented as an *evidence dossier and reproduction tool for
   incoming reports*, not a "slop detector". The README credits slopcheck and its
   negative result as the baseline to beat, and the "no tool does this" claim is dropped.
2. **Spec changes** that target slopcheck's measured failure modes:
   - **Version pinning per report.** Each report is resolved to the version it names
     (SPEC §10). A report with no resolvable version is INSUFFICIENT and is never
     silently checked against HEAD.
   - **Claim scoping (M1).** Each claim gets a provenance:
     - `project_attributed`: tied to the project by a project path, an in-repo trace
       frame, or explicit wording such as "in src/x.c";
     - `reporter_artifact`: inside a PoC, build or command block;
     - `third_party`: an external API list hit, or a non-project frame;
     - `unscoped`.
   - **Polarity (M1).** Negated or absence statements never become existence claims.
   - **Line binding (M1).** A line number binds to a path only in `file:line` form, in
     the same clause, or through a blob URL.
   - **Refutation gating (M3).** C02, C03, C04, C06 and C07 may refute only
     `project_attributed`, non-negated claims; everything else is NEUTRAL, with a note
     saying why. C07's −2.5 and C06's −2.0 additionally require explicit attribution to
     a project location.
   - The structural checks (C05, C08–C12, C16) and reproduction (C19) stay central.
3. **M3.5, an early real-world gate, runs before any polish (M4).**
   - Run the static pipeline on slopcheck's curl corpus, reusing its MIT index of IDs and
     labels with attribution. Report text is fetched at runtime and never committed.
   - Compute slopcheck's metrics: flag rate on genuine reports, Youden J, and per-finding
     precision from a hand-checked random sample of 40.
   - Compute our own: false UNGROUNDED on genuine reports, and recall of UNGROUNDED and
     of UNGROUNDED ∪ MIXED on slop.
   - Ablate each change above.
   - Results are published whatever they are, and the maintainer decides between
     continuing, repositioning around reproduction and dossiers, or stopping. Thresholds
     are never adjusted to pass the gate.

## Consequences

- M1 grows by the scoping, polarity and line-binding extractors and their tests.
- NikashaBench's genuine set grows from about 124 (`vuln.json` entries with HackerOne
  links) to 126 or more confirmed reports, and it gains a directly comparable baseline.
- Before fetching, we must check HackerOne's terms for the disclosed-report `.json`
  endpoint. If they're unclear, the maintainer decides (SPEC §8).
- There is a real risk that Nikasha's static layer also shows little separation. The
  gate exists to learn that cheaply and honestly.
