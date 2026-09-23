<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0001: A staged, pure, deterministic pipeline

- **Status:** accepted
- **Date:** 2026-09-23

## Context

A maintainer must be able to trust, re-run and audit every verdict (principles P2 and P6),
and every input is hostile (P7). The spec (§4) describes a pipeline from intake to
rendered verdict.

## Decision

1. **Staged pipeline with typed boundaries:** ingest → extract → resolve → code
   intelligence → checks → fusion → render. Each stage is a function from immutable
   pydantic models (`frozen=True, extra="forbid"`) to immutable models, so each stage can
   be cached, tested and replayed on its own.
2. **Deterministic core.** No LLM, clock, randomness or environment-dependent ordering in
   extraction, checks or fusion.
   - IDs are `sha256(kind + canonical fields)[:12]`.
   - JSON is emitted with sorted keys and stable ordering.
   - Timings live in their own field, which comparisons exclude.
3. **Evidence ledger, then fusion.** Checks never produce verdicts. They emit evidence
   items (outcome, strength as a log likelihood ratio, group, locations with permalinks,
   and command records). Fusion combines them with log-odds and per-group damping, and
   applies ordered, conservative verdict rules (SPEC §14).
4. **Process boundary.** Only two modules may spawn processes:
   - `nikasha.code.gitio` runs git, hardened per §19.3 with the corrections in
     [the M0 verification](../research/2026-09-23-m0-verification.md);
   - `nikasha.repro.sandbox` runs the podman and docker CLIs.

   One network module, arriving in M2, is the only one allowed to open network
   connections, and only when `--online` is given. Ruff's banned-API rule and an AST
   scanning test enforce this.
5. **Plumbing-only git.** Trees are read with `ls-tree` and `cat-file --batch` and
   materialized with `git archive`. Nikasha never checks out attacker-controlled
   working trees.
6. **Integrations are thin shells** over the same pipeline: CLI, GitHub Action, MCP
   server and local web UI.

## Consequences

- Every behaviour is testable offline. Golden tests can assert byte-identical output.
- New checks plug in through a registry without touching fusion.
- The process boundary makes the security review of git and sandbox handling local to
  two files.
