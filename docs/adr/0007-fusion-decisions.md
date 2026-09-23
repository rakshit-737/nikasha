<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0007: Four fusion and evidence decisions taken at the end of M3

- **Status:** accepted
- **Date:** 2026-09-23

## Context

Building the nineteen checks (M3) surfaced four questions that no single check could
answer, because each one is about how evidence *combines* rather than about what any one
check measures. They are recorded together because they share a theme: when the honest
answer is "we do not know yet", the conservative direction is the one that cannot cause a
false UNGROUNDED (P4).

## Decision 1: C02 and C08 keep their overlap, and M3.5 measures it

`C02 FILE_EXISTS` checks paths from trace frames (group `locus`), and `C08 TRACE_FRAMES`
re-checks the same frames (group `trace`). SPEC §12 specifies both. Because §14.1 damps
evidence *within* a group, the overlap is not damped, and one fabricated path can on its
own satisfy rule 3a's requirement for "refutations from at least 2 independent groups".

**Decision: change nothing, and measure it at the M3.5 gate.**

The alternatives were to make C02 skip trace frames, or to move C02's frame findings into
the `trace` group. Both are plausible, and both are guesses about a quantity we are about
to measure. ADR 0003 committed us to running the slopcheck corpus before polishing
anything, precisely so that questions like this are settled by data rather than by
intuition. Adjusting the scoring model first would also make the gate's ablation
meaningless.

**Consequence:** this is a known, recorded P4 risk. M3.5 must report the false-UNGROUNDED
rate with and without C02's trace-frame findings, as one of its ablations.

## Decision 2: a reproduced crash is high confidence by definition

SPEC §14.3's confidence formula ("high when |λ| ≥ 4 **and** 3 or more groups contributed")
gives *medium* for a lone `C19` signature match, because a reproduction is one finding in
one group. `fuse/verdict.py` rule 1 returns `high` instead.

**Decision: keep `high`, and treat it as a documented exception to the formula.**

The formula exists to distrust correlated statistical evidence: several findings in one
group may all be restatements of the same fact, so breadth is evidence of independence. A
reproduction is not statistical evidence at all. The PoC ran in the sandbox and the crash
signature matched; that is direct proof, and demanding corroboration from two more groups
would report our strongest possible result as merely medium.

**Consequence:** SPEC §14.3's confidence sentence applies to rules 2–6. Rule 1 is an
exception, noted here. The test that recorded the divergence now asserts this behaviour.

## Decision 3: no new strength keys before calibration

Four checks asked for strength keys that do not exist, for the case where a P4 safeguard
downgrades a refutation: `C03 absent_in_sampled_supporting`, `C06 elsewhere_in_repo` and
`absent_in_sampled_releases`, `C07 absent_in_sampled`. Today those paths emit NEUTRAL 0.0
and record the withheld strength in `details`.

**Decision: leave them at 0.0 until calibration (SPEC §14.2) fits real values.**

Adding a key means inventing a number, and CLAUDE.md forbids tuning strengths by hand.
Collapsing to 0.0 discards signal, but it can only ever *weaken* a refutation, never
strengthen one, so the conservative direction is the safe one for P4. The information is
not lost: `details["withheld_strength"]` records what the check would have scored, so
M3.5 and M6 can measure what these keys are worth before anyone picks a value.

**Consequence:** M6 calibration adds these four keys with fitted values, and the checks
switch to them in one line each.

## Decision 4: one shared `CommandRecord` helper, in M4

P6 asks that evidence carry "the command with output hashes". No check emits a
`CommandRecord`. Nine checks shell out to git, and four independently reported the same
two blockers: `GitResult.argv` contains the absolute cache path of the clone (a P3 leak
once it is rendered into a report someone forwards), and `CommandRecord.duration_ms` would
differ between two runs on the same input, breaking the byte-identical JSON guarantee (P2).

**Decision: add one helper in M4 that redacts argv to a repo-relative form and keeps the
duration out of the identity payload; adopt it across the checks then.**

M4 is the milestone that renders the command record to a human, so it is the milestone
that defines what the record has to contain. Until then, checks record the equivalent
command as a string in `details`, which is re-runnable but carries no exit code or output
hashes.

**Consequence:** P6 is partially satisfied in M3 and fully satisfied in M4. The helper
belongs in `code/gitio.py`, beside the only code allowed to run git.

## Consequences overall

- Three of the four decisions defer a scoring change to a milestone that will have data.
  That is deliberate: M3 built the machinery, and the numbers in it are still priors.
- The one decision taken now (rule 1's confidence) changes no score, only a label, and is
  the case where the spec's own reasoning does not apply.
