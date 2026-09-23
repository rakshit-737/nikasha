<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Progress

The living build log. Milestones follow SPEC §22, plus **M3.5** from ADR 0003.

| Milestone | Status |
|---|---|
| M0 Bootstrap | **done**: repo live at https://github.com/rakshit-737/nikasha |
| M1 Models, intake, extraction (+ claim scoping, polarity) | not started |
| M2 Resolution and code intelligence | not started |
| M3 Checks, fusion, CLI outputs | not started |
| M3.5 Early real-world gate (curl corpus vs. slopcheck) | not started |
| M4 HTML report and media v1 | not started |
| M5 Sandbox reproduction | not started |
| M6 NikashaBench | not started |
| M7 Integrations | not started |
| M8 Launch polish and v0.1.0 | not started |
| M9 Stretch | not started |

## M0: Bootstrap (2026-09-23)

### Done

- Verification of SPEC §0 and Appendix A.2 against current sources, recorded in
  `docs/research/2026-09-23-m0-verification.md`.
- Direct competitor found (slopcheck, with a published negative result). The maintainer
  chose "differentiate and gate early" (ADR 0003).
- Project renamed Pramaan → Nikasha (ADR 0000). `nikasha` is free on PyPI.
- Decisions:
  - repo `rakshit-737/nikasha`, public;
  - author Rakshit Rameshbabu <rakshitoffl@gmail.com>;
  - DCO sign-off required;
  - the working tree stays on the NTFS volume.
- Scaffold:
  - uv, hatchling, `src/` layout, Python ≥3.11, `uv.lock`;
  - `nikasha version`, `nikasha doctor`;
  - the hardened `gitio` base, container-engine detection, the process-boundary test.
- Legal: Apache-2.0 `LICENSE`, `NOTICE`, `LICENSES/`, `REUSE.toml`, `CITATION.cff`.
- Community: Code of Conduct (Contributor Covenant 3.0), CONTRIBUTING, SECURITY, SUPPORT,
  GOVERNANCE, CHANGELOG.
- `.github/`:
  - workflows: CI (lint, 3 OSes × 4 Pythons, gitleaks, DCO), CodeQL (python and
    actions), dependency review, Scorecard;
  - 6 issue forms plus `config.yml`, a PR template, CODEOWNERS, dependabot (uv and
    actions), release-notes categories, a label file.
- ADRs 0000–0003, `CLAUDE.md`.

### Published (2026-09-23, with the maintainer's approval)

- Created the public repo `rakshit-737/nikasha` (wiki off) and pushed.
- Settings applied and verified through the API:
  - Discussions on;
  - squash-merge only, with head branches deleted after merge;
  - private vulnerability reporting on;
  - secret scanning and push protection on;
  - Dependabot alerts and security updates on;
  - 13 labels from `.github/labels.yml`.
- The community profile is at 100%.
- At the maintainer's request, the history was rebuilt as one signed-off commit per
  file, and force-pushed once.
- Fixes after the first CI run:
  - a Windows test assumed a lowercase `git.exe` (the runner has `git.EXE`);
  - gitleaks-action v3 cannot scan a push that starts at the root commit (`<root>^`), so
    CI now runs the gitleaks v8.30.1 image, pinned by digest, over the full history.

### Open questions for the maintainer

- Ruleset on `main`: should there be an admin bypass while you are the only maintainer?
  (Decide before M8; the spec asks.)

## Carry-overs to later milestones

- **M1:** `extract/scope.py`, `extract/polarity.py` and line binding (ADR 0003).
  Coverage gate ≥85% on core packages once they exist. Schema drift check.
- **M2:** check `GIT_NO_LAZY_FETCH` in the git docs before relying on it. Build the git
  hazard canary test.
- **M3.5:** check HackerOne's terms for the disclosed-report `.json` endpoint before
  fetching the corpus.
- **M5:** engine-specific sandbox flags (see the verification report, §6).
- **M8:**
  - choose Zensical or Material for the docs (ADR);
  - `date-released` in `CITATION.cff` at v0.1.0;
  - add the docker ecosystem to Dependabot;
  - use `actions/attest` rather than `attest-build-provenance`;
  - re-verify every §0 fact for the README; drop or re-source the Alpha-Omega claim.
