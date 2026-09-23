<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# M0 verification report (2026-09-23)

SPEC.md asks that every external fact, API, flag and format be checked against current
sources before use. This is the record of that check, done on 2026-09-23 through web
research, the `gh api`, the local `--help` and man pages (git 2.55.0, podman 5.8.4,
docker 29.7.2, gh 2.97.0), and experiments in a scratch virtual environment on
CPython 3.14.7. Items marked **unverified** must not be relied on until re-checked.

## 1. Problem statistics (SPEC §0.1)

| Claim | Result | Source |
|---|---|---|
| curl ended its bug bounty, effective 2026-01-31, citing AI slop; the confirmed share fell below 5% from more than 15% | Confirmed. The blog post is dated 2026-01-26, but press coverage began on 2026-01-21, so use "announced in January 2026". | <https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/>, <https://www.theregister.com/2026/01/21/curl_ends_bug_bounty/> |
| curl's public AI-slop list has about 49 HackerOne entries | Confirmed: 49 entries, last updated 2026-09-05 | <https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd> |
| JFrog: 54 of 55 advisories from one account were fabricated | Confirmed. Named CVEs: CVE-2026-51296, -51297, -51300, -51302, -51303, -51304 | <https://research.jfrog.com/post/sqlite-critical-cves-or-llm-slops/> |
| The Register: MITRE rejected the set; JFrog quote about reproduction not being required | Confirmed, quote exact | <https://www.theregister.com/security/2026/08/03/ai-slop-pollutes-the-cve-pipeline-with-fake-vulns/5282462> |
| arXiv 2608.25667: "not a single study provides execution-level validation of claims in LLM outputs" | Confirmed, quote exact | <https://arxiv.org/abs/2608.25667> |
| Alpha-Omega guidance for AI-assisted finders (2026-04-30) | **Unverified.** No such post found. Candidate re-source: the OpenSSF/CNCF guide from May 2026, not yet read | <https://openssf.org/resources/securing-open-source-in-the-age-of-ai-a-practical-guide/> |
| $12.5M from the Linux Foundation via Alpha-Omega and OpenSSF (2026-03-17) | Confirmed | <https://www.theregister.com/2026/03/18/linux_foundation_ai_slop_defense/> |
| HackerOne submissions "up more than 100% since February 2026" | **Differs:** the source says "doubled year-over-year in April" | <https://www.bankinfosecurity.com/ai-reshapes-bug-bounties-but-humans-still-matter-a-31855> |
| Bugcrowd queues rose 334% in three weeks | Confirmed (March 2026) | <https://www.bugcrowd.com/blog/sloptimism-is-breaking-any-system-built-on-human-validation/> |

## 2. Prior art (SPEC §0.2)

See [ADR 0003](../adr/0003-differentiation-vs-slopcheck.md). In summary:

- **slopcheck** (<https://github.com/GaganGanesh98/SlopCheck>, MIT) is a direct,
  deterministic, maintainer-facing competitor that has published a negative result.
- **Scrutineer** (<https://github.com/alpha-omega-security/scrutineer>) now ingests
  external reports and has a `revalidate` skill; it is LLM-based.
- **AnyPoC** has released code (<https://github.com/zzjas/anypoc>, Apache-2.0), and so has
  **CVE-Genie** (<https://github.com/BUseclab/cve-genie>).
- GitHub has announced, but not shipped, codebase-inconsistency detection for private
  vulnerability reports (GitHub Discussion #189802).

## 3. Name

- `nikasha` is free on PyPI (`/pypi/nikasha/json` returns 404), npm and crates.io.
- The GitHub user `nikasha` exists and is dormant; the project lives at
  `rakshit-737/nikasha`, so this doesn't matter.
- `pramaan` clashes with ONDC-Official/pramaan. See [ADR 0000](../adr/0000-rename.md).

## 4. Libraries

See [ADR 0002](../adr/0002-dependencies.md). The key corrections to the spec:

- py-tree-sitter 0.26 removed `Language.query()`.
- tree-sitter-language-pack downloads grammars at runtime.
- The MCP SDK is 2.x, where FastMCP became `MCPServer`.
- httpx is stagnant, so Nikasha uses stdlib `urllib` instead.
- Supported CPython versions are 3.11–3.14 (3.15 is due on 2026-10-01).
- Material for MkDocs is in maintenance mode, and Zensical is pre-1.0; the choice is made
  in M8.

## 5. Git hardening (SPEC §19.3), with corrections

- Confirmed valid:
  - the `-c` overrides `core.fsmonitor=false`, `core.hooksPath=/dev/null`,
    `core.pager=cat`, `core.sshCommand=false`, `credential.helper=` (an empty value resets
    the helper list), `protocol.file.allow=never` and `submodule.recurse=false`;
  - the environment variables `GIT_CONFIG_NOSYSTEM`, `GIT_TERMINAL_PROMPT=0` and
    `GIT_OPTIONAL_LOCKS=0`.
- **`-c diff.external=` does not disable external diff.** An empty string makes git try
  to run an empty command. Use `--no-ext-diff`.
- **textconv is on by default for `git log`**, which covers `-S`, `-G` and `-p`. Nikasha
  passes `--no-textconv` to `log` and `show`. `git grep` already defaults to no textconv,
  and `cat-file --batch` never applies filters unless `--textconv` or `--filters` is
  given.
- `GIT_CONFIG_GLOBAL=/dev/null` is documented. It also drops any global
  `safe.directory`, so Nikasha passes `-c safe.directory=<repo>` per command. That setting
  is honoured from the command scope.
- `git archive` honours the tree's own `.gitattributes` (`export-ignore` and
  `export-subst`). It runs commands only through configured `tar.<format>.command`, which
  Nikasha never sets.

## 6. Container flags (SPEC §13.4)

- Both engines support `--network none`, `--read-only`, `--tmpfs`, `--cap-drop ALL`,
  `--pids-limit`, `--memory`, `--cpus`, `--user`, `--ulimit`, `--init` and `--rm`.
- **podman `--read-only-tmpfs` defaults to true**, which mounts writable tmpfs on /dev,
  /dev/shm, /run, /tmp and /var/tmp. Pass `--read-only-tmpfs=false`.
- **`--runtime` is a global podman flag** (`podman --runtime X run …`), but a `run` flag
  on docker.
- no-new-privileges is spelled `no-new-privileges=true` in the docker docs and bare
  `no-new-privileges` in the podman man page. The M5 sandbox tests must assert the effect
  (`NoNewPrivs: 1` in `/proc/self/status`), not just the spelling.
- On cgroup v1 rootless setups, podman does not support `--memory` and `--cpus`. This
  development host has cgroup v2 with the cpu, io, memory and pids controllers delegated.

## 7. GitHub, release and community

- **Actions:** pinned by commit SHA, with annotated tags peeled to the commit.
  - The CodeQL action's "latest release" is the CLI bundle (`codeql-bundle-v2.27.1`); the
    action itself is v4.38.1.
  - `actions/attest-build-provenance` v4 is a wrapper, and its docs recommend
    `actions/attest` for new code.
  - `astral-sh/setup-uv` v10.2.0 has no floating `@v10` tag.
  - gitleaks-action v3 needs no licence for user-owned repositories.
- **PyPI Trusted Publishing:**
  - the pending publisher needs project, owner, repository, workflow file and
    environment;
  - reusable workflows are not supported;
  - `id-token: write` is required;
  - PEP 740 attestations are on by default.
- **gh CLI:** no flag enables private vulnerability reporting. Use
  `gh api -X PUT repos/{owner}/{repo}/private-vulnerability-reporting`.
- **Topics:** at most 20, lowercase letters, digits and hyphens, 50 characters or fewer.
  The social preview has no API.
- **Contributor Covenant 3.0:** CC BY-SA 4.0. The canonical text is in
  `EthicalSource/contributor_covenant` (`content/version/3/0/code_of_conduct.md`).
- **REUSE.toml:** `version = 1` and `[[annotations]]`; precedence is `closest`,
  `aggregate` or `override`. `CITATION.cff` uses cff-version 1.2.0.
- **Dependabot:** supports the `uv`, `pre-commit`, `github-actions` and `docker`
  ecosystems, `groups` with `update-types`, and `cooldown`.

## 8. Data sources

- **cvelistV5:** paths are `cves/{year}/{n // 1000}xxx/CVE-{year}-{n}.json`; there is also
  `cves/deltaLog.json`.
- **OSV:** `POST /v1/query`, `POST /v1/querybatch` and `GET /v1/vulns/{id}` confirmed.
- **curl's `vuln.json`:** OSV 1.5.0 with 215 entries. **Only 124 carry
  `database_specific.issue`** (a HackerOne URL).
- **HackerOne API:** `GET /v1/reports/{id}` with Basic auth. No environment variable names
  are documented, so Nikasha will define `NIKASHA_H1_API_ID` and `NIKASHA_H1_API_TOKEN`.
- **GitHub repository advisories:** `?state=triage` needs a security manager, an admin or
  an advisory collaborator.
- **SQLite amalgamation:**
  - download names follow `YYYY/sqlite-amalgamation-3XXYYZZ.zip`;
  - the source banners look like `/************** Begin file X.c ****…*/`, plus `End of`
    and `Continuing where we left off in` markers.
- **Claude MCP setup:** `claude mcp add [-s scope] [-e K=V] <name> -- <cmd> [args…]`. The
  Claude Desktop config location is documented for macOS and Windows only.
