<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Security policy

Nikasha processes hostile input by design: report text, attachments, git repositories
and proof-of-concept code. We take vulnerabilities in Nikasha itself seriously.

## Supported versions

Nikasha is pre-release. Until v0.1.0 ships, only the `main` branch is supported. After
that, the latest minor release gets security fixes.

| Version | Supported |
|---|---|
| `main` | ✅ |
| < 0.1.0 (pre-releases) | ❌ |

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on
[rakshit-737/nikasha](https://github.com/rakshit-737/nikasha/security/advisories/new).
If you can't use GitHub, email **rakshitoffl@gmail.com** with "Nikasha security" in the
subject.

Please include:

- the Nikasha version or commit, your OS, and the container engine if relevant;
- a minimal reproduction (for example a report file, repository or PoC that triggers it);
- the impact as you understand it.

**Response targets** (a single maintainer; best effort):

- acknowledgement within 7 days;
- an initial assessment within 14 days;
- a fix or mitigation plan within 90 days, with coordinated disclosure afterwards.

## In scope

- **Sandbox escapes:** a proof of concept run with `--repro` affecting the host, reaching
  the network, or escaping the resource limits.
- **Git hazards:** a repository that makes Nikasha execute commands or read files outside
  the repository (hooks, `fsmonitor`, pagers, textconv or external diff drivers,
  submodules).
- **XSS or script injection** in the HTML report, the Markdown output or the local web UI.
- **Web UI and MCP server hardening:** DNS rebinding, missing token or `Origin` checks,
  exposed reproduction.
- **Confidentiality:** network access or data leaving the machine without `--online` or
  an explicit cloud-LLM opt-in.
- **Resource exhaustion:** ReDoS or archive bombs in report or attachment parsing.
- **GitHub Action:** script injection through issue or event text.

Wrong verdicts (a genuine report labelled UNGROUNDED, or the reverse) are **bugs, not
vulnerabilities**. Please use the "False verdict" issue form, and **never paste an
embargoed report into a public issue.**

## Safe harbor

We will not pursue or support legal action against good-faith research that follows this
policy: research that avoids privacy violations, data destruction and service
disruption; only interacts with your own installations and test repositories; and gives
us reasonable time to fix the issue before disclosure.

## A friendly note

If you are reporting a bug to *another* project and want a second look at your report's
facts, the maintainers are happy to run `nikasha lint` on it with you.
