<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# The Nikasha GitHub Action

The action runs `nikasha check` on a security report filed as a GitHub issue (or on a file
in the checkout), writes the verdict and the evidence to the job summary, uploads the JSON
result as an artifact and, when asked, comments on the issue and labels it with the verdict.
It is a composite action defined in [`action.yml`](../action.yml); the example workflow is
[`examples/workflows/nikasha-issues.yml`](../examples/workflows/nikasha-issues.yml).

> ## Warning: public issues only
>
> **Everything a GitHub Actions run touches on a public repository is public**: the logs,
> the job summary, the uploaded artifact and the comment. Never route a private or embargoed
> report through this action. Private reports, HackerOne submissions, emailed reports and
> private vulnerability advisories belong to a **local run**:
>
> ```sh
> nikasha check report.md --repo . --format markdown -o reply.md
> ```
>
> On a private repository the run is visible to every collaborator, which is still wider
> than a security contact list. The action is for reports the reporter has already made
> public.

## What one run does

1. Installs Nikasha **from the action's own checkout** (`pip install "$GITHUB_ACTION_PATH"`),
   so the action ref you pin is exactly the tool version you get.
2. Writes the report to a file. In `issue` mode the issue title and body come from the event
   payload through environment variables and are written with `printf`; they are never
   interpolated into a shell script (see [Security](#security)).
3. Runs `nikasha check` twice on the same input, once with `--format json` for the complete
   evidence record and once with `--format markdown` for people. Both runs are deterministic
   (principle P2), so the two outputs describe the same result.
4. Appends the Markdown to the job summary and uploads `result.json` and `result.md` as the
   `nikasha-result` artifact.
5. In `issue` mode, optionally posts a comment (updated in place on later runs) and sets a
   `nikasha:<verdict>` label.
6. Exits with the status `--fail-on` decided: `0` unless the verdict reached `fail-on`. An
   error in the check itself (a missing repository, a bad option) fails the job at step 3.

## Setup

1. Create the label that marks security reports, `security-report` by default. To use a
   different name, set the repository variable `NIKASHA_REPORT_LABEL` (Settings →
   Secrets and variables → Actions → Variables).
2. Add that label to the issue form reporters use (`labels: [security-report]` in the form's
   front matter), or apply it by hand: the workflow also runs when the label is added.
3. Copy [`examples/workflows/nikasha-issues.yml`](../examples/workflows/nikasha-issues.yml)
   to `.github/workflows/nikasha-issues.yml`. Keep `fetch-depth: 0` on the checkout step:
   Nikasha resolves the version a report names to a **tag**, and a shallow clone has none.
4. Replace the commit SHA on the `rakshit-737/nikasha` line with the release commit you
   audited (see [Pinned actions](#pinned-actions)). If your repository has a Dependabot
   configuration with `package-ecosystem: github-actions`, Dependabot keeps the pin
   current afterwards.

No secret is needed: the workflow's own `GITHUB_TOKEN` comments and labels.

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  with:
    fetch-depth: 0
    persist-credentials: false
- uses: rakshit-737/nikasha@<release commit SHA> # v0.1.0
  with:
    mode: issue
    comment: summary
    labels: true
```

### Checking a file instead of an issue

`mode: file` checks a report committed to the repository (or produced by an earlier step),
for example from a `workflow_dispatch` run. No `issues: write` permission is needed:

```yaml
- uses: rakshit-737/nikasha@<release commit SHA> # v0.1.0
  with:
    mode: file
    report-path: reports/2026-09-issue-42.md
    version: 1.2.0
    fail-on: ungrounded
    comment: none
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `mode` | `issue` | `issue` takes the title and body of the issue in the event payload (`issues` events only). `file` reads `report-path`. |
| `report-path` | | The report to check in `file` mode: Markdown, plain text or HTML, relative to the checkout. |
| `repo-path` | `.` | The repository the report is about, as a local path. Check it out with `fetch-depth: 0`. |
| `version` | | The release the report is about, for example `1.2.0`. Empty uses the version the report names. |
| `fail-on` | `none` | Fail the job when the verdict is this label or worse: `mixed`, `ungrounded` or `insufficient`. `none` never fails the job on a verdict. |
| `comment` | `summary` | `none`; `summary` (verdict line, target, verdict notes and the questions for the reporter, plus a link to the run); or `full` (the whole Markdown report). `issue` mode only. |
| `labels` | `false` | `true` labels the issue `nikasha:<verdict>`, replacing any earlier `nikasha:` label. `issue` mode only. |
| `nikasha-version` | | Empty installs Nikasha from the action's checkout. A PyPI version such as `0.1.0` installs that release instead, which decouples the tool version from the action ref. |
| `artifact-name` | `nikasha-result` | Name of the uploaded artifact with `result.json` and `result.md`. Empty skips the upload. |
| `token` | `${{ github.token }}` | The token used to comment and label. It needs `issues: write`. |
| `comment-author` | `github-actions[bot]` | The login `token` posts as. The in-place update only touches a comment that carries the marker **and** this author. Set it with a custom `token`: `<app>[bot]` for a GitHub App, the account's login for a personal access token. |

## Outputs

| Output | Meaning |
|---|---|
| `verdict` | `REPRODUCED`, `GROUNDED`, `MIXED`, `UNGROUNDED` or `INSUFFICIENT`. |
| `score` | The grounding score, 0 to 100. |
| `confidence` | `low`, `medium` or `high`. |
| `json` | Path of `result.json`, the complete evidence record (`nikasha explain` reads it). |
| `markdown` | Path of `result.md`, what the summary and the comment show. |

## Exit status and `fail-on`

`nikasha check` exits `0` for GROUNDED and REPRODUCED, `10` for MIXED, `20` for
UNGROUNDED, `30` for INSUFFICIENT and `1` on an error. The action treats every verdict as a
successful check and applies `fail-on` in its last step, after the summary, the artifact,
the comment and the label have been produced:

| `fail-on` | Job fails when |
|---|---|
| `none` | Never on a verdict (an error in the check still fails the job). |
| `mixed` | The verdict is MIXED, UNGROUNDED or INSUFFICIENT. |
| `ungrounded` | The verdict is UNGROUNDED or INSUFFICIENT. |
| `insufficient` | The verdict is INSUFFICIENT. |

A failed job is a signal to the maintainer, not a message to the reporter: the comment
wording is the same either way, and it describes claims, never people (principle P1).

## Comments and labels

The comment starts with a hidden marker, `<!-- nikasha:comment -->`. When the issue is
edited and the workflow runs again, the action finds that comment and updates it in place
instead of posting another one. Every string derived from the report or from the code is
escaped by Nikasha's Markdown renderer before it reaches the comment; the action only
selects lines from that output.

The comment to update is the first one that carries the marker **and** was posted by
`comment-author`, `github-actions[bot]` by default. The marker alone is not a control:
`action.yml` is public, so anyone can start a comment with it, and the token can edit any
comment on the issue. Without the author check, a marker comment posted before the first
run would receive every verdict, in a comment its author can edit at will. The comparison
is an exact string match in the shell; the login never enters the `jq` program, and the
comment id is checked to be digits before it is spliced into a URL. With a custom `token`
the action posts a fresh comment on every run unless `comment-author` is set to the login
that token posts as (`<app>[bot]` for a GitHub App, the account's login for a personal
access token).

Labels are `nikasha:grounded`, `nikasha:reproduced`, `nikasha:mixed`, `nikasha:ungrounded`
and `nikasha:insufficient`. The action creates a label the first time it needs it (this
requires `issues: write`) and removes any other `nikasha:` label from the issue, so an edited
report ends up with exactly one verdict label. Adding a `nikasha:` label raises a `labeled`
event, but the example workflow only reacts to the security-report label being added, so
the labels never trigger another run.

## Permissions

The example workflow grants `contents: read` at the top level and adds `issues: write` on
the one job that comments and labels. With `comment: none` and `labels: false` the job needs
`contents: read` only. The checkout step sets `persist-credentials: false`; Nikasha never
writes to the repository.

## Security

- **No event text in scripts.** The issue title and body reach the shell only as
  environment variables (`ISSUE_TITLE`, `ISSUE_BODY`) and are written to a file with
  `printf '%s'`. No `${{ ... }}` expression is interpolated into any `run:` script of the
  action or the example workflow, not even the action's own inputs; they all travel through
  `env:`. `tests/unit/test_action_yaml.py` fails if that changes. This is the class of bug
  behind the PromptPwnd and Clinejection incidents (SPEC §19.2).
- **Hostile input stays data.** The report is parsed by Nikasha with the same limits and
  escaping as a local run: linear-time patterns, size caps, Markdown escaping of every
  report- and code-derived string. The action adds a marker comment line and nothing else.
- **Only the closed sets reach outputs.** The verdict label, score and confidence are
  validated against their enumerations before they are written to `$GITHUB_OUTPUT`.
- **The comment is matched by marker and author.** See
  [Comments and labels](#comments-and-labels): a marker anyone can post never selects the
  comment to update.
- **Configuration comes from the checkout.** `nikasha check` honours the nearest
  `nikasha.toml` above its working directory, which in the action is the repository the
  workflow checked out. On `issues` events that is the default branch, so the thresholds
  and the LLM settings are the maintainers', never the reporter's.
- **Offline.** Nikasha runs without network access to anything but the local checkout;
  `--online` is never passed. The only network calls are `pip install`, the artifact upload
  and, when enabled, the `gh` calls that post the comment and the labels.
- **`gh` in the action shell.** The comment and label steps call the `gh` CLI, which is
  preinstalled on GitHub-hosted runners (a self-hosted runner needs it on `PATH` when
  `comment` or `labels` is on). Nikasha's own rule that processes are spawned only through
  `nikasha.code.gitio` and `nikasha.repro.sandbox` is about the Python package; the action
  shell is the workflow's, not the tool's.
- **Minimal permissions, pinned actions, no persisted credentials.** See above.

## Pinned actions

Every `uses:` in `action.yml` and in the example workflow names a full 40-character commit
SHA with the tag in a trailing comment:

| Action | Pin | Where |
|---|---|---|
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) | example workflow |
| `actions/setup-python` | `e797f83bcb11b83ae66e0230d6156d7c80228e7c` (v6.0.0) | `action.yml` |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (v7.0.1) | `action.yml` |
| `rakshit-737/nikasha` | the release commit; the example carries a pre-release commit | example workflow |

**These SHAs must be re-verified with `gh api` before the first release (M8).** All three
pins were resolved with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` on 2026-09-24 and
point directly at the listed commits: each `git/ref/tags/<tag>` object came back as
`type: commit` (a lightweight tag), so no peeling was needed. Re-run the commands before
M8, and peel any tag that has become annotated since to the commit it points at:

```sh
gh api repos/actions/setup-python/git/ref/tags/v6.0.0 --jq '.object'
# "type": "tag" means an annotated tag: peel it.
gh api repos/actions/setup-python/git/tags/<sha from above> --jq '.object.sha'
```

The `rakshit-737/nikasha` line in the example must point at the audited release commit.
The SHA it carries today is a placeholder (its trailing comment says so): it predates
`action.yml`, so a workflow copied verbatim before the re-pin fails at runtime with
"Can't find 'action.yml'". Re-pin it to the commit that adds `action.yml` as soon as that
commit exists, and to the audited release commit at M8.

## Where this fits

The action is one intake among several (SPEC §16). The same `nikasha check` powers the CLI,
the MCP server and the local web UI; the Markdown the action posts is the `--format markdown`
output described in [`docs/checks.md`](checks.md) and the spec's §15.3. Reporters can run
`nikasha lint` on a draft before filing it.
