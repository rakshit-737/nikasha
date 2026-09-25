<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Quickstart

This walk-through uses **vulnlab**, a small fictional C library that ships with the source
tree. The whole walk-through runs offline and gives the same results on every machine.

## 1. Build the demo repository

```sh
python scripts/build_vulnlab.py ~/vulnlab.git
```

The script replays a fixed commit plan with `git fast-import`, so the five tags (`v1.0.0`
to `v1.3.0`) land on the same commit SHAs on every machine.

## 2. Check three reports

```sh
nikasha check examples/reports/fabricated_hdr_overflow.md --repo ~/vulnlab.git
nikasha check examples/reports/genuine_hdr_overflow.md    --repo ~/vulnlab.git --explain
nikasha check examples/reports/mixed_wrong_version.md     --repo ~/vulnlab.git
```

- The first report ends UNGROUNDED (exit code 20).
- The second ends GROUNDED (exit code 0). `--explain` adds the log-odds ledger behind the
  score.
- The third ends MIXED (exit code 10), because its findings fit a different release from
  the one it names.

## 3. Choose an output

```sh
nikasha check REPORT --repo ~/vulnlab.git --format markdown -o reply.md
nikasha check REPORT --repo ~/vulnlab.git --format html -o report.html
nikasha check REPORT --repo ~/vulnlab.git --format json -o result.json
nikasha explain result.json
```

- **markdown** gives a reply you can paste into an issue. Everything taken from the report
  is escaped.
- **html** gives one self-contained file that makes no network requests.
- **json** is byte-identical for identical inputs and follows `schema/result-v1.json`.

## 4. Look underneath

```sh
nikasha extract examples/reports/fabricated_hdr_overflow.md
nikasha timeline SYMBOL --repo ~/vulnlab.git
```

`extract` lists every claim in the report before any check runs. `timeline` shows which
releases define a symbol, and suggests close matches when a name is not found.

## Against a real project

Nikasha clones a remote repository only when you pass `--online`. A local path never
touches the network.

```sh
nikasha index --repo https://github.com/curl/curl --online
nikasha check report.md --repo https://github.com/curl/curl
```

Exit codes: 0 for REPRODUCED or GROUNDED, 10 for MIXED, 20 for UNGROUNDED, 30 for
INSUFFICIENT and 1 for an error. `--fail-on VERDICT` sets which verdicts fail a CI job.
