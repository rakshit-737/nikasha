<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Getting help

- **Questions and ideas:** use [GitHub Discussions](https://github.com/rakshit-737/nikasha/discussions).
- **Bugs:** open an issue with the "Bug report" form.
- **A verdict you think is wrong:** use the "False verdict" issue form. It asks for
  the verdict you got, the one you expected, and the evidence.
- **Security problems in Nikasha itself:** follow [SECURITY.md](SECURITY.md). Don't use
  public issues.

## What to include

- the output of `nikasha doctor` and `nikasha version`;
- the exact command you ran;
- for verdict questions, the JSON result (`--format json`), after removing anything
  confidential.

> **Never paste an embargoed or private vulnerability report into a public issue or
> discussion.** Describe the shape of the problem instead ("a trace whose frame 2 cites
> a generated file"), or build a synthetic report that shows the same behaviour.

Nikasha is maintained by volunteers. Responses are best effort.
