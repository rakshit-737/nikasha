<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# Governance

## Roles

- **Maintainers** review and merge pull requests, triage issues, cut releases and
  enforce the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Contributors** are anyone who opens an issue, discussion or pull request.

### Current maintainers

| Name | GitHub | Areas |
|---|---|---|
| Rakshit Rameshbabu | [@rakshit-737](https://github.com/rakshit-737) | Everything (project lead) |

## How decisions are made

- Day-to-day changes are decided in pull requests, by a maintainer's review.
- **Significant technical decisions** get an Architecture Decision Record in
  [`docs/adr/`](docs/adr/), proposed through a pull request and open for comment for at
  least 7 days, unless the change is a security fix. Examples: a new dependency, a change
  to scoring or verdict rules, a new check, or a new supported language.
- The product principles (P1–P8 in [`SPEC.md`](SPEC.md) §1) can only be changed through
  an ADR. When principles conflict, safety wins: P4 comes before P5, which comes before P3,
  which comes before the rest.
- While there is a single maintainer, the project lead decides after the comment
  period. Once there are three or more maintainers, decisions need lazy consensus;
  failing that, a simple majority of maintainers.

## Becoming a maintainer

A contributor with a sustained record of high-quality reviews and contributions can be
nominated by any maintainer. The nomination is accepted if no maintainer objects within
14 days. Maintainers who are inactive for 12 months become emeritus and can return on
request.

## Security and conduct

Security reports follow [SECURITY.md](SECURITY.md). Conduct reports follow the
[Code of Conduct](CODE_OF_CONDUCT.md). A maintainer involved in a conduct report recuses
themselves from handling it.
