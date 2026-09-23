<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0006: Repository access: full clones, no `git archive`, hardened arguments

- **Status:** accepted
- **Date:** 2026-09-23

## Context

SPEC §10 asks for cached **partial** clones (`--filter=blob:none`) and §13.3 for trees
materialized with **`git archive`**. While building the M2 git layer and its hazard canary
test (§19.3), both turned out to conflict with the principles:

1. **Lazy fetching breaks offline mode.** In a partial clone, reading any blob that isn't
   there yet silently fetches it from the promisor remote. That is a network call without
   `--online` (P3), and it makes history searches crawl, as slopcheck also reported. git ≥2.44
   documents `GIT_NO_LAZY_FETCH`, but with lazy fetching off, a blob-less clone can't read
   files at all.
2. **`git archive` runs a command from the repository's own config.** With
   `tar.tar.command` set in `.git/config`, `git archive --format=tar` pipes its output through
   that command. The canary test proves it: plain git creates the canary file.
3. **Revisions come from report text.** A "version" like `--upload-pack=touch /tmp/x` would
   become a git option (classic argument injection). A local repository's `origin` URL can
   also be `ext::sh -c …`, which runs a command on fetch.

## Decision

- **Full bare clones** for remote repositories, cached at
  `~/.cache/nikasha/repos/<host>/<owner>/<repo>.git` (owner-only permissions). Only
  `https://` URLs are accepted, and path components are validated.
- **`GIT_NO_LAZY_FETCH=1`** on every git call unless `--online`, so even a user's own partial
  clone can never reach the network offline.
- **No `git archive`.** Trees are materialized with `ls-tree` and `cat-file --batch`
  (`GitRepo.export_tree`), which read objects and never consult drivers. Symlinks and
  submodules are skipped, paths are validated to stay inside the destination, and exec bits
  are kept.
- **Argument hardening** in `code/gitio.py`:
  - untrusted revisions are validated (`safe_rev`: no leading `-`, no control characters,
    length ≤256) and passed after `--end-of-options`;
  - options that execute programs or rewrite config (`--upload-pack`, `-u`, `--exec`,
    `--remote`, `-c`/`--config`, `--open-files-in-pager`/`-O`, `--ext-diff`, `--textconv`,
    `--filters`, `--template`) can never appear in an argv;
  - `archive`, `checkout`, `status`, `diff`, `config` and other porcelain are not allowed.
- **Extra `-c` overrides:**
  - `core.bare=true`: no worktree, so an attacker's `core.worktree` or worktree
    `.gitattributes` is never consulted;
  - `protocol.ext.allow=never` and `protocol.git.allow=never`;
  - `--no-textconv` on `grep`, as well as on `log`/`show`.

## Consequences

- A remote clone costs more disk space than a partial clone (curl 134 MB, sqlite 562 MB,
  libxml2 30 MB) and a one-time download, done only with `--online`. In exchange, every later
  check is fast and fully offline.
- `tests/security/test_git_hazards.py` builds a repository whose config wires 20 execution
  hooks (fsmonitor, pager, textconv, filters, external diff, credential helper, askpass,
  `tar.tar.command`, an `ext::` remote, hooks, `include.path`) to a canary. Control cases
  confirm the hazards are live in plain git. Every Nikasha git code path, including running
  from inside the malicious checkout, leaves the canary untouched.
- M5 materializes build trees with `export_tree`, not `git archive`.
