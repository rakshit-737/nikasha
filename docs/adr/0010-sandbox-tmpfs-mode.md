<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# ADR 0010: Sandbox tmpfs mounts are world-writable with the sticky bit

- **Status:** accepted
- **Date:** 2026-09-25
- **Amends:** SPEC §13.4 (container flags)

## Context

SPEC §13.4 gives the scratch mounts as `--tmpfs /tmp:rw,size=64m` and
`--tmpfs /work:rw,exec,size=256m`. The PoC and build run as uid 65534. When a recipe image
sets `WORKDIR /work`, the engine creates `/work` as root-owned mode 0755, and the tmpfs
mounted over it keeps that mode. uid 65534 then cannot write its own working directory, so
the first vulnlab build in a real container failed with `cp: cannot create ... Permission
denied`. This was found on 2026-09-25, the first time the sandbox tests ran against a real
Docker engine.

## Decision

Both tmpfs mounts add `mode=1777`:

```
--tmpfs /tmp:rw,size=64m,mode=1777 --tmpfs /work:rw,exec,size=256m,mode=1777
```

`nikasha.repro.sandbox.run_argv` builds these flags, and `tests/unit/repro/test_run_argv.py`
pins them.

## Consequences

- The sticky bit stops one uid from deleting another uid's files. Only uid 65534 runs in the
  container, so no isolation is lost: both mounts are private to the container, capped in
  size and gone when it exits.
- No other §13.4 flag changes. The root filesystem is still read-only, there is still no
  network, all capabilities are still dropped and `no-new-privileges` still applies.
- The deviation is recorded in `docs/sandbox.md`.
