<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->

# The reproduction sandbox

`nikasha repro` builds a project at the exact commit a report names and runs one proof of
concept (PoC) against it, inside a hardened container (SPEC §13). A PoC is hostile input
(P5). **It never runs on the host.** If no container engine is available, Nikasha refuses to
run it.

```console
$ nikasha recipes list
$ nikasha recipes validate
$ nikasha repro --repo ./vulnlab.git --ref v1.2.0 --recipe vulnlab --poc poc.txt
$ nikasha repro --repo https://github.com/curl/curl --ref curl-8_10_1 --recipe curl \
      --kind cli --arg --version --poc ./empty-dir --online
```

## Engines

- **Detection order.** Rootless podman comes first, then docker, then rootful podman.
  `--sandbox podman|docker` names an engine. If the named engine is missing, Nikasha
  refuses; it never falls back to another one.
- **No engine means refusal.** `--repro` fails with a clear error. A test runs this
  refusal for real on every machine (`tests/unit/repro/test_repro_cli.py`).
- **`--runtime runsc`** passes an OCI runtime such as gVisor through to the engine. For
  podman it is a global flag (`podman --runtime runsc run …`); for docker it is a `run`
  flag.
- **Engine facts.** `nikasha.repro.sandbox.engine_facts()` reports the engine name,
  version, rootless mode, cgroup version, and whether `--memory` and `--pids-limit` are
  actually enforced. The engine's own report decides the last two where it gives one:
  docker's `MemoryLimit`/`PidsLimit`, or the cgroup controllers delegated to podman.
  Without such a report, rootless on cgroup v1 means "not enforced", and anything Nikasha
  cannot tell is reported as unknown. It is never guessed.

## Recipes

A recipe (`recipes/<id>.yaml`) is validated against
[`schema/recipe-v1.json`](../schema/recipe-v1.json). The pydantic models in
`nikasha/repro/recipes.py` enforce the same shape, and a unit test keeps the two in step.
The models also enforce these rules:

- output basenames are unique, because each output lands at `/build/<basename>`;
- `{args}` may appear only as a whole argument, and `{file}` is the only other placeholder;
- no path is absolute or contains `..`, and the Dockerfile lives under `docker/recipes/`;
- the `id` matches the file name.

| Recipe | Status | Verified |
|---|---|---|
| `vulnlab` | MUST | Build steps checked against `examples/vulnlab/src/*/Makefile`. The container build and a real heap-overflow PoC run are in the sandbox suite. |
| `curl` | MUST | **Not verified.** See below. |
| `sqlite` | MUST | **Not verified.** See below. |
| `libxml2` | SHOULD | **Not verified.** See below. |

**Stated plainly: the real-project recipes' build flags have not been run.** They were
written on a development machine that has no container engine and cannot install one. They
follow each project's documented build: curl uses `autoreconf` and `configure` with minimal
features, sqlite uses `configure` then `make sqlite3`, and libxml2 uses `autogen.sh`,
`configure` and `make xmllint`. Each recipe says this in a comment. Their build tests are
`test_real_project_recipe_builds` in `tests/sandbox/test_sandbox_safety.py`, marked
`sandbox`, `network` and `slow`. They build one pinned tag each and are meant for the
nightly job. Configure flags change between eras, so they need checking per era as well.

All four recipes share one image, `docker/recipes/c-toolchain.Dockerfile`. It pins the same
Fedora digest as the trace-capture image. That image has not been built on the development
machine either.

## Build (SPEC §13.3)

1. The tree at the commit is written out with `GitRepo.export_tree`, which uses plumbing
   only. Nikasha never runs `git archive` (ADR 0006: it pipes output through a
   repository-configured tar command) or `checkout`.
2. The build runs in the recipe image with the full hardened flag set below and
   `--network none`. Every toolchain dependency is baked into the image.
3. The source is mounted read-only at `/src` and copied into the writable `/work` tmpfs
   (sized by `build.work_size`). Each declared output is copied to `/out/<basename>`.
4. The log is captured and truncated to `limits.output_bytes`. A failed build raises an
   error that shows the last 20 log lines.
5. Outputs are cached under `<cache_dir>/repro/builds/<recipe_id>/<sha256[:16]>/<commit>/`,
   keyed by `(recipe_id, recipe_sha256, commit)`. Any edit to the recipe file changes the
   key. `complete.json` marks a finished build.
6. `/out` is hostile: it was written by project code. The host copies it into a private
   staging directory without following any link (see Caveats). Files keep only their
   executable bit, so setuid, setgid and group or other write bits never reach the cache.
7. The staging directory is renamed into place under a per-key lock file
   (`.<commit>.lock`, released by the OS when the process exits). Two builds of the same
   key can run at once: the first complete build wins, and the other becomes a cache hit.
   A complete build is never removed; only an incomplete leftover from a crash is replaced.
8. The scratch directory is always removed, whether the build succeeded or not (see
   Caveats).

Building the recipe image pulls a base image, so it needs `--online` (P3). Without that flag,
Nikasha prints the `build` command for you to run yourself.

## Run (SPEC §13.4)

Every PoC runs in a fresh container with these flags:

```
run --rm --init --pull never --name <name>
    --network none --read-only [--read-only-tmpfs=false  (podman only)]
    --tmpfs /tmp:rw,size=64m,mode=1777 --tmpfs /work:rw,exec,size=256m,mode=1777
    --cap-drop ALL --security-opt no-new-privileges        (podman)
                   --security-opt no-new-privileges=true   (docker)
    --pids-limit 256 --memory 2g --cpus 2 --user 65534:65534 --ulimit core=0
    --workdir /work --env K=V...
    -v <poc_dir>:/poc:ro -v <build_outputs>:/build:ro  <image> <cmd...>
```

These flags differ from the SPEC list in a few places. The per-engine differences come from
`docs/research/2026-09-23-m0-verification.md` §6. Two flags are additions:

- `--pull never` keeps the run offline;
- `--name` lets a container that times out be killed and removed by name.

Limits come from the recipe's `limits`.

- **Timeout.** A wall-clock timeout kills the container (`kill`, then `rm -f`) and marks
  the run `timed_out`. `--timeout` overrides the recipe's `run.timeout_s` and must be
  greater than 0 and at most 3600 seconds (the schema's maximum); anything else, including
  `nan` and `inf`, is refused.
- **Terminal output.** The text view prints the last 40 lines of the PoC's stderr. It is
  hostile, so every C0 and C1 control character except tab and newline (ESC, CSI, OSC, BEL,
  DEL and so on) and every bidirectional override is shown as a visible `\xNN` or `\uNNNN`
  escape, and Rich markup, emoji codes and highlighting are off. A PoC cannot clear the
  screen, set the title, plant an OSC 8 link or write the clipboard (OSC 52). `--json`
  output escapes control characters as JSON always does.
- **Output cap.** Each stream is capped at `limits.output_bytes` (1 MB by default). The
  rest is read and discarded so the engine never blocks, and the run is marked `truncated`.
- **Staging.** The PoC is copied into a private staging directory. Symbolic links are never
  followed. Unsafe file names are replaced. Size (64 MB) and file count (1000) are capped.
- **Arguments.** `--arg` values become separate argv entries and never pass through a
  shell. Only a `compile` step (the `c_harness` kind) uses `/bin/sh -c`, and every word in
  it is `shlex`-quoted.
- **Command record.** The full argv goes into a `CommandRecord`. As with
  `gitio.redact_argv`, it holds no host paths (`-v <path>:/poc:ro`) and no random names
  (`--name <name>`), and argv[0] is the bare engine name. The same run on two machines
  therefore records the same bytes.

## Safety tests (SPEC §13.6)

`tests/sandbox/test_sandbox_safety.py` has one test for each bullet in SPEC §13.6. Each test
checks the effect, not the flag:

- refusal without an engine;
- network egress fails (only `lo` exists);
- a fork bomb is contained (a fork counter stops below the pids limit; a shell fork bomb
  is refused forks and burns out long before its timeout; its container is gone and the
  engine still answers afterwards);
- writes to the rootfs fail with `Read-only file system`;
- the process runs as uid and gid 65534, with `NoNewPrivs: 1` and an empty `CapEff`;
- a timeout kills the container, and no container with its name is left behind.

The file also checks output truncation and runs vulnlab end to end: build, cache hit, and
the heap overflow from `examples/reports/genuine_hdr_overflow.md` reproduced under ASan.
Hostile builds are covered too: symlinks (absolute, relative, to `/`) and FIFOs left in
`/out` refuse the build and cache nothing, and a build that drops its exit trap and locks
its directories still leaves no scratch behind.

`.github/workflows/sandbox.yml` runs this suite on docker (ubuntu) for every push to `main`
and every pull request.

These tests need a real engine. They are marked `sandbox`, which the default run excludes.
Run them with:

```console
$ uv run pytest -m "sandbox and not network" tests/sandbox
```

In a sandbox run, a missing engine **fails** the suite rather than skipping it.

## Caveats

- The build runs as uid 65534. On the host that uid is `nobody` (rootful docker) or a
  subordinate uid (rootless podman), so the host user cannot delete a directory the build
  creates in `/out`. The build script therefore starts with an `EXIT` trap that runs
  `chmod -R a+rwX /out`. That trap does not run when a timed-out build is killed, and a
  hostile build can remove it. When the host cannot delete `/out`, Nikasha starts one more
  container from the same image, with the same hardened flags and only `/out` mounted,
  which makes every entry writable and deletes it as the uid that wrote it. Nikasha copies
  the outputs into the cache as the host user, so you always own the cache.
- Build outputs must be regular files and directories. A symlink, device, FIFO or socket
  in `/out` refuses the build, because the host never follows a link the build left behind.
- Crash-signature matching (SPEC §13.5) is a separate module (`repro/signature.py`).
