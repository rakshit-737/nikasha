# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Capture real LSan, MSan and TSan fixtures for the deferred trace parsers (ADR 0009).

Sources follow the maintainer's M2 decision (PROGRESS.md, ADR 0005): **already-fixed bugs
in public projects at pinned tags**. No crash program is written for the capture, and no
compiler-rt regression program is used. Each :class:`Bug` in :data:`BUGS` names the
project, the vulnerable tag, the fixed tag, the fix commit and the public bug reference,
and it triggers the bug with an input that already exists in the project's tree (for
example the regression input the fix added), read out of the *fixed* tag.

:data:`BUGS` is empty on purpose. Its entries must be checked by a person against the
upstream history before they are added; nothing here is guessed. While it is empty the
script stops with a message and writes nothing.

Nothing runs on the host (P5):

1. Each project is cloned in full (ADR 0006) through :mod:`nikasha.resolve.repo`. Both tags
   are resolved, and the fix commit must be reachable from the fixed tag. The vulnerable
   tree is written with :meth:`GitRepo.export_tree` (plumbing only; never ``git archive``
   or ``checkout``), and so is the fixed tree.
2. Each tree is built and run inside the pinned ``docker/capture`` image through
   :func:`nikasha.repro.sandbox.run_container` (no network, read-only root, no capabilities,
   non-root user, capped output).
3. A capture is accepted only if, at the vulnerable tag, the sanitizer header is present,
   the run neither timed out nor was truncated, the build succeeded and the exit code is the
   sanitizer's pinned one; **and** the same build at the fixed tag produces no sanitizer
   report (so the trace is the fixed bug and not noise). Outputs are staged and moved into
   ``tests/fixtures/traces/{lsan,msan,tsan}/`` only after every selected bug passed,
   together with a README that records repository, tags, commits, fix, image ID, base
   digest, compiler version, environment and commands.

Usage (``--online`` for the one-time clones and image build; needs a container engine)::

    python scripts/capture_sanitizer_fixtures.py --online
    python scripts/capture_sanitizer_fixtures.py --only tsan
"""

from __future__ import annotations

import argparse
import re
import shlex
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from nikasha.errors import NikashaError
from nikasha.repro import sandbox
from nikasha.resolve.repo import open_repo

ROOT = Path(__file__).resolve().parents[1]
CONTAINERFILE = ROOT / "docker" / "capture" / "Containerfile"
IMAGE = "localhost/nikasha-capture:latest"
FIXTURES = ROOT / "tests" / "fixtures" / "traces"
TIMEOUT_S = 900.0
#: TSan reports are timing-dependent; bounded retries inside the container.
TSAN_ATTEMPTS = 10
#: Exit codes the in-container script uses for "build failed" and "no report".
BUILD_FAILED = 125
NO_REPORT = 124
#: Built from parts so REUSE does not read the README header literals as this file's own tags.
_SPDX = "SPDX" + "-"

FORMATS = ("lsan", "msan", "tsan")
#: Sanitizer header each capture must contain, and the exit code pinned in its options.
HEADERS = {
    "lsan": re.compile(rb"^==\d{1,10}==ERROR: LeakSanitizer: ", re.MULTILINE),
    "msan": re.compile(rb"^==\d{1,10}==WARNING: MemorySanitizer: ", re.MULTILINE),
    "tsan": re.compile(rb"^WARNING: ThreadSanitizer: ", re.MULTILINE),
}
EXIT_CODES = {"lsan": 23, "msan": 77, "tsan": 66}
SANITIZE_FLAGS = {
    "lsan": "-fsanitize=leak",
    "msan": "-fsanitize=memory",
    "tsan": "-fsanitize=thread",
}
_OPTION_VARS = {"lsan": "LSAN_OPTIONS", "msan": "MSAN_OPTIONS", "tsan": "TSAN_OPTIONS"}
_HEADER_TEXT = {
    "lsan": "ERROR: LeakSanitizer: ",
    "msan": "WARNING: MemorySanitizer: ",
    "tsan": "WARNING: ThreadSanitizer: ",
}
_SHA_RE = re.compile(r"[0-9a-f]{40}+")


@dataclass(frozen=True)
class Bug:
    """One already-fixed bug in a public project, pinned by tags and fix commit.

    ``build`` runs in a writable copy of the tree at ``/work/tree`` and must honour
    ``$CC``, ``$CXX``, ``$CFLAGS`` and ``$CXXFLAGS`` (set here with the sanitizer flag).
    ``run`` triggers the bug with an input already in the project's tree; its stderr is
    the fixture.
    """

    fmt: str
    name: str
    repo: str  # public clone URL
    vulnerable_tag: str
    fixed_tag: str
    fix_commit: str  # full 40-hex SHA, reachable from fixed_tag, not from vulnerable_tag
    reference: str  # public bug or advisory URL
    build: str
    run: str
    options: str = ""  # extra sanitizer options, colon-separated
    env: dict[str, str] = field(default_factory=dict)

    def environment(self) -> dict[str, str]:
        opts = f"exitcode={EXIT_CODES[self.fmt]}"
        if self.options:
            opts = f"{self.options}:{opts}"
        flags = f"{SANITIZE_FLAGS[self.fmt]} -g -O1 -fno-omit-frame-pointer"
        return {
            "CC": "clang",
            "CXX": "clang++",
            "CFLAGS": flags,
            "CXXFLAGS": flags,
            "LDFLAGS": SANITIZE_FLAGS[self.fmt],
            **self.env,
            _OPTION_VARS[self.fmt]: opts,
        }

    def script(self) -> str:
        """The shell run in the container (the tree is mounted read-only at ``/src``)."""
        attempts = TSAN_ATTEMPTS if self.fmt == "tsan" else 1
        header = shlex.quote(_HEADER_TEXT[self.fmt])
        return (
            "cp -r /src/tree /work/tree && cd /work/tree && "
            f"{{ ( {self.build} ) >/work/build.log 2>&1 "
            f"|| {{ tail -c 4000 /work/build.log >&2; exit {BUILD_FAILED}; }}; }}; "
            f"for i in $(seq 1 {attempts}); do "
            f"( {self.run} ) >/dev/null 2>/work/out; rc=$?; "
            f"if grep -qF -- {header} /work/out; then cat /work/out >&2; exit $rc; fi; "
            f"done; cat /work/out >&2; exit {NO_REPORT}"
        )


#: Verified by hand against upstream history before an entry is added (see module docstring).
BUGS: tuple[Bug, ...] = ()


def check_catalogue(bugs: tuple[Bug, ...]) -> list[str]:
    """Structural problems in ``bugs`` (empty when every entry is well-formed)."""
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    for bug in bugs:
        where = f"{bug.fmt}/{bug.name}"
        if bug.fmt not in FORMATS:
            problems.append(f"{where}: unknown format")
        if (bug.fmt, bug.name) in seen:
            problems.append(f"{where}: duplicate name")
        seen.add((bug.fmt, bug.name))
        if not bug.repo.startswith("https://"):
            problems.append(f"{where}: repo must be an https URL")
        if not bug.reference.startswith("https://"):
            problems.append(f"{where}: reference must be a public https URL")
        if _SHA_RE.fullmatch(bug.fix_commit) is None:
            problems.append(f"{where}: fix_commit must be a full 40-hex SHA")
        if bug.vulnerable_tag == bug.fixed_tag:
            problems.append(f"{where}: vulnerable and fixed tags must differ")
        if not bug.build.strip() or not bug.run.strip():
            problems.append(f"{where}: build and run are required")
    return problems


def acceptable(fmt: str, result: sandbox.ContainerResult) -> str | None:
    """Why ``result`` (at the vulnerable tag) is not a real, complete capture, or ``None``."""
    if result.timed_out:
        return "timed out"
    if result.truncated:
        return "output truncated"
    if result.exit_code == BUILD_FAILED:
        return "build failed"
    if HEADERS[fmt].search(result.stderr) is None:
        return "no sanitizer report in the output"
    if result.exit_code != EXIT_CODES[fmt]:
        return f"exit code {result.exit_code}, expected {EXIT_CODES[fmt]}"
    return None


def fixed_is_clean(fmt: str, result: sandbox.ContainerResult) -> str | None:
    """Why ``result`` (at the fixed tag) does not show the bug fixed, or ``None``."""
    if result.timed_out:
        return "fixed tag: timed out"
    if result.truncated:
        return "fixed tag: output truncated"
    if result.exit_code == BUILD_FAILED:
        return "fixed tag: build failed"
    if HEADERS[fmt].search(result.stderr) is not None:
        return "fixed tag still produces a sanitizer report"
    return None


def base_digest() -> str:
    """The pinned ``FROM`` reference of the capture image."""
    for line in CONTAINERFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("FROM "):
            return line.split(None, 1)[1].strip()
    return "unknown"


def stage(bug: Bug, dest: Path, *, online: bool) -> dict[str, str]:
    """Export both tags of ``bug`` under ``dest``; return the resolved commits."""
    repo = open_repo(bug.repo, online=online)
    vulnerable = repo.rev_parse(bug.vulnerable_tag)
    fixed = repo.rev_parse(bug.fixed_tag)
    fix = repo.rev_parse(bug.fix_commit)
    if vulnerable is None or fixed is None or fix is None:
        sys.exit(f"{bug.fmt}/{bug.name}: a tag or the fix commit is missing from {bug.repo}.")
    between = repo.run(["rev-list", "--end-of-options", f"{vulnerable}..{fixed}"])
    if between.returncode != 0 or fix.encode() not in between.stdout.split():
        sys.exit(f"{bug.fmt}/{bug.name}: the fix commit does not sit between the two tags.")
    repo.export_tree(vulnerable, dest / "vulnerable" / "tree")
    repo.export_tree(fixed, dest / "fixed" / "tree")
    return {"vulnerable": vulnerable, "fixed": fixed, "fix": fix}


def run(engine: sandbox.EngineInfo, bug: Bug, tree_parent: Path) -> sandbox.ContainerResult:
    spec = sandbox.ContainerSpec(
        image=IMAGE,
        cmd=("bash", "-c", bug.script()),
        mounts=(sandbox.Mount(tree_parent, "/src"),),
        env=bug.environment(),
        work_size="2g",
    )
    return sandbox.run_container(engine, spec, timeout_s=TIMEOUT_S)


def compiler_version(engine: sandbox.EngineInfo) -> str:
    spec = sandbox.ContainerSpec(image=IMAGE, cmd=("clang", "--version"))
    result = sandbox.run_container(engine, spec, timeout_s=60.0)
    first = result.stdout.decode("utf-8", "replace").splitlines()
    return first[0] if first else "unknown"


#: ``nikasha.repro.sandbox`` exposes no image-ID query yet (ADR 0009); say so in the README.
IMAGE_ID_UNRECORDED = "not recorded: nikasha.repro.sandbox has no image-ID query yet"


def readme(
    fmt: str, bugs: list[Bug], meta: dict[str, str], commits: dict[str, dict[str, str]]
) -> str:
    lines = [
        "<!--",
        f"{_SPDX}FileCopyrightText: 2026 The Nikasha Authors",
        f"{_SPDX}License-Identifier: CC-BY-4.0",
        "-->",
        "",
        f"# `{fmt}` trace fixtures",
        "",
        "Real, unedited sanitizer output (stderr) from already-fixed bugs in public projects. "
        f"Regenerate with `python scripts/capture_sanitizer_fixtures.py --only {fmt}`.",
        "",
        f"- Image: `{IMAGE}` (ID `{meta['image_id']}`) built from `docker/capture/Containerfile`,"
        f" base `{meta['base']}`",
        f"- Compiler in the image: `{meta['clang']}`",
        f"- Engine: {meta['engine']}, run through `nikasha.repro.sandbox.run_container`",
        "- Each capture was checked: the fixed tag builds and produces no sanitizer report.",
        "",
        "| Fixture | Project | Vulnerable | Fixed | Fix commit | Reference | Environment |"
        " Script |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for b in bugs:
        c = commits[b.name]
        env = " ".join(f"{k}={v}" for k, v in sorted(b.environment().items()))
        script = b.script().replace("|", chr(92) + "|")
        lines.append(
            f"| `{b.name}.txt` | {b.repo} | `{b.vulnerable_tag}` (`{c['vulnerable']}`) | "
            f"`{b.fixed_tag}` (`{c['fixed']}`) | `{c['fix']}` | {b.reference} | `{env}` | "
            f"`{script}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--only", choices=FORMATS)
    parser.add_argument("--online", action="store_true", help="allow clones and the image build")
    args = parser.parse_args(argv[1:])
    if problems := check_catalogue(BUGS):
        sys.exit("BUGS is malformed:\n" + "\n".join(problems))
    selected = [b for b in BUGS if args.only in (None, b.fmt)]
    if not selected:
        sys.exit(
            "no already-fixed bugs are catalogued for this format yet (BUGS is empty; "
            "ADR 0009). Add hand-verified entries first; nothing was written."
        )
    try:
        engine = sandbox.select_engine()
    except NikashaError as exc:
        sys.exit(f"{exc} PoCs never run on the host (P5).")
    try:
        if not sandbox.image_exists(engine, IMAGE):
            sandbox.build_image(
                engine, CONTAINERFILE, CONTAINERFILE.parent, IMAGE, online=args.online
            )
    except NikashaError as exc:
        sys.exit(str(exc))
    commits: dict[str, dict[str, str]] = {}
    with tempfile.TemporaryDirectory(prefix="nikasha-sancap-") as tmp:
        out = Path(tmp) / "out"
        for bug in selected:
            work = Path(tmp) / bug.fmt / bug.name
            commits[bug.name] = stage(bug, work, online=args.online)
            result = run(engine, bug, work / "vulnerable")
            problem = acceptable(bug.fmt, result)
            if problem is None:
                problem = fixed_is_clean(bug.fmt, run(engine, bug, work / "fixed"))
            if problem is not None:
                tail = result.stderr[-2000:].decode("utf-8", "replace")
                print(f"!! {bug.fmt}/{bug.name}: {problem}; nothing written\n{tail}")
                return 1
            staged = out / bug.fmt / f"{bug.name}.txt"
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(result.stderr)
            print(f"captured {bug.fmt}/{bug.name} ({len(result.stderr)} bytes)")
        meta = {
            "engine": engine.name,
            "base": base_digest(),
            "clang": compiler_version(engine),
            "image_id": IMAGE_ID_UNRECORDED,
        }
        for fmt in sorted({b.fmt for b in selected}):
            fmt_bugs = [b for b in selected if b.fmt == fmt]
            dest = FIXTURES / fmt
            dest.mkdir(parents=True, exist_ok=True)
            for b in fmt_bugs:
                shutil.move(out / fmt / f"{b.name}.txt", dest / f"{b.name}.txt")
            (dest / "README.md").write_text(readme(fmt, fmt_bugs, meta, commits), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
