# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Capture real LSan, MSan and TSan fixtures for the deferred trace parsers (ADR 0009).

Sources follow the maintainer's M2 decision (PROGRESS.md, ADR 0005): **already-fixed bugs
in public projects at pinned tags**. No crash program is written for the capture, and no
compiler-rt regression program is used. Each :class:`Bug` in :data:`BUGS` names the
project, the vulnerable tag, the fixed tag, the fix commit and the public bug reference.
It triggers the bug only through the project's own programs (its CLI, or an example
program shipped in its tree), fed with the project's own files or a literal input of a few
bytes written in :attr:`Bug.run`.

:data:`BUGS` holds three bugs per format (SPEC §9.5). Each entry was checked against the
upstream history (ADR 0009 lists the evidence): both tags exist, the fix commit exists and
lies between them, and the vulnerable code is present at the vulnerable tag. Whether each
trigger really produces a report is known only once the capture has run; a bug that does
not reproduce is reported, and nothing is written.

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
    python scripts/capture_sanitizer_fixtures.py --only tsan --engine docker --keep-going

``--keep-going`` runs every selected bug and reports each failure, but still writes nothing
unless all of them passed.
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
            f"|| {{ {_BUILD_ERRORS} >&2; exit {BUILD_FAILED}; }}; }}; "
            f"for i in $(seq 1 {attempts}); do "
            f"( {self.run} ) >/dev/null 2>/work/out; rc=$?; "
            f"if grep -qF -- {header} /work/out; then cat /work/out >&2; exit $rc; fi; "
            f"done; cat /work/out >&2; exit {NO_REPORT}"
        )


#: What a failed build prints: first the lines that name an error (a parallel build buries
#: them), then the end of the log.
_BUILD_ERRORS = (
    "{ grep -m 40 -E 'error|Error|No such file|not found' /work/build.log | cut -c1-300;"
    " echo '--- build log tail ---'; tail -c 2500 /work/build.log; }"
)


def _corpus(globs: str, times: int) -> str:
    """Repeat the tree's own sources into ``/work/in`` so threaded runs get many jobs."""
    return f"for i in $(seq 1 {times}); do cat {globs}; done > /work/in"


_ZSTD = "https://github.com/facebook/zstd.git"
_XZ = "https://github.com/tukaani-project/xz.git"
_JQ = "https://github.com/jqlang/jq.git"
_PIGZ = "https://github.com/madler/pigz.git"
_ZSTD_CLI = "make -C programs zstd HAVE_ZLIB=0 HAVE_LZMA=0 HAVE_LZ4=0"
_XZ_CMAKE = (
    "cmake -S . -B build -DBUILD_SHARED_LIBS=OFF -DXZ_NLS=OFF -DXZ_DOC=OFF"
    " -DXZ_TOOL_XZDEC=OFF -DXZ_TOOL_LZMADEC=OFF -DXZ_TOOL_LZMAINFO=OFF"
    " -DXZ_TOOL_SCRIPTS=OFF -DXZ_SANDBOX=no && cmake --build build --target xz -j4"
)
#: libjpeg-turbo, pure C (the SIMD code is assembly MSan cannot see). CMake 4 refuses the
#: 2.8.12 minimum without the policy floor, and BUILD_TYPE=None keeps its -O3 out of CFLAGS.
_LJT_CMAKE = (
    "cmake -S . -B build -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=None"
    " -DENABLE_SHARED=0 -DWITH_SIMD=0 -DWITH_TURBOJPEG=0"
    " && cmake --build build --target cjpeg-static -j4"
)
#: libvpx, pure C (generic-gnu), VP8 encoder only, no C++ (webm, libyuv) and no tests.
_VPX_CONFIGURE = (
    "./configure --target=generic-gnu --disable-vp9 --disable-unit-tests --disable-docs"
    " --disable-install-docs --disable-webm-io --disable-libyuv && make -j4"
)
#: The exported tree has no .git (scripts/version needs one) and no submodule checkout, and
#: automake insists that the conditional SUBDIRS entry modules/oniguruma exists even when
#: Oniguruma is disabled, so an empty directory stands in for it.
_JQ_BUILD = (
    "printf '#!/bin/sh\\necho exported\\n' > scripts/version && mkdir -p modules/oniguruma"
    " && autoreconf -i"
    " && ./configure --with-oniguruma=no --disable-docs --disable-shared"
    # `make jq` alone skips BUILT_SOURCES (src/builtin.inc), so build the default target.
    " && make -j4"
)
#: The zlib MSan bug is a short-circuit branch on an uninitialised pointer. At -O1 clang may
#: turn it into a select, which MSan does not report, so this one entry builds at -O0.
_MSAN_O0 = "-fsanitize=memory -g -O0 -fno-omit-frame-pointer"

#: Checked against upstream history on 2026-09-26: both tags and the fix commit exist, the
#: fix lies between the tags, and the vulnerable code is present at the vulnerable tag (ADR
#: 0009 has the evidence). Reproduction is established only by a capture run.
BUGS: tuple[Bug, ...] = (
    # --- LeakSanitizer ---------------------------------------------------------------
    Bug(
        fmt="lsan",
        name="01-zstd-simple-compression",
        repo=_ZSTD,
        vulnerable_tag="v1.1.3",
        fixed_tag="v1.1.4",
        fix_commit="2bb6fc2a944d30d0ec3ec18d3db0fc462cf06ccf",
        reference="https://github.com/facebook/zstd/pull/546",
        build=(
            "$CC $CFLAGS -Ilib -Ilib/common examples/simple_compression.c"
            " lib/common/*.c lib/compress/*.c -o simple_compression $LDFLAGS"
        ),
        run="cp README.md /work/r.md && ./simple_compression /work/r.md",
    ),
    Bug(
        fmt="lsan",
        name="02-jq-setpath-array-key",
        repo=_JQ,
        vulnerable_tag="jq-1.7.1",
        fixed_tag="jq-1.8.0",
        fix_commit="5bbd02f581dff4060815e4291b80a9316841195e",
        reference="https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=66061",
        build=_JQ_BUILD,
        run="./jq -n '[] | setpath([[1]]; 1)'",
    ),
    Bug(
        fmt="lsan",
        name="03-zstd-recursive-symlink",
        repo=_ZSTD,
        vulnerable_tag="v1.4.1",
        fixed_tag="v1.4.2",
        fix_commit="793b94b3541de7535787b5ddebc555bc63d9bef3",
        reference="https://github.com/facebook/zstd/pull/1701",
        build=_ZSTD_CLI,
        run=(
            "rm -rf /work/d && mkdir /work/d && cp README.md /work/d/r.md"
            " && ln -s r.md /work/d/link && ./programs/zstd -q -r /work/d"
        ),
    ),
    # --- MemorySanitizer -------------------------------------------------------------
    Bug(
        fmt="msan",
        name="01-jq-check-literal",
        repo=_JQ,
        vulnerable_tag="jq-1.7.1",
        fixed_tag="jq-1.8.0",
        fix_commit="96d19ca2eef4bed201c5b1175ed013bc3122a001",
        reference="https://github.com/jqlang/jq/issues/3316",
        build=_JQ_BUILD,
        run="printf n | ./jq .",
    ),
    Bug(
        fmt="msan",
        name="02-zlib-gzclose-next-in",
        repo="https://github.com/madler/zlib.git",
        vulnerable_tag="v1.2.8",
        fixed_tag="v1.2.9",
        fix_commit="c901a34c92c4aa74028f541a9773df726ce2b769",
        reference="https://github.com/madler/zlib/commit/c901a34c92c4aa74028f541a9773df726ce2b769",
        build="./configure --static && make minigzip",
        run="./minigzip < /dev/null",
        env={"CFLAGS": _MSAN_O0, "CXXFLAGS": _MSAN_O0},
    ),
    Bug(
        fmt="msan",
        name="03-libjpeg-turbo-ppm-rescale",
        repo="https://github.com/libjpeg-turbo/libjpeg-turbo.git",
        vulnerable_tag="2.0.90",
        fixed_tag="2.1.0",
        fix_commit="b1079002ad451aab896617098b6bcbaae1d967e4",
        reference=(
            "https://github.com/libjpeg-turbo/libjpeg-turbo/commit/"
            "b1079002ad451aab896617098b6bcbaae1d967e4"
        ),
        build=_LJT_CMAKE,
        # A 1x1 binary PGM with maxval 1 and sample 8: rescale[8] was never written, and the
        # value reaches the encoder's own branches (quantisation, Huffman coding).
        run="printf 'P5\\n1 1\\n1\\n\\010' | ./build/cjpeg-static > /work/out.jpg",
        env={"CFLAGS": _MSAN_O0, "CXXFLAGS": _MSAN_O0},
    ),
    # --- ThreadSanitizer -------------------------------------------------------------
    Bug(
        fmt="tsan",
        name="01-libvpx-vp8-psnr-loopfilter",
        repo="https://github.com/webmproject/libvpx.git",
        vulnerable_tag="v1.14.0",
        fixed_tag="v1.14.1",
        fix_commit="4c80888a71829941c8a4218e61433e8443901dea",
        reference="https://github.com/webmproject/libvpx/commit/4c80888a71829941c8a4218e61433e8443901dea",
        build=_VPX_CONFIGURE,
        # Raw 1280x720 I420 frames cut from the tree's own sources. With --psnr and threads,
        # the main thread reads the frame for PSNR while the loop-filter thread writes it.
        run=(
            _corpus("vp8/encoder/*.c vp8/common/*.c", 16)
            + " && ./vpxenc --codec=vp8 --i420 -w 1280 -h 720 --limit=6 --threads=4 --psnr"
            " --end-usage=cbr --target-bitrate=300 --rt --cpu-used=8 -q -o /work/o.ivf /work/in"
        ),
    ),
    Bug(
        fmt="tsan",
        name="02-pigz-lock-order",
        repo=_PIGZ,
        vulnerable_tag="v2.4",
        fixed_tag="v2.5",
        fix_commit="1e847e68cc96f311b15bb091ce5b9b20d110e37f",
        reference="https://github.com/madler/pigz/commit/1e847e68cc96f311b15bb091ce5b9b20d110e37f",
        # The Makefile assigns CC and CFLAGS itself, so they are passed on the command line.
        build='make pigz CC="$CC" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"',
        run=_corpus("pigz.c", 40) + " && ./pigz -p 4 -c /work/in",
    ),
    Bug(
        fmt="tsan",
        name="03-xz-mt-decoder-progress",
        repo=_XZ,
        vulnerable_tag="v5.8.3",
        fixed_tag="v5.8.4",
        fix_commit="c6e3aadbb510e44cecfe870408ecfea1d1ca792c",
        reference="https://github.com/tukaani-project/xz/pull/243",
        build=_XZ_CMAKE,
        run=(
            _corpus("src/liblzma/*/*.c", 8)
            + " && ./build/xz -T2 -0 --block-size=131072 -c /work/in > /work/in.xz"
            " && ./build/xz -T4 -d -c /work/in.xz"
        ),
    ),
)


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


#: Written to the README only if the engine cannot report the image ID after the build.
IMAGE_ID_UNKNOWN = "unknown: the engine did not report an image ID"


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
    parser.add_argument("--engine", choices=("auto", "docker", "podman"), default="auto")
    parser.add_argument(
        "--keep-going", action="store_true", help="report every failing bug (still writes nothing)"
    )
    args = parser.parse_args(argv[1:])
    if problems := check_catalogue(BUGS):
        sys.exit("BUGS is malformed:\n" + "\n".join(problems))
    selected = [b for b in BUGS if args.only in (None, b.fmt)]
    if not selected:
        sys.exit(
            "no already-fixed bugs are catalogued for this format (ADR 0009). "
            "Add hand-verified entries first; nothing was written."
        )
    try:
        engine = sandbox.select_engine(args.engine)
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
    failed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="nikasha-sancap-") as tmp:
        out = Path(tmp) / "out"
        for bug in selected:
            work = Path(tmp) / bug.fmt / bug.name
            commits[bug.name] = stage(bug, work, online=args.online)
            result = run(engine, bug, work / "vulnerable")
            problem = acceptable(bug.fmt, result)
            shown = result  # the run the problem is about
            if problem is None:
                shown = run(engine, bug, work / "fixed")
                problem = fixed_is_clean(bug.fmt, shown)
            if problem is not None:
                tail = shown.stderr[-2000:].decode("utf-8", "replace")
                print(f"!! {bug.fmt}/{bug.name}: {problem}; nothing written\n{tail}")
                if not args.keep_going:
                    return 1
                failed.append(f"{bug.fmt}/{bug.name}: {problem}")
                continue
            staged = out / bug.fmt / f"{bug.name}.txt"
            staged.parent.mkdir(parents=True, exist_ok=True)
            staged.write_bytes(result.stderr)
            print(f"captured {bug.fmt}/{bug.name} ({len(result.stderr)} bytes)")
        if failed:
            print("nothing written; failing bugs:\n" + "\n".join(failed))
            return 1
        meta = {
            "engine": engine.name,
            "base": base_digest(),
            "clang": compiler_version(engine),
            "image_id": sandbox.image_id(engine, IMAGE) or IMAGE_ID_UNKNOWN,
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
