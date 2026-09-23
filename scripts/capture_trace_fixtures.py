# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Capture real crash-trace fixtures for the trace parsers (SPEC §9.5).

Every fixture is the *unedited* output of really running a tool, and every run happens inside
the pinned toolchain image (``docker/capture/Containerfile``) under rootless podman with
``--network none``, a read-only root filesystem, all capabilities dropped, no new privileges,
and the host user's UID (never root).

Scope (maintainer decision, recorded in PROGRESS.md): memory-error traces come **only** from
the deliberate vulnlab bug (``examples/vulnlab``, tags v1.2.0/v1.2.1); every other fixture is
a benign error (arithmetic UB, a failed assert, or an ordinary language exception) from the
small programs in ``tests/fixtures/traces/programs/``.

Usage:
    python scripts/capture_trace_fixtures.py                  # build the image, capture all
    python scripts/capture_trace_fixtures.py --only vulnlab   # vulnlab captures only
    python scripts/capture_trace_fixtures.py --only python    # one format
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTAINERFILE = ROOT / "docker" / "capture" / "Containerfile"
IMAGE = "localhost/nikasha-capture:latest"
FIXTURES = ROOT / "tests" / "fixtures" / "traces"
PROGRAMS = FIXTURES / "programs"
TIMEOUT_S = 600
#: Built from parts so REUSE does not read the README header literals as this file's own tags.
_SPDX = "SPDX" + "-"

#: A value longer than util_copy_value's 64-byte buffer (96 bytes: past valgrind's redzone).
POC_LARGE = "Host: example.test\nX-Overflow: " + "A" * 96 + "\n"
#: A value that overflows by 6 bytes, staying inside valgrind's redzone (no heap corruption).
POC_SMALL = "Host: example.test\nX-Overflow: " + "B" * 70 + "\n"

_CLANG_ASAN = (
    'make -s CC=clang CFLAGS="{opt} -g -fno-omit-frame-pointer -fsanitize=address,undefined" '
    'LDFLAGS="-fsanitize=address,undefined" >/dev/null 2>&1'
)
_GCC_PLAIN = 'make -s CC=gcc CFLAGS="-O0 -g" >/dev/null 2>&1'


def _vulnlab(tag: str, build: str, run: str) -> str:
    return f"cp -r /src/vulnlab/{tag} /work/libhdr && cd /work/libhdr && {build} && {run}"


def _c(src: str, flags: str, run: str) -> str:
    return f"clang {flags} -o /work/prog /src/programs/{src} && {run}"


@dataclass(frozen=True)
class Capture:
    fmt: str
    name: str
    what: str
    script: str
    stream: str = "stderr"  # stderr | stdout | both
    group: str = "benign"  # vulnlab | benign


CAPTURES: tuple[Capture, ...] = (
    # --- vulnlab: the only memory-error traces ------------------------------------------
    Capture("asan", "01-vulnlab-heap-overflow-v1.2.0", "vulnlab v1.2.0, clang -O1, ASan+UBSan, 96-byte value",
            _vulnlab("v1.2.0", _CLANG_ASAN.format(opt="-O1"),
                     "ASAN_OPTIONS=symbolize=1:detect_leaks=0 ./build/hdrcat /poc/large.txt"), group="vulnlab"),
    Capture("asan", "02-vulnlab-heap-overflow-v1.2.1", "vulnlab v1.2.1 (line numbers shifted), clang -O1",
            _vulnlab("v1.2.1", _CLANG_ASAN.format(opt="-O1"),
                     "ASAN_OPTIONS=symbolize=1:detect_leaks=0 ./build/hdrcat /poc/large.txt"), group="vulnlab"),
    Capture("asan", "03-vulnlab-heap-overflow-v1.2.0-O0-fold", "vulnlab v1.2.0, clang -O0, --fold, slow unwinding",
            _vulnlab("v1.2.0", _CLANG_ASAN.format(opt="-O0"),
                     "ASAN_OPTIONS=symbolize=1:detect_leaks=0:fast_unwind_on_malloc=0 "
                     "./build/hdrcat --fold /poc/large.txt"), group="vulnlab"),
    Capture("valgrind", "01-vulnlab-invalid-write-v1.2.0", "vulnlab v1.2.0, gcc -O0, valgrind, 96-byte value",
            _vulnlab("v1.2.0", _GCC_PLAIN, "valgrind ./build/hdrcat /poc/large.txt"), group="vulnlab"),
    Capture("valgrind", "02-vulnlab-invalid-write-v1.2.1", "vulnlab v1.2.1, gcc -O0, valgrind, 96-byte value",
            _vulnlab("v1.2.1", _GCC_PLAIN, "valgrind ./build/hdrcat /poc/large.txt"), group="vulnlab"),
    Capture("valgrind", "03-vulnlab-small-overflow-v1.2.0", "vulnlab v1.2.0, 70-byte value, --track-origins",
            _vulnlab("v1.2.0", _GCC_PLAIN,
                     "valgrind --track-origins=yes --leak-check=full ./build/hdrcat /poc/small.txt"),
            group="vulnlab"),
    Capture("gdb", "01-vulnlab-heap-corruption-abort-v1.2.0", "vulnlab v1.2.0, gcc -O0, gdb bt after glibc abort",
            _vulnlab("v1.2.0", _GCC_PLAIN,
                     "gdb -batch -ex run -ex bt --args ./build/hdrcat /poc/large.txt"),
            stream="both", group="vulnlab"),
    # --- benign: arithmetic, assert, and language exceptions ------------------------------
    Capture("gdb", "02-sigfpe-divide", "integer division by zero, clang -O0 -g, gdb bt",
            _c("gdb/divide_sigfpe.c", "-O0 -g", "gdb -batch -ex run -ex bt --args /work/prog"), stream="both"),
    Capture("gdb", "03-failed-assert-abort", "failed assert() -> abort, clang -O0 -g, gdb bt full",
            _c("gdb/failed_assert.c", "-O0 -g", "gdb -batch -ex run -ex 'bt full' --args /work/prog"),
            stream="both"),
    Capture("ubsan", "01-signed-integer-overflow", "clang -fsanitize=undefined -g -O0",
            _c("ubsan/signed_overflow.c", "-fsanitize=undefined -g -O0",
               "UBSAN_OPTIONS=print_stacktrace=1 /work/prog")),
    Capture("ubsan", "02-shift-exponent", "clang -fsanitize=undefined -g -O0",
            _c("ubsan/shift_exponent.c", "-fsanitize=undefined -g -O0",
               "UBSAN_OPTIONS=print_stacktrace=1 /work/prog")),
    Capture("ubsan", "03-divide-by-zero-halt", "clang -fsanitize=undefined -g -O0, halt_on_error=1",
            _c("ubsan/divide_by_zero.c", "-fsanitize=undefined -g -O0",
               "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 /work/prog")),
    Capture("python", "01-zero-division", "python3", "python3 /src/programs/python/zero_division.py"),
    Capture("python", "02-chained-exception", "python3", "python3 /src/programs/python/chained_exception.py"),
    Capture("python", "03-stdlib-json-cause", "python3", "python3 /src/programs/python/stdlib_json.py"),
    Capture("java", "01-null-pointer", "java (single-file source launch)",
            "java /src/programs/java/NullField.java"),
    Capture("java", "02-array-index", "java (single-file source launch)",
            "java /src/programs/java/IndexOutOfBounds.java"),
    Capture("java", "03-caused-by", "java (single-file source launch)", "java /src/programs/java/CausedBy.java"),
    Capture("go", "01-index-out-of-range", "go run", "go run /src/programs/go/index_out_of_range.go"),
    Capture("go", "02-nil-map", "go run", "go run /src/programs/go/nil_map.go"),
    Capture("go", "03-goroutine-panic-traceback-all", "go run, GOTRACEBACK=all",
            "GOTRACEBACK=all go run /src/programs/go/goroutine_panic.go"),
    Capture("rust", "01-index-oob-backtrace", "rustc -g, RUST_BACKTRACE=1",
            "rustc -g -o /work/prog /src/programs/rust/index_oob.rs && RUST_BACKTRACE=1 /work/prog"),
    Capture("rust", "02-unwrap-none-backtrace-full", "rustc -g, RUST_BACKTRACE=full",
            "rustc -g -o /work/prog /src/programs/rust/unwrap_none.rs && RUST_BACKTRACE=full /work/prog"),
    Capture("rust", "03-thread-panic", "rustc -g, RUST_BACKTRACE=1",
            "rustc -g -o /work/prog /src/programs/rust/thread_panic.rs && RUST_BACKTRACE=1 /work/prog"),
    Capture("node", "01-type-error", "node", "node /src/programs/node/type_error.js"),
    Capture("node", "02-custom-error", "node", "node /src/programs/node/custom_error.js"),
    Capture("node", "03-unhandled-rejection", "node", "node /src/programs/node/unhandled_rejection.js"),
)  # fmt: skip

_VERSION_CMDS = {
    "clang": "clang --version | head -1",
    "gcc": "gcc --version | head -1",
    "gdb": "gdb --version | head -1",
    "valgrind": "valgrind --version",
    "python": "python3 --version",
    "java": "java -version 2>&1 | head -1",
    "node": "node --version",
    "rustc": "rustc --version",
    "go": "go version",
}


def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, capture_output=True, timeout=TIMEOUT_S, check=False, **kwargs)  # type: ignore[call-overload,no-any-return]


def build_image() -> str:
    result = run(
        ["podman", "build", "-q", "-t", IMAGE, "-f", str(CONTAINERFILE), str(CONTAINERFILE.parent)]
    )
    if result.returncode != 0:
        sys.exit(f"image build failed:\n{result.stderr.decode(errors='replace')}")
    return image_id()


def image_id() -> str:
    result = run(["podman", "image", "inspect", "--format", "{{.Id}}", IMAGE])
    return result.stdout.decode().strip()[:12]


def base_digest() -> str:
    for line in CONTAINERFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("FROM "):
            return line.split()[1]
    return "unknown"


def container(script: str, mounts: dict[Path, str]) -> subprocess.CompletedProcess[bytes]:
    argv = [
        "podman", "run", "--rm", "--network", "none", "--read-only", "--userns=keep-id",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--tmpfs", "/work:rw,exec,size=512m", "--tmpfs", "/tmp:rw,exec,size=1g",
    ]  # fmt: skip
    for host, target in mounts.items():
        argv += ["-v", f"{host}:{target}:ro,Z"]
    return run([*argv, IMAGE, "bash", "-c", script])


def tool_versions(mounts: dict[Path, str]) -> dict[str, str]:
    script = "; ".join(f'echo "{k}=$({v})"' for k, v in _VERSION_CMDS.items())
    out = container(script, mounts).stdout.decode(errors="replace")
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def stage_vulnlab(workdir: Path) -> Path:
    """Build the deterministic vulnlab history and export the two buggy tags."""
    spec = importlib.util.spec_from_file_location(
        "build_vulnlab", ROOT / "scripts" / "build_vulnlab.py"
    )
    if spec is None or spec.loader is None:
        sys.exit("cannot load scripts/build_vulnlab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    repo = workdir / "vulnlab.git"
    module.build_vulnlab(repo)
    src = workdir / "vulnlab"
    for tag in ("v1.2.0", "v1.2.1"):
        dest = src / tag
        dest.mkdir(parents=True)
        archive = run(["git", f"--git-dir={repo}", "archive", "--format=tar", tag])
        extracted = run(["tar", "-x", "-C", str(dest)], input=archive.stdout)
        if archive.returncode or extracted.returncode:
            sys.exit(f"could not export vulnlab {tag}")
    return src


def write_readme(fmt: str, captures: list[Capture], meta: dict[str, str]) -> None:
    lines = [
        "<!--",
        f"{_SPDX}FileCopyrightText: 2026 The Nikasha Authors",
        f"{_SPDX}License-Identifier: CC-BY-4.0",
        "-->",
        "",
        f"# `{fmt}` trace fixtures",
        "",
        "Real, unedited tool output. Regenerate with "
        f"`python scripts/capture_trace_fixtures.py --only {fmt}`.",
        "",
        f"- Captured: {meta['date']}",
        f"- Image: `{IMAGE}` (ID `{meta['image']}`), base `{meta['base']}`",
        "- Sandbox: rootless podman, `--network none`, `--read-only`, `--cap-drop ALL`, "
        "`no-new-privileges`, host UID (`--userns=keep-id`)",
        f"- Tools: {meta['tools']}",
        "",
        "| Fixture | What | Command run in the container |",
        "|---|---|---|",
    ]
    for c in captures:
        command = c.script.replace("|", "\\|")
        lines.append(f"| `{c.name}.txt` | {c.what} | `{command}` |")
    lines.append("")
    if any(c.group == "vulnlab" for c in captures):
        lines += [
            "Vulnlab inputs: `large.txt` is a header whose value is 96 bytes (the heap buffer is "
            "64); `small.txt` uses a 70-byte value. Both come from this script (`POC_LARGE`, "
            "`POC_SMALL`).",
            "",
        ]
    (FIXTURES / fmt / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", help="a format (e.g. asan) or 'vulnlab' / 'benign'")
    parser.add_argument("--no-build", action="store_true", help="reuse the existing image")
    args = parser.parse_args(argv[1:])
    selected = [c for c in CAPTURES if args.only in (None, c.fmt, c.group)]
    if not selected:
        parser.error(f"nothing matches --only {args.only}")
    image = image_id() if args.no_build else build_image()
    with tempfile.TemporaryDirectory(prefix="nikasha-capture-") as tmp:
        workdir = Path(tmp)
        poc = workdir / "poc"
        poc.mkdir()
        (poc / "large.txt").write_text(POC_LARGE, encoding="utf-8")
        (poc / "small.txt").write_text(POC_SMALL, encoding="utf-8")
        mounts = {PROGRAMS: "/src/programs", poc: "/poc"}
        if any(c.group == "vulnlab" for c in selected):
            mounts[stage_vulnlab(workdir)] = "/src/vulnlab"
        tools = tool_versions(mounts)
        meta = {
            "date": dt.datetime.now(dt.UTC).strftime("%Y-%m-%d"),
            "image": image,
            "base": base_digest(),
            "tools": ", ".join(f"{k} {v}" for k, v in sorted(tools.items())),
        }
        for capture in selected:
            result = container(capture.script, mounts)
            output = {
                "stderr": result.stderr,
                "stdout": result.stdout,
                "both": result.stdout + result.stderr,
            }[capture.stream]
            if not output.strip():
                print(f"!! {capture.fmt}/{capture.name}: no output (exit {result.returncode})")
                print(result.stderr.decode(errors="replace")[-2000:])
                return 1
            target = FIXTURES / capture.fmt / f"{capture.name}.txt"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(output)
            print(
                f"captured {target.relative_to(ROOT)} ({len(output)} bytes, exit {result.returncode})"
            )
        for fmt in sorted({c.fmt for c in selected}):
            write_readme(fmt, [c for c in CAPTURES if c.fmt == fmt], meta)
    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
