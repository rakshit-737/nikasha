# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""LSAN parser: API-contract tests and value tests on the real fixtures (ADR 0009).

No hand-written LSAN traces are used (CLAUDE.md: trace fixtures are real output only). The
fixture tests read `tests/fixtures/traces/lsan/`, which only
`scripts/capture_sanitizer_fixtures.py` writes.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nikasha.extract.traces import PARSERS
from nikasha.extract.traces.lsan import LsanParser
from nikasha.repro import sandbox

FIXTURES = Path(__file__).parents[2] / "fixtures" / "traces" / "lsan"
PARSER = LsanParser()
HEADER = "==1==ERROR: LeakSanitizer: detected memory leaks"


def test_registered() -> None:
    assert isinstance(PARSERS["lsan"], type(PARSER))  # ADR 0009: real fixtures committed
    assert PARSER.format == "lsan"


@pytest.mark.parametrize("text", ["", "\n", "hello world", "#0 0x1 in main /a.c:1:2", "=" * 80])
def test_no_trace_without_header(text: str) -> None:
    assert PARSER.parse(text) == []


def test_header_alone_is_one_trace_without_frames() -> None:
    traces = PARSER.parse("noise\n" + HEADER + "\n")
    assert len(traces) == 1
    trace = traces[0]
    assert trace.data.format == "lsan"
    assert trace.data.frames == ()
    assert ("noise\n" + HEADER + "\n")[: trace.end] == "noise\n" + HEADER


def test_output_is_deterministic() -> None:
    text = ("x\n" + HEADER + "\n#0 0x1 in f /a.c:1:2\n") * 3
    assert PARSER.parse(text) == PARSER.parse(text)


@given(st.text(max_size=400))
@settings(max_examples=200, deadline=None)
def test_never_raises_on_arbitrary_text(text: str) -> None:
    PARSER.parse(text)
    PARSER.parse(HEADER + "\n" + text)


@pytest.mark.parametrize(
    "seed",
    ["#0 0x1 in ", "    #0 ", HEADER + "\n", "(a+0x1) ", ":1:2 ", "SUMMARY: ", "a" * 7 + ":"],
)
def test_linear_time_on_hostile_input(seed: str) -> None:
    text = HEADER + "\n" + seed * (200_000 // len(seed))
    started = time.perf_counter()
    PARSER.parse(text)
    assert time.perf_counter() - started < 5.0


def _fixtures() -> list[Path]:
    return sorted(FIXTURES.glob("*.txt")) if FIXTURES.is_dir() else []


def test_real_fixtures_parse() -> None:
    fixtures = _fixtures()
    assert fixtures, "real lsan fixtures are committed (ADR 0009)"
    assert len(fixtures) >= 3  # SPEC §9.5
    for path in fixtures:
        traces = PARSER.parse(path.read_text(encoding="utf-8"))
        assert traces, path.name
        data = traces[0].data
        assert data.format == "lsan"
        assert data.frames, path.name
        assert any(not f.is_runtime and f.path and f.line for f in data.frames), path.name
        assert data.summary, path.name


# --- values from the real fixtures (tests/fixtures/traces/lsan/README.md) -----------------

LSAN_CASES = [
    # name, pid, bytes, first app frame (function, file, line, col)
    ("01-zstd-simple-compression.txt", 24, 15,
     ("malloc_orDie", "/work/tree/examples/simple_compression.c", 39, 24)),
    ("02-jq-setpath-array-key.txt", 4072, 272,
     ("jv_mem_alloc", "/work/tree/src/jv_alloc.c", 141, 13)),
    ("03-zstd-recursive-symlink.txt", 93, 13,
     ("UTIL_prepareFileList", "/work/tree/programs/util.c", 237, 24)),
]  # fmt: skip


@pytest.mark.parametrize(("name", "pid", "size", "app"), LSAN_CASES)
def test_fixture_values(name: str, pid: int, size: int, app: tuple[str, str, int, int]) -> None:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    traces = PARSER.parse(text)
    assert len(traces) == 1
    trace = traces[0]
    data = trace.data
    body = text[trace.start : trace.end]
    summary = f"SUMMARY: LeakSanitizer: {size} byte(s) leaked in 1 allocation(s)."
    assert body.startswith("=" * 65 + f"\n=={pid}==ERROR: LeakSanitizer: detected memory leaks")
    assert body.endswith(summary)
    assert (data.bug_type, data.message, data.pid, data.pids_seen) == (
        "memory-leak",
        "detected memory leaks",
        pid,
        (pid,),
    )
    assert data.summary == summary
    assert data.frames == data.alloc_frames
    assert data.other_stacks == ()
    assert data.frames[0].function == "malloc"
    assert data.frames[0].is_runtime
    first_app = next(f for f in data.frames if not f.is_runtime)
    assert (first_app.function, first_app.path, first_app.line, first_app.col) == app
    assert data.frames[-1].function == "_start"
    assert data.frames[-1].is_runtime
    assert [f.index for f in data.frames] == list(range(len(data.frames)))
    assert not next(f for f in data.frames if f.function == "main").is_runtime


def test_frame_with_file_but_no_line_keeps_the_path() -> None:
    # jq 1.7.1 prints ``#7 0x... in jv_setpath /work/tree/src/jv_aux.c`` (no :line). The path
    # used to end up inside the function name.
    text = (FIXTURES / "02-jq-setpath-array-key.txt").read_text(encoding="utf-8")
    frames = PARSER.parse(text)[0].data.frames
    assert (frames[7].function, frames[7].path, frames[7].line) == (
        "jv_setpath",
        "/work/tree/src/jv_aux.c",
        None,
    )
    assert (frames[8].function, frames[8].path) == ("jq_next", "/work/tree/src/execute.c")
    assert (frames[6].function, frames[6].line) == ("jv_array_indexes", 1026)


def test_prose_before_the_report_is_not_part_of_it() -> None:
    text = (FIXTURES / "02-jq-setpath-array-key.txt").read_text(encoding="utf-8")
    trace = PARSER.parse(text)[0]
    assert text.startswith("jq: error")
    assert "jq: error" not in text[trace.start : trace.end]


# --- capture script (scripts/capture_sanitizer_fixtures.py): pure parts, no engine needed ---


def _capture_module() -> ModuleType:
    path = Path(__file__).parents[3] / "scripts" / "capture_sanitizer_fixtures.py"
    spec = importlib.util.spec_from_file_location("capture_sanitizer_fixtures", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _result(
    stderr: bytes = b"", exit_code: int = 23, timed_out: bool = False, truncated: bool = False
) -> sandbox.ContainerResult:
    return sandbox.ContainerResult((), (), exit_code, b"", stderr, timed_out, truncated, 0)


def _bug(cap: ModuleType, **kw: str) -> Any:
    fields = {
        "fmt": "lsan",
        "name": "01-example",
        "repo": "https://example.invalid/project",
        "vulnerable_tag": "v1.0.0",
        "fixed_tag": "v1.0.1",
        "fix_commit": "a" * 40,
        "reference": "https://example.invalid/issues/1",
        "build": "make",
        "run": "./prog tests/input",
    }
    fields.update(kw)
    return cap.Bug(**fields)


def test_capture_accepts_only_complete_sanitizer_output() -> None:
    cap = _capture_module()
    good = b"==7==ERROR: LeakSanitizer: detected memory leaks\n"
    assert cap.acceptable("lsan", _result(good)) is None
    assert cap.acceptable("lsan", _result(good, timed_out=True)) == "timed out"
    assert cap.acceptable("lsan", _result(good, truncated=True)) == "output truncated"
    assert cap.acceptable("lsan", _result(b"x.c:1: error", exit_code=125)) == "build failed"
    assert cap.acceptable("lsan", _result(b"clang: error\n", exit_code=1)) is not None
    assert cap.acceptable("lsan", _result(good, exit_code=1)) is not None
    tsan = b"WARNING: ThreadSanitizer: data race (pid=9)\n"
    assert cap.acceptable("tsan", _result(tsan, exit_code=66)) is None
    assert cap.acceptable("msan", _result(tsan, exit_code=77)) is not None


def test_capture_requires_the_fixed_tag_to_be_clean() -> None:
    cap = _capture_module()
    good = b"==7==ERROR: LeakSanitizer: detected memory leaks\n"
    assert cap.fixed_is_clean("lsan", _result(b"", exit_code=0)) is None
    assert cap.fixed_is_clean("lsan", _result(good)) is not None
    assert cap.fixed_is_clean("lsan", _result(b"", exit_code=125)) is not None
    assert cap.fixed_is_clean("lsan", _result(b"", timed_out=True)) is not None


def test_capture_catalogue_is_checked() -> None:
    cap = _capture_module()
    assert cap.check_catalogue(cap.BUGS) == []
    assert cap.check_catalogue((_bug(cap),)) == []
    assert cap.check_catalogue((_bug(cap), _bug(cap)))  # duplicate
    assert cap.check_catalogue((_bug(cap, fix_commit="abc123"),))
    assert cap.check_catalogue((_bug(cap, fixed_tag="v1.0.0"),))
    assert cap.check_catalogue((_bug(cap, reference="see chat"),))
    assert cap.check_catalogue((_bug(cap, fmt="asan"),))


def test_capture_script_pins_exit_code_sanitizer_and_retries() -> None:
    cap = _capture_module()
    for fmt, flag in (("lsan", "leak"), ("msan", "memory"), ("tsan", "thread")):
        bug = _bug(cap, fmt=fmt, options="report_objects=1")
        env = bug.environment()
        assert env[f"{fmt.upper()}_OPTIONS"] == f"report_objects=1:exitcode={cap.EXIT_CODES[fmt]}"
        assert f"-fsanitize={flag}" in env["CFLAGS"] and f"-fsanitize={flag}" in env["LDFLAGS"]
        script = bug.script()
        assert f"exit {cap.BUILD_FAILED}" in script and f"exit {cap.NO_REPORT}" in script
        attempts = cap.TSAN_ATTEMPTS if fmt == "tsan" else 1
        assert f"seq 1 {attempts})" in script


def test_capture_container_argv_is_hardened() -> None:
    cap = _capture_module()
    bug = _bug(cap)
    spec = sandbox.ContainerSpec(
        image=cap.IMAGE,
        cmd=("bash", "-c", bug.script()),
        mounts=(sandbox.Mount(Path(__file__).parent.resolve(), "/src"),),
        env=bug.environment(),
    )
    for engine in ("docker", "podman"):
        argv = sandbox.run_argv(engine, spec, name="nikasha-test")
        assert "--read-only" in argv
        assert any(a in ("--network=none", "none") for a in argv)


def test_capture_catalogue_has_three_fixed_bugs_per_format() -> None:
    cap = _capture_module()
    for fmt in cap.FORMATS:  # SPEC §9.5; entries and their evidence are listed in ADR 0009
        bugs = [b for b in cap.BUGS if b.fmt == fmt]
        assert len(bugs) == 3
        assert len({b.repo + b.vulnerable_tag for b in bugs}) == 3
    for bug in cap.BUGS:
        # Triggers go through the project's own programs; the script adds no crash program.
        assert ".c <<" not in bug.run and "cat >" not in bug.build
        assert bug.repo.startswith("https://github.com/") and bug.repo.endswith(".git")


def test_capture_refuses_when_no_fixed_bug_is_catalogued(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cap = _capture_module()
    monkeypatch.setattr(cap, "BUGS", ())
    with pytest.raises(SystemExit) as exc:
        cap.main(["capture"])
    assert "nothing was written" in str(exc.value.code)
