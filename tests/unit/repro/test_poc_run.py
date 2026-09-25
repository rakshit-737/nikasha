# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""PoC staging and command construction (SPEC §13.4). No PoC is ever executed here."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

from nikasha.repro import recipes, run
from nikasha.repro.run import PocError

VULNLAB = recipes.find_recipe("vulnlab").recipe
KINDS = VULNLAB.run.kinds


def test_choose_kind() -> None:
    assert run.choose_kind(VULNLAB, Path("poc.c"), None) == "c_harness"
    assert run.choose_kind(VULNLAB, Path("crash.bin"), None) == "file_input"
    assert run.choose_kind(VULNLAB, Path("x"), "cli") == "cli"
    with pytest.raises(PocError, match="no kind"):
        run.choose_kind(VULNLAB, Path("x"), "python")


def test_cli_args_are_separate_argv_entries_without_a_shell() -> None:
    cmd = run.poc_command(KINDS["cli"], args=("--in", "$(reboot)", "a b"))
    assert cmd == ("/build/hdrcat", "--in", "$(reboot)", "a b")


def test_file_placeholder() -> None:
    assert run.poc_command(KINDS["file_input"], file="crash.bin") == (
        "/build/hdrcat",
        "/poc/crash.bin",
    )
    with pytest.raises(PocError, match="single PoC file"):
        run.poc_command(KINDS["file_input"], file=None)


def test_c_harness_compiles_then_execs_with_quoting() -> None:
    cmd = run.poc_command(KINDS["c_harness"], file="poc.c")
    assert cmd[:2] == ("/bin/sh", "-c")
    compile_part, _, exec_part = cmd[2].partition(" && exec ")
    assert shlex.split(compile_part)[0] == "clang"
    assert "/poc/poc.c" in shlex.split(compile_part)
    assert shlex.split(exec_part) == ["/work/poc"]


def test_argument_limits() -> None:
    with pytest.raises(PocError):
        run.poc_command(KINDS["cli"], args=("a\0b",))
    with pytest.raises(PocError):
        run.poc_command(KINDS["cli"], args=("x",) * (run.MAX_ARGS + 1))


def test_stage_single_file(tmp_path: Path) -> None:
    poc = tmp_path / "crash input.bin"
    poc.write_bytes(b"\x00\x01")
    dest = tmp_path / "stage"
    dest.mkdir()
    name = run.stage_poc(poc, "file_input", dest)
    assert name == "poc.bin"  # an unsafe name is replaced, never passed through
    assert (dest / name).read_bytes() == b"\x00\x01"


def test_stage_harness_is_named_poc_c(tmp_path: Path) -> None:
    poc = tmp_path / "exploit.c"
    poc.write_text("int main(void){return 0;}\n", encoding="utf-8")
    dest = tmp_path / "stage"
    dest.mkdir()
    assert run.stage_poc(poc, "c_harness", dest) == "poc.c"
    assert (dest / "poc.c").is_file()


def test_stage_directory(tmp_path: Path) -> None:
    src = tmp_path / "pocdir"
    (src / "sub").mkdir(parents=True)
    (src / "sub" / "a.txt").write_text("a", encoding="utf-8")
    dest = tmp_path / "stage"
    dest.mkdir()
    assert run.stage_poc(src, "cli", dest) is None
    assert (dest / "sub" / "a.txt").read_text(encoding="utf-8") == "a"


def test_stage_refuses_missing_and_oversized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "stage"
    dest.mkdir()
    with pytest.raises(PocError, match="does not exist"):
        run.stage_poc(tmp_path / "missing", "cli", dest)
    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 20)
    monkeypatch.setattr(run, "MAX_POC_BYTES", 10)
    with pytest.raises(PocError, match="larger"):
        run.stage_poc(big, "file_input", dest)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_stage_refuses_symlink_and_skips_links_in_dirs(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("s", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(secret)
    except OSError:
        pytest.skip("creating symlinks needs a privilege this Windows account lacks")
    dest = tmp_path / "stage"
    dest.mkdir()
    with pytest.raises(PocError, match="symbolic link"):
        run.stage_poc(link, "file_input", dest)
    pocdir = tmp_path / "pocdir"
    pocdir.mkdir()
    (pocdir / "leak").symlink_to(secret)
    run.stage_poc(pocdir, "cli", dest)
    assert not (dest / "leak").exists()


def test_run_spec_mounts_are_read_only(tmp_path: Path) -> None:
    spec = run.run_spec(VULNLAB, tmp_path / "b", tmp_path / "p", ("/build/hdrcat",))
    assert {(m.target, m.read_only) for m in spec.mounts} == {("/poc", True), ("/build", True)}
    assert spec.limits.output_bytes == 1024 * 1024
    assert spec.env["ASAN_OPTIONS"].startswith("abort_on_error=1")


def test_run_poc_refuses_without_an_engine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    poc = tmp_path / "crash.bin"
    poc.write_bytes(b"x")
    engine = run.sandbox.EngineInfo("docker", False, error="not found on PATH")  # type: ignore[attr-defined]
    with pytest.raises(run.sandbox.NoEngineError):  # type: ignore[attr-defined]
        run.run_poc(engine, VULNLAB, tmp_path, poc, cache_root=tmp_path / "cache")


@pytest.mark.parametrize("timeout", [0.0, -1.0, 3601.0, float("nan"), float("inf")])
def test_run_poc_refuses_out_of_range_timeouts(tmp_path: Path, timeout: float) -> None:
    poc = tmp_path / "p.txt"
    poc.write_bytes(b"x")
    with pytest.raises(run.PocError, match="timeout"):
        run.run_poc(
            run.sandbox.EngineInfo("docker", True),  # type: ignore[attr-defined]
            VULNLAB,
            tmp_path,
            poc,
            timeout_s=timeout,
            cache_root=tmp_path / "cache",
        )
