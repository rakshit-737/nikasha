# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Build planning and the build cache (SPEC §13.3). The container build itself is sandbox."""

from __future__ import annotations

import importlib.util
import itertools
import json
import os
import shutil
import threading
from pathlib import Path

import pytest

from nikasha.code.gitio import GitRepo
from nikasha.errors import NikashaError
from nikasha.repro import build, recipes, sandbox

ROOT = Path(__file__).resolve().parents[3]
LOADED = recipes.find_recipe("vulnlab")
COMMIT = "a" * 40
NO_ENGINE = sandbox.EngineInfo("docker", False, error="not found on PATH")


def _load_builder():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "build_vulnlab_repro", ROOT / "scripts" / "build_vulnlab.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def vulnlab(tmp_path_factory) -> tuple[Path, dict[str, str]]:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    dest = tmp_path_factory.mktemp("vulnlab") / "repo.git"
    tags = _load_builder().build_vulnlab(dest)
    return dest, tags


def test_build_key_is_recipe_id_sha_and_commit():
    key = build.build_key("vulnlab", LOADED.sha256, COMMIT)
    assert key.parts == ("repro", "builds", "vulnlab", LOADED.sha256[:16], COMMIT)


@pytest.mark.parametrize("commit", ["HEAD", "a" * 39, "g" * 40, "--all"])
def test_build_key_refuses_non_sha_commits(commit):
    with pytest.raises(NikashaError):
        build.build_key("vulnlab", LOADED.sha256, commit)


def test_build_dir_changes_when_the_recipe_changes(tmp_path):
    other = recipes.LoadedRecipe(LOADED.recipe, LOADED.path, "b" * 64)
    assert build.build_dir(LOADED, COMMIT, tmp_path) != build.build_dir(other, COMMIT, tmp_path)
    assert build.build_dir(LOADED, COMMIT, tmp_path).is_relative_to(tmp_path)


def test_build_script_copies_source_then_outputs():
    script = build.build_script(LOADED.recipe)
    lines = script.splitlines()
    assert lines[1:4] == ["set -eu", "cp -R /src/. /work/", "cd /work"]
    assert "make -j4" in lines
    assert "cp -R /work/build/hdrcat /out/hdrcat" in lines
    assert "cp -R /work/include /out/include" in lines


def test_build_spec_is_hardened_and_offline(tmp_path):
    spec = build.build_spec(LOADED.recipe, tmp_path / "src", tmp_path / "out")
    assert {(m.target, m.read_only) for m in spec.mounts} == {("/src", True), ("/out", False)}
    assert spec.env["CC"] == "clang"
    argv = sandbox.run_argv("docker", spec, name="b1")
    assert ("--network", "none") in itertools.pairwise(argv)
    assert "--read-only" in argv
    assert spec.work_size == "512m"


def _fake_cache(target: Path) -> None:
    (target / "outputs").mkdir(parents=True)
    (target / "outputs" / "hdrcat").write_bytes(b"\x7fELF")
    (target / "build.log").write_text("ok\n", encoding="utf-8")
    record = {
        "argv": ["docker", "run"],
        "exit_code": 0,
        "stdout_sha256": "0" * 64,
        "stderr_sha256": "0" * 64,
    }
    (target / "complete.json").write_text(json.dumps({"record": record}), encoding="utf-8")


def test_cached_build_is_reused_without_an_engine(tmp_path):
    target = build.build_dir(LOADED, COMMIT, tmp_path)
    _fake_cache(target)
    result = build.build(None, COMMIT, LOADED, NO_ENGINE, cache_root=tmp_path)  # type: ignore[arg-type]
    assert result.cached is True
    assert result.outputs_dir == target / "outputs"
    assert result.log == "ok\n"
    assert result.record is not None
    assert result.record.exit_code == 0


def test_incomplete_cache_is_ignored(tmp_path):
    target = build.build_dir(LOADED, COMMIT, tmp_path)
    (target / "outputs").mkdir(parents=True)
    assert build.load_cached(target) is None
    (target / "complete.json").write_text("{not json", encoding="utf-8")
    assert build.load_cached(target) is None


def test_uncached_build_refuses_without_an_engine(vulnlab, tmp_path):
    """Real repository and real export; an unavailable engine: the build must refuse."""
    git_dir, tags = vulnlab
    commit = tags["v1.2.0"]
    with GitRepo(git_dir) as repo, pytest.raises(sandbox.NoEngineError):
        build.build(repo, commit, LOADED, NO_ENGINE, cache_root=tmp_path)
    assert not build.build_dir(LOADED, commit, tmp_path).exists()


def test_build_script_opens_out_on_every_exit():
    lines = build.build_script(LOADED.recipe).splitlines()
    assert lines[0] == "trap 'chmod -R a+rwX /out 2>/dev/null || true' EXIT"
    assert lines[1] == "set -eu"


def test_copy_outputs_copies_plain_files_and_dirs(tmp_path):
    out = tmp_path / "out"
    (out / "include").mkdir(parents=True)
    (out / "include" / "hdr.h").write_bytes(b"int x;\n")
    (out / "hdrcat").write_bytes(b"\x7fELF")
    dest = tmp_path / "dest"
    build.copy_outputs(out, dest)
    assert (dest / "include" / "hdr.h").read_bytes() == b"int x;\n"
    assert (dest / "hdrcat").read_bytes() == b"\x7fELF"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="symlinks and FIFOs need a POSIX host")
@pytest.mark.parametrize("plant", ["relative_link", "absolute_link", "dangling_link", "fifo"])
def test_copy_outputs_refuses_links_and_special_files(tmp_path, plant):

    secret = tmp_path / "secret"
    secret.write_bytes(b"host secret")
    out = tmp_path / "a" / "b" / "out"
    (out / "include").mkdir(parents=True)
    victim = out / "include" / "x"
    if plant == "relative_link":
        victim.symlink_to(os.path.relpath(secret, victim.parent))
    elif plant == "absolute_link":
        victim.symlink_to(secret)
    elif plant == "dangling_link":
        victim.symlink_to("does-not-exist")
    else:
        os.mkfifo(victim)
    dest = tmp_path / "dest"
    with pytest.raises(build.BuildFailedError, match="not a regular file"):
        build.copy_outputs(out, dest)
    assert not dest.exists()


FAKE_ENGINE = sandbox.EngineInfo("docker", True, version="test")


def _fake_container(calls: list[sandbox.ContainerSpec], *, fail: bool = False):  # type: ignore[no-untyped-def]
    """A stand-in for ``run_container`` that writes the recipe outputs into ``/out``."""

    def run(engine, spec, *, timeout_s, runtime=None, name=None):  # type: ignore[no-untyped-def]
        calls.append(spec)
        out = next(m.host for m in spec.mounts if m.target == "/out")
        if spec.cmd[-1] != build.SCRUB_SCRIPT and not fail:
            (out / "include").mkdir()
            (out / "include" / "hdr.h").write_bytes(b"int x;\n")
            (out / "hdrcat").write_bytes(b"\x7fELF")
            (out / "hdrcat").chmod(0o4755)  # setuid must not survive the copy
            (out / "libhdr.a").write_bytes(b"!<arch>\n")
        return sandbox.ContainerResult(
            argv=("docker",),
            recorded_argv=("docker",),
            exit_code=1 if fail else 0,
            stdout=b"built\n",
            stderr=b"",
            timed_out=False,
            truncated=False,
            duration_ms=1,
        )

    return run


class _Repo:
    def export_tree(self, commit: str, dest: Path) -> None:
        (dest / "Makefile").write_text("all:\n", encoding="utf-8")


def test_build_installs_outputs_with_exec_bits_and_no_setuid(tmp_path, monkeypatch):
    calls: list[sandbox.ContainerSpec] = []
    monkeypatch.setattr(sandbox, "run_container", _fake_container(calls))
    result = build.build(_Repo(), COMMIT, LOADED, FAKE_ENGINE, cache_root=tmp_path)  # type: ignore[arg-type]
    assert result.cached is False
    assert (result.outputs_dir / "include" / "hdr.h").read_bytes() == b"int x;\n"
    if os.name == "posix":
        assert (result.outputs_dir / "hdrcat").stat().st_mode & 0o7777 == 0o755
        assert (result.outputs_dir / "include" / "hdr.h").stat().st_mode & 0o7777 == 0o644
    assert list((tmp_path / "repro" / "tmp").iterdir()) == []
    assert len(calls) == 1  # the host could delete /out itself: no scrub container
    again = build.build(_Repo(), COMMIT, LOADED, FAKE_ENGINE, cache_root=tmp_path)  # type: ignore[arg-type]
    assert again.cached is True


def test_failed_build_cleans_its_scratch_and_caches_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "run_container", _fake_container([], fail=True))
    with pytest.raises(build.BuildFailedError, match="exited with 1"):
        build.build(_Repo(), COMMIT, LOADED, FAKE_ENGINE, cache_root=tmp_path)  # type: ignore[arg-type]
    assert build.load_cached(build.build_dir(LOADED, COMMIT, tmp_path)) is None
    assert list((tmp_path / "repro" / "tmp").iterdir()) == []


def test_undeletable_out_is_scrubbed_by_a_container(tmp_path, monkeypatch):
    """Host rmtree fails (uid 65534 owns the tree): the scrub container runs, hardened."""
    calls: list[sandbox.ContainerSpec] = []
    out = tmp_path / "out"
    (out / "include").mkdir(parents=True)
    real_rmtree = shutil.rmtree
    attempts = []

    def rmtree(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        attempts.append(Path(path))
        if len(attempts) == 1:
            raise PermissionError(13, "Permission denied")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(build.shutil, "rmtree", rmtree)
    monkeypatch.setattr(sandbox, "run_container", _fake_container(calls))
    assert build.remove_out(FAKE_ENGINE, "img:1", out) is True
    assert not out.exists()
    (spec,) = calls
    assert spec.cmd == ("/bin/sh", "-c", build.SCRUB_SCRIPT)
    assert [(m.host, m.target, m.read_only) for m in spec.mounts] == [(out, "/out", False)]
    argv = sandbox.run_argv("docker", spec, name="s1")
    assert ("--network", "none") in itertools.pairwise(argv)
    assert ("--user", "65534:65534") in itertools.pairwise(argv)


def test_remove_out_never_raises_when_the_engine_is_gone(tmp_path, monkeypatch):
    out = tmp_path / "out"
    out.mkdir()

    def rmtree(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if not kwargs.get("ignore_errors"):
            raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(build.shutil, "rmtree", rmtree)
    assert build.remove_out(NO_ENGINE, "img:1", out) is False


def test_an_incomplete_leftover_is_replaced(tmp_path, monkeypatch):
    target = build.build_dir(LOADED, COMMIT, tmp_path)
    (target / "outputs").mkdir(parents=True)
    (target / "outputs" / "stale").write_bytes(b"x")
    monkeypatch.setattr(sandbox, "run_container", _fake_container([]))
    result = build.build(_Repo(), COMMIT, LOADED, FAKE_ENGINE, cache_root=tmp_path)  # type: ignore[arg-type]
    assert not (result.outputs_dir / "stale").exists()
    assert (result.outputs_dir / "hdrcat").is_file()
    assert [p.name for p in target.parent.iterdir() if p.suffix != ".lock"] == [
        COMMIT
    ]  # no staging or trash left


def test_concurrent_builds_of_one_key_both_succeed(tmp_path, monkeypatch):
    """Eight racing builds of one key: no FileExistsError, one complete build installed."""
    monkeypatch.setattr(sandbox, "run_container", _fake_container([]))
    barrier = threading.Barrier(8)
    results: list[build.BuildResult] = []
    errors: list[BaseException] = []

    real_install = build._install

    def install(staging: Path, target: Path) -> None:
        barrier.wait(timeout=10)  # everyone reaches the install step together
        real_install(staging, target)

    monkeypatch.setattr(build, "_install", install)

    def worker() -> None:
        try:
            results.append(
                build.build(_Repo(), COMMIT, LOADED, FAKE_ENGINE, cache_root=tmp_path)  # type: ignore[arg-type]
            )
        except BaseException as exc:  # collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert errors == []
    assert len(results) == 8
    target = build.build_dir(LOADED, COMMIT, tmp_path)
    assert build.load_cached(target) is not None
    assert all((r.outputs_dir / "hdrcat").is_file() for r in results)
    assert [p.name for p in target.parent.iterdir() if p.suffix != ".lock"] == [COMMIT]


def test_install_raises_a_nikasha_error_when_it_cannot_install(tmp_path, monkeypatch):
    staging = tmp_path / "staging"
    staging.mkdir()
    target = tmp_path / "target"

    def replace(self: Path, other: Path) -> Path:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "replace", replace)
    with pytest.raises(build.BuildFailedError, match="could not install"):
        build._install(staging, target)
