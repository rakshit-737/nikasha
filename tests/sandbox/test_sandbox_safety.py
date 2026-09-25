# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Sandbox safety tests (SPEC §13.6), run against a real container engine.

Every test here is ``@pytest.mark.sandbox``: the default run excludes them and the ubuntu CI
job runs them with ``-m sandbox``. They never skip when the engine is missing: in a sandbox
run, a missing engine is a failure. Each hostile behaviour is asserted by its *effect*
(research §6: e.g. ``NoNewPrivs: 1``, not just the flag spelling).

The first run builds the recipe image ``nikasha/recipe-c:1`` (network is used only for
that image build, never by a container).
"""

from __future__ import annotations

import importlib.util
import re
import shutil
from pathlib import Path

import pytest

from nikasha.code.gitio import GitRepo
from nikasha.repro import build, recipes, run, sandbox
from nikasha.repro.sandbox import ContainerSpec, EngineInfo, Limits, NoEngineError

pytestmark = pytest.mark.sandbox

ROOT = Path(__file__).resolve().parents[2]
VULNLAB = recipes.find_recipe("vulnlab")
IMAGE = VULNLAB.recipe.image.tag
PIDS = 64
FORK_REFUSED = re.compile(rb"Cannot fork|fork: (?:retry: )?Resource temporarily unavailable")


@pytest.fixture(scope="module")
def engine() -> EngineInfo:
    try:
        chosen = sandbox.select_engine("auto")
    except NoEngineError as exc:  # a sandbox run without an engine is a failure, not a skip
        pytest.fail(f"the sandbox suite needs a container engine: {exc}")
    if not sandbox.image_exists(chosen, IMAGE):
        sandbox.build_image(
            chosen, VULNLAB.dockerfile, VULNLAB.dockerfile.parent, IMAGE, online=True
        )
    return chosen


def _run(
    engine: EngineInfo, script: str, *, timeout_s: float = 60, name: str | None = None
) -> sandbox.ContainerResult:
    spec = ContainerSpec(image=IMAGE, cmd=("/bin/sh", "-c", script), limits=Limits(pids=PIDS))
    return sandbox.run_container(engine, spec, timeout_s=timeout_s, name=name)


def test_repro_is_refused_when_no_engine_is_present(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(NoEngineError, match="never run on the host"):
        sandbox.select_engine("auto")


def test_network_egress_fails(engine):
    script = (
        'python3 -c "import socket; s=socket.socket(); s.settimeout(5); '
        "s.connect(('1.1.1.1', 80)); print('CONNECTED')\""
    )
    result = _run(engine, script)
    assert result.exit_code != 0
    assert b"CONNECTED" not in result.stdout
    only_lo = _run(engine, "ls /sys/class/net")
    assert only_lo.stdout.split() == [b"lo"]


def test_fork_bomb_is_contained_by_the_pids_limit(engine):
    counter = (
        'python3 -c "import os,sys\n'
        "n=0\n"
        "try:\n"
        "    while True:\n"
        "        pid=os.fork()\n"
        "        if pid==0:\n"
        "            import time; time.sleep(30); os._exit(0)\n"
        "        n+=1\n"
        "except OSError:\n"
        "    print('LIMIT', n); sys.stdout.flush(); os._exit(0)\""
    )
    result = _run(engine, counter, timeout_s=60)
    assert result.stdout.startswith(b"LIMIT"), result.stderr
    assert int(result.stdout.split()[1]) < PIDS
    name = "nikasha-test-forkbomb"
    bomb = _run(
        engine, "bomb() { bomb | bomb & }; bomb; sleep 5; echo SURVIVED", timeout_s=30, name=name
    )
    # The effect of the limit: forks were refused (dash says "Cannot fork", bash says
    # "fork: ... Resource temporarily unavailable"), and the bomb burned out on its own
    # well before the wall-clock timeout instead of having to be killed.
    assert FORK_REFUSED.search(bomb.stderr), bomb.stderr[:400]
    assert bomb.timed_out is False
    assert bomb.duration_ms < 25_000
    assert not sandbox.container_exists(engine, name)
    after = _run(engine, "echo alive")
    assert after.exit_code == 0 and after.stdout.strip() == b"alive"


def test_writes_to_the_read_only_rootfs_fail(engine):
    for path in ("/usr/nikasha-probe", "/etc/nikasha-probe", "/nikasha-probe", "/var/tmp/x"):
        result = _run(engine, f"touch {path}")
        assert result.exit_code != 0, path
        assert b"Read-only file system" in result.stderr, (path, result.stderr)
    assert _run(engine, "touch /tmp/ok && touch /work/ok").exit_code == 0


def test_process_runs_as_uid_65534_without_new_privileges(engine):
    result = _run(engine, "id -u; id -g; grep -E '^(NoNewPrivs|CapEff)' /proc/self/status")
    lines = result.stdout.decode().split("\n")
    assert lines[0] == "65534"
    assert lines[1] == "65534"
    status = dict(line.split(":\t", 1) for line in lines[2:] if ":\t" in line)
    assert status["NoNewPrivs"].strip() == "1"
    assert int(status["CapEff"].strip(), 16) == 0


def test_timeout_kills_the_container_and_leaves_none_running(engine):
    name = sandbox.new_container_name("nikasha-timeout")
    result = _run(engine, "sleep 600", timeout_s=3, name=name)
    assert result.timed_out is True
    assert result.duration_ms < 60_000
    assert not sandbox.container_exists(engine, name)


def test_output_is_truncated_at_the_limit(engine):
    result = _run(engine, "head -c 3000000 /dev/zero")
    assert result.truncated is True
    assert len(result.stdout) == 1024 * 1024


def test_vulnlab_build_and_poc_reproduce_the_heap_overflow(engine, tmp_path):
    """End to end: export, sandboxed build, cached outputs, and one real PoC run."""
    if shutil.which("git") is None:
        pytest.fail("git is required")
    spec = importlib.util.spec_from_file_location("bv", ROOT / "scripts" / "build_vulnlab.py")
    assert spec is not None and spec.loader is not None
    bv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bv)
    git_dir = tmp_path / "vulnlab.git"
    commit = bv.build_vulnlab(git_dir)["v1.2.0"]
    cache = tmp_path / "cache"
    with GitRepo(git_dir) as repo:
        first = build.build(repo, commit, VULNLAB, engine, cache_root=cache)
        again = build.build(repo, commit, VULNLAB, engine, cache_root=cache)
    assert first.cached is False
    assert again.cached is True
    assert (first.outputs_dir / "hdrcat").is_file()
    poc = tmp_path / "poc.txt"
    poc.write_text("Host: example.test\nX-Overflow: " + "A" * 96 + "\n", encoding="utf-8")
    outcome = run.run_poc(engine, VULNLAB.recipe, first.outputs_dir, poc, cache_root=cache)
    assert outcome.kind == "file_input"
    assert "heap-buffer-overflow" in outcome.stderr
    assert "util_copy_value" in outcome.stderr
    assert outcome.record.argv[0] == engine.name
    assert "<path>:/poc:ro" in outcome.record.argv
    assert not any(str(tmp_path) in arg for arg in outcome.record.argv)


def _vulnlab_repo(tmp_path: Path) -> tuple[Path, str]:
    spec = importlib.util.spec_from_file_location("bv", ROOT / "scripts" / "build_vulnlab.py")
    assert spec is not None and spec.loader is not None
    bv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bv)
    git_dir = tmp_path / "vulnlab.git"
    return git_dir, bv.build_vulnlab(git_dir)["v1.2.0"]


def _hostile(steps: list[str]) -> recipes.LoadedRecipe:
    """vulnlab with other build steps (same image), as if the project's build were hostile."""
    data = VULNLAB.recipe.model_dump(mode="json")
    data["build"]["steps"] = steps
    return recipes.LoadedRecipe(recipes.Recipe.model_validate(data), VULNLAB.path, "b" * 64)


@pytest.mark.parametrize(
    "plant",
    [
        "ln -s /etc/passwd build/hdrcat",
        "ln -s ../../../../../../../../etc/passwd include/x.h",
        "ln -s / include/root",
        "mkfifo include/fifo",
    ],
)
def test_links_left_in_out_by_a_hostile_build_are_refused(engine, tmp_path, plant):
    git_dir, commit = _vulnlab_repo(tmp_path)
    cache = tmp_path / "cache"
    loaded = _hostile(
        [
            "mkdir -p build include",
            "touch build/libhdr.a",
            plant,
            "[ -L build/hdrcat ] || touch build/hdrcat",
        ]
    )
    with GitRepo(git_dir) as repo, pytest.raises(build.BuildFailedError, match="not a regular"):
        build.build(repo, commit, loaded, engine, cache_root=cache)
    assert build.load_cached(build.build_dir(loaded, commit, cache)) is None
    assert list((cache / "repro" / "tmp").iterdir()) == []  # the scratch tree is gone


def test_scratch_is_removed_even_when_the_build_skips_its_exit_trap(engine, tmp_path):
    """A build that drops the trap and locks its directories still leaves nothing behind."""
    git_dir, commit = _vulnlab_repo(tmp_path)
    cache = tmp_path / "cache"
    loaded = _hostile(
        [
            "trap - EXIT",
            "mkdir -p build include/deep/er && touch build/hdrcat build/libhdr.a",
            "touch include/deep/er/f && chmod 0500 include/deep/er include/deep include",
            "cp -R include /out/locked && chmod 0500 /out/locked/deep/er /out/locked/deep"
            " /out/locked && exit 3",
        ]
    )
    with GitRepo(git_dir) as repo, pytest.raises(build.BuildFailedError, match="exited with 3"):
        build.build(repo, commit, loaded, engine, cache_root=cache)
    assert list((cache / "repro" / "tmp").iterdir()) == []


def test_scrub_container_empties_a_tree_the_host_cannot_delete(engine, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    out.chmod(0o777)
    locked = (
        "mkdir -p /out/a/b /out/.hidden && touch /out/a/b/f /out/.hidden/g /out/..x"
        " && chmod 0500 /out/a/b /out/a /out/.hidden"
    )
    spec = ContainerSpec(
        image=IMAGE,
        cmd=("/bin/sh", "-c", locked),
        mounts=(sandbox.Mount(out, "/out", read_only=False),),
        limits=Limits(pids=PIDS),
    )
    assert sandbox.run_container(engine, spec, timeout_s=60).exit_code == 0
    assert (out / "a" / "b" / "f").exists()
    result = sandbox.run_container(engine, build.scrub_spec(IMAGE, out), timeout_s=60)
    assert result.exit_code == 0
    assert list(out.iterdir()) == []


REAL_PROJECTS = [
    ("curl", "https://github.com/curl/curl", "curl-8_10_1", "curl"),
    ("sqlite", "https://github.com/sqlite/sqlite", "version-3.46.1", "sqlite3"),
    ("libxml2", "https://gitlab.gnome.org/GNOME/libxml2", "v2.13.4", "xmllint"),
]


@pytest.mark.network
@pytest.mark.slow
@pytest.mark.parametrize(("recipe_id", "url", "tag", "binary"), REAL_PROJECTS)
def test_real_project_recipe_builds(engine, tmp_path, recipe_id, url, tag, binary):  # noqa: PLR0917
    """Nightly: the real-project recipes' build steps, which were never run offline."""
    from nikasha.resolve.repo import open_repo  # noqa: PLC0415

    loaded = recipes.find_recipe(recipe_id)
    with open_repo(url, online=True, cache_root=tmp_path / "repos") as repo:
        commit = repo.rev_parse(tag)
        assert commit is not None
        result = build.build(repo, commit, loaded, engine, cache_root=tmp_path / "cache")
    assert (result.outputs_dir / binary).is_file()
