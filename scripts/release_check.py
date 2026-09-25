# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Pre-release check: build, inspect and smoke-test the distribution (SPEC §21.7).

Publishes nothing. Steps:

1. ``uv build`` the sdist and the wheel into a temporary directory;
2. read the wheel's ``METADATA`` and check name, version, licence and requires-python;
3. check that the wheel carries the packaged data and nothing it should not
   (tests, caches, bytecode);
4. check that the version agrees between ``src/nikasha/version.py``, both file names,
   the wheel metadata and the sdist ``PKG-INFO``;
5. install the wheel into a fresh virtual environment and run ``nikasha version`` from it.

Exit code 0 when every check passes, 1 otherwise. Each failure is printed.
"""

from __future__ import annotations

import argparse
import email.parser
import fnmatch
import re
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = ROOT / "src" / "nikasha" / "version.py"
_VERSION_RE = re.compile(r'^__version__ = "([^"\n]{1,64})"$', re.MULTILINE)

# Globs inside the wheel. Each must match at least one member.
REQUIRED_IN_WHEEL: tuple[str, ...] = (
    "nikasha/__init__.py",
    "nikasha/py.typed",
    "nikasha/data/known_projects.yaml",
    "nikasha/checks/lr_defaults.yaml",
    "nikasha/checks/cwe_compat.yaml",
    "nikasha/fuse/questions/*.j2",
    "nikasha/render/html/*.py",
    "nikasha/code/queries/*.scm",
    "nikasha/integrations/web/templates/*.html",
    "nikasha/*schema*/result-v1.json",
)
# Globs that must match nothing in the wheel.
FORBIDDEN_IN_WHEEL: tuple[str, ...] = (
    "tests/*",
    "*/tests/*",
    "*.pyc",
    "*/__pycache__/*",
    "*.sqlite",
    "*/.cache/*",
    "*.orig",
)


def _read_version() -> str:
    match = _VERSION_RE.search(VERSION_FILE.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"cannot read __version__ from {VERSION_FILE}")
    return match.group(1)


def _run(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)


def check_wheel_members(names: list[str]) -> list[str]:
    """Return failures for missing packaged data and forbidden members."""
    failures = [
        f"wheel is missing {pattern}"
        for pattern in REQUIRED_IN_WHEEL
        if not any(fnmatch.fnmatchcase(n, pattern) for n in names)
    ]
    for pattern in FORBIDDEN_IN_WHEEL:
        bad = sorted(n for n in names if fnmatch.fnmatchcase(n, pattern))
        if bad:
            failures.append(f"wheel contains {pattern}: {', '.join(bad[:5])}")
    return failures


def check_metadata(meta_text: str, version: str) -> list[str]:
    """Return failures in a wheel METADATA or sdist PKG-INFO document."""
    meta = email.parser.Parser().parsestr(meta_text)
    failures: list[str] = []
    if meta.get("Name") != "nikasha":
        failures.append(f"metadata Name is {meta.get('Name')!r}, expected 'nikasha'")
    if meta.get("Version") != version:
        failures.append(f"metadata Version is {meta.get('Version')!r}, expected {version!r}")
    if not meta.get("Requires-Python"):
        failures.append("metadata has no Requires-Python")
    if not (meta.get("License-Expression") or meta.get("License")):
        failures.append("metadata has no licence")
    if not meta.get("Summary"):
        failures.append("metadata has no Summary")
    return failures


def _inspect(wheel: Path, sdist: Path, version: str) -> list[str]:
    """Check file names, wheel members and both metadata documents."""
    failures: list[str] = []
    if not wheel.name.startswith(f"nikasha-{version}-"):
        failures.append(f"wheel file name {wheel.name} does not carry {version}")
    if sdist.name != f"nikasha-{version}.tar.gz":
        failures.append(f"sdist file name {sdist.name} does not carry {version}")
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        failures += check_wheel_members(names)
        meta_name = f"nikasha-{version}.dist-info/METADATA"
        if meta_name in names:
            failures += check_metadata(zf.read(meta_name).decode("utf-8"), version)
        else:
            failures.append(f"wheel has no {meta_name}")
        ep = f"nikasha-{version}.dist-info/entry_points.txt"
        if ep not in names or "nikasha" not in zf.read(ep).decode("utf-8"):
            failures.append("wheel declares no 'nikasha' console script")
    print(f"wheel members: {len(names)}")
    with tarfile.open(sdist) as tf:
        member = tf.extractfile(f"nikasha-{version}/PKG-INFO")
        if member is None:
            failures.append("sdist has no PKG-INFO")
        else:
            pkg_info = member.read().decode("utf-8")
            failures += [f"sdist {f}" for f in check_metadata(pkg_info, version)]
    return failures


def _smoke_test(wheel: Path, version: str, tmp: Path) -> list[str]:
    """Install the wheel into a fresh venv and run ``nikasha version`` from it."""
    venv = tmp / "venv"
    steps = [
        ["uv", "venv", "--quiet", str(venv)],
        ["uv", "pip", "install", "--quiet", "--python", str(venv), str(wheel)],
    ]
    for step in steps:
        proc = _run(step, cwd=tmp)
        if proc.returncode != 0:
            return [f"{' '.join(step[:3])} failed: {proc.stderr.strip()[-400:]}"]
    bindir = venv / ("Scripts" if sys.platform == "win32" else "bin")
    exe = bindir / ("nikasha.exe" if sys.platform == "win32" else "nikasha")
    proc = _run([str(exe), "version"], cwd=tmp)
    out = (proc.stdout + proc.stderr).strip()
    print(f"installed 'nikasha version' -> {out.splitlines()[0] if out else '(empty)'}")
    if proc.returncode != 0:
        return [f"'nikasha version' exited {proc.returncode}: {out[-400:]}"]
    if version not in out:
        return [f"'nikasha version' output does not contain {version}"]
    return []


def _check_in(tmp: Path, version: str, dist: Path | None = None) -> list[str]:
    """Build into ``dist`` (default: a temp dir) and inspect exactly those files."""
    dist = dist if dist is not None else tmp / "dist"
    if dist.exists() and any(dist.iterdir()):
        return [f"{dist} is not empty; the checked files must be the ones built here"]
    build = _run(["uv", "build", "--out-dir", str(dist), str(ROOT)])
    if build.returncode != 0:
        print(build.stdout, build.stderr, sep="\n")
        return ["uv build failed"]
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        return [f"expected one wheel and one sdist, got {wheels} {sdists}"]
    print(f"built {wheels[0].name} and {sdists[0].name}")
    return _inspect(wheels[0], sdists[0], version) + _smoke_test(wheels[0], version, tmp)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--keep", action="store_true", help="keep the temporary directory")
    parser.add_argument(
        "--dist",
        type=Path,
        default=None,
        help="build into this directory and keep the checked artifacts there (for upload)",
    )
    args = parser.parse_args(argv)

    version = _read_version()
    print(f"release-check: version.py says {version}")
    tmp_obj = tempfile.TemporaryDirectory(prefix="nikasha-release-")
    try:
        failures = _check_in(
            Path(tmp_obj.name), version, args.dist.resolve() if args.dist else None
        )
    finally:
        if args.keep:
            print(f"kept {tmp_obj.name}")
        else:
            tmp_obj.cleanup()
    for failure in failures:
        print(f"FAIL: {failure}")
    print("release-check: " + ("OK" if not failures else f"{len(failures)} failure(s)"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
