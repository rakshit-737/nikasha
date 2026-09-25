# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Only the approved wrappers may spawn processes (SPEC §19.3, §13).

Git hazards and hostile PoCs are contained only if every external command goes through
``code/gitio.py`` (git) or ``repro/sandbox.py`` (container engines). This test scans the
source tree so a new call site cannot slip in unnoticed.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "nikasha"
ALLOWED = {SRC / "code" / "gitio.py", SRC / "repro" / "sandbox.py"}

FORBIDDEN_MODULES = {"subprocess", "pty", "multiprocessing"}
FORBIDDEN_ATTRS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "spawnl"),
    ("os", "spawnlp"),
    ("os", "spawnv"),
    ("os", "spawnvp"),
    ("os", "execv"),
    ("os", "execvp"),
    ("os", "execvpe"),
    ("os", "posix_spawn"),
    ("os", "posix_spawnp"),
    ("asyncio", "create_subprocess_exec"),
    ("asyncio", "create_subprocess_shell"),
}


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[0] in FORBIDDEN_MODULES]
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in FORBIDDEN_MODULES:
                found.append(node.module)
            found += [
                f"{node.module}.{a.name}" for a in node.names if (root, a.name) in FORBIDDEN_ATTRS
            ]
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and (node.value.id, node.attr) in FORBIDDEN_ATTRS
        ):
            found.append(f"{node.value.id}.{node.attr}")
    return found


def test_source_tree_exists() -> None:
    assert (SRC / "__init__.py").is_file()


def test_only_wrappers_spawn_processes() -> None:
    offenders = {
        str(p.relative_to(SRC)): v
        for p in sorted(SRC.rglob("*.py"))
        if p not in ALLOWED and (v := _violations(p))
    }
    assert offenders == {}


def test_detector_catches_known_patterns(tmp_path):
    sample = tmp_path / "bad.py"
    sample.write_text(
        "import subprocess\nimport os\nfrom os import system\nos.popen('x')\n",
        encoding="utf-8",
    )
    assert set(_violations(sample)) == {"subprocess", "os.system", "os.popen"}
