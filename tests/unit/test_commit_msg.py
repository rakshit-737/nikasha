# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check_commit_msg.py"
_spec = importlib.util.spec_from_file_location("check_commit_msg", _PATH)
assert _spec is not None
assert _spec.loader is not None
ccm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ccm)

SIGNOFF = "Signed-off-by: Ada Lovelace <ada@example.org>"


@pytest.mark.parametrize(
    "header",
    [
        "feat: add doctor",
        "fix(gitio): pass --no-textconv",
        "chore!: drop py3.10",
        "docs(adr): 0003",
    ],
)
def test_valid_messages(header):
    assert ccm.problems(f"{header}\n\nBody.\n\n{SIGNOFF}\n") == []


def test_missing_signoff():
    assert any("sign-off" in p for p in ccm.problems("feat: x\n"))


@pytest.mark.parametrize("header", ["Add stuff", "feature: x", "feat:x", "feat(Big): x", ""])
def test_bad_headers(header):
    assert any("Conventional" in p for p in ccm.problems(f"{header}\n\n{SIGNOFF}\n"))


def test_comment_lines_are_ignored():
    msg = f"# Please enter the commit message\nfeat: x\n\n{SIGNOFF}\n# comment\n"
    assert ccm.problems(msg) == []


def test_merge_commits_are_exempt():
    assert ccm.problems("Merge pull request #1 from x/y\n") == []


def test_cli_reads_file(tmp_path):
    f = tmp_path / "MSG"
    f.write_text("fix: y\n", encoding="utf-8")
    assert ccm.main(["prog", str(f)]) == 1
    f.write_text(f"fix: y\n\n{SIGNOFF}\n", encoding="utf-8")
    assert ccm.main(["prog", str(f)]) == 0
