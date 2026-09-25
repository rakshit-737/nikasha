# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Attachments are attacker-controlled (SPEC §8, §19.2)."""

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from nikasha.ingest.attachments import (
    MAX_NAME_LEN,
    ArchiveLimits,
    ArchiveRejectedError,
    AttachmentLimits,
    safe_extract_archive,
    sanitize_name,
    store_attachments,
)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("poc.txt", "poc.txt"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Windows\\evil.dll", "evil.dll"),
        (".bashrc", "bashrc"),
        ("a b;c|d.txt", "a_b_c_d.txt"),
        ("", "attachment"),
        ("...", "attachment"),
        ("\u202etxt.exe", "_txt.exe"),
    ],
)
def test_sanitize_name(name: str, expected: str) -> None:
    assert sanitize_name(name) == expected


def test_sanitize_name_length_and_dedup() -> None:
    taken: set[str] = set()
    long_name = "x" * 300 + ".txt"
    first = sanitize_name(long_name, taken)
    second = sanitize_name(long_name, taken)
    assert len(first) <= MAX_NAME_LEN
    assert first.endswith(".txt")
    assert second != first
    assert len(second) <= MAX_NAME_LEN


def test_store_attachments_caps_and_permissions(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    stored, warnings = store_attachments(
        [
            ("poc.bin", b"a" * 10),
            ("big.bin", b"b" * 100),
            ("poc.bin", b"c" * 5),
            ("more", b"d" * 20),
        ],
        run_dir,
        AttachmentLimits(per_file_bytes=50, total_bytes=30),
    )
    assert [a.name_sanitized for a in stored] == ["poc.bin", "poc-1.bin"]
    assert len(warnings) == 2
    assert (run_dir / "poc.bin").read_bytes() == b"a" * 10
    if os.name == "posix":
        assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE((run_dir / "poc.bin").stat().st_mode) == 0o600


def _zip(tmp_path: Path, entries: list[tuple[str, str | bytes]], name: str = "a.zip") -> Path:
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, data in entries:
            zf.writestr(arcname, data)
    return path


def test_safe_extract_zip(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("dir/poc.txt", "hi"), ("b.txt", "x")])
    out = safe_extract_archive(archive, tmp_path / "out")
    assert sorted(p.name for p in out) == ["b.txt", "poc.txt"]


@pytest.mark.parametrize("bad", ["../evil.txt", "/abs.txt", "a/../../evil.txt", "C:/x.txt"])
def test_zip_traversal_is_rejected(tmp_path: Path, bad: str) -> None:
    archive = _zip(tmp_path, [(bad, "x")])
    with pytest.raises(ArchiveRejectedError):
        safe_extract_archive(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "evil.txt").exists()


def test_zip_bomb_ratio_is_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [("zeros", b"\0" * 5_000_000)])
    with pytest.raises(ArchiveRejectedError):
        safe_extract_archive(archive, tmp_path / "out", ArchiveLimits(max_ratio=10))


def test_zip_file_count_is_limited(tmp_path: Path) -> None:
    archive = _zip(tmp_path, [(f"f{i}", "x") for i in range(5)])
    with pytest.raises(ArchiveRejectedError):
        safe_extract_archive(archive, tmp_path / "out", ArchiveLimits(max_files=3))


def test_zip_symlink_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "l.zip"
    info = zipfile.ZipInfo("link")
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(info, "/etc/passwd")
    with pytest.raises(ArchiveRejectedError):
        safe_extract_archive(path, tmp_path / "out")


def _symlink_member() -> tarfile.TarInfo:
    info = tarfile.TarInfo("link")
    info.type = tarfile.SYMTYPE
    info.linkname = "/etc"
    return info


def test_tar_symlink_and_traversal_are_rejected(tmp_path: Path) -> None:
    for member in (tarfile.TarInfo("../escape"), _symlink_member()):
        path = tmp_path / "t.tar"
        with tarfile.open(path, "w") as tf:
            tf.addfile(member, io.BytesIO(b"") if member.isfile() else None)
        with pytest.raises(ArchiveRejectedError):
            safe_extract_archive(path, tmp_path / "out")


def test_tar_ok(tmp_path: Path) -> None:
    path = tmp_path / "ok.tar.gz"
    data = b"payload"
    info = tarfile.TarInfo("poc.bin")
    info.size = len(data)
    with tarfile.open(path, "w:gz") as tf:
        tf.addfile(info, io.BytesIO(data))
    (out,) = safe_extract_archive(path, tmp_path / "out")
    assert out.read_bytes() == data


def test_not_an_archive(tmp_path: Path) -> None:
    path = tmp_path / "x.bin"
    path.write_bytes(b"not an archive")
    with pytest.raises(ArchiveRejectedError):
        safe_extract_archive(path, tmp_path / "out")
