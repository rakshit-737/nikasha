# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Attachment handling (SPEC §8, §19.2). Attachments are attacker-controlled.

* Filenames are reduced to a sanitized basename (``[A-Za-z0-9._-]``, ≤100 chars, no
  leading dots, de-duplicated), so nothing can escape the per-run directory.
* Files are stored in a per-run directory (0700) with mode 0600, under size caps.
* Archives are **not** extracted unless the caller opts in; safe extraction rejects absolute
  paths, ``..``, links and special files, and enforces file-count, size and ratio limits,
  counting real bytes rather than trusting declared sizes.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
import shutil
import tarfile
import zipfile
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, cast

from nikasha.errors import NikashaError
from nikasha.model.report import Attachment

MAX_NAME_LEN = 100
MAX_EXT_LEN = 10
_UNSAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")
_COPY_CHUNK = 64 * 1024


class ArchiveRejectedError(NikashaError):
    """An archive violated a safety rule; nothing from it was kept."""


@dataclass(frozen=True, slots=True)
class AttachmentLimits:
    per_file_bytes: int = 10 * 1024 * 1024
    total_bytes: int = 50 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_files: int = 1000
    max_ratio: float = 100.0
    max_total_bytes: int = 200 * 1024 * 1024


def sanitize_name(name: str, taken: set[str] | None = None) -> str:
    """Return a safe, unique basename for ``name`` (``taken`` is updated in place)."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE_CHARS_RE.sub("_", base).lstrip(".")
    if not base or set(base) <= {"_", "."}:
        base = "attachment"
    if len(base) > MAX_NAME_LEN:
        stem, dot, ext = base.rpartition(".")
        if dot and 0 < len(ext) <= MAX_EXT_LEN and stem:
            base = stem[: MAX_NAME_LEN - len(ext) - 1] + "." + ext
        else:
            base = base[:MAX_NAME_LEN]
    if taken is None:
        return base
    candidate, n = base, 1
    while candidate in taken:
        stem, dot, ext = base.rpartition(".")
        suffix = f"-{n}"
        if dot and stem:
            candidate = f"{stem[: MAX_NAME_LEN - len(ext) - 1 - len(suffix)]}{suffix}.{ext}"
        else:
            candidate = f"{base[: MAX_NAME_LEN - len(suffix)]}{suffix}"
        n += 1
    taken.add(candidate)
    return candidate


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def store_attachments(
    items: Sequence[tuple[str, bytes]],
    run_dir: Path,
    limits: AttachmentLimits = AttachmentLimits(),  # noqa: B008  (immutable dataclass)
) -> tuple[tuple[Attachment, ...], tuple[str, ...]]:
    """Store ``(original_name, content)`` pairs under ``run_dir``.

    Returns the stored attachments (in input order) and warnings for skipped ones.
    """
    run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        run_dir.chmod(0o700)
    taken: set[str] = set()
    stored: list[Attachment] = []
    warnings: list[str] = []
    total = 0
    for original_name, content in items:
        name = sanitize_name(original_name, taken)
        size = len(content)
        if size > limits.per_file_bytes:
            warnings.append(f"attachment {name} skipped: {size:,} bytes exceeds the per-file cap")
            continue
        if total + size > limits.total_bytes:
            warnings.append(f"attachment {name} skipped: total attachment cap reached")
            continue
        total += size
        target = run_dir / name
        _write_private(target, content)
        media_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
        stored.append(
            Attachment(
                name_sanitized=name,
                sha256=hashlib.sha256(content).hexdigest(),
                size=size,
                media_type=media_type,
                stored_path=str(target),
            )
        )
    return tuple(stored), tuple(warnings)


# --- opt-in archive extraction --------------------------------------------------------


def _safe_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or ".." in path.parts
    ):
        raise ArchiveRejectedError(f"unsafe path in archive: {name!r}")
    return path


@dataclass(frozen=True, slots=True)
class _Member:
    path: PurePosixPath
    is_dir: bool
    opener: object  # zipfile.ZipInfo | tarfile.TarInfo


def _zip_members(zf: zipfile.ZipFile) -> Iterator[_Member]:
    for info in zf.infolist():
        mode = (info.external_attr >> 16) & 0o170000
        if mode and mode not in (0o100000, 0o040000):  # regular file or directory only
            raise ArchiveRejectedError(f"link or special file in archive: {info.filename!r}")
        yield _Member(_safe_member_path(info.filename), info.is_dir(), info)


def _tar_members(tf: tarfile.TarFile) -> Iterator[_Member]:
    for info in tf:
        if not (info.isfile() or info.isdir()):
            raise ArchiveRejectedError(f"link or special file in archive: {info.name!r}")
        yield _Member(_safe_member_path(info.name), info.isdir(), info)


def _copy_limited(src: IO[bytes], dst: IO[bytes], budget: int) -> int:
    written = 0
    while chunk := src.read(_COPY_CHUNK):
        written += len(chunk)
        if written > budget:
            raise ArchiveRejectedError("archive expands beyond the size limit")
        dst.write(chunk)
    return written


def safe_extract_archive(
    archive: Path,
    dest: Path,
    limits: ArchiveLimits = ArchiveLimits(),  # noqa: B008  (immutable dataclass)
) -> tuple[Path, ...]:
    """Extract a zip or tar archive into ``dest`` under the §8 rules.

    On any violation the partially extracted content is removed and
    :class:`ArchiveRejectedError` is raised.
    """
    archive_size = max(archive.stat().st_size, 1)
    budget = min(limits.max_total_bytes, int(archive_size * limits.max_ratio))
    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
    extracted: list[Path] = []
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as zf:
                members = list(_zip_members(zf))
                _check_count(members, limits)

                def open_zip(o: object) -> IO[bytes]:
                    return zf.open(cast(zipfile.ZipInfo, o))

                for m in members:
                    budget -= _extract_one(m, dest, extracted, budget, open_zip)
        elif tarfile.is_tarfile(archive):
            with tarfile.open(archive) as tf:
                members = list(_tar_members(tf))
                _check_count(members, limits)

                def open_tar(o: object) -> IO[bytes]:
                    fh = tf.extractfile(cast(tarfile.TarInfo, o))
                    if fh is None:
                        raise ArchiveRejectedError("unreadable archive member")
                    return fh

                for m in members:
                    budget -= _extract_one(m, dest, extracted, budget, open_tar)
        else:
            raise ArchiveRejectedError("not a zip or tar archive")
    except ArchiveRejectedError:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise ArchiveRejectedError(f"corrupt archive: {exc}") from exc
    return tuple(extracted)


def _check_count(members: list[_Member], limits: ArchiveLimits) -> None:
    files = sum(1 for m in members if not m.is_dir)
    if files > limits.max_files:
        raise ArchiveRejectedError(f"archive has {files} files (limit {limits.max_files})")


def _extract_one(
    member: _Member,
    dest: Path,
    extracted: list[Path],
    budget: int,
    open_member: Callable[[object], IO[bytes]],
) -> int:
    target = dest.joinpath(*member.path.parts)
    if member.is_dir:
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        return 0
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    with (
        open_member(member.opener) as src,
        os.fdopen(os.open(target, flags, 0o600), "wb") as dst,
    ):
        written = _copy_limited(src, dst, budget)
    extracted.append(target)
    return written
