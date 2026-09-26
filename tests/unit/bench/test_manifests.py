# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Bench manifests hold IDs, URLs and labels only, and the committed ones load."""

from __future__ import annotations

from pathlib import Path

import pytest

from nikasha.bench.manifests import ManifestError, for_split, load_manifest, load_manifests

ROOT = Path(__file__).resolve().parents[3]
MANIFESTS = ROOT / "bench" / "manifests"


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "m.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_committed_manifests_load_and_split() -> None:
    manifests = load_manifests(MANIFESTS)
    assert [m.source for m in manifests] == ["S1", "S2", "S3", "S5", "S6"]
    assert [m.source for m in for_split(manifests, "synthetic")] == ["S5", "S6"]
    assert [m.source for m in for_split(manifests, "real")] == ["S1", "S2", "S3"]
    assert len(for_split(manifests, "all")) == 5


def test_real_sources_hold_only_hackerone_ids_after_terms_check() -> None:
    # ADR 0011: S1/S2 carry the slopcheck curl index (IDs, URLs, labels); S3/S4 stay empty.
    counts = {}
    for manifest in for_split(load_manifests(MANIFESTS), "real"):
        counts[manifest.source] = len(manifest.entries)
        for entry in manifest.entries:
            assert manifest.terms_checked is True
            assert entry.path is None
            assert entry.url == "https://hackerone.com/reports/" + entry.id.removeprefix("h1-")
    assert counts == {"S1": 49, "S2": 126, "S3": 0}
    s1 = next(m for m in load_manifests(MANIFESTS) if m.source == "S1")
    assert {e.label for e in s1.entries} == {"fabricated"}


def test_s6_labels_point_at_existing_fixtures() -> None:
    s6 = next(m for m in load_manifests(MANIFESTS) if m.source == "S6")
    expected = {e.id: (e.label, e.expected) for e in s6.entries}
    assert expected == {
        "vulnlab-genuine": ("genuine", "GROUNDED"),
        "vulnlab-mixed-wrong-version": ("genuine", "MIXED"),
        "vulnlab-already-fixed": ("genuine", "MIXED"),
        "vulnlab-fabricated": ("fabricated", "UNGROUNDED"),
        "vulnlab-vague": ("insufficient", "INSUFFICIENT"),
    }
    for entry in s6.entries:
        assert entry.path is not None
        assert (ROOT / entry.path).is_file()


def test_report_text_is_refused(tmp_path: Path) -> None:
    body = (
        "source: S6\ntitle: t\nentries:\n"
        "  - {id: a, path: x.md, label: genuine, text: 'the report body'}\n"
    )
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, body))


@pytest.mark.parametrize("path", ["../secret.md", "/etc/passwd", "C:/x.md", "a\\b.md"])
def test_paths_must_stay_in_the_repository(tmp_path: Path, path: str) -> None:
    body = f"source: S6\ntitle: t\nentries:\n  - {{id: a, path: '{path}', label: genuine}}\n"
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, body))


def test_remote_entries_need_the_terms_check(tmp_path: Path) -> None:
    entry = "  - {id: a, url: 'https://hackerone.com/reports/1', label: fabricated}\n"
    with pytest.raises(ManifestError, match="terms_checked"):
        load_manifest(_write(tmp_path, "source: S1\ntitle: t\nentries:\n" + entry))
    ok = load_manifest(
        _write(tmp_path, "source: S1\ntitle: t\nterms_checked: true\nentries:\n" + entry)
    )
    assert ok.entries[0].url == "https://hackerone.com/reports/1"


@pytest.mark.parametrize(
    "entry",
    [
        "{id: a, url: 'http://example.com/x', label: genuine}",
        "{id: a, label: genuine}",
        "{id: a, path: x.md, url: 'https://e.com/x', label: genuine}",
        "{id: 'Bad Id', path: x.md, label: genuine}",
        "{id: a, path: x.md, label: plausible}",
    ],
)
def test_malformed_entries_are_rejected(tmp_path: Path, entry: str) -> None:
    body = f"source: S1\ntitle: t\nterms_checked: true\nentries:\n  - {entry}\n"
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, body))


def test_duplicate_ids_and_unknown_sources_are_rejected(tmp_path: Path) -> None:
    dup = "  - {id: a, path: x.md, label: genuine}\n"
    with pytest.raises(ManifestError, match="duplicate"):
        load_manifest(_write(tmp_path, "source: S6\ntitle: t\nentries:\n" + dup + dup))
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, "source: S9\ntitle: t\n"))


def test_unknown_split_and_mutation_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        for_split((), "everything")
    body = "source: S5\ntitle: t\ngenerator: {bases: [a], mutations: [M8], seeds: [0]}\n"
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, body))


@pytest.mark.parametrize("path", ["", ".", "   "])
def test_empty_paths_are_refused(path: str) -> None:
    from nikasha.bench.manifests import Entry  # noqa: PLC0415

    with pytest.raises(ValueError, match="path"):
        Entry(id="x", label="genuine", path=path)


@pytest.mark.parametrize("notes", ["a" * 201, "line one\nline two"])
def test_notes_are_short_single_lines(notes: str) -> None:
    from nikasha.bench.manifests import Entry  # noqa: PLC0415

    with pytest.raises(ValueError, match="notes"):
        Entry(id="x", label="genuine", path="a.md", notes=notes)
