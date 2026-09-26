# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The committed manifests: S3/S4 exclusions are recorded, and S6 has a repro subset."""

from __future__ import annotations

from pathlib import Path

import pytest

from nikasha.bench.manifests import MANIFEST_DIR, Manifest, load_manifests
from nikasha.bench.runner import collect_cases

ROOT = Path(__file__).resolve().parents[3]


def _by_source() -> dict[str, Manifest]:
    return {m.source: m for m in load_manifests(ROOT / MANIFEST_DIR)}


def test_s3_records_every_blanked_rejected_cve_as_an_exclusion() -> None:
    s3 = _by_source()["S3"]
    assert s3.entries == ()
    ids = {x.id for x in s3.excluded}
    assert ids == {f"cve-2026-{n}" for n in (51296, 51297, 51300, 51302, 51303, 51304)}
    assert all("REJECTED" in x.reason for x in s3.excluded)


def test_s4_is_empty_because_the_dataset_has_no_license() -> None:
    s4 = _by_source()["S4"]
    assert s4.entries == ()
    assert s4.terms_checked is False


def test_s6_repro_subset_is_non_empty_and_points_at_real_files() -> None:
    s6 = _by_source()["S6"]
    cases, skipped = collect_cases((s6,), ROOT)
    assert skipped == ()
    subset = {c.id: c for c in cases if c.poc is not None}
    assert set(subset) == {"vulnlab-genuine", "vulnlab-already-fixed"}
    for case in subset.values():
        assert case.recipe == "vulnlab"
        assert case.poc is not None and case.poc.is_file()
    assert subset["vulnlab-genuine"].version == "v1.2.0"
    assert subset["vulnlab-already-fixed"].version == "v1.3.0"


def test_exclusion_ids_may_not_repeat_entry_ids() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        Manifest.model_validate(
            {
                "source": "S3",
                "title": "t",
                "entries": [{"id": "a", "label": "fabricated", "path": "r.md"}],
                "excluded": [{"id": "a", "reason": "r"}],
            }
        )


def test_exclusion_reason_is_one_line() -> None:
    with pytest.raises(ValueError, match="one non-empty line"):
        Manifest.model_validate(
            {"source": "S3", "title": "t", "excluded": [{"id": "a", "reason": "x\ny"}]}
        )
