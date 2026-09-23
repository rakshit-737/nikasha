# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Stable, content-derived identifiers (SPEC §7).

An ID is ``sha256(kind + canonical fields)[:12]``: the same content always gets the same ID,
on every machine and every run, which is what makes results byte-identical.
"""

from __future__ import annotations

import hashlib
import json

ID_LENGTH = 12


def canonical_json(value: object) -> str:
    """Serialize ``value`` deterministically (sorted keys, no whitespace, UTF-8 kept)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def stable_id(kind: str, payload: object) -> str:
    """Return the 12-hex-digit ID for an object of ``kind`` with canonical ``payload``."""
    digest = hashlib.sha256()
    digest.update(kind.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()[:ID_LENGTH]
