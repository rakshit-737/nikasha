# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared base class for every Nikasha data model (SPEC §7)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Model(BaseModel):
    """Immutable, strict pydantic model.

    ``frozen`` makes instances hashable and safe to share between pipeline stages;
    ``extra="forbid"`` turns typos and schema drift into validation errors.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")
