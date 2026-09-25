# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""NikashaBench (SPEC §17): manifests, synthetic mutations, runner, metrics and calibration.

Manifests hold IDs, URLs and labels only, never report text. The only report text the
bench ever touches offline is the project's own fictional vulnlab fixtures and the
mutations generated from them in memory.
"""

from __future__ import annotations
