# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""One module per view of the HTML report (SPEC §15.2).

Each module exposes ``ORDER: int`` and ``render(ctx) -> Fragment | None``. They are
discovered, not registered, so adding a view is adding a file.
"""

from __future__ import annotations
