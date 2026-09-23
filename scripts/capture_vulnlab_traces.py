# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Re-capture the vulnlab traces (ASan, valgrind, gdb) named in SPEC §20.2.

A thin wrapper for ``capture_trace_fixtures.py --only vulnlab``; see that script for the
sandbox it runs in. The genuine and mixed fixture reports in ``examples/reports/`` embed
``tests/fixtures/traces/asan/01-vulnlab-heap-overflow-v1.2.0.txt`` verbatim.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--only", "vulnlab", *sys.argv[1:]]
    runpy.run_path(str(Path(__file__).with_name("capture_trace_fixtures.py")), run_name="__main__")
