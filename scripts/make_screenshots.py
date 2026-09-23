#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Regenerate every image in the README and the docs (SPEC §21.5).

**Never hand-edit a screenshot, and never put a mock-up in the README.** Every image here
comes from a real command run against the real vulnlab history, which is the whole point:
a tool whose pitch is "proof, not prose" cannot illustrate itself with a drawing.

Two kinds of output:

* **Terminal SVGs** from `rich`'s own recorder, in a light and a dark variant. These need
  nothing but the project itself, so they always regenerate.
* **HTML report PNGs** via Playwright (Chromium, light and dark, full page). Playwright
  needs a browser binary it downloads over the network, so this step *skips with a clear
  message* when it is unavailable, and `.github/workflows/screenshots.yml` is the source
  of truth (SPEC §21.5).

Usage:
    python scripts/make_screenshots.py            # everything available
    python scripts/make_screenshots.py --terminal # SVGs only
    python scripts/make_screenshots.py --list     # what would be produced
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
REPORTS = ROOT / "examples" / "reports"

#: Themes to record, as (suffix, NIKASHA_RECORD_SVG_THEME value).
THEMES = (("light", "light"), ("dark", "dark"))


@dataclass(frozen=True, slots=True)
class Shot:
    """One terminal capture: a name, and the CLI arguments that produce it."""

    name: str
    args: tuple[str, ...]


def shots(repo: Path) -> tuple[Shot, ...]:
    """The commands the README shows. Each one is a command a reader can run."""
    return (
        Shot(
            "check-ungrounded",
            ("check", str(REPORTS / "fabricated_hdr_overflow.md"), "--repo", str(repo)),
        ),
        Shot(
            "check-grounded",
            ("check", str(REPORTS / "genuine_hdr_overflow.md"), "--repo", str(repo)),
        ),
        Shot(
            "check-mixed",
            ("check", str(REPORTS / "mixed_wrong_version.md"), "--repo", str(repo)),
        ),
        Shot(
            "explain",
            (
                "check",
                str(REPORTS / "fabricated_hdr_overflow.md"),
                "--repo",
                str(repo),
                "--explain",
            ),
        ),
        Shot("extract", ("extract", str(REPORTS / "fabricated_hdr_overflow.md"))),
    )


def build_vulnlab(dest: Path) -> Path:
    """Build the deterministic demo repository the screenshots are taken against."""
    if (dest / "HEAD").exists():
        return dest
    spec = importlib.util.spec_from_file_location("bv", ROOT / "scripts" / "build_vulnlab.py")
    if spec is None or spec.loader is None:  # pragma: no cover - the script is in-tree
        raise RuntimeError("cannot load scripts/build_vulnlab.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.build_vulnlab(dest)
    return dest


#: An SVG of a real terminal contains whatever the terminal showed. When that is a report
#: fixture carrying its own SPDX header, `reuse lint` parses the tag out of the *image* and
#: fails. Wrapping the body in REUSE's own ignore markers is the documented fix, and unlike
#: editing the SVG it does not change a single pixel of what the screenshot shows.
_REUSE_HEADER = """<!--
SPDX-FileCopyrightText: 2026 The Nikasha Authors
SPDX-License-Identifier: CC-BY-4.0
-->
<!-- REUSE-IgnoreStart -->
"""
_REUSE_FOOTER = chr(10) + "<!-- REUSE-IgnoreEnd -->" + chr(10)


def seal(path: Path) -> None:
    """Give a generated SVG its own licence header and fence off the terminal content."""
    body = path.read_text(encoding="utf-8")
    if body.startswith("<!--"):
        return
    path.write_text(_REUSE_HEADER + body.rstrip() + _REUSE_FOOTER, encoding="utf-8")


def record_terminal(repo: Path) -> list[Path]:
    """Run each command for real, with rich recording to SVG."""
    written: list[Path] = []
    for shot in shots(repo):
        for suffix, theme in THEMES:
            out = ASSETS / f"terminal-{shot.name}-{suffix}.svg"
            env = {
                **os.environ,
                "NIKASHA_RECORD_SVG": str(out),
                "NIKASHA_RECORD_SVG_THEME": theme,
                "PYTHONIOENCODING": "utf-8",
                "COLUMNS": "100",
            }
            # The CLI exits non-zero by design (10 MIXED, 20 UNGROUNDED, ...), so the exit
            # code is not an error here; a missing file would be.
            subprocess.run(
                [sys.executable, "-m", "nikasha", *shot.args],
                cwd=ROOT,
                env=env,
                check=False,
                capture_output=True,
            )
            if out.exists():
                seal(out)
                written.append(out)
            else:
                print(f"  ! {out.name} was not written", file=sys.stderr)
    return written


def render_reports(repo: Path) -> list[Path]:
    """Write the HTML reports the PNG step screenshots (and that CI publishes)."""
    from nikasha.config import cache_dir  # noqa: PLC0415
    from nikasha.pipeline import check_report  # noqa: PLC0415
    from nikasha.render.html import render_html  # noqa: PLC0415
    from nikasha.render.html.excerpts import repo_excerpts  # noqa: PLC0415

    out_dir = cache_dir() / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in ("fabricated_hdr_overflow", "genuine_hdr_overflow", "mixed_wrong_version"):
        checked = check_report(REPORTS / f"{name}.md", repo=str(repo))
        with repo_excerpts(str(repo)) as excerpts:
            html = render_html(checked, excerpts=excerpts, source=f"examples/reports/{name}.md")
        path = out_dir / f"{name}.html"
        path.write_text(html, encoding="utf-8")
        written.append(path)
    return written


def capture_pngs(pages: list[Path]) -> list[Path]:
    """Screenshot each HTML report with Playwright, in light and dark."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except ImportError:
        print(
            "  - skipping PNGs: playwright is not installed.\n"
            "    Install it with `uv add --group dev playwright` and "
            "`uv run playwright install chromium` (both need network),\n"
            "    or let .github/workflows/screenshots.yml regenerate them (SPEC §21.5).",
            file=sys.stderr,
        )
        return []
    written: list[Path] = []
    with sync_playwright() as play:
        try:
            browser = play.chromium.launch()
        except Exception as exc:  # the browser binary is downloaded separately
            print(f"  - skipping PNGs: chromium is unavailable ({exc})", file=sys.stderr)
            return []
        for page_path in pages:
            for scheme in ("light", "dark"):
                page = browser.new_page(
                    viewport={"width": 1440, "height": 900}, color_scheme=scheme
                )
                page.goto(page_path.as_uri())
                out = ASSETS / f"report-{page_path.stem}-{scheme}.png"
                page.screenshot(path=str(out), full_page=True)
                page.close()
                written.append(out)
        browser.close()
    optimize(written)
    return written


def optimize(pngs: list[Path]) -> None:
    """Shrink the PNGs with oxipng when it is installed."""
    if not pngs or shutil.which("oxipng") is None:
        return
    subprocess.run(
        ["oxipng", "-o", "4", "--strip", "safe", *[str(p) for p in pngs]],
        check=False,
        capture_output=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal", action="store_true", help="Only the terminal SVGs.")
    parser.add_argument("--list", action="store_true", help="List the outputs and exit.")
    args = parser.parse_args()

    ASSETS.mkdir(parents=True, exist_ok=True)
    if args.list:
        for shot in shots(Path("REPO")):
            for suffix, _ in THEMES:
                print(f"docs/assets/terminal-{shot.name}-{suffix}.svg")
        print("docs/assets/report-*.png (needs playwright)")
        return 0

    if shutil.which("git") is None:
        print("error: git is required to build the demo repository", file=sys.stderr)
        return 1

    from nikasha.config import cache_dir  # noqa: PLC0415

    repo = build_vulnlab(cache_dir() / "screenshots" / "vulnlab.git")
    print(f"vulnlab: {repo}")

    print("terminal SVGs:")
    for path in record_terminal(repo):
        print(f"  + {path.relative_to(ROOT)}")

    if args.terminal:
        return 0

    print("HTML reports:")
    pages = render_reports(repo)
    for path in pages:
        print(f"  + {path}")

    print("report PNGs:")
    for path in capture_pngs(pages):
        print(f"  + {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
