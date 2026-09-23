# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Report intake (SPEC §8): turn a file or stdin into a normalized :class:`Report`."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Literal

from nikasha.errors import NikashaError
from nikasha.ingest.html import ingest_html
from nikasha.ingest.markdown import ingest_markdown
from nikasha.ingest.text import MAX_BODY_CHARS, ingest_text
from nikasha.model.report import Report

InputFormat = Literal["auto", "text", "markdown", "html"]

#: Raw input larger than this is refused before decoding (bytes); the body cap applies after.
MAX_INPUT_BYTES = 20 * 1024 * 1024

_EXTENSIONS: dict[str, InputFormat] = {
    ".md": "markdown",
    ".markdown": "markdown",
    ".mdown": "markdown",
    ".txt": "text",
    ".text": "text",
    ".log": "text",
    ".html": "html",
    ".htm": "html",
}
_HTML_SNIFF_RE = re.compile(r"\A\s*(?:<!doctype html|<html\b|<body\b|<p\b|<div\b|<pre\b)", re.I)
_MD_SNIFF_RE = re.compile(r"^(?:#{1,6} \S|```|~~~)", re.MULTILINE)


class UnsupportedInputError(NikashaError):
    """The input format is not supported (yet)."""


def detect_format(text: str, name: str | None = None) -> Literal["text", "markdown", "html"]:
    """Pick an ingester from the file extension, falling back to content sniffing."""
    if name:
        suffix = Path(name).suffix.lower()
        if suffix in _EXTENSIONS:
            fmt = _EXTENSIONS[suffix]
            if fmt != "auto":
                return fmt
        if suffix in (".eml", ".mbox"):
            raise UnsupportedInputError("email intake arrives in milestone M7")
    head = text[:4096]
    if _HTML_SNIFF_RE.match(head):
        return "html"
    if _MD_SNIFF_RE.search(head) or "`" in head:
        return "markdown"
    return "text"


def decode(data: bytes) -> str:
    """Decode input as UTF-8 (with or without BOM); undecodable bytes become U+FFFD."""
    if len(data) > MAX_INPUT_BYTES:
        raise NikashaError(f"input is {len(data):,} bytes; the limit is {MAX_INPUT_BYTES:,} bytes")
    return data.decode("utf-8-sig", errors="replace")


def ingest_string(
    text: str,
    *,
    input_format: InputFormat = "auto",
    uri: str | None = None,
    max_chars: int = MAX_BODY_CHARS,
) -> Report:
    fmt = detect_format(text, uri) if input_format == "auto" else input_format
    if fmt == "markdown":
        return ingest_markdown(text, uri=uri, max_chars=max_chars)
    if fmt == "html":
        return ingest_html(text, uri=uri, max_chars=max_chars)
    return ingest_text(text, uri=uri, max_chars=max_chars)


def load_report(
    source: str | Path,
    *,
    input_format: InputFormat = "auto",
    max_chars: int = MAX_BODY_CHARS,
) -> Report:
    """Load a report from a path, or from stdin when ``source`` is ``"-"``.

    The URI recorded in the result is the path exactly as given (never resolved), so
    results do not depend on the machine they were produced on.
    """
    if str(source) == "-":
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        return ingest_string(decode(data), input_format=input_format, uri=None, max_chars=max_chars)
    path = Path(source)
    try:
        size = path.stat().st_size
        if size > MAX_INPUT_BYTES:
            raise NikashaError(f"{source} is {size:,} bytes; the limit is {MAX_INPUT_BYTES:,}")
        data = path.read_bytes()
    except OSError as exc:
        raise NikashaError(f"cannot read {source}: {exc.strerror or exc}") from exc
    return ingest_string(
        decode(data), input_format=input_format, uri=str(source), max_chars=max_chars
    )


__all__ = ["InputFormat", "UnsupportedInputError", "detect_format", "ingest_string", "load_report"]
