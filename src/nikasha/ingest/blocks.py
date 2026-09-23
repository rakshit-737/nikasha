# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Code-block role classification (SPEC §9.1).

The fence info string decides first when it is unambiguous (``diff`` → patch,
``console`` → poc). Otherwise content signatures decide: sanitizer or traceback headers
→ trace; unified-diff markers → patch; shebangs, ``int main(``, shell prompts, ``curl``
commands, raw HTTP requests, or a "PoC"/"reproduce" heading → poc; log-ish info strings →
log; anything else → snippet. All patterns are anchored and linear-time.
"""

from __future__ import annotations

import re

from nikasha.model.report import CodeBlockRole

_PATCH_INFOS = frozenset({"diff", "patch", "udiff"})
_POC_INFOS = frozenset(
    {"console", "shell-session", "sh", "bash", "zsh", "shell", "ps1", "powershell", "cmd", "http"}
)
_LOG_INFOS = frozenset({"log", "output", "stderr", "stdout", "txt", "text", "plaintext", "plain"})

_TRACE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^==\d+==\s*(?:ERROR|WARNING): \w*Sanitizer", re.MULTILINE),
    re.compile(r"^(?:WARNING|ERROR): (?:ThreadSanitizer|LeakSanitizer|MemorySanitizer)", re.M),
    re.compile(r"^[^\n:]{1,300}:\d+:\d+: runtime error: ", re.MULTILINE),
    re.compile(r"^Traceback \(most recent call last\):", re.MULTILINE),
    re.compile(r"^==\d+== (?:Invalid (?:read|write)|Conditional jump|Use of uninitialised)", re.M),
    re.compile(
        r"^(?:Exception in thread \"[^\"\n]{0,200}\" )?[\w$.]{1,200}(?:Exception|Error)\b", re.M
    ),
    re.compile(r"^panic: ", re.MULTILINE),
    re.compile(r"^goroutine \d+ \[", re.MULTILINE),
    re.compile(r"^thread '[^'\n]{0,200}' panicked at ", re.MULTILINE),
    re.compile(r"^Program (?:received|terminated with) signal ", re.MULTILINE),
    re.compile(r"^#\d{1,4} {1,3}0x[0-9a-fA-F]{1,16} in \S", re.MULTILINE),
    re.compile(r"^\s{2,8}at \S[^\n]{0,300}:\d+:\d+\)?$", re.MULTILINE),
)
# The indent is *horizontal* whitespace only, and bounded. With `\s+` under re.MULTILINE
# the newline class and the per-line `^` anchor combine into a quadratic scan: every line
# start re-consumes the rest of the run before failing on "at " (16k newlines took 0.43 s).
_JAVA_FRAME_RE = re.compile(
    r"^[^\S\r\n]{1,16}at [\w$.<>]{1,300}\([\w$.]{0,200}(?::\d+)?\)", re.MULTILINE
)

_PATCH_GIT_RE = re.compile(r"^diff --git ", re.MULTILINE)
_PATCH_MINUS_RE = re.compile(r"^--- \S", re.MULTILINE)
_PATCH_PLUS_RE = re.compile(r"^\+\+\+ \S", re.MULTILINE)
_PATCH_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.MULTILINE)

_POC_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\A#!"),
    re.compile(r"\bint\s+main\s*\("),
    re.compile(r"^\$ \S", re.MULTILINE),
    re.compile(r"^curl\s", re.MULTILINE),
    re.compile(r"^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) \S{1,2000} HTTP/\d", re.MULTILINE),
    re.compile(r"\bif __name__ == ['\"]__main__['\"]"),
)
_POC_HEADING_RE = re.compile(
    r"\b(?:poc|proof[ -]of[ -]concept|reproduc\w*|steps to reproduce|exploit)\b", re.IGNORECASE
)


def looks_like_trace(content: str) -> bool:
    return any(p.search(content) for p in _TRACE_RES) or bool(_JAVA_FRAME_RE.search(content))


def looks_like_patch(content: str) -> bool:
    if _PATCH_GIT_RE.search(content):
        return True
    return bool(
        _PATCH_MINUS_RE.search(content)
        and _PATCH_PLUS_RE.search(content)
        and _PATCH_HUNK_RE.search(content)
    )


def looks_like_poc(content: str, heading: str | None) -> bool:
    if any(p.search(content) for p in _POC_RES):
        return True
    return bool(heading and _POC_HEADING_RE.search(heading))


def guess_role(content: str, lang_hint: str | None, heading: str | None = None) -> CodeBlockRole:
    """Classify a code block as trace, patch, poc, snippet or log."""
    info = (lang_hint or "").strip().lower()
    decisions: tuple[tuple[bool, CodeBlockRole], ...] = (
        (info in _PATCH_INFOS, "patch"),
        (info in _POC_INFOS, "poc"),
    )
    for matched, role in decisions:
        if matched:
            return role
    if looks_like_trace(content):
        return "trace"
    if looks_like_patch(content):
        return "patch"
    if looks_like_poc(content, heading):
        return "poc"
    return "log" if info in _LOG_INFOS else "snippet"
