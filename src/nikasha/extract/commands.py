# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Command lines in PoC blocks and inline code (a helper for PoC and option extraction).

A command's *program* decides who an option belongs to: ``hdrcat --fold`` is a claim about
the project's CLI, ``gcc --version`` is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from nikasha.extract.registry import ExtractContext
from nikasha.extract.spans import inline_code_spans
from nikasha.model.report import CodeBlock, Span

_PROMPT_RE = re.compile(r"^[ \t]{0,8}(?:\$|%|>|PS[^>\n]{0,40}>)[ \t]{1,3}(?P<cmd>\S.*)$")
_SHELL_LANGS = frozenset(
    {"sh", "bash", "zsh", "shell", "console", "shell-session", "ps1", "powershell", "cmd"}
)

#: Programs that are never the project under test (their options are third-party).
EXTERNAL_TOOLS = frozenset(
    """
    gcc g++ cc c++ clang clang++ ld lld make cmake ninja meson ./configure configure autoreconf
    python python3 pip pip3 uv node npm npx yarn pnpm deno cargo rustc go java javac mvn gradle
    git gdb lldb valgrind strace ltrace sudo env bash sh zsh docker podman kubectl echo printf cat
    head tail grep sed awk xxd od base64 perl ruby php chmod chown mkdir cd ls rm cp mv touch
    export time timeout ulimit afl-fuzz honggfuzz
    """.split()
)


@dataclass(frozen=True, slots=True)
class Command:
    span: Span
    text: str
    program: str


def _program(cmd: str) -> str:
    tokens = cmd.split()
    while tokens and ("=" in tokens[0] and not tokens[0].startswith("-")):
        tokens.pop(0)  # leading VAR=value assignments
    if tokens and tokens[0] in ("sudo", "env", "time", "timeout"):
        tokens.pop(0)
        while tokens and (tokens[0].startswith("-") or tokens[0].isdigit() or "=" in tokens[0]):
            tokens.pop(0)
    return tokens[0].rsplit("/", 1)[-1] if tokens else ""


def block_commands(ctx: ExtractContext, block: CodeBlock) -> list[Command]:
    """Command lines in a PoC or log block: prompt lines, or every line of a shell block."""
    body = ctx.report.body
    lang = (block.lang_hint or "").lower()
    out: list[Command] = []
    pos = block.span.start
    while pos < block.span.end:
        nl = body.find("\n", pos, block.span.end)
        end = nl if nl >= 0 else block.span.end
        line = body[pos:end]
        m = _PROMPT_RE.match(line)
        if m:
            start = pos + m.start("cmd")
            out.append(
                Command(ctx.report.span(start, end), m.group("cmd"), _program(m.group("cmd")))
            )
        elif lang in _SHELL_LANGS and line.strip() and not line.lstrip().startswith("#"):
            start = pos + (len(line) - len(line.lstrip()))
            out.append(Command(ctx.report.span(start, end), line.strip(), _program(line)))
        pos = end + 1
    return out


def inline_commands(ctx: ExtractContext) -> list[Command]:
    """Inline code spans that look like commands (contain an option or start with a program)."""
    out: list[Command] = []
    for code in inline_code_spans(ctx.report, ctx.prose):
        text = code.text.strip()
        if " -" in f" {text}" and len(text.split()) >= 1:
            out.append(Command(code.span, text, _program(text)))
    return out
