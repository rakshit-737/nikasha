# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Proof-of-concept claims (SPEC §9.6). PoCs are *hostile code*: they are recorded here and
only ever run inside the sandbox (M5, P5). Every PoC claim is a reporter artifact."""

from __future__ import annotations

import re

from nikasha.extract.commands import block_commands
from nikasha.extract.registry import ExtractContext, make_claim, register
from nikasha.model.claims import PocClaim, PocKind
from nikasha.model.report import CodeBlock

NAME = "pocs"

_C_LANGS = frozenset({"c", "cpp", "c++", "cc", "cxx", "objc"})
_PY_LANGS = frozenset({"python", "py", "python3"})
_SHELL_LANGS = frozenset(
    {"sh", "bash", "zsh", "shell", "console", "shell-session", "ps1", "powershell"}
)
_POC_NAME_RE = re.compile(
    r"^(?:poc|exploit|crash|repro|reproducer|testcase|trigger|payload|input|fuzz)[\w.-]{0,80}$"
    r"|\.(?:poc|crash|bin|raw|fuzz)$",
    re.IGNORECASE,
)


def infer_kind(block: CodeBlock, n_commands: int) -> PocKind:
    lang = (block.lang_hint or "").lower()
    text = block.span.text
    if "LLVMFuzzerTestOneInput" in text:
        return "libfuzzer_input" if "int main" not in text else "c_harness"
    if lang in _C_LANGS or ("#include" in text and re.search(r"\bint\s+main\s*\(", text)):
        return "c_harness"
    if lang in _PY_LANGS or (text.startswith("#!") and "python" in text.split("\n", 1)[0]):
        return "python"
    if n_commands == 1 and len([ln for ln in text.splitlines() if ln.strip()]) == 1:
        return "cli"
    if lang in _SHELL_LANGS or n_commands > 0 or text.startswith("#!"):
        return "shell"
    return "file_input"


@register(NAME)
def extract_pocs(ctx: ExtractContext) -> list[PocClaim]:
    report = ctx.report
    claims: list[PocClaim] = []
    for block in report.code_blocks:
        if block.role_guess != "poc":
            continue
        commands = block_commands(ctx, block)
        kind = infer_kind(block, len(commands))
        claims.append(
            make_claim(
                PocClaim,
                spans=[block.span],
                extractor=NAME,
                confidence=0.9,
                poc_kind=kind,
                content=block.span.text,
                entry=commands[0].text if commands else None,
            )
        )
    for attachment in report.attachments:
        if _POC_NAME_RE.search(attachment.name_sanitized):
            # Attachments have no span in the body; anchor the claim to the title line.
            anchor = report.span(0, min(len(report.body), max(1, report.body.find("\n"))))
            claims.append(
                make_claim(
                    PocClaim,
                    spans=[anchor],
                    extractor=NAME,
                    confidence=0.6,
                    poc_kind="file_input",
                    attachment_ref=attachment.name_sanitized,
                )
            )
    return claims
