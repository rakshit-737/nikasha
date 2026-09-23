# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Exception hierarchy. Every error Nikasha raises on purpose derives from :class:`NikashaError`."""


class NikashaError(Exception):
    """Base class for expected, user-facing failures (CLI exit code 1)."""


class ExternalToolError(NikashaError):
    """An external program (git, podman, docker) was missing, failed or timed out."""


class ForbiddenCommandError(NikashaError):
    """A caller asked a process wrapper to run something outside its allowlist."""
