# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Integrations (SPEC §16): the CLI modes and services built on the check pipeline.

Each CLI-bearing module exposes ``register(app: typer.Typer) -> None``, which adds its
command(s); :mod:`nikasha.cli` wires them. Nothing here changes what the engine concludes,
only who it talks to and how.
"""
