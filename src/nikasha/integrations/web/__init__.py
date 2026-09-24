# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha serve``: the hardened local web UI (SPEC §16.4; the ``[web]`` extra).

Importing this package never imports FastAPI or uvicorn, so the CLI can register the
command whether or not the extra is installed; the command itself says how to install it.
The security model is documented in :mod:`nikasha.integrations.web.security` and in
``docs/web-ui.md``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.markup import escape

from nikasha.errors import NikashaError
from nikasha.integrations.web.security import LOOPBACK, bind_loopback, build_url, make_token

INSTALL_HINT = "the web UI needs its optional dependencies: pip install 'nikasha[web]'"


def register(app: typer.Typer) -> None:
    """Add ``serve`` to the CLI (called by :mod:`nikasha.cli`)."""
    app.command(name="serve")(serve)


def serve(
    port: Annotated[
        int, typer.Option("--port", help="Port on 127.0.0.1; 0 picks a free one.", min=0, max=65535)
    ] = 0,
) -> None:
    """Start the local web UI on 127.0.0.1 and print its one-time URL.

    The server listens on the loopback address only, on a random port unless --port is
    given, and every request must carry the access token in the printed URL. Nothing
    leaves the machine: reports and results stay in this process and are gone when it
    stops.

    Example:
        nikasha serve
        nikasha serve --port 8765
    """
    try:
        serve_forever(port=port)
    except NikashaError as exc:
        # ``escape``: the hint says "nikasha[web]", which rich would otherwise read as markup.
        Console(stderr=True).print(f"[red]error:[/] {escape(str(exc))}", highlight=False)
        raise typer.Exit(code=1) from exc


def server_settings(port: int) -> dict[str, Any]:
    """The uvicorn settings: loopback, no access log (URLs carry the token), no banner."""
    return {
        "host": LOOPBACK,
        "port": port,
        "access_log": False,
        "log_level": "warning",
        "server_header": False,
        "proxy_headers": False,
        "lifespan": "off",
        "interface": "asgi3",
    }


def serve_forever(port: int = 0, *, announce: Callable[[str], None] = typer.echo) -> None:
    """Bind, print the URL and serve until interrupted. Raises ``NikashaError`` when
    the ``[web]`` extra is missing or the port cannot be bound."""
    try:
        import uvicorn  # noqa: PLC0415 - optional extra

        from nikasha.integrations.web.app import create_app  # noqa: PLC0415 - optional extra
    except ImportError as exc:
        raise NikashaError(INSTALL_HINT) from exc

    sock = bind_loopback(port)
    try:
        actual = int(sock.getsockname()[1])
        token = make_token()
        app = create_app(token=token, port=actual)
        announce(f"Nikasha web UI: {build_url(actual, token)}")
        announce(
            f"Listening on {LOOPBACK} only. The URL carries this run's access token; "
            "do not share it. Press Ctrl+C to stop."
        )
        config = uvicorn.Config(app, **server_settings(actual))
        uvicorn.Server(config).run(sockets=[sock])
    finally:
        sock.close()


__all__ = ["INSTALL_HINT", "register", "serve", "serve_forever", "server_settings"]
