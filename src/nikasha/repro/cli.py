# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""``nikasha repro`` and ``nikasha recipes`` (SPEC §13). Registered by ``nikasha.cli``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from nikasha.errors import NikashaError

recipes_app = typer.Typer(
    help="List, show and validate reproduction recipes (SPEC §13.2).", no_args_is_help=True
)

RecipesDirOption = Annotated[
    str | None, typer.Option("--recipes-dir", help="Directory of recipe YAML files.")
]


MAX_TIMEOUT_S = 3600.0

# C0 controls except tab and LF, DEL, and C1 controls. PoC output is hostile, and ESC/CSI/OSC
# sequences would reach the maintainer's terminal (screen clears, title or link spoofing,
# OSC 52 clipboard writes). Rich does not strip these.
_UNSAFE_CONTROLS = frozenset(
    [chr(c) for c in range(0x20) if chr(c) not in "\t\n"]
    + ["\x7f"]
    + [chr(c) for c in range(0x80, 0xA0)]
)


def terminal_safe(text: str) -> str:
    """Replace terminal control characters with visible ``\\xNN`` escapes."""
    return "".join(f"\\x{ord(ch):02x}" if ch in _UNSAFE_CONTROLS else ch for ch in text)


def _fail(exc: NikashaError) -> typer.Exit:
    Console(stderr=True).print(f"[red]error:[/] {escape(str(exc))}", highlight=False)
    raise typer.Exit(code=1)


def _dir(value: str | None) -> Path | None:
    return Path(value) if value else None


@recipes_app.command("list")
def recipes_list(recipes_dir: RecipesDirOption = None) -> None:
    """List the available recipes: id, products and title."""
    from nikasha.repro.recipes import list_recipes, load_recipe  # noqa: PLC0415

    try:
        for path in list_recipes(_dir(recipes_dir)):
            recipe = load_recipe(path).recipe
            products = ",".join(recipe.match.products)
            typer.echo(f"{recipe.id}\t{products}\t{recipe.title}")
    except NikashaError as exc:
        _fail(exc)


@recipes_app.command("show")
def recipes_show(
    name: Annotated[str, typer.Argument(help="Recipe id or path to a .yaml file.")],
    recipes_dir: RecipesDirOption = None,
) -> None:
    """Print one recipe, validated and normalized, as JSON (with its sha256)."""
    from nikasha.repro.recipes import find_recipe  # noqa: PLC0415

    try:
        loaded = find_recipe(name, _dir(recipes_dir))
    except NikashaError as exc:
        _fail(exc)
    payload = {"recipe": loaded.recipe.model_dump(mode="json"), "sha256": loaded.sha256}
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@recipes_app.command("validate")
def recipes_validate(
    paths: Annotated[
        list[str] | None, typer.Argument(help="Recipe files; default: every shipped recipe.")
    ] = None,
    recipes_dir: RecipesDirOption = None,
) -> None:
    """Validate recipes against schema/recipe-v1.json. Exit 1 if any is invalid."""
    from nikasha.repro.recipes import list_recipes, load_recipe  # noqa: PLC0415

    try:
        files = [Path(p) for p in paths] if paths else list_recipes(_dir(recipes_dir))
    except NikashaError as exc:
        _fail(exc)
    bad = 0
    for path in files:
        try:
            load_recipe(path)
        except NikashaError as exc:
            bad += 1
            typer.echo(f"invalid\t{path.name}\t{exc}")
        else:
            typer.echo(f"ok\t{path.name}")
    if bad:
        raise typer.Exit(code=1)


def repro(  # noqa: PLR0917 - a CLI command's options are its signature
    repo: Annotated[str, typer.Option("--repo", help="Repository URL (https) or local path.")],
    ref: Annotated[str, typer.Option("--ref", help="Tag, branch or commit to build.")],
    recipe: Annotated[str, typer.Option("--recipe", help="Recipe id or path to a .yaml.")],
    poc: Annotated[str, typer.Option("--poc", help="PoC file or directory (hostile).")],
    kind: Annotated[
        str | None, typer.Option("--kind", help="Run kind: cli, file_input, c_harness...")
    ] = None,
    poc_args: Annotated[
        list[str] | None, typer.Option("--arg", help="An argument for {args}; repeatable.")
    ] = None,
    sandbox_choice: Annotated[
        str, typer.Option("--sandbox", help="Container engine: auto, podman or docker.")
    ] = "auto",
    runtime: Annotated[
        str | None, typer.Option("--runtime", help="OCI runtime passthrough, e.g. runsc.")
    ] = None,
    timeout: Annotated[
        float | None, typer.Option("--timeout", help="Wall-clock seconds for the PoC run.")
    ] = None,
    online: Annotated[
        bool, typer.Option("--online", help="Allow network (repository fetch, image build).")
    ] = False,
    recipes_dir: RecipesDirOption = None,
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Build the project at --ref in a sandbox and run one PoC against it (SPEC §13).

    Refuses to run when no container engine is available: PoCs never run on the host.

    Example:
        nikasha repro --repo ./vulnlab.git --ref v1.2.0 --recipe vulnlab --poc crash.bin
    """
    from nikasha.repro import build, run, sandbox  # noqa: PLC0415
    from nikasha.repro.recipes import find_recipe  # noqa: PLC0415
    from nikasha.resolve.repo import open_repo  # noqa: PLC0415

    try:
        if timeout is not None and not 0 < timeout <= MAX_TIMEOUT_S:
            raise NikashaError(f"--timeout must be > 0 and <= {MAX_TIMEOUT_S} seconds")
        engine = sandbox.select_engine(sandbox_choice)  # refuse before touching anything
        loaded = find_recipe(recipe, _dir(recipes_dir))
        poc_path = Path(poc)
        if not poc_path.exists():
            raise NikashaError("the --poc path does not exist")
        with open_repo(repo, online=online) as git_repo:
            resolved = git_repo.rev_parse(ref)
            if resolved is None:
                raise NikashaError(f"{ref!r} does not name a commit in {repo}")
            commit: str = resolved
            if not sandbox.image_exists(engine, loaded.recipe.image.tag):
                sandbox.build_image(
                    engine,
                    loaded.dockerfile,
                    loaded.dockerfile.parent,
                    loaded.recipe.image.tag,
                    online=online,
                )
            built = build.build(git_repo, commit, loaded, engine, runtime=runtime)
        outcome = run.run_poc(
            engine,
            loaded.recipe,
            built.outputs_dir,
            poc_path,
            kind=kind,
            args=tuple(poc_args or ()),
            timeout_s=timeout,
            runtime=runtime,
        )
    except NikashaError as exc:
        _fail(exc)
    payload = {
        "engine": sandbox.engine_facts(engine).as_dict(),
        "recipe": {"id": loaded.recipe.id, "sha256": loaded.sha256},
        "commit": commit,
        "build": {
            "cached": built.cached,
            "command": built.record.model_dump(mode="json") if built.record else None,
        },
        "run": {
            "kind": outcome.kind,
            "exit_code": outcome.exit_code,
            "timed_out": outcome.timed_out,
            "truncated": outcome.truncated,
            "command": outcome.record.model_dump(mode="json"),
            "stdout": outcome.stdout,
            "stderr": outcome.stderr,
        },
    }
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    console = Console(highlight=False)
    state = "timed out" if outcome.timed_out else f"exit {outcome.exit_code}"
    console.print(
        f"{escape(loaded.recipe.id)} @ {commit[:12]} in {engine.name}: "
        f"{escape(outcome.kind)} run, {state}"
        + (" (output truncated)" if outcome.truncated else "")
    )
    tail = terminal_safe("\n".join(outcome.stderr.strip().splitlines()[-40:]))
    if tail:
        console.print(escape(tail), markup=True)


def register(app: typer.Typer) -> None:
    """Attach ``repro`` and the ``recipes`` group to the main app."""
    app.command("repro")(repro)
    app.add_typer(recipes_app, name="recipes")


__all__ = ["MAX_TIMEOUT_S", "recipes_app", "register", "repro", "terminal_safe"]
