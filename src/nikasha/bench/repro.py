# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""The ``bench run --repro`` subset (SPEC §17.3): dynamic reproduction for cases with recipes.

Only cases whose manifest entry names a ``poc``, a ``recipe`` and a ``version`` join the
subset. Each is built at ``version`` with :mod:`nikasha.repro.build` and its PoC run once
with :mod:`nikasha.repro.run`, both of which go through :mod:`nikasha.repro.sandbox`; this
module never starts a process itself. A :class:`Reproducer` exists only when the caller
passed ``--repro`` *and* an engine was selected, so a static run can never reach a
container (P5). The build and run are offline: a missing recipe image is built with
``online=False``.

Every attempt returns a status string for the record (deterministic, no messages: they can
echo local paths) and, when something ran or failed, the object C19 consumes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from nikasha.errors import NikashaError

if TYPE_CHECKING:
    from nikasha.bench.runner import Case
    from nikasha.repro.run import ReproRun
    from nikasha.repro.sandbox import EngineInfo
    from nikasha.repro.signature import ReproFailure

#: Record statuses. ``not_in_subset``: the entry has no PoC and recipe.
NOT_IN_SUBSET = "not_in_subset"
RAN = "ran"
FAILED = "failed"


def select_engine(choice: str = "auto") -> EngineInfo | None:
    """The engine for ``--repro``, or ``None`` when there is none (the caller skips repro)."""
    from nikasha.repro import sandbox  # noqa: PLC0415 - static runs never import the sandbox

    try:
        return sandbox.select_engine(choice)
    except sandbox.NoEngineError:
        return None


def _attempt(case: Case, repo: Path, engine: EngineInfo, recipes_dir: Path | None) -> ReproRun:
    from nikasha.repro import build, run, sandbox  # noqa: PLC0415
    from nikasha.repro.recipes import find_recipe  # noqa: PLC0415
    from nikasha.resolve.repo import open_repo  # noqa: PLC0415

    if case.poc is None or case.recipe is None or case.version is None:
        raise NikashaError("the case is not in the repro subset")
    loaded = find_recipe(case.recipe, recipes_dir)
    if not case.poc.exists():
        raise NikashaError("the case's PoC path does not exist")
    with open_repo(str(repo), online=False) as git_repo:
        commit = git_repo.rev_parse(case.version)
        if commit is None:
            raise NikashaError("the case's version does not name a commit")
        if not sandbox.image_exists(engine, loaded.recipe.image.tag):
            sandbox.build_image(
                engine,
                loaded.dockerfile,
                loaded.dockerfile.parent,
                loaded.recipe.image.tag,
                online=False,
            )
        built = build.build(git_repo, commit, loaded, engine)
    return run.run_poc(engine, loaded.recipe, built.outputs_dir, case.poc)


@dataclass(slots=True)
class Reproducer:
    """Runs the repro subset in ``engine``. ``attempt_fn`` is replaceable for tests."""

    engine: EngineInfo
    recipes_dir: Path | None = None
    attempt_fn: Callable[[Case, Path, EngineInfo, Path | None], ReproRun] = field(default=_attempt)

    def attempt(self, case: Case, repo: Path) -> tuple[str, ReproRun | ReproFailure | None]:
        """``(status, repro)`` for one case; ``repro`` is ``None`` outside the subset."""
        if case.poc is None or case.recipe is None or case.version is None:
            return NOT_IN_SUBSET, None
        from nikasha.repro.signature import ReproFailure  # noqa: PLC0415

        try:
            return RAN, self.attempt_fn(case, repo, self.engine, self.recipes_dir)
        except NikashaError as exc:
            # Class name only: messages can carry local paths or build output.
            stage = "build_failed" if type(exc).__name__ == "BuildFailedError" else "infra_error"
            return FAILED, ReproFailure(stage, type(exc).__name__)
