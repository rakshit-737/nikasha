# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Recipe validation and the schema/model contract (SPEC §13.2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import BaseModel

from nikasha.repro import recipes
from nikasha.repro.recipes import Recipe, RecipeError, parse_recipe

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((ROOT / "schema" / "recipe-v1.json").read_text(encoding="utf-8"))
VULNLAB = (ROOT / "recipes" / "vulnlab.yaml").read_bytes()


def _vulnlab() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(VULNLAB)
    return data


def _dump(data: dict[str, Any]) -> bytes:
    return yaml.safe_dump(data).encode()


def test_shipped_recipes_all_validate():
    ids = [recipes.load_recipe(p).recipe.id for p in recipes.list_recipes()]
    assert ids == ["curl", "libxml2", "sqlite", "vulnlab"]


def test_shipped_dockerfiles_exist():
    for path in recipes.list_recipes():
        loaded = recipes.load_recipe(path)
        assert loaded.dockerfile.is_file(), loaded.recipe.image.dockerfile


def test_real_project_recipes_say_they_are_unverified():
    for name in ("curl", "sqlite", "libxml2"):
        assert "UNVERIFIED" in (ROOT / "recipes" / f"{name}.yaml").read_text(encoding="utf-8")


def test_vulnlab_matches_the_spec_example():
    recipe = recipes.find_recipe("vulnlab").recipe
    assert recipe.build.outputs == ("build/hdrcat", "build/libhdr.a", "include/")
    assert recipe.run.kinds["c_harness"].cmd == ("/work/poc",)
    assert recipe.limits.output_bytes == 1024 * 1024


def test_sha256_is_of_the_file_bytes():
    loaded = recipes.find_recipe("vulnlab")
    assert loaded.sha256 == recipes.hashlib.sha256(VULNLAB).hexdigest()


def _schema_props(node: dict[str, Any]) -> dict[str, Any]:
    ref = node.get("$ref")
    if ref:
        node = SCHEMA["$defs"][ref.rsplit("/", 1)[-1]]
    return node


def _check(model: type[BaseModel], schema: dict[str, Any], where: str) -> None:
    props = schema["properties"]
    assert set(props) == set(model.model_fields), where
    assert schema["additionalProperties"] is False, where
    required = {n for n, f in model.model_fields.items() if f.is_required()}
    assert set(schema.get("required", [])) == required, where
    for name, info in model.model_fields.items():
        sub = info.annotation
        if isinstance(sub, type) and issubclass(sub, BaseModel):
            _check(sub, _schema_props(props[name]), f"{where}.{name}")


def test_schema_and_models_agree():
    _check(Recipe, SCHEMA, "recipe")
    _check(recipes.RunKind, SCHEMA["$defs"]["kind"], "kind")


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda d: d.update(extra=1), "extra"),
        (lambda d: d.pop("run"), "run"),
        (lambda d: d.update(id="Bad Id"), "id"),
        (lambda d: d["image"].update(dockerfile="/etc/passwd"), "dockerfile"),
        (lambda d: d["image"].update(dockerfile="docker/recipes/../../x.Dockerfile"), "path"),
        (lambda d: d["image"].update(tag="--privileged"), "tag"),
        (lambda d: d["build"].update(outputs=["../escape"]), "unsafe path"),
        (lambda d: d["build"].update(outputs=["/abs"]), "unsafe path"),
        (lambda d: d["build"].update(outputs=["a/x", "b/x"]), "unique"),
        (lambda d: d["build"].update(steps=[]), "steps"),
        (lambda d: d["build"]["env"].update({"BAD-NAME": "1"}), "environment"),
        (lambda d: d["run"]["kinds"]["cli"].update(cmd=["/b", "--x={args}"]), "whole argument"),
        (lambda d: d["run"]["kinds"]["cli"].update(cmd=["/b", "{home}"]), "placeholder"),
        (lambda d: d["run"].update(kinds={}), "kinds"),
        (lambda d: d["limits"].update(memory="lots"), "size"),
        (lambda d: d["limits"].update(memory="1gg"), "size"),
        (lambda d: d["limits"].update(memory="1g2m"), "size"),
        (lambda d: d["limits"].update(pids=1), "pids"),
        (lambda d: d["run"].update(timeout_s=0), "timeout_s"),
    ],
)
def test_invalid_recipes_are_refused(mutate, message):
    data = _vulnlab()
    mutate(data)
    with pytest.raises(RecipeError, match=message):
        parse_recipe(_dump(data))


def test_non_mapping_and_bad_yaml_are_refused():
    with pytest.raises(RecipeError, match="mapping"):
        parse_recipe(b"- a\n- b\n")
    with pytest.raises(RecipeError, match="YAML"):
        parse_recipe(b"id: [unclosed\n")
    with pytest.raises(RecipeError, match="larger"):
        parse_recipe(b"#" * (recipes.MAX_RECIPE_BYTES + 1))


def test_id_must_match_file_name(tmp_path):
    path = tmp_path / "other.yaml"
    path.write_bytes(VULNLAB)
    with pytest.raises(RecipeError, match="file name"):
        recipes.load_recipe(path)


def test_find_recipe_refuses_path_like_ids():
    with pytest.raises(RecipeError):
        recipes.find_recipe("../vulnlab")
    with pytest.raises(RecipeError, match="no recipe"):
        recipes.find_recipe("nope")


def test_recipe_for_product():
    found = recipes.recipe_for_product("libhdr")
    assert found is not None
    assert found.recipe.id == "vulnlab"
    assert recipes.recipe_for_product("no-such-product") is None
