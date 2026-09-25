# SPDX-FileCopyrightText: 2026 The Nikasha Authors
# SPDX-License-Identifier: Apache-2.0
"""Recipe validation and the schema/model contract (SPEC §13.2)."""

from __future__ import annotations

import dataclasses
import json
import re
from pathlib import Path
from typing import Any

import annotated_types
import pytest
import yaml
from pydantic import BaseModel, ValidationError

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


def test_shipped_recipes_all_validate() -> None:
    ids = [recipes.load_recipe(p).recipe.id for p in recipes.list_recipes()]
    assert ids == ["curl", "libxml2", "sqlite", "vulnlab"]


def test_shipped_dockerfiles_exist() -> None:
    for path in recipes.list_recipes():
        loaded = recipes.load_recipe(path)
        assert loaded.dockerfile.is_file(), loaded.recipe.image.dockerfile


def test_real_project_recipes_say_they_are_unverified() -> None:
    for name in ("curl", "sqlite", "libxml2"):
        assert "UNVERIFIED" in (ROOT / "recipes" / f"{name}.yaml").read_text(encoding="utf-8")


def test_vulnlab_matches_the_spec_example() -> None:
    recipe = recipes.find_recipe("vulnlab").recipe
    assert recipe.build.outputs == ("build/hdrcat", "build/libhdr.a", "include/")
    assert recipe.run.kinds["c_harness"].cmd == ("/work/poc",)
    assert recipe.limits.output_bytes == 1024 * 1024


def test_sha256_is_of_the_file_bytes() -> None:
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


def test_schema_and_models_agree() -> None:
    _check(Recipe, SCHEMA, "recipe")
    _check(recipes.RunKind, SCHEMA["$defs"]["kind"], "kind")


_BOUNDS = {
    annotated_types.Ge: "minimum",
    annotated_types.Le: "maximum",
    annotated_types.Gt: "exclusiveMinimum",
    annotated_types.Lt: "exclusiveMaximum",
}


def _model_bounds(info: Any) -> dict[str, Any]:
    """A field's numeric and length constraints, spelled as JSON-schema keywords."""
    found: dict[str, Any] = {}
    for meta in info.metadata:
        for kind, keyword in _BOUNDS.items():
            if isinstance(meta, kind):
                found[keyword] = getattr(meta, dataclasses.fields(meta)[0].name)
        if isinstance(meta, annotated_types.MinLen):
            found["min"] = meta.min_length
        if isinstance(meta, annotated_types.MaxLen):
            found["max"] = meta.max_length
    return found


def _schema_bounds(node: dict[str, Any]) -> dict[str, Any]:
    found = {k: node[k] for k in _BOUNDS.values() if k in node}
    for key in ("minLength", "minItems", "minProperties"):
        if key in node:
            found["min"] = node[key]
    if "maxLength" in node:
        found["max"] = node["maxLength"]
    return found


def _walk_constraints(model: type[BaseModel], schema: dict[str, Any], where: str) -> None:
    for name, info in model.model_fields.items():
        node = _schema_props(schema["properties"][name])
        assert _model_bounds(info) == _schema_bounds(node), f"{where}.{name}"
        if "default" in node:
            default = info.get_default(call_default_factory=True)
            assert default == node["default"], f"{where}.{name} default"
        sub = info.annotation
        if isinstance(sub, type) and issubclass(sub, BaseModel):
            _walk_constraints(sub, node, f"{where}.{name}")


def test_schema_and_models_agree_on_bounds_and_defaults() -> None:
    _walk_constraints(Recipe, SCHEMA, "recipe")


def _schema_accepts(pattern: str, value: str) -> bool:
    """ECMA-262 semantics of a JSON-schema ``pattern``: search, and ``$`` is end of input."""
    return re.search(pattern.replace("$", r"\Z"), value) is not None


def _model_accepts(mutate: Any) -> bool:
    data = _vulnlab()
    mutate(data)
    try:
        Recipe.model_validate(data)
    except ValidationError:
        return False
    return True


SIZES = ["1", "0", "2g", "256m", "64k", "1G", "1M", "1K", "123456789012345g"]
SIZES_BAD = ["", "g", "1gg", "1g2m", "1t", "-1", " 1g", "1g ", "1g\n", "1.5g", "1234567890123456"]
IDS = ["a", "vulnlab", "c-harness", "x_1", "0a"]
IDS_BAD = ["", "A", "-a", "_a", "a b", "a/b", "a.b", "é", "a" * 65]
RELPATHS = ["build/hdrcat", "include/", "a.b+c@d", "x/-y", "lib/.libs/x.a"]
RELPATHS_BAD = ["", "/abs", "-x", "a b", "a\\b", "a:b", "a\nb"]
DOCKERFILES = ["docker/recipes/c-toolchain.Dockerfile", "docker/recipes/a+b@c.Dockerfile"]
DOCKERFILES_BAD = [
    "docker/recipes/x.dockerfile",
    "docker/recipes/sub/x.Dockerfile",
    "docker/x.Dockerfile",
    "/docker/recipes/x.Dockerfile",
    "docker/recipes/.Dockerfile",
    "docker/recipes/x.Dockerfile\n",
]
TAGS = ["nikasha/recipe-c:1", "a", "reg:5000/x/y:tag", "a@sha256:00"]
TAGS_BAD = ["", "-x", "a b", "a\tb", " a", "a\n"]
ENV_NAMES = ["CC", "_X", "a1"]
ENV_NAMES_BAD = ["", "1A", "A-B", "A B", "A=B"]


def _cases(good: list[str], bad: list[str]) -> list[tuple[str, bool]]:
    return [(v, True) for v in good] + [(v, False) for v in bad]


def _set_output(data: dict[str, Any], value: str) -> None:
    data["build"]["outputs"] = [value]


def _set_kind(data: dict[str, Any], value: str) -> None:
    data["run"]["kinds"] = {value: {"cmd": ["/x"]}}


FIELDS = [
    ("size", SIZES, SIZES_BAD, lambda d, v: d["limits"].update(memory=v)),
    ("size", SIZES, SIZES_BAD, lambda d, v: d["build"].update(work_size=v)),
    ("identifier", IDS, IDS_BAD, lambda d, v: d.update(id=v)),
    ("relpath", RELPATHS, RELPATHS_BAD, _set_output),
]


@pytest.mark.parametrize(("ref", "good", "bad", "setter"), FIELDS)
def test_schema_patterns_and_models_accept_the_same_values(ref, good, bad, setter):
    """The schema is the published contract: it must accept exactly what Nikasha accepts."""
    pattern = SCHEMA["$defs"][ref]["pattern"]
    for value, expected in _cases(good, bad):
        schema_ok = (
            _schema_accepts(pattern, value)
            and (len(value) <= SCHEMA["$defs"][ref].get("maxLength", len(value)))
            and len(value) >= SCHEMA["$defs"][ref].get("minLength", 0)
        )
        assert schema_ok is expected, (ref, value, "schema")
        assert _model_accepts(lambda d, v=value: setter(d, v)) is expected, (ref, value, "model")


def test_kind_names_env_names_dockerfile_and_tag_patterns_agree() -> None:
    run_props = SCHEMA["properties"]["run"]["properties"]
    kind_pattern = run_props["kinds"]["propertyNames"]["pattern"]
    for value, expected in _cases(IDS, IDS_BAD[:-1]):
        assert _schema_accepts(kind_pattern, value) is expected, value
        assert _model_accepts(lambda d, v=value: _set_kind(d, v)) is expected, value
    env_pattern = SCHEMA["$defs"]["env"]["propertyNames"]["pattern"]
    for value, expected in _cases(ENV_NAMES, ENV_NAMES_BAD):
        assert _schema_accepts(env_pattern, value) is expected, value
        ok = _model_accepts(lambda d, v=value: d["build"].update(env={v: "1"}))
        assert ok is expected, value
    image = SCHEMA["properties"]["image"]["properties"]
    for value, expected in _cases(DOCKERFILES, DOCKERFILES_BAD):
        assert _schema_accepts(image["dockerfile"]["pattern"], value) is expected, value
        ok = _model_accepts(lambda d, v=value: d["image"].update(dockerfile=v))
        assert ok is expected, value
    for value, expected in _cases(TAGS, TAGS_BAD):
        schema_ok = _schema_accepts(image["tag"]["pattern"], value) and len(value) >= 1
        assert schema_ok is expected, value
        assert _model_accepts(lambda d, v=value: d["image"].update(tag=v)) is expected, value


def test_sandbox_and_recipes_share_one_size_grammar() -> None:
    from nikasha.repro import sandbox  # noqa: PLC0415

    for value, expected in _cases(SIZES, SIZES_BAD):
        try:
            sandbox._check_size(value, "size")
        except sandbox.SandboxError:
            accepted = False
        else:
            accepted = True
        assert accepted is expected, value


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


def test_non_mapping_and_bad_yaml_are_refused() -> None:
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


def test_find_recipe_refuses_path_like_ids() -> None:
    with pytest.raises(RecipeError):
        recipes.find_recipe("../vulnlab")
    with pytest.raises(RecipeError, match="no recipe"):
        recipes.find_recipe("nope")


def test_recipe_for_product() -> None:
    found = recipes.recipe_for_product("libhdr")
    assert found is not None
    assert found.recipe.id == "vulnlab"
    assert recipes.recipe_for_product("no-such-product") is None
