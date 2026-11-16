from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from openapi_spec_validator import validate
from ruamel.yaml import YAML


def load(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = YAML(typ="safe", pure=True).load(path.read_text(encoding="utf-8"))
    return data


@pytest.mark.parametrize("name", ["clean.yaml", "open_override.yaml"])
def test_fixture_is_a_valid_openapi_30_spec(fixtures_dir: Path, name: str) -> None:
    spec = load(fixtures_dir / name)
    assert spec["openapi"].startswith("3.0.")
    validate(spec)


def test_clean_fixture_has_no_security_override(fixtures_dir: Path) -> None:
    spec = load(fixtures_dir / "clean.yaml")
    assert spec["security"] == [{"bearerAuth": []}]
    for operations in spec["paths"].values():
        for operation in operations.values():
            assert "security" not in operation


def test_vulnerable_fixture_has_an_open_override(fixtures_dir: Path) -> None:
    spec = load(fixtures_dir / "open_override.yaml")
    assert spec["security"] == [{"bearerAuth": []}]
    assert spec["paths"]["/users/{id}"]["delete"]["security"] == []
