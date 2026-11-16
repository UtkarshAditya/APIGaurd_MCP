"""Structural guarantees: transport-neutral core, importable modules, honest stubs."""

from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import pytest

import apiguard
from apiguard.diffing import diff_specs
from apiguard.dynamic.prober import run_probe
from apiguard.models import Confidence, Finding, RuleMeta, Severity
from apiguard.report.fixes import suggest_fix
from apiguard.report.markdown import render_markdown
from apiguard.report.sarif import render_sarif
from apiguard.spec.model import SpecModel

EXPECTED_MODULES = {
    "apiguard.config",
    "apiguard.diffing",
    "apiguard.dynamic.checks",
    "apiguard.dynamic.guard",
    "apiguard.dynamic.prober",
    "apiguard.models",
    "apiguard.report.fixes",
    "apiguard.report.markdown",
    "apiguard.report.sarif",
    "apiguard.rules.auth",
    "apiguard.rules.bfla",
    "apiguard.rules.bola",
    "apiguard.rules.bopla",
    "apiguard.rules.inventory",
    "apiguard.rules.misconfig",
    "apiguard.rules.registry",
    "apiguard.rules.resources",
    "apiguard.rules.ssrf",
    "apiguard.server",
    "apiguard.spec.loader",
    "apiguard.spec.model",
    "apiguard.store",
}


def all_module_names() -> set[str]:
    return {
        info.name
        for info in pkgutil.walk_packages(apiguard.__path__, prefix="apiguard.")
        if not info.ispkg
    }


def imported_top_level_packages(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_layout_matches_the_architecture_doc() -> None:
    assert all_module_names() == EXPECTED_MODULES


@pytest.mark.parametrize("name", sorted(EXPECTED_MODULES))
def test_every_module_imports_and_has_a_docstring(name: str) -> None:
    module = importlib.import_module(name)
    assert module.__doc__


def test_only_server_imports_mcp(src_dir: Path) -> None:
    offenders = [
        str(path.relative_to(src_dir))
        for path in src_dir.rglob("*.py")
        if path.name != "server.py" and "mcp" in imported_top_level_packages(path)
    ]
    assert offenders == []
    assert "mcp" in imported_top_level_packages(src_dir / "server.py")


def test_unbuilt_core_functions_raise_not_implemented() -> None:
    spec = SpecModel(spec_id="s", openapi_version="3.0.3")
    meta = RuleMeta("API2-X", "API2:2023", "t", Severity.HIGH, Confidence.HIGH)
    found = Finding.from_rule(meta, "GET /x", evidence="e")
    with pytest.raises(NotImplementedError):
        diff_specs(spec, spec)
    with pytest.raises(NotImplementedError):
        render_markdown([found])
    with pytest.raises(NotImplementedError):
        render_sarif([found])
    with pytest.raises(NotImplementedError):
        suggest_fix(found, "openapi")
    with pytest.raises(NotImplementedError):
        run_probe(object(), "s", "http://localhost", ["cors"])  # type: ignore[arg-type]
