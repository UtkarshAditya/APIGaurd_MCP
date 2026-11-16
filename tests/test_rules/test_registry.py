from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

import pytest

from apiguard.config import RuleConfig
from apiguard.models import Confidence, Finding, RuleMeta, Severity
from apiguard.rules import registry
from apiguard.rules.registry import (
    DuplicateRuleError,
    RuleRegistry,
    discover_rules,
    register_rule,
)
from apiguard.spec.model import SpecModel

RULE_MODULES = ["auth", "bfla", "bola", "bopla", "inventory", "misconfig", "resources", "ssrf"]


def meta(rule_id: str) -> RuleMeta:
    return RuleMeta(
        id=rule_id,
        owasp="API2:2023",
        title="t",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )


def no_findings(spec: SpecModel, cfg: RuleConfig) -> Iterable[Finding]:
    return []


@pytest.fixture
def clean_default_registry(monkeypatch: pytest.MonkeyPatch) -> RuleRegistry:
    """Give the default registry an empty rule table for the duration of a test."""
    monkeypatch.setattr(registry.default_registry, "_rules", {})
    return registry.default_registry


@pytest.fixture
def make_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[object]:
    """Return a function that writes an importable package of rule modules."""
    monkeypatch.syspath_prepend(str(tmp_path))
    created: list[str] = []

    def build(name: str, modules: dict[str, str]) -> str:
        pkg = tmp_path / name
        pkg.mkdir()
        (pkg / "__init__.py").write_text("", encoding="utf-8")
        for module, body in modules.items():
            (pkg / f"{module}.py").write_text(body, encoding="utf-8")
        created.append(name)
        return name

    yield build
    for module_name in [m for m in sys.modules if m.split(".")[0] in created]:
        del sys.modules[module_name]


def rule_module(rule_id: str) -> str:
    return (
        "from apiguard.models import Confidence, RuleMeta, Severity\n"
        "from apiguard.rules.registry import register_rule\n"
        f"@register_rule(RuleMeta({rule_id!r}, 'API2:2023', 't', Severity.HIGH, Confidence.HIGH))\n"
        "def check(spec, cfg):\n"
        "    return []\n"
    )


# ------------------------------------------------------------- registration


def test_register_stores_the_rule_and_returns_the_function_unchanged() -> None:
    reg = RuleRegistry()
    decorated = reg.register(meta("API2-A"))(no_findings)
    assert decorated is no_findings
    assert "API2-A" in reg
    assert len(reg) == 1
    assert reg.get("API2-A").meta.id == "API2-A"
    assert reg.get("API2-A").check is no_findings


def test_all_is_sorted_by_id() -> None:
    reg = RuleRegistry()
    for rule_id in ("API9-Z", "API2-B", "API2-A"):
        reg.register(meta(rule_id))(no_findings)
    assert [r.meta.id for r in reg.all()] == ["API2-A", "API2-B", "API9-Z"]


def test_get_unknown_rule_raises_key_error() -> None:
    with pytest.raises(KeyError):
        RuleRegistry().get("nope")


def test_duplicate_id_is_rejected_and_first_registration_kept() -> None:
    reg = RuleRegistry()
    reg.register(meta("API2-A"))(no_findings)

    def other(spec: SpecModel, cfg: RuleConfig) -> Iterable[Finding]:
        return []

    with pytest.raises(DuplicateRuleError, match=r"API2-A.*no_findings.*other"):
        reg.register(meta("API2-A"))(other)
    assert reg.get("API2-A").check is no_findings
    assert len(reg) == 1


def test_register_rule_decorator_uses_the_default_registry(
    clean_default_registry: RuleRegistry,
) -> None:
    @register_rule(meta("API2-A"))
    def check(spec: SpecModel, cfg: RuleConfig) -> Iterable[Finding]:
        return []

    assert clean_default_registry.get("API2-A").check is check
    with pytest.raises(DuplicateRuleError):
        register_rule(meta("API2-A"))(no_findings)


# ---------------------------------------------------------------- discovery


def test_discovers_every_module_under_rules(clean_default_registry: RuleRegistry) -> None:
    assert discover_rules() == [f"apiguard.rules.{name}" for name in RULE_MODULES]
    for name in RULE_MODULES:
        assert f"apiguard.rules.{name}" in sys.modules


def test_scaffold_rule_modules_register_nothing_yet() -> None:
    discover_rules()
    assert len(registry.default_registry) == 0


def test_rule_modules_on_disk_match_the_expected_list(src_dir: Path) -> None:
    on_disk = sorted(
        p.stem for p in (src_dir / "rules").glob("*.py") if p.stem not in {"__init__", "registry"}
    )
    assert on_disk == RULE_MODULES


def test_discovery_registers_rules_from_imported_modules(
    clean_default_registry: RuleRegistry, make_package: object
) -> None:
    pkg = make_package(  # type: ignore[operator]
        "fake_rules_ok",
        {
            "beta": rule_module("API9-B"),
            "alpha": rule_module("API2-A"),
            "_private": "raise RuntimeError('must not be imported')\n",
            "registry": "raise RuntimeError('must not be imported')\n",
        },
    )
    assert discover_rules(pkg) == ["fake_rules_ok.alpha", "fake_rules_ok.beta"]
    assert [r.meta.id for r in clean_default_registry.all()] == ["API2-A", "API9-B"]


def test_discovery_is_idempotent(
    clean_default_registry: RuleRegistry, make_package: object
) -> None:
    pkg = make_package("fake_rules_twice", {"alpha": rule_module("API2-A")})  # type: ignore[operator]
    discover_rules(pkg)
    discover_rules(pkg)
    assert len(clean_default_registry) == 1


def test_discovery_surfaces_duplicate_ids_across_modules(
    clean_default_registry: RuleRegistry, make_package: object
) -> None:
    pkg = make_package(  # type: ignore[operator]
        "fake_rules_dupe",
        {"alpha": rule_module("API2-SAME"), "beta": rule_module("API2-SAME")},
    )
    with pytest.raises(DuplicateRuleError, match=r"fake_rules_dupe\.alpha.*fake_rules_dupe\.beta"):
        discover_rules(pkg)


def test_discovery_does_not_hide_a_broken_module(
    clean_default_registry: RuleRegistry, make_package: object
) -> None:
    pkg = make_package("fake_rules_broken", {"alpha": "raise RuntimeError('boom')\n"})  # type: ignore[operator]
    with pytest.raises(RuntimeError, match="boom"):
        discover_rules(pkg)


def test_discovery_of_a_missing_package_raises() -> None:
    with pytest.raises(ModuleNotFoundError):
        discover_rules("apiguard.no_such_rules_package")
