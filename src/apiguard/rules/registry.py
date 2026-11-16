"""Rule registry: the ``@register_rule`` decorator and module discovery."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from apiguard.config import RuleConfig
from apiguard.models import Finding, RuleMeta
from apiguard.spec.model import SpecModel

RuleFunc = Callable[[SpecModel, RuleConfig], Iterable[Finding]]

RULES_PACKAGE = "apiguard.rules"
_NON_RULE_MODULES = frozenset({"registry"})


class DuplicateRuleError(ValueError):
    """Two rules were registered under the same id."""


@dataclass(frozen=True)
class RegisteredRule:
    meta: RuleMeta
    check: RuleFunc


class RuleRegistry:
    """Rules keyed by id."""

    def __init__(self) -> None:
        self._rules: dict[str, RegisteredRule] = {}

    def register(self, meta: RuleMeta) -> Callable[[RuleFunc], RuleFunc]:
        """Return a decorator that registers a rule function under ``meta.id``."""

        def decorator(func: RuleFunc) -> RuleFunc:
            existing = self._rules.get(meta.id)
            if existing is not None:
                raise DuplicateRuleError(
                    f"Rule id {meta.id!r} is already registered by "
                    f"{_describe(existing.check)}; cannot register {_describe(func)}"
                )
            self._rules[meta.id] = RegisteredRule(meta=meta, check=func)
            return func

        return decorator

    def get(self, rule_id: str) -> RegisteredRule:
        """Return the rule with this id, or raise ``KeyError``."""
        return self._rules[rule_id]

    def all(self) -> list[RegisteredRule]:
        """Return every registered rule, sorted by id for reproducible runs."""
        return [self._rules[rule_id] for rule_id in sorted(self._rules)]

    def __contains__(self, rule_id: object) -> bool:
        return rule_id in self._rules

    def __len__(self) -> int:
        return len(self._rules)


default_registry = RuleRegistry()


def register_rule(meta: RuleMeta) -> Callable[[RuleFunc], RuleFunc]:
    """Register a rule function in the default registry."""
    return default_registry.register(meta)


def discover_rules(package: str = RULES_PACKAGE) -> list[str]:
    """Import every rule module directly under ``package`` so its rules register.

    Returns the imported module names, sorted. Modules whose name starts with an
    underscore, and the registry itself, are skipped. An import error or a
    duplicate rule id propagates: a broken rule module must not be skipped quietly.
    """
    pkg = importlib.import_module(package)
    names = sorted(
        info.name
        for info in pkgutil.iter_modules(pkg.__path__)
        if not info.name.startswith("_") and info.name not in _NON_RULE_MODULES
    )
    imported: list[str] = []
    for name in names:
        full_name = f"{package}.{name}"
        importlib.import_module(full_name)
        imported.append(full_name)
    return imported


def _describe(func: Callable[..., object]) -> str:
    module = getattr(func, "__module__", "?")
    qualname = getattr(func, "__qualname__", repr(func))
    return f"{module}.{qualname}"
