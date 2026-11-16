from __future__ import annotations

import pytest

from apiguard.config import DynamicConfig
from apiguard.dynamic.checks import CHECK_NAMES
from apiguard.dynamic.guard import SAFE_METHODS, Budget, ConfigPolicy, Policy


class AllowLocalReadOnly:
    """A minimal structural implementation, as Phase 2 might supply."""

    def allow_host(self, host: str) -> bool:
        return host == "localhost"

    def allow_method(self, method: str) -> bool:
        return method in SAFE_METHODS

    @property
    def budget(self) -> Budget:
        return Budget(max_requests_per_run=10, requests_per_second=1)


def test_policy_is_satisfied_structurally() -> None:
    policy: Policy = AllowLocalReadOnly()
    assert isinstance(policy, Policy)
    assert policy.allow_host("localhost")
    assert not policy.allow_host("evil.example")
    assert not policy.allow_method("DELETE")
    assert policy.budget.max_requests_per_run == 10


def test_object_missing_a_member_is_not_a_policy() -> None:
    class NoBudget:
        def allow_host(self, host: str) -> bool:
            return True

        def allow_method(self, method: str) -> bool:
            return True

    assert not isinstance(NoBudget(), Policy)


def test_safe_methods_are_read_only() -> None:
    assert frozenset({"GET", "HEAD", "OPTIONS"}) == SAFE_METHODS


def test_config_policy_is_not_implemented_yet() -> None:
    policy = ConfigPolicy(DynamicConfig())
    with pytest.raises(NotImplementedError):
        policy.allow_host("localhost")
    with pytest.raises(NotImplementedError):
        policy.allow_method("GET")
    with pytest.raises(NotImplementedError):
        _ = policy.budget


def test_check_names_match_the_architecture_doc() -> None:
    assert CHECK_NAMES == (
        "unauth-access",
        "bola",
        "security-headers",
        "cors",
        "error-leak",
        "rate-limit",
    )
