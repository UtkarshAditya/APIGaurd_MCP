"""The single choke point for outbound network access.

``Policy`` is the interface the prober asks before every request. It is a
Protocol so that Phase 2 (the A2A gateway) can reuse or replace the engine.
The config-backed implementation, IP pinning and redirect checks are planned
for Phase 1c.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from apiguard.config import DynamicConfig

SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class Budget:
    """Request limits for one probe run."""

    max_requests_per_run: int
    requests_per_second: float


@runtime_checkable
class Policy(Protocol):
    """What the guard is allowed to send, and how much."""

    def allow_host(self, host: str) -> bool:
        """Return True if requests to ``host`` are permitted."""
        ...

    def allow_method(self, method: str) -> bool:
        """Return True if the HTTP ``method`` is permitted."""
        ...

    @property
    def budget(self) -> Budget:
        """The request budget for a run."""
        ...


class ConfigPolicy:
    """``Policy`` backed by the user's config file. Planned for Phase 1c."""

    def __init__(self, config: DynamicConfig) -> None:
        self._config = config

    def allow_host(self, host: str) -> bool:
        raise NotImplementedError("the host allowlist is planned for Phase 1c")

    def allow_method(self, method: str) -> bool:
        raise NotImplementedError("method policy is planned for Phase 1c")

    @property
    def budget(self) -> Budget:
        raise NotImplementedError("request budgets are planned for Phase 1c")
