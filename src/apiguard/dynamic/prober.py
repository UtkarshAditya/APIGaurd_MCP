"""Request execution and probe logging. Planned for Phase 1c.

The prober sends only what the ``Policy`` allows, runs requests sequentially
under the rate limit, and logs every request to ``probe_log``.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from apiguard.dynamic.checks import CheckName
from apiguard.dynamic.guard import Policy


def run_probe(
    policy: Policy,
    spec_id: str,
    base_url: str,
    checks: Sequence[CheckName],
    *,
    token_env: str | None = None,
) -> dict[str, Any]:
    """Run the requested checks against ``base_url`` and return a compact summary."""
    raise NotImplementedError("dynamic probing is planned for Phase 1c")
