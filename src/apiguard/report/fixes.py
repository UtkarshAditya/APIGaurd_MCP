"""Rule-specific fix templates. Planned for Phase 1b.

Fixes are returned as text only; nothing here ever writes a file.
"""

from __future__ import annotations

from typing import Literal

from apiguard.models import Finding

FixTarget = Literal["openapi", "fastapi"]


def suggest_fix(finding: Finding, target: FixTarget) -> str:
    """Return a spec patch or code snippet that addresses ``finding``."""
    raise NotImplementedError("fix suggestions are planned for Phase 1b")
