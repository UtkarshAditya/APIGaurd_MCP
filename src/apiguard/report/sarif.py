"""SARIF 2.1.0 report. Planned for Phase 1b."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from apiguard.models import Finding


def render_sarif(findings: Sequence[Finding]) -> dict[str, Any]:
    """Render a SARIF 2.1.0 log for one scan run."""
    raise NotImplementedError("SARIF reports are planned for Phase 1b")
