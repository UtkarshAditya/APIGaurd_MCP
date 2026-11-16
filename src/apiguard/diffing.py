"""Spec diffing: added, removed and changed endpoints. Planned for Phase 1d."""

from __future__ import annotations

from typing import Any

from apiguard.spec.model import SpecModel


def diff_specs(old: SpecModel, new: SpecModel) -> dict[str, Any]:
    """Compare two specs and report endpoint changes and auth or schema regressions."""
    raise NotImplementedError("spec diffing is planned for Phase 1d")
