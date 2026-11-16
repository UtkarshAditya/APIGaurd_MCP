"""Markdown report. Planned for Phase 1b."""

from __future__ import annotations

from collections.abc import Sequence

from apiguard.models import Finding


def render_markdown(findings: Sequence[Finding]) -> str:
    """Render a Markdown report for one scan run."""
    raise NotImplementedError("Markdown reports are planned for Phase 1b")
