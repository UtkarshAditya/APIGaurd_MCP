"""Load, validate and normalize an OpenAPI 3.0/3.1 spec into a ``SpecModel``.

Planned for Phase 1a. URL sources must go through the guard; local paths and
external ``$ref`` targets must pass the path checks.
"""

from __future__ import annotations

from apiguard.spec.model import SpecModel


def load_spec(source: str, *, name: str | None = None) -> SpecModel:
    """Load a spec from a local path or URL and return its normalized model."""
    raise NotImplementedError("spec loading is planned for Phase 1a")
