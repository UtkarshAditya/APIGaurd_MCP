"""Pure assertion functions for dynamic checks. Planned for Phase 1c.

Each check evaluates already-captured responses, so it is unit-testable
without a network.
"""

from __future__ import annotations

from typing import Literal, get_args

CheckName = Literal[
    "unauth-access",
    "bola",
    "security-headers",
    "cors",
    "error-leak",
    "rate-limit",
]

CHECK_NAMES: tuple[str, ...] = get_args(CheckName)
