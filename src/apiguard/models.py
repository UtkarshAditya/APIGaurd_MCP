"""Core finding models: severities, confidence, statuses, rule metadata and findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict

FINDING_ID_PREFIX = "F-"
FINDING_ID_HEX_LENGTH = 12

FindingSource = Literal["static", "dynamic"]


class Severity(StrEnum):
    """How bad a finding is, most severe first."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric order for comparisons: higher means more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    """How sure a rule is that a finding is real."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(StrEnum):
    """Triage state of a finding."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass(frozen=True)
class RuleMeta:
    """Static metadata describing one rule."""

    id: str  # e.g. "API2-OPEN-OVERRIDE"
    owasp: str  # e.g. "API2:2023"
    title: str
    severity: Severity
    confidence: Confidence


def compute_finding_id(rule: str, endpoint: str, evidence_key: str) -> str:
    """Return a stable short id for a finding.

    The id depends only on the rule id, the endpoint id and the evidence key, so
    re-scanning the same spec yields the same id. The three parts are JSON-encoded
    before hashing so that no choice of values can collide by shifting a separator.
    """
    payload = json.dumps([rule, endpoint, evidence_key], ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"{FINDING_ID_PREFIX}{digest[:FINDING_ID_HEX_LENGTH]}"


class Finding(BaseModel):
    """One detected issue, as stored and as returned to the client."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    rule: str
    owasp: str
    severity: Severity
    confidence: Confidence
    endpoint: str
    evidence: str
    fix_hint: str = ""
    status: FindingStatus = FindingStatus.OPEN
    source: FindingSource = "static"

    @classmethod
    def from_rule(
        cls,
        meta: RuleMeta,
        endpoint: str,
        *,
        evidence: str,
        evidence_key: str | None = None,
        fix_hint: str = "",
        source: FindingSource = "static",
    ) -> Finding:
        """Build a finding from a rule's metadata.

        ``endpoint`` is the endpoint id (``"GET /users/{id}"``). ``evidence_key`` is
        the stable part of the evidence used for the id; it defaults to ``evidence``.
        Pass it explicitly when the evidence text contains details that may change
        between scans of the same issue.
        """
        key = evidence if evidence_key is None else evidence_key
        return cls(
            id=compute_finding_id(meta.id, endpoint, key),
            rule=meta.id,
            owasp=meta.owasp,
            severity=meta.severity,
            confidence=meta.confidence,
            endpoint=endpoint,
            evidence=evidence,
            fix_hint=fix_hint,
            source=source,
        )
