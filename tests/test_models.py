from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from apiguard.models import (
    Confidence,
    Finding,
    FindingStatus,
    RuleMeta,
    Severity,
    compute_finding_id,
)

META = RuleMeta(
    id="API2-OPEN-OVERRIDE",
    owasp="API2:2023",
    title="Empty security override",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
)


def test_enum_values_match_the_architecture_doc() -> None:
    assert [s.value for s in Severity] == ["critical", "high", "medium", "low", "info"]
    assert [c.value for c in Confidence] == ["high", "medium", "low"]
    assert [s.value for s in FindingStatus] == [
        "open",
        "confirmed",
        "false_positive",
        "accepted_risk",
    ]


def test_severity_rank_orders_most_severe_highest() -> None:
    ordered = sorted(Severity, key=lambda s: s.rank, reverse=True)
    assert ordered == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


def test_finding_id_format() -> None:
    assert re.fullmatch(r"F-[0-9a-f]{6}", compute_finding_id("R", "GET /x", "k"))


def test_finding_id_is_stable_across_runs() -> None:
    # A pinned value: changing the hashing scheme would orphan stored findings
    # and suppressions, so it must be a deliberate, visible change.
    found = compute_finding_id("API2-OPEN-OVERRIDE", "DELETE /users/{id}", "security=[]")
    assert found == "F-7a1f53"


def test_finding_id_changes_with_each_part() -> None:
    base = compute_finding_id("R1", "GET /x", "k")
    assert compute_finding_id("R2", "GET /x", "k") != base
    assert compute_finding_id("R1", "GET /y", "k") != base
    assert compute_finding_id("R1", "GET /x", "k2") != base


def test_finding_id_parts_cannot_bleed_into_each_other() -> None:
    assert compute_finding_id("ab", "c", "d") != compute_finding_id("a", "bc", "d")
    assert compute_finding_id("a", "bc", "d") != compute_finding_id("a", "b", "cd")


def test_from_rule_copies_metadata_and_defaults() -> None:
    f = Finding.from_rule(META, "DELETE /users/{id}", evidence="operation.security = []")
    assert f.rule == "API2-OPEN-OVERRIDE"
    assert f.owasp == "API2:2023"
    assert f.severity is Severity.HIGH
    assert f.confidence is Confidence.HIGH
    assert f.status is FindingStatus.OPEN
    assert f.source == "static"
    assert f.id == compute_finding_id(META.id, "DELETE /users/{id}", "operation.security = []")


def test_evidence_key_keeps_the_id_stable_when_evidence_text_varies() -> None:
    a = Finding.from_rule(META, "GET /x", evidence="3 fields exposed", evidence_key="fields")
    b = Finding.from_rule(META, "GET /x", evidence="4 fields exposed", evidence_key="fields")
    assert a.id == b.id
    assert a.evidence != b.evidence


def test_finding_serializes_to_the_documented_shape() -> None:
    f = Finding.from_rule(META, "DELETE /users/{id}", evidence="e", fix_hint="h")
    assert f.model_dump(mode="json") == {
        "id": f.id,
        "rule": "API2-OPEN-OVERRIDE",
        "owasp": "API2:2023",
        "severity": "high",
        "confidence": "high",
        "endpoint": "DELETE /users/{id}",
        "evidence": "e",
        "fix_hint": "h",
        "status": "open",
        "source": "static",
    }


def test_finding_rejects_unknown_values_and_is_immutable() -> None:
    f = Finding.from_rule(META, "GET /x", evidence="e")
    with pytest.raises(ValidationError):
        Finding.model_validate({**f.model_dump(), "severity": "catastrophic"})
    with pytest.raises(ValidationError):
        Finding.model_validate({**f.model_dump(), "extra": 1})
    with pytest.raises(ValidationError):
        f.status = FindingStatus.CONFIRMED  # type: ignore[misc]


def test_rule_meta_is_frozen() -> None:
    with pytest.raises(AttributeError):
        META.id = "other"  # type: ignore[misc]
