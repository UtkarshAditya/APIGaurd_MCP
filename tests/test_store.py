from __future__ import annotations

import contextlib
import os
import sqlite3
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from apiguard.models import Confidence, FindingStatus, Severity
from apiguard.store import RUN_STATUSES, SCHEMA_VERSION, TABLES, Store

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not enforced")


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "data" / "apiguard.db")
    s.initialize()
    return s


@pytest.fixture
def conn(store: Store) -> Iterator[sqlite3.Connection]:
    with contextlib.closing(store.connect()) as c:
        yield c


def columns(conn: sqlite3.Connection, table: str) -> dict[str, sqlite3.Row]:
    return {row["name"]: row for row in conn.execute(f"PRAGMA table_info({table})")}


def seed_run(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO specs VALUES ('s1', 'demo', 'demo.yaml', 'abc', '3.0.3', 'now')")
    conn.execute(
        "INSERT INTO scan_runs (run_id, spec_id, started_at, ruleset_version, config_json) "
        "VALUES ('r1', 's1', 'now', '1', '{}')"
    )


def insert_finding(conn: sqlite3.Connection, **overrides: str) -> None:
    values = {
        "finding_id": "F-000001",
        "run_id": "r1",
        "rule": "API2-OPEN-OVERRIDE",
        "owasp": "API2:2023",
        "severity": "high",
        "confidence": "high",
        "endpoint_id": "DELETE /users/{id}",
        "evidence": "e",
        **overrides,
    }
    conn.execute(
        "INSERT INTO findings (finding_id, run_id, rule, owasp, severity, confidence, "
        "endpoint_id, evidence) VALUES (:finding_id, :run_id, :rule, :owasp, :severity, "
        ":confidence, :endpoint_id, :evidence)",
        values,
    )


def test_creates_file_parent_dirs_and_all_tables(store: Store, conn: sqlite3.Connection) -> None:
    assert store.path.is_file()
    names = {
        row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert set(TABLES) <= names
    assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_expected_columns(conn: sqlite3.Connection) -> None:
    assert {"spec_id", "source", "sha256", "openapi_version", "loaded_at"} <= set(
        columns(conn, "specs")
    )
    assert set(columns(conn, "endpoints")) == {"spec_id", "endpoint_id", "json"}
    assert {
        "run_id",
        "spec_id",
        "started_at",
        "ruleset_version",
        "config_json",
        "status",
        "progress",
    } <= set(columns(conn, "scan_runs"))
    assert {
        "finding_id",
        "run_id",
        "rule",
        "severity",
        "confidence",
        "endpoint_id",
        "evidence",
        "status",
    } <= set(columns(conn, "findings"))
    assert {"run_id", "ts", "method", "url", "status", "duration_ms", "actor"} <= set(
        columns(conn, "probe_log")
    )


def test_probe_log_actor_is_nullable(conn: sqlite3.Connection) -> None:
    assert columns(conn, "probe_log")["actor"]["notnull"] == 0
    conn.execute(
        "INSERT INTO probe_log (run_id, ts, method, url, status, duration_ms) "
        "VALUES ('p1', 'now', 'GET', 'http://localhost/x', 200, 3)"
    )
    assert conn.execute("SELECT actor FROM probe_log").fetchone()["actor"] is None


def test_scan_run_defaults_and_status_values(conn: sqlite3.Connection) -> None:
    seed_run(conn)
    row = conn.execute("SELECT status, progress FROM scan_runs").fetchone()
    assert (row["status"], row["progress"]) == ("submitted", 0)
    for status in RUN_STATUSES:
        conn.execute("UPDATE scan_runs SET status = ?", (status,))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE scan_runs SET status = 'paused'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE scan_runs SET progress = 1.5")


def test_finding_constraints_match_the_enums(conn: sqlite3.Connection) -> None:
    seed_run(conn)
    insert_finding(conn)
    for severity in Severity:
        conn.execute("UPDATE findings SET severity = ?", (severity.value,))
    for confidence in Confidence:
        conn.execute("UPDATE findings SET confidence = ?", (confidence.value,))
    for status in FindingStatus:
        conn.execute("UPDATE findings SET status = ?", (status.value,))
    for column in ("severity", "confidence", "status"):
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(f"UPDATE findings SET {column} = 'bogus'")  # noqa: S608


def test_foreign_keys_are_enforced(conn: sqlite3.Connection) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO endpoints VALUES ('no-such-spec', 'GET /x', '{}')")


def test_same_finding_id_may_recur_across_runs_but_not_within_one(
    conn: sqlite3.Connection,
) -> None:
    seed_run(conn)
    conn.execute(
        "INSERT INTO scan_runs (run_id, spec_id, started_at, ruleset_version, config_json) "
        "VALUES ('r2', 's1', 'later', '1', '{}')"
    )
    insert_finding(conn)
    insert_finding(conn, run_id="r2")
    with pytest.raises(sqlite3.IntegrityError):
        insert_finding(conn)


def test_initialize_is_idempotent_and_keeps_data(store: Store) -> None:
    with contextlib.closing(store.connect()) as c:
        seed_run(c)
        c.commit()
    store.initialize()
    store.initialize()
    with contextlib.closing(store.connect()) as c:
        assert c.execute("SELECT count(*) FROM specs").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM scan_runs").fetchone()[0] == 1


@posix_only
def test_new_database_file_is_owner_only(store: Store) -> None:
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


@posix_only
def test_existing_loose_permissions_are_tightened(tmp_path: Path) -> None:
    path = tmp_path / "apiguard.db"
    path.touch()
    path.chmod(0o644)
    Store(path).initialize()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@posix_only
def test_file_is_owner_only_even_with_a_permissive_umask(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        s = Store(tmp_path / "apiguard.db")
        s.initialize()
    finally:
        os.umask(old)
    assert stat.S_IMODE(s.path.stat().st_mode) == 0o600
