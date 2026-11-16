"""SQLite store: database file creation and schema.

Only initialization lives here for now; query methods arrive with the features
that need them. Tokens, request bodies and response bodies are never stored.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

TABLES: tuple[str, ...] = ("specs", "endpoints", "scan_runs", "findings", "probe_log")

# scan_runs.status values map onto A2A task states (Phase 2).
RUN_STATUSES: tuple[str, ...] = ("submitted", "working", "input_required", "completed", "failed")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS specs (
    spec_id         TEXT PRIMARY KEY,
    name            TEXT,
    source          TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    openapi_version TEXT NOT NULL,
    loaded_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    spec_id     TEXT NOT NULL REFERENCES specs (spec_id) ON DELETE CASCADE,
    endpoint_id TEXT NOT NULL,
    json        TEXT NOT NULL,
    PRIMARY KEY (spec_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    run_id          TEXT PRIMARY KEY,
    spec_id         TEXT NOT NULL REFERENCES specs (spec_id) ON DELETE CASCADE,
    started_at      TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    config_json     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'submitted'
        CHECK (status IN ('submitted', 'working', 'input_required', 'completed', 'failed')),
    progress        REAL NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 1)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT NOT NULL,
    run_id      TEXT NOT NULL REFERENCES scan_runs (run_id) ON DELETE CASCADE,
    rule        TEXT NOT NULL,
    owasp       TEXT NOT NULL,
    severity    TEXT NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence  TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    endpoint_id TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    fix_hint    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'confirmed', 'false_positive', 'accepted_risk')),
    source      TEXT NOT NULL DEFAULT 'static' CHECK (source IN ('static', 'dynamic')),
    PRIMARY KEY (run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS probe_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    ts          TEXT NOT NULL,
    method      TEXT NOT NULL,
    url         TEXT NOT NULL,
    status      INTEGER,
    duration_ms INTEGER,
    actor       TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings (finding_id);
CREATE INDEX IF NOT EXISTS idx_scan_runs_spec_id ON scan_runs (spec_id);
CREATE INDEX IF NOT EXISTS idx_probe_log_run_id ON probe_log (run_id);
"""


class Store:
    """Repository over one local SQLite file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def initialize(self) -> None:
        """Create the database file and schema. Safe to call repeatedly.

        The file is created with owner-only permissions (0600) before SQLite
        opens it, and the mode is re-applied to a pre-existing file. On Windows
        ``chmod`` cannot express owner-only access, so the file relies on the
        ACL inherited from the user's profile directory.
        """
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)

        with contextlib.closing(self.connect()) as conn:
            conn.executescript(_SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION:d}")
            conn.commit()

    def connect(self) -> sqlite3.Connection:
        """Open a connection with foreign keys enforced. The caller closes it."""
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
