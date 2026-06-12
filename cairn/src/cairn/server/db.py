from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

DEFAULT_DB = Path.home() / ".local" / "share" / "cairn" / "cairn.db"

_db_path: Path | None = None

SCHEMA = """\
CREATE TABLE IF NOT EXISTS settings (
    intent_timeout INTEGER NOT NULL DEFAULT 15,
    reason_timeout INTEGER NOT NULL DEFAULT 15
);

INSERT OR IGNORE INTO settings (rowid, intent_timeout, reason_timeout) VALUES (1, 15, 15);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    reason_worker TEXT,
    reason_trigger TEXT,
    reason_started_at TEXT,
    reason_last_heartbeat_at TEXT
);

CREATE TABLE IF NOT EXISTS facts (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    fact_type TEXT NOT NULL DEFAULT 'observation',
    source TEXT NOT NULL DEFAULT 'worker',
    confidence REAL NOT NULL DEFAULT 0.7,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    parent_fact_ids_json TEXT NOT NULL DEFAULT '[]',
    fingerprint TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intents (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    to_fact_id TEXT,
    description TEXT NOT NULL,
    creator TEXT NOT NULL,
    worker TEXT,
    last_heartbeat_at TEXT,
    created_at TEXT NOT NULL,
    concluded_at TEXT,
    fingerprint TEXT,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open', 'claimed', 'completed', 'blocked', 'superseded', 'cooldown')),
    superseded_by TEXT,
    target_kind TEXT,
    target_id TEXT,
    objective TEXT,
    evidence_gap TEXT,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS intent_sources (
    intent_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    fact_id TEXT NOT NULL,
    PRIMARY KEY (intent_id, project_id, fact_id),
    FOREIGN KEY (intent_id, project_id) REFERENCES intents(id, project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TEXT NOT NULL,
    hint_type TEXT NOT NULL DEFAULT 'focus',
    target TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    max_uses INTEGER,
    use_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (id, project_id)
);

CREATE TABLE IF NOT EXISTS counters (
    name TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO counters (name, value) VALUES ('project', 0);

CREATE TABLE IF NOT EXISTS scoped_counters (
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, kind)
);
"""

FACT_COLUMNS: dict[str, str] = {
    "fact_type": "TEXT NOT NULL DEFAULT 'observation'",
    "source": "TEXT NOT NULL DEFAULT 'worker'",
    "confidence": "REAL NOT NULL DEFAULT 0.7",
    "evidence_refs_json": "TEXT NOT NULL DEFAULT '[]'",
    "parent_fact_ids_json": "TEXT NOT NULL DEFAULT '[]'",
    "fingerprint": "TEXT",
}

INTENT_COLUMNS: dict[str, str] = {
    "fingerprint": "TEXT",
    "status": (
        "TEXT NOT NULL DEFAULT 'open' "
        "CHECK(status IN ('open', 'claimed', 'completed', 'blocked', 'superseded', 'cooldown'))"
    ),
    "superseded_by": "TEXT",
    "target_kind": "TEXT",
    "target_id": "TEXT",
    "objective": "TEXT",
    "evidence_gap": "TEXT",
}

HINT_COLUMNS: dict[str, str] = {
    "hint_type": "TEXT NOT NULL DEFAULT 'focus'",
    "target": "TEXT",
    "priority": "INTEGER NOT NULL DEFAULT 0",
    "expires_at": "TEXT",
    "max_uses": "INTEGER",
    "use_count": "INTEGER NOT NULL DEFAULT 0",
}

CORE_INDEXES = (
    """
    CREATE INDEX IF NOT EXISTS idx_intents_project_fingerprint
        ON intents(project_id, fingerprint, to_fact_id)
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_intents_open_fingerprint_unique
        ON intents(project_id, fingerprint)
        WHERE fingerprint IS NOT NULL
          AND to_fact_id IS NULL
          AND status IN ('open', 'claimed', 'cooldown')
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_intents_project_status
        ON intents(project_id, status, created_at)
    """,
)


def configure(path: Path) -> None:
    global _db_path
    if _db_path is not None:
        return
    _db_path = path
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        _ensure_columns(conn, "facts", FACT_COLUMNS)
        _ensure_columns(conn, "intents", INTENT_COLUMNS)
        _ensure_columns(conn, "hints", HINT_COLUMNS)
        _backfill_core_metadata(conn)
        _ensure_indexes(conn)


def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
    existing = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def _backfill_core_metadata(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        UPDATE intents
        SET status = CASE
            WHEN to_fact_id IS NOT NULL OR concluded_at IS NOT NULL THEN 'completed'
            WHEN worker IS NOT NULL THEN 'claimed'
            ELSE 'open'
        END
        WHERE status IS NULL
           OR (status = 'open' AND (to_fact_id IS NOT NULL OR concluded_at IS NOT NULL))
           OR (status = 'open' AND worker IS NOT NULL)
        """
    )


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    for statement in CORE_INDEXES:
        conn.execute(statement)


def current_path() -> Path:
    return _db_path or DEFAULT_DB


@contextmanager
def get_conn() -> Generator[sqlite3.Connection, None, None]:
    assert _db_path is not None
    conn = sqlite3.connect(str(_db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
