from __future__ import annotations

from cairn.server import db

# Product feature tables (vulnerability reports, and future product tables).
#
# These are additive: each statement uses ``CREATE ... IF NOT EXISTS`` so the
# DDL is idempotent and never touches the existing core ``SCHEMA`` in
# ``db.py``. This mirrors the pattern established by ``auth_db.py`` for the
# authentication tables.
#
# The ``vulnerabilities`` table materializes security findings extracted from
# project facts (see the vulnerability extraction service). It references
# ``projects(id)`` with ``ON DELETE CASCADE`` so deleting a project removes its
# vulnerabilities. The ``UNIQUE(project_id, fact_id)`` constraint lets the
# extraction service upsert findings keyed by their source fact without
# creating duplicates.
#
# The ``worker_task_history`` table records each task a worker has executed so
# the worker dashboard can show recent activity and derive health metrics
# (tasks completed, average duration). Rows are appended when a task finishes;
# ``completed_at`` and ``duration_seconds`` are nullable so an in-flight or
# abandoned task can still be recorded. The supporting indexes speed up the two
# dashboard access patterns: lookups by ``worker_name`` and ordering by
# ``completed_at``.
#
# The ``templates`` table stores user-created custom project templates. It
# references ``users(id)`` with ``ON DELETE CASCADE`` so removing a user removes
# their saved templates. The template's hints are serialized as a JSON array of
# ``{content, creator}`` objects in ``hints_json`` (defaulting to an empty
# array). Built-in templates are *not* stored here -- they live as a Python
# constant in ``templates_service.py``. The ``idx_templates_user`` index speeds
# up listing a single user's templates.
PRODUCT_SCHEMA = """\
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fact_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    discovered_at TEXT NOT NULL,
    source_intent_id TEXT,
    source_intent_description TEXT,
    source_worker TEXT,
    source_fact_ids_json TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    process_json TEXT NOT NULL DEFAULT '[]',
    proof_packets_json TEXT NOT NULL DEFAULT '[]',
    reproduction_poc_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'confirmed' CHECK(status IN ('confirmed', 'ignored')),
    UNIQUE(project_id, fact_id)
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_project
    ON vulnerabilities(project_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
    ON vulnerabilities(severity);

CREATE TABLE IF NOT EXISTS worker_task_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_name TEXT NOT NULL,
    project_id TEXT NOT NULL,
    task_type TEXT NOT NULL,
    intent_id TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_seconds REAL,
    outcome TEXT NOT NULL CHECK(outcome IN ('success', 'failed', 'rejected', 'released')),
    error_type TEXT,
    error_detail TEXT,
    rate_limited INTEGER NOT NULL DEFAULT 0,
    used_fallback INTEGER NOT NULL DEFAULT 0,
    stdout_preview TEXT,
    stderr_preview TEXT
);

CREATE INDEX IF NOT EXISTS idx_worker_history_worker
    ON worker_task_history(worker_name);
CREATE INDEX IF NOT EXISTS idx_worker_history_time
    ON worker_task_history(completed_at);

CREATE TABLE IF NOT EXISTS templates (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    origin TEXT NOT NULL,
    goal TEXT NOT NULL,
    hints_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_templates_user
    ON templates(user_id);

CREATE TABLE IF NOT EXISTS export_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    format TEXT NOT NULL,
    filename TEXT NOT NULL,
    scope TEXT NOT NULL,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    project_id TEXT,
    project_name TEXT,
    severity TEXT,
    status TEXT
);

CREATE INDEX IF NOT EXISTS idx_export_records_time
    ON export_records(created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    summary TEXT NOT NULL,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_log_time
    ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    body TEXT,
    link TEXT,
    read INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_notifications_time
    ON notifications(created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_read
    ON notifications(read);

CREATE TABLE IF NOT EXISTS source_snapshots (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source_type TEXT NOT NULL CHECK(source_type IN ('git', 'zip')),
    original_name TEXT,
    repository_url TEXT,
    requested_ref TEXT,
    resolved_commit TEXT,
    archive_sha256 TEXT,
    snapshot_sha256 TEXT,
    status TEXT NOT NULL CHECK(status IN ('importing', 'ready', 'failed')),
    file_count INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    detected_languages_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_source_snapshots_project
    ON source_snapshots(project_id, created_at);

CREATE TABLE IF NOT EXISTS code_files (
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    language TEXT,
    is_binary INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (snapshot_id, path)
);

CREATE INDEX IF NOT EXISTS idx_code_files_language
    ON code_files(snapshot_id, language);

CREATE TABLE IF NOT EXISTS code_symbols (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    language TEXT,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    container TEXT,
    signature TEXT,
    line_start INTEGER,
    line_end INTEGER
);

CREATE INDEX IF NOT EXISTS idx_code_symbols_snapshot
    ON code_symbols(snapshot_id, path, kind);
CREATE INDEX IF NOT EXISTS idx_code_symbols_name
    ON code_symbols(snapshot_id, name);

CREATE TABLE IF NOT EXISTS code_entrypoints (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    language TEXT,
    kind TEXT NOT NULL,
    framework TEXT,
    method TEXT,
    route TEXT NOT NULL,
    handler TEXT,
    line_start INTEGER,
    evidence TEXT
);

CREATE INDEX IF NOT EXISTS idx_code_entrypoints_snapshot
    ON code_entrypoints(snapshot_id, path, kind);
CREATE INDEX IF NOT EXISTS idx_code_entrypoints_route
    ON code_entrypoints(snapshot_id, route);

CREATE TABLE IF NOT EXISTS dependency_manifests (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    manifest_type TEXT NOT NULL,
    package_name TEXT,
    dependencies_json TEXT NOT NULL DEFAULT '[]',
    dev_dependencies_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_dependency_manifests_snapshot
    ON dependency_manifests(snapshot_id, manifest_type);

CREATE TABLE IF NOT EXISTS tool_findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    rule_id TEXT,
    severity TEXT NOT NULL DEFAULT 'info'
        CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK(status IN ('candidate', 'investigating', 'pending_review', 'confirmed', 'rejected', 'needs_more_evidence')),
    raw_artifact_path TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_findings_project
    ON tool_findings(project_id, snapshot_id, status);

CREATE TABLE IF NOT EXISTS audit_findings (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK(status IN ('candidate', 'investigating', 'pending_review', 'confirmed', 'rejected', 'needs_more_evidence')),
    cwe TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    symbol TEXT,
    entry_point TEXT,
    business_node_id TEXT REFERENCES business_nodes(id) ON DELETE SET NULL,
    description TEXT NOT NULL,
    impact TEXT,
    evidence TEXT,
    proof_packets_json TEXT NOT NULL DEFAULT '[]',
    reproduction_poc_json TEXT NOT NULL DEFAULT '{}',
    remediation TEXT,
    discovered_by TEXT NOT NULL,
    reviewed_by TEXT,
    created_at TEXT NOT NULL,
    reviewed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_findings_project
    ON audit_findings(project_id, snapshot_id, status, severity);

CREATE TABLE IF NOT EXISTS business_nodes (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    node_type TEXT NOT NULL
        CHECK(node_type IN (
            'feature', 'role', 'endpoint', 'data_object', 'state',
            'control', 'asset', 'risk', 'external_system'
        )),
    title TEXT NOT NULL,
    description TEXT,
    risk_level TEXT NOT NULL DEFAULT 'unknown'
        CHECK(risk_level IN ('critical', 'high', 'medium', 'low', 'unknown')),
    review_status TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK(review_status IN ('unreviewed', 'investigating', 'covered', 'blocked')),
    coverage_note TEXT,
    last_intent_id TEXT,
    risk_tags_json TEXT NOT NULL DEFAULT '[]',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_business_nodes_project
    ON business_nodes(project_id, node_type);

CREATE TABLE IF NOT EXISTS business_edges (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    from_node_id TEXT NOT NULL REFERENCES business_nodes(id) ON DELETE CASCADE,
    to_node_id TEXT NOT NULL REFERENCES business_nodes(id) ON DELETE CASCADE,
    relation TEXT NOT NULL
        CHECK(relation IN (
            'contains', 'exposes', 'calls', 'uses', 'owns',
            'guards', 'transitions_to', 'depends_on', 'risk_of', 'relates_to'
        )),
    description TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_business_edges_project
    ON business_edges(project_id, relation);

CREATE TABLE IF NOT EXISTS business_node_conclusions (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    business_node_id TEXT NOT NULL REFERENCES business_nodes(id) ON DELETE CASCADE,
    conclusion TEXT NOT NULL
        CHECK(conclusion IN ('confirmed_finding', 'rejected', 'needs_more_evidence')),
    summary TEXT NOT NULL,
    evidence TEXT,
    audit_finding_id TEXT REFERENCES audit_findings(id) ON DELETE SET NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_business_node_conclusions_project
    ON business_node_conclusions(project_id, business_node_id, created_at);

CREATE TABLE IF NOT EXISTS audit_candidates (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    candidate_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'unknown'
        CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    entry_point TEXT,
    symbol TEXT,
    tool_finding_id TEXT REFERENCES tool_findings(id) ON DELETE SET NULL,
    business_node_id TEXT REFERENCES business_nodes(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK(status IN ('candidate', 'investigating', 'confirmed', 'rejected', 'needs_more_evidence')),
    conclusion_summary TEXT,
    evidence TEXT,
    audit_finding_id TEXT REFERENCES audit_findings(id) ON DELETE SET NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    concluded_by TEXT,
    concluded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_candidates_project
    ON audit_candidates(project_id, snapshot_id, status, severity);
CREATE INDEX IF NOT EXISTS idx_audit_candidates_location
    ON audit_candidates(project_id, snapshot_id, file_path, line_start);

CREATE TABLE IF NOT EXISTS tool_scan_tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'running', 'completed', 'failed')),
    created_by TEXT NOT NULL,
    worker TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    last_heartbeat_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    tools_json TEXT NOT NULL DEFAULT '[]',
    timeout_per_tool INTEGER NOT NULL DEFAULT 180,
    summaries_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_tool_scan_tasks_project
    ON tool_scan_tasks(project_id, snapshot_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_tool_scan_tasks_status
    ON tool_scan_tasks(status, created_at);

CREATE TABLE IF NOT EXISTS dynamic_validation_plans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    status TEXT NOT NULL
        CHECK(status IN ('static_only', 'ready', 'blocked')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    summary TEXT NOT NULL,
    plan_json TEXT NOT NULL DEFAULT '{}',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE(project_id, snapshot_id)
);

CREATE INDEX IF NOT EXISTS idx_dynamic_validation_project
    ON dynamic_validation_plans(project_id, snapshot_id, status, updated_at);

CREATE TABLE IF NOT EXISTS report_enrichment_tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending', 'running', 'completed', 'failed')),
    created_by TEXT NOT NULL,
    worker TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    last_heartbeat_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    packet_templates_json TEXT NOT NULL DEFAULT '[]',
    reproduction_poc_json TEXT NOT NULL DEFAULT '{}',
    evidence_chain_json TEXT NOT NULL DEFAULT '[]',
    report_sections_json TEXT NOT NULL DEFAULT '{}',
    delivery_notes_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_report_enrichment_project
    ON report_enrichment_tasks(project_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_report_enrichment_finding
    ON report_enrichment_tasks(project_id, finding_id, status, created_at);
"""

VULNERABILITY_COLUMNS: dict[str, str] = {
    "source_intent_id": "TEXT",
    "source_intent_description": "TEXT",
    "source_worker": "TEXT",
    "source_fact_ids_json": "TEXT NOT NULL DEFAULT '[]'",
    "evidence_json": "TEXT NOT NULL DEFAULT '[]'",
    "process_json": "TEXT NOT NULL DEFAULT '[]'",
    "proof_packets_json": "TEXT NOT NULL DEFAULT '[]'",
    "reproduction_poc_json": "TEXT NOT NULL DEFAULT '{}'",
    "status": "TEXT NOT NULL DEFAULT 'confirmed'",
}


AUDIT_FINDING_COLUMNS: dict[str, str] = {
    "symbol": "TEXT",
    "entry_point": "TEXT",
    "business_node_id": "TEXT REFERENCES business_nodes(id) ON DELETE SET NULL",
    "proof_packets_json": "TEXT NOT NULL DEFAULT '[]'",
    "reproduction_poc_json": "TEXT NOT NULL DEFAULT '{}'",
}

BUSINESS_NODE_COLUMNS: dict[str, str] = {
    "risk_level": (
        "TEXT NOT NULL DEFAULT 'unknown' "
        "CHECK(risk_level IN ('critical', 'high', 'medium', 'low', 'unknown'))"
    ),
    "review_status": (
        "TEXT NOT NULL DEFAULT 'unreviewed' "
        "CHECK(review_status IN ('unreviewed', 'investigating', 'covered', 'blocked'))"
    ),
    "coverage_note": "TEXT",
    "last_intent_id": "TEXT",
}

WORKER_TASK_HISTORY_COLUMNS: dict[str, str] = {
    "error_type": "TEXT",
    "error_detail": "TEXT",
    "rate_limited": "INTEGER NOT NULL DEFAULT 0",
    "used_fallback": "INTEGER NOT NULL DEFAULT 0",
    "stdout_preview": "TEXT",
    "stderr_preview": "TEXT",
}

REPORT_ENRICHMENT_COLUMNS: dict[str, str] = {
    "packet_templates_json": "TEXT NOT NULL DEFAULT '[]'",
    "reproduction_poc_json": "TEXT NOT NULL DEFAULT '{}'",
    "evidence_chain_json": "TEXT NOT NULL DEFAULT '[]'",
    "report_sections_json": "TEXT NOT NULL DEFAULT '{}'",
    "delivery_notes_json": "TEXT NOT NULL DEFAULT '[]'",
}


def _ensure_vulnerability_columns(conn) -> None:
    existing = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(vulnerabilities)").fetchall()
    }
    for name, ddl in VULNERABILITY_COLUMNS.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE vulnerabilities ADD COLUMN {name} {ddl}")


def _ensure_columns(conn, table: str, columns: dict[str, str]) -> None:
    existing = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    for name, ddl in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def configure_product_db() -> None:
    """Run the product-feature schema DDL on the existing SQLite connection.

    This is additive: it creates the ``vulnerabilities``, ``worker_task_history``,
    and ``templates`` tables (and supporting indexes) if they do not already
    exist. It must be called after :func:`cairn.server.db.configure` so that the
    database connection is initialized, and after the core schema (which defines
    ``projects``) and the auth schema (which defines ``users``) so the foreign
    key targets exist.
    """
    with db.get_conn() as conn:
        conn.executescript(PRODUCT_SCHEMA)
        _ensure_vulnerability_columns(conn)
        _ensure_columns(conn, "audit_findings", AUDIT_FINDING_COLUMNS)
        _ensure_columns(conn, "business_nodes", BUSINESS_NODE_COLUMNS)
        _ensure_columns(conn, "worker_task_history", WORKER_TASK_HISTORY_COLUMNS)
        _ensure_columns(conn, "report_enrichment_tasks", REPORT_ENRICHMENT_COLUMNS)
        from cairn.server.services import sync_business_node_coverage_from_latest_conclusions

        sync_business_node_coverage_from_latest_conclusions(conn)
