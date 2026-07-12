from __future__ import annotations

import json

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

CREATE TABLE IF NOT EXISTS model_usage_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id TEXT NOT NULL,
    model TEXT NOT NULL,
    request_id TEXT,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    cached_prompt_tokens INTEGER NOT NULL DEFAULT 0,
    estimated INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_model_usage_project_time
    ON model_usage_records(project_id, created_at);

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
    status TEXT,
    content_sha256 TEXT
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
    project_id TEXT,
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
    project_id TEXT,
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
    line_end INTEGER,
    confidence REAL NOT NULL DEFAULT 0.8,
    source TEXT NOT NULL DEFAULT 'heuristic'
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
    evidence TEXT,
    confidence REAL NOT NULL DEFAULT 0.8,
    source TEXT NOT NULL DEFAULT 'heuristic'
);

CREATE INDEX IF NOT EXISTS idx_code_entrypoints_snapshot
    ON code_entrypoints(snapshot_id, path, kind);
CREATE INDEX IF NOT EXISTS idx_code_entrypoints_route
    ON code_entrypoints(snapshot_id, route);

CREATE TABLE IF NOT EXISTS code_relationships (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    from_path TEXT NOT NULL,
    from_symbol TEXT,
    to_path TEXT NOT NULL,
    to_symbol TEXT,
    relation TEXT NOT NULL
        CHECK(relation IN (
            'imports', 'calls', 'uses', 'references',
            'implements', 'implemented_by', 'extends', 'extended_by'
        )),
    evidence TEXT,
    confidence REAL NOT NULL DEFAULT 0.55,
    source TEXT NOT NULL DEFAULT 'heuristic',
    line_start INTEGER
);

CREATE INDEX IF NOT EXISTS idx_code_relationships_snapshot
    ON code_relationships(snapshot_id, from_path, relation);
CREATE INDEX IF NOT EXISTS idx_code_relationships_target
    ON code_relationships(snapshot_id, to_path, relation);

CREATE TABLE IF NOT EXISTS code_capabilities (
    id TEXT PRIMARY KEY,
    snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    symbol TEXT,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    evidence TEXT,
    risk_level TEXT NOT NULL DEFAULT 'unknown'
        CHECK(risk_level IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    risk_tags_json TEXT NOT NULL DEFAULT '[]',
    confidence REAL NOT NULL DEFAULT 0.65,
    source TEXT NOT NULL DEFAULT 'heuristic'
);

CREATE INDEX IF NOT EXISTS idx_code_capabilities_snapshot
    ON code_capabilities(snapshot_id, path, category);
CREATE INDEX IF NOT EXISTS idx_code_capabilities_risk
    ON code_capabilities(snapshot_id, risk_level, category);

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
    cluster_key TEXT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status TEXT NOT NULL DEFAULT 'candidate'
        CHECK(status IN ('candidate', 'investigating', 'pending_review', 'confirmed', 'rejected', 'needs_more_evidence')),
    evidence_level TEXT NOT NULL DEFAULT 'L0'
        CHECK(evidence_level IN ('L0', 'L1', 'L2', 'L3', 'L4', 'L5')),
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
    source_snapshot_id TEXT,
    semantic_key TEXT,
    graph_layer TEXT NOT NULL DEFAULT 'semantic'
        CHECK(graph_layer IN ('evidence', 'semantic', 'audit')),
    source_kind TEXT NOT NULL DEFAULT 'model'
        CHECK(source_kind IN ('static_index', 'model', 'human', 'mixed')),
    evidence_status TEXT NOT NULL DEFAULT 'unverified'
        CHECK(evidence_status IN ('source_backed', 'inferred', 'unverified')),
    contributors_json TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 1,
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
            'guards', 'transitions_to', 'depends_on', 'risk_of',
            'implements', 'implemented_by', 'extends', 'extended_by',
            'evidenced_by', 'relates_to'
        )),
    description TEXT,
    graph_layer TEXT NOT NULL DEFAULT 'semantic'
        CHECK(graph_layer IN ('evidence', 'semantic', 'audit')),
    source_kind TEXT NOT NULL DEFAULT 'model'
        CHECK(source_kind IN ('static_index', 'model', 'human', 'mixed')),
    contributors_json TEXT NOT NULL DEFAULT '[]',
    revision INTEGER NOT NULL DEFAULT 1,
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
    is_current INTEGER NOT NULL DEFAULT 1 CHECK(is_current IN (0, 1)),
    superseded_at TEXT,
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

CREATE TABLE IF NOT EXISTS review_tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN (
            'pending', 'running', 'waiting_for_reviewer',
            'blocked_no_independent_worker', 'completed', 'failed'
        )),
    created_by TEXT NOT NULL,
    excluded_workers_json TEXT NOT NULL DEFAULT '[]',
    worker TEXT,
    blocked_reason TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    last_heartbeat_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_review_tasks_project
    ON review_tasks(project_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_review_tasks_finding
    ON review_tasks(project_id, finding_id, status, created_at);

CREATE TABLE IF NOT EXISTS quality_benchmark_runs (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    snapshot_id TEXT REFERENCES source_snapshots(id) ON DELETE SET NULL,
    suite_name TEXT NOT NULL,
    expectations_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_quality_benchmark_project
    ON quality_benchmark_runs(project_id, created_at);

CREATE TABLE IF NOT EXISTS backup_records (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    label TEXT,
    integrity_status TEXT NOT NULL CHECK(integrity_status IN ('ok', 'failed')),
    created_at TEXT NOT NULL,
    verified_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_records_time
    ON backup_records(created_at);
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
    "cluster_key": "TEXT",
    "evidence_level": (
        "TEXT NOT NULL DEFAULT 'L0' "
        "CHECK(evidence_level IN ('L0', 'L1', 'L2', 'L3', 'L4', 'L5'))"
    ),
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
    "source_snapshot_id": "TEXT",
    "confidence": "REAL NOT NULL DEFAULT 0.7",
    "semantic_key": "TEXT",
    "graph_layer": (
        "TEXT NOT NULL DEFAULT 'semantic' "
        "CHECK(graph_layer IN ('evidence', 'semantic', 'audit'))"
    ),
    "source_kind": (
        "TEXT NOT NULL DEFAULT 'model' "
        "CHECK(source_kind IN ('static_index', 'model', 'human', 'mixed'))"
    ),
    "evidence_status": (
        "TEXT NOT NULL DEFAULT 'unverified' "
        "CHECK(evidence_status IN ('source_backed', 'inferred', 'unverified'))"
    ),
    "contributors_json": "TEXT NOT NULL DEFAULT '[]'",
    "revision": "INTEGER NOT NULL DEFAULT 1",
}

BUSINESS_EDGE_COLUMNS: dict[str, str] = {
    "confidence": "REAL NOT NULL DEFAULT 0.7",
    "graph_layer": (
        "TEXT NOT NULL DEFAULT 'semantic' "
        "CHECK(graph_layer IN ('evidence', 'semantic', 'audit'))"
    ),
    "source_kind": (
        "TEXT NOT NULL DEFAULT 'model' "
        "CHECK(source_kind IN ('static_index', 'model', 'human', 'mixed'))"
    ),
    "contributors_json": "TEXT NOT NULL DEFAULT '[]'",
    "revision": "INTEGER NOT NULL DEFAULT 1",
}

CODE_SYMBOL_COLUMNS: dict[str, str] = {
    "confidence": "REAL NOT NULL DEFAULT 0.8",
    "source": "TEXT NOT NULL DEFAULT 'heuristic'",
}

CODE_ENTRYPOINT_COLUMNS: dict[str, str] = {
    "confidence": "REAL NOT NULL DEFAULT 0.8",
    "source": "TEXT NOT NULL DEFAULT 'heuristic'",
}

CODE_CAPABILITY_COLUMNS: dict[str, str] = {
    "symbol": "TEXT",
    "line_end": "INTEGER",
    "risk_tags_json": "TEXT NOT NULL DEFAULT '[]'",
    "confidence": "REAL NOT NULL DEFAULT 0.65",
    "source": "TEXT NOT NULL DEFAULT 'heuristic'",
}

WORKER_TASK_HISTORY_COLUMNS: dict[str, str] = {
    "error_type": "TEXT",
    "error_detail": "TEXT",
    "rate_limited": "INTEGER NOT NULL DEFAULT 0",
    "used_fallback": "INTEGER NOT NULL DEFAULT 0",
    "stdout_preview": "TEXT",
    "stderr_preview": "TEXT",
    "model_call_count": "INTEGER NOT NULL DEFAULT 1",
    "estimated_input_tokens": "INTEGER NOT NULL DEFAULT 0",
}

AUDIT_LOG_COLUMNS: dict[str, str] = {
    "project_id": "TEXT",
}

NOTIFICATION_COLUMNS: dict[str, str] = {
    "project_id": "TEXT",
}

REPORT_ENRICHMENT_COLUMNS: dict[str, str] = {
    "packet_templates_json": "TEXT NOT NULL DEFAULT '[]'",
    "reproduction_poc_json": "TEXT NOT NULL DEFAULT '{}'",
    "evidence_chain_json": "TEXT NOT NULL DEFAULT '[]'",
    "report_sections_json": "TEXT NOT NULL DEFAULT '{}'",
    "delivery_notes_json": "TEXT NOT NULL DEFAULT '[]'",
}

REVIEW_TASK_COLUMNS: dict[str, str] = {
    "excluded_workers_json": "TEXT NOT NULL DEFAULT '[]'",
    "blocked_reason": "TEXT",
    "retry_count": "INTEGER NOT NULL DEFAULT 0",
}

EXPORT_RECORD_COLUMNS: dict[str, str] = {
    "content_sha256": "TEXT",
}

BUSINESS_NODE_CONCLUSION_COLUMNS: dict[str, str] = {
    "is_current": "INTEGER NOT NULL DEFAULT 1 CHECK(is_current IN (0, 1))",
    "superseded_at": "TEXT",
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


def _table_create_sql(conn, table: str) -> str:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    return str(row["sql"] or "") if row else ""


def _ensure_code_relationship_relation_values(conn) -> None:
    sql = _table_create_sql(conn, "code_relationships")
    if not sql or "implemented_by" in sql:
        return
    conn.executescript(
        """
        DROP INDEX IF EXISTS idx_code_relationships_snapshot;
        DROP INDEX IF EXISTS idx_code_relationships_target;
        ALTER TABLE code_relationships RENAME TO code_relationships_legacy;
        CREATE TABLE code_relationships (
            id TEXT PRIMARY KEY,
            snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
            from_path TEXT NOT NULL,
            from_symbol TEXT,
            to_path TEXT NOT NULL,
            to_symbol TEXT,
            relation TEXT NOT NULL
                CHECK(relation IN (
                    'imports', 'calls', 'uses', 'references',
                    'implements', 'implemented_by', 'extends', 'extended_by'
                )),
            evidence TEXT,
            confidence REAL NOT NULL DEFAULT 0.55,
            source TEXT NOT NULL DEFAULT 'heuristic',
            line_start INTEGER
        );
        INSERT OR IGNORE INTO code_relationships (
            id, snapshot_id, from_path, from_symbol, to_path, to_symbol,
            relation, evidence, confidence, source, line_start
        )
        SELECT
            id, snapshot_id, from_path, from_symbol, to_path, to_symbol,
            relation, evidence, confidence, source, line_start
        FROM code_relationships_legacy;
        DROP TABLE code_relationships_legacy;
        CREATE INDEX IF NOT EXISTS idx_code_relationships_snapshot
            ON code_relationships(snapshot_id, from_path, relation);
        CREATE INDEX IF NOT EXISTS idx_code_relationships_target
            ON code_relationships(snapshot_id, to_path, relation);
        """
    )


def _ensure_business_edge_relation_values(conn) -> None:
    sql = _table_create_sql(conn, "business_edges")
    if not sql or "evidenced_by" in sql:
        return
    conn.executescript(
        """
        DROP INDEX IF EXISTS idx_business_edges_project;
        DROP INDEX IF EXISTS idx_business_edges_identity;
        ALTER TABLE business_edges RENAME TO business_edges_legacy;
        CREATE TABLE business_edges (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            from_node_id TEXT NOT NULL REFERENCES business_nodes(id) ON DELETE CASCADE,
            to_node_id TEXT NOT NULL REFERENCES business_nodes(id) ON DELETE CASCADE,
            relation TEXT NOT NULL
                CHECK(relation IN (
                    'contains', 'exposes', 'calls', 'uses', 'owns',
                    'guards', 'transitions_to', 'depends_on', 'risk_of',
                    'implements', 'implemented_by', 'extends', 'extended_by',
                    'evidenced_by', 'relates_to'
                )),
            description TEXT,
            confidence REAL NOT NULL DEFAULT 0.7,
            graph_layer TEXT NOT NULL DEFAULT 'semantic'
                CHECK(graph_layer IN ('evidence', 'semantic', 'audit')),
            source_kind TEXT NOT NULL DEFAULT 'model'
                CHECK(source_kind IN ('static_index', 'model', 'human', 'mixed')),
            contributors_json TEXT NOT NULL DEFAULT '[]',
            revision INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        INSERT OR IGNORE INTO business_edges (
            id, project_id, from_node_id, to_node_id, relation,
            description, confidence, graph_layer, source_kind,
            contributors_json, revision, created_by, created_at
        )
        SELECT
            id, project_id, from_node_id, to_node_id, relation,
            description, confidence, graph_layer, source_kind,
            contributors_json, revision, created_by, created_at
        FROM business_edges_legacy;
        DROP TABLE business_edges_legacy;
        CREATE INDEX IF NOT EXISTS idx_business_edges_project
            ON business_edges(project_id, relation);
        """
    )


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
        _ensure_code_relationship_relation_values(conn)
        _ensure_columns(conn, "business_edges", BUSINESS_EDGE_COLUMNS)
        _ensure_business_edge_relation_values(conn)
        _ensure_vulnerability_columns(conn)
        _ensure_columns(conn, "audit_findings", AUDIT_FINDING_COLUMNS)
        _normalize_and_merge_audit_findings(conn)
        _ensure_audit_finding_indexes(conn)
        _ensure_columns(conn, "business_nodes", BUSINESS_NODE_COLUMNS)
        _ensure_columns(
            conn,
            "business_node_conclusions",
            BUSINESS_NODE_CONCLUSION_COLUMNS,
        )
        _ensure_business_node_conclusion_state(conn)
        _ensure_business_graph_indexes(conn)
        _ensure_columns(conn, "code_symbols", CODE_SYMBOL_COLUMNS)
        _ensure_columns(conn, "code_entrypoints", CODE_ENTRYPOINT_COLUMNS)
        _ensure_columns(conn, "code_capabilities", CODE_CAPABILITY_COLUMNS)
        _ensure_columns(conn, "worker_task_history", WORKER_TASK_HISTORY_COLUMNS)
        _ensure_columns(conn, "audit_log", AUDIT_LOG_COLUMNS)
        _ensure_columns(conn, "notifications", NOTIFICATION_COLUMNS)
        _ensure_columns(conn, "export_records", EXPORT_RECORD_COLUMNS)
        _ensure_columns(conn, "report_enrichment_tasks", REPORT_ENRICHMENT_COLUMNS)
        _backfill_failed_report_enrichments(conn)
        _ensure_columns(conn, "review_tasks", REVIEW_TASK_COLUMNS)
        from cairn.server.services import sync_business_node_coverage_from_latest_conclusions

        sync_business_node_coverage_from_latest_conclusions(conn)


def _ensure_audit_finding_indexes(conn) -> None:
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_findings_cluster
            ON audit_findings(project_id, snapshot_id, cluster_key, status)
        """
    )


def _backfill_failed_report_enrichments(conn) -> None:
    rows = conn.execute(
        """
        SELECT t.id, f.title, f.description, f.impact, f.evidence, f.remediation,
               f.proof_packets_json, f.reproduction_poc_json
        FROM report_enrichment_tasks t
        JOIN audit_findings f ON f.id = t.finding_id AND f.project_id = t.project_id
        WHERE t.status = 'failed' AND f.status = 'confirmed'
        """
    ).fetchall()
    for row in rows:
        proof_packets = _safe_json_value(row["proof_packets_json"], [])
        reproduction_poc = _safe_json_value(row["reproduction_poc_json"], {})
        evidence_chain = [
            value
            for value in (row["evidence"], row["impact"])
            if isinstance(value, str) and value.strip()
        ]
        report_sections = {
            "summary": row["description"] or row["title"],
            "impact": row["impact"] or "未单独记录影响说明",
            "evidence": row["evidence"] or "请按源码位置复核",
            "remediation": row["remediation"] or "根据根因补充输入校验、边界控制和安全 API",
            "generation_mode": "deterministic_static_fallback",
        }
        conn.execute(
            """
            UPDATE report_enrichment_tasks
            SET status = 'completed',
                completed_at = COALESCE(completed_at, CURRENT_TIMESTAMP),
                error_message = NULL,
                packet_templates_json = ?,
                reproduction_poc_json = ?,
                evidence_chain_json = ?,
                report_sections_json = ?,
                delivery_notes_json = ?
            WHERE id = ? AND status = 'failed'
            """,
            (
                json.dumps(proof_packets, ensure_ascii=False),
                json.dumps(reproduction_poc, ensure_ascii=False),
                json.dumps(evidence_chain, ensure_ascii=False),
                json.dumps(report_sections, ensure_ascii=False),
                json.dumps(
                    ["历史模型补全失败，已使用确定性静态证据生成，不代表动态抓包结果。"],
                    ensure_ascii=False,
                ),
                row["id"],
            ),
        )


def _safe_json_value(raw: str | None, default):
    if not raw:
        return default
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return default
    return value


def _normalize_and_merge_audit_findings(conn) -> None:
    """Canonicalize taxonomy and merge only exact source identities."""
    from cairn.server.finding_taxonomy import (
        canonical_cwe,
        canonical_finding_category,
        finding_cluster_key,
    )

    rows = conn.execute(
        """
        SELECT id, project_id, snapshot_id, category, cwe, file_path, symbol,
               line_start, entry_point, status, evidence_level, created_at
        FROM audit_findings
        ORDER BY project_id, snapshot_id, created_at, id
        """
    ).fetchall()
    groups: dict[tuple[str, str, str], list] = {}
    for row in rows:
        cwe = canonical_cwe(row["cwe"])
        category = canonical_finding_category(row["category"], cwe)
        cluster_key = finding_cluster_key(
            category=category,
            cwe=cwe,
            file_path=row["file_path"],
            symbol=row["symbol"],
            line_start=row["line_start"],
            entry_point=row["entry_point"],
        )
        conn.execute(
            "UPDATE audit_findings SET category = ?, cwe = ?, cluster_key = ? WHERE id = ?",
            (category, cwe, cluster_key, row["id"]),
        )
        if row["status"] != "rejected":
            groups.setdefault(
                (row["project_id"], row["snapshot_id"], cluster_key), []
            ).append(row)

    status_rank = {
        "confirmed": 5,
        "pending_review": 4,
        "needs_more_evidence": 3,
        "investigating": 2,
        "candidate": 1,
    }
    for duplicates in groups.values():
        if len(duplicates) < 2:
            continue
        survivor = max(
            duplicates,
            key=lambda row: (
                status_rank.get(row["status"], 0),
                _evidence_level_value(row["evidence_level"]),
                -duplicates.index(row),
            ),
        )
        for duplicate in duplicates:
            if duplicate["id"] == survivor["id"]:
                continue
            _replace_audit_finding_reference(conn, duplicate["id"], survivor["id"])
            conn.execute("DELETE FROM audit_findings WHERE id = ?", (duplicate["id"],))


def _evidence_level_value(value: str | None) -> int:
    if value and value.startswith("L") and value[1:].isdigit():
        return int(value[1:])
    return -1


def _replace_audit_finding_reference(conn, old_id: str, new_id: str) -> None:
    conn.execute(
        "UPDATE audit_candidates SET audit_finding_id = ? WHERE audit_finding_id = ?",
        (new_id, old_id),
    )
    conn.execute(
        "UPDATE business_node_conclusions SET audit_finding_id = ? WHERE audit_finding_id = ?",
        (new_id, old_id),
    )
    conn.execute(
        "UPDATE review_tasks SET finding_id = ? WHERE finding_id = ?",
        (new_id, old_id),
    )
    conn.execute(
        "UPDATE report_enrichment_tasks SET finding_id = ? WHERE finding_id = ?",
        (new_id, old_id),
    )


def _ensure_business_graph_indexes(conn) -> None:
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_business_nodes_semantic_key
            ON business_nodes(project_id, semantic_key)
            WHERE semantic_key IS NOT NULL
        """
    )
    conn.execute(
        """
        DELETE FROM business_edges
        WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM business_edges
            GROUP BY project_id, from_node_id, to_node_id, relation
        )
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_business_edges_identity
            ON business_edges(project_id, from_node_id, to_node_id, relation)
        """
    )


def _ensure_business_node_conclusion_state(conn) -> None:
    """Select one decisive current conclusion while retaining full history."""
    conn.execute("UPDATE business_node_conclusions SET is_current = 0")
    rows = conn.execute(
        """
        SELECT c.id, c.project_id, c.business_node_id
        FROM business_node_conclusions c
        LEFT JOIN audit_findings af
          ON af.id = c.audit_finding_id
         AND af.project_id = c.project_id
        ORDER BY
          c.project_id,
          c.business_node_id,
          CASE
            WHEN c.conclusion = 'confirmed_finding' AND af.status = 'confirmed' THEN 0
            WHEN c.conclusion = 'rejected' THEN 1
            WHEN c.conclusion = 'needs_more_evidence' THEN 2
            ELSE 3
          END,
          c.created_at DESC,
          c.rowid DESC
        """
    ).fetchall()
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (row["project_id"], row["business_node_id"])
        if key in seen:
            continue
        seen.add(key)
        conn.execute(
            """
            UPDATE business_node_conclusions
            SET is_current = 1, superseded_at = NULL
            WHERE id = ?
            """,
            (row["id"],),
        )
    conn.execute(
        """
        UPDATE business_node_conclusions
        SET superseded_at = COALESCE(superseded_at, created_at)
        WHERE is_current = 0
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_business_node_conclusions_current
        ON business_node_conclusions(project_id, business_node_id)
        WHERE is_current = 1
        """
    )
