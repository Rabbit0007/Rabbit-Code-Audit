from __future__ import annotations

from cairn.server import product_db
from cairn.server.db import get_conn


def test_product_db_migrates_audit_finding_cluster_index_after_column_backfill(temp_db):
    with get_conn() as conn:
        conn.execute("DROP TABLE audit_findings")
        conn.execute(
            """
            CREATE TABLE audit_findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                snapshot_id TEXT NOT NULL REFERENCES source_snapshots(id) ON DELETE CASCADE,
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
            )
            """
        )

    product_db.configure_product_db()

    with get_conn() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_findings)").fetchall()}
        indexes = {row["name"] for row in conn.execute("PRAGMA index_list(audit_findings)").fetchall()}
    assert "cluster_key" in columns
    assert "idx_audit_findings_cluster" in indexes
