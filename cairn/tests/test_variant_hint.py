"""Confirming a finding leaves a non-blocking variant-analysis hint.

A hint (advisory) is used rather than an audit candidate, so it never gates
completion. De-duplicated per finding.
"""

from __future__ import annotations

from cairn.server import db
from cairn.server.routers.findings import _record_variant_sweep_hint
from cairn.server.services import utcnow


def _project(project_id: str) -> None:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES (?, 'p', 'active', ?)",
            (project_id, utcnow()),
        )


def _finding_row(**overrides):
    base = {
        "id": "finding_x",
        "category": "sql_injection",
        "file_path": "app/search.py",
        "line_start": 12,
        "entry_point": "GET /search",
    }
    base.update(overrides)
    return base


def test_confirmation_creates_variant_hint(temp_db):
    _project("proj_v")
    with db.get_conn() as conn:
        _record_variant_sweep_hint(conn, "proj_v", _finding_row())
        rows = conn.execute(
            "SELECT content, creator, hint_type, target FROM hints WHERE project_id = ?",
            ("proj_v",),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["creator"] == "variant_analysis"
    assert rows[0]["hint_type"] == "focus"
    assert "变体分析" in rows[0]["content"]
    assert "finding_x" in rows[0]["content"]
    assert "app/search.py:12" in rows[0]["content"]


def test_variant_hint_is_deduped_per_finding(temp_db):
    _project("proj_v2")
    with db.get_conn() as conn:
        _record_variant_sweep_hint(conn, "proj_v2", _finding_row(id="finding_y"))
        _record_variant_sweep_hint(conn, "proj_v2", _finding_row(id="finding_y"))
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM hints WHERE project_id = ?", ("proj_v2",)
        ).fetchone()["c"]
    assert count == 1


def test_variant_hint_does_not_create_an_audit_candidate(temp_db):
    _project("proj_v3")
    with db.get_conn() as conn:
        _record_variant_sweep_hint(conn, "proj_v3", _finding_row(id="finding_z"))
        candidates = conn.execute(
            "SELECT COUNT(*) AS c FROM audit_candidates WHERE project_id = ?", ("proj_v3",)
        ).fetchone()["c"]
    assert candidates == 0  # advisory hint only; never gates completion


def test_variant_hint_handles_missing_location(temp_db):
    _project("proj_v4")
    with db.get_conn() as conn:
        _record_variant_sweep_hint(conn, "proj_v4", _finding_row(id="finding_w", file_path=None, line_start=None))
        row = conn.execute(
            "SELECT content FROM hints WHERE project_id = ?", ("proj_v4",)
        ).fetchone()
    assert row is not None
    assert "finding_w" in row["content"]
