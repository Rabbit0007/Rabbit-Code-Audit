"""Replay evidence must reach the reviewer packet and the report provenance.

Both builders take a row-like mapping, so these are pure tests with dict rows.
"""

from __future__ import annotations

import json

from cairn.server.routers.findings import _report_process_steps
from cairn.server.routers.review_tasks import _finding_packet, _replay_summary


def _row(**overrides):
    base = {
        "id": "finding_1",
        "title": "SQLi",
        "category": "sql_injection",
        "severity": "high",
        "status": "pending_review",
        "cwe": "CWE-89",
        "file_path": "app/x.py",
        "line_start": 10,
        "line_end": 10,
        "symbol": "handler",
        "entry_point": "GET /x",
        "business_node_id": None,
        "description": "d",
        "impact": "read",
        "evidence": "concat SQL",
        "evidence_level": "L4",
        "proof_packets_json": "[]",
        "reproduction_poc_json": "{}",
        "verification_plan_json": json.dumps({"oracle": "sql_error", "requests": {"attack": {"path": "/x"}}}),
        "replay_verdict": "confirmed",
        "replay_result_json": json.dumps(
            {
                "verdict": "confirmed",
                "oracle": "sql_error",
                "reason": "db error only in attack",
                "ran_at": "2026-01-01T00:00:00Z",
                "checks": [
                    {"name": "baseline_has_no_sql_error", "passed": True, "detail": ""},
                    {"name": "attack_has_sql_error", "passed": True, "detail": "..."},
                ],
                "exchanges": [{"name": "attack", "response_excerpt": "x" * 5000}],
            }
        ),
        "remediation": "parameterize",
        "discovered_by": "worker-a",
        "reviewed_by": None,
    }
    base.update(overrides)
    return base


# --- reviewer packet ---------------------------------------------------------


def test_finding_packet_exposes_replay_evidence():
    packet = _finding_packet(_row())
    assert packet["evidence_level"] == "L4"
    assert packet["replay_verdict"] == "confirmed"
    assert packet["replay_summary"]["verdict"] == "confirmed"
    assert packet["replay_summary"]["oracle"] == "sql_error"
    assert {c["name"] for c in packet["replay_summary"]["checks"]} == {
        "baseline_has_no_sql_error",
        "attack_has_sql_error",
    }
    assert packet["verification_plan"]["oracle"] == "sql_error"


def test_replay_summary_is_compact_and_drops_bodies():
    summary = _replay_summary(_row()["replay_result_json"])
    # Only name/passed survive per check; response bodies are not carried.
    assert all(set(c.keys()) == {"name", "passed"} for c in summary["checks"])
    assert "exchanges" not in summary


def test_replay_summary_empty_when_no_result():
    assert _replay_summary(None) == {}
    assert _replay_summary("{}") == {}
    assert _replay_summary("not json") == {}


def test_finding_packet_without_replay_is_blank():
    packet = _finding_packet(_row(replay_verdict=None, replay_result_json="{}"))
    assert packet["replay_verdict"] is None
    assert packet["replay_summary"] == {}


# --- report provenance -------------------------------------------------------


def test_report_process_includes_server_replay_step_when_verdict_present():
    steps = _report_process_steps(_row(reviewed_by="worker-b"), "app/x.py:10")
    types = [s["type"] for s in steps]
    assert types == ["audit_finding", "independent_review", "server_replay"]
    replay_step = steps[-1]
    assert replay_step["description"] == "confirmed"
    assert replay_step["worker"] == "server_replay"


def test_report_process_omits_replay_step_without_verdict():
    steps = _report_process_steps(_row(replay_verdict=None), "app/x.py:10")
    assert [s["type"] for s in steps] == ["audit_finding", "independent_review"]
