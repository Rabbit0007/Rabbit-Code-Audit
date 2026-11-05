"""Dispatcher auto-trigger of server-side replay, and plan sanitization.

Two independently testable pieces:
  * ``_sanitize_verification_plan`` / ``_validate_one_finding`` keep a well-formed
    plan and silently drop a malformed one so a bad plan never costs the finding;
  * ``_trigger_replay_verifications`` replays eligible findings, stops on 409
    (no target), and never raises.
"""

from __future__ import annotations

from types import SimpleNamespace

from cairn.dispatcher.contracts import _sanitize_verification_plan, _validate_one_finding
from cairn.dispatcher.tasks.explore import _trigger_replay_verifications

GOOD_PLAN = {"oracle": "sql_error", "requests": {"attack": {"path": "/x?q=1%27"}, "baseline": {"path": "/x?q=1"}}}
STATIC_POC = {
    "payload": "q=1'",
    "request_template": "curl 'http://target/x?q=1%27'",
    "steps": ["send it", "watch the error"],
    "expected_result": "a database error appears",
    "verification": "error only with the quote",
}


# --------------------------------------------------------------------------
# Plan sanitization
# --------------------------------------------------------------------------


def test_sanitize_keeps_wellformed_plan():
    assert _sanitize_verification_plan(GOOD_PLAN) == GOOD_PLAN


def test_sanitize_drops_bad_plans():
    assert _sanitize_verification_plan(None) == {}
    assert _sanitize_verification_plan({}) == {}
    assert _sanitize_verification_plan("nope") == {}
    assert _sanitize_verification_plan({"oracle": "magic", "requests": {"a": {}}}) == {}
    assert _sanitize_verification_plan({"oracle": "sql_error"}) == {}
    assert _sanitize_verification_plan({"oracle": "sql_error", "requests": {}}) == {}


def test_finding_keeps_good_plan():
    finding = _validate_one_finding(
        {"title": "t", "category": "sql injection", "severity": "medium", "description": "d", "verification_plan": GOOD_PLAN}
    )
    assert finding["verification_plan"] == GOOD_PLAN


def test_finding_survives_bad_plan():
    finding = _validate_one_finding(
        {"title": "t", "category": "sql injection", "severity": "medium", "description": "d",
         "verification_plan": {"oracle": "not-real", "requests": {"a": {}}}}
    )
    assert finding["verification_plan"] == {}


def test_high_finding_with_valid_proof_and_bad_plan_is_kept():
    finding = _validate_one_finding(
        {
            "title": "t", "category": "sql injection", "severity": "high", "description": "d",
            "file_path": "a.py", "line_start": 1, "entry_point": "GET /x", "impact": "read",
            "evidence": "concatenated SQL", "reproduction_poc": STATIC_POC,
            "verification_plan": {"oracle": "bogus"},
        }
    )
    assert finding["verification_plan"] == {}  # dropped, but the finding validated


# --------------------------------------------------------------------------
# Trigger helper
# --------------------------------------------------------------------------


class _Resp:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self.data = data if data is not None else {"verdict": "confirmed"}

    @property
    def ok(self):
        return 200 <= self.status_code < 300


class _Client:
    def __init__(self, by_id=None, raise_on=None):
        self.by_id = by_id or {}
        self.raise_on = raise_on
        self.calls: list[str] = []

    def replay_finding(self, project_id, finding_id):
        self.calls.append(finding_id)
        if self.raise_on == finding_id:
            raise RuntimeError("boom")
        return self.by_id.get(finding_id, _Resp())


def test_trigger_replays_every_eligible_finding():
    client = _Client()
    _trigger_replay_verifications(client, "p1", "worker-a", ["f1", "f2", "f3"])
    assert client.calls == ["f1", "f2", "f3"]


def test_trigger_stops_on_409_no_target():
    client = _Client(by_id={"f1": _Resp(409, {})})
    _trigger_replay_verifications(client, "p1", "worker-a", ["f1", "f2", "f3"])
    assert client.calls == ["f1"]  # stopped after learning there is no target


def test_trigger_continues_past_non_ok():
    client = _Client(by_id={"f1": _Resp(500, {})})
    _trigger_replay_verifications(client, "p1", "worker-a", ["f1", "f2"])
    assert client.calls == ["f1", "f2"]


def test_trigger_swallows_client_crash():
    client = _Client(raise_on="f1")
    # Must not raise: replay is best-effort and may never fail the explore task.
    _trigger_replay_verifications(client, "p1", "worker-a", ["f1", "f2"])
    assert client.calls == ["f1"]
