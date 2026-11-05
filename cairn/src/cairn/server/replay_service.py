"""Server-side glue between stored findings and the replay verification engine.

The engine in :mod:`cairn.server.replay_validation` is deliberately free of any
database or framework imports.  This module is the part that knows about the
``audit_findings`` table and the per-project ``validation_targets`` row: it
loads a finding's verification plan and the project's lab target, runs the
replay, and writes the program's verdict back onto the finding.

A ``confirmed`` replay is the only way a finding reaches evidence level ``L4``:
it is the one grade that does not depend on any model's self-report, because the
server sent the requests and a program judged the responses.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit

from cairn.server import db
from cairn.server.replay_validation import (
    ReplayError,
    ValidationTarget,
    execute_plan,
    packet_from_result,
    validate_target_url,
)
from cairn.server.services import utcnow

REPLAY_CONFIRMED_EVIDENCE_LEVEL = "L4"
_EVIDENCE_RANK = {"L0": 0, "L1": 1, "L2": 2, "L3": 3, "L4": 4, "L5": 5}

SENSITIVE_PROFILE_HINT = ("cookie", "authorization", "token", "secret", "api-key", "apikey", "session", "password")


class TargetConfigError(Exception):
    """Raised when a validation-target configuration is invalid."""


# --------------------------------------------------------------------------
# Target configuration CRUD
# --------------------------------------------------------------------------


def _coerce_profiles(raw: Any) -> dict[str, dict[str, Any]]:
    if raw in (None, {}):
        return {}
    if not isinstance(raw, dict):
        raise TargetConfigError("profiles must be an object of {name: {headers: {...}}}")
    profiles: dict[str, dict[str, Any]] = {}
    for name, spec in raw.items():
        key = str(name).strip()
        if not key:
            raise TargetConfigError("profile names must be non-empty")
        if not isinstance(spec, dict):
            raise TargetConfigError(f"profile {key!r} must be an object")
        headers = spec.get("headers") or {}
        if not isinstance(headers, dict):
            raise TargetConfigError(f"profile {key!r} headers must be an object")
        profiles[key] = {"headers": {str(h): str(v) for h, v in headers.items()}}
    return profiles


def normalize_target_config(config: Any) -> dict[str, Any]:
    """Validate an incoming target config and return a stored-shape dict."""
    if not isinstance(config, dict):
        raise TargetConfigError("target configuration must be an object")
    base_url = config.get("base_url")
    try:
        base_url = validate_target_url(str(base_url or ""))
    except ReplayError as exc:
        raise TargetConfigError(str(exc)) from exc
    callback = config.get("callback") or {}
    if callback and not isinstance(callback, dict):
        raise TargetConfigError("callback must be an object")
    return {
        "base_url": base_url,
        "allow_state_changing": bool(config.get("allow_state_changing", False)),
        "profiles": _coerce_profiles(config.get("profiles")),
        "callback": {str(k): v for k, v in callback.items()} if callback else {},
    }


def redact_target_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy safe to send to a browser: credential values are masked."""
    profiles = {}
    for name, spec in (config.get("profiles") or {}).items():
        headers = {}
        for header, value in (spec.get("headers") or {}).items():
            lowered = header.lower()
            headers[header] = "***" if any(part in lowered for part in SENSITIVE_PROFILE_HINT) else value
        profiles[name] = {"headers": headers}
    return {
        "base_url": config.get("base_url"),
        "allow_state_changing": bool(config.get("allow_state_changing", False)),
        "profiles": profiles,
        "callback": config.get("callback") or {},
    }


def set_validation_target(project_id: str, config: Any, *, updated_by: str) -> dict[str, Any]:
    stored = normalize_target_config(config)
    now = utcnow()
    with db.get_conn() as conn:
        row = conn.execute("SELECT id FROM projects WHERE id = ?", (project_id,)).fetchone()
        if row is None:
            raise TargetConfigError("project not found")
        conn.execute(
            """
            INSERT INTO validation_targets (project_id, config_json, updated_by, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(project_id) DO UPDATE SET
                config_json = excluded.config_json,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
            """,
            (project_id, json.dumps(stored, ensure_ascii=False), updated_by, now),
        )
    return stored


def get_validation_target(project_id: str) -> dict[str, Any] | None:
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT config_json FROM validation_targets WHERE project_id = ?",
            (project_id,),
        ).fetchone()
    if row is None:
        return None
    try:
        config = json.loads(row["config_json"])
    except json.JSONDecodeError:
        return None
    return config if isinstance(config, dict) else None


def delete_validation_target(project_id: str) -> bool:
    with db.get_conn() as conn:
        cursor = conn.execute("DELETE FROM validation_targets WHERE project_id = ?", (project_id,))
        return cursor.rowcount > 0


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def _target_from_config(config: dict[str, Any]) -> ValidationTarget:
    return ValidationTarget(
        base_url=str(config.get("base_url") or ""),
        allow_state_changing=bool(config.get("allow_state_changing", False)),
        profiles=config.get("profiles") or {},
        callback=config.get("callback") or {},
    )


def _max_level(current: str | None, candidate: str) -> str:
    if _EVIDENCE_RANK.get(candidate or "", -1) > _EVIDENCE_RANK.get(current or "", -1):
        return candidate
    return current or "L0"


def verify_finding(project_id: str, finding_id: str) -> dict[str, Any]:
    """Replay a finding's verification plan against the project target.

    Returns a status dict.  Never raises for the ordinary "can't run" cases
    (no plan, no target); those are reported as a status so the caller can
    surface them without treating them as server errors.
    """
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM audit_findings WHERE id = ? AND project_id = ?",
            (finding_id, project_id),
        ).fetchone()
        if row is None:
            return {"status": "finding_not_found"}
        try:
            plan = json.loads(row["verification_plan_json"] or "{}")
        except json.JSONDecodeError:
            plan = {}
        if not isinstance(plan, dict) or not plan:
            return {"status": "no_plan", "detail": "finding has no verification_plan"}

    config = get_validation_target(project_id)
    if not config:
        return {"status": "no_target", "detail": "no validation target configured for this project"}

    target = _target_from_config(config)
    result = execute_plan(plan, target)
    verdict = result.get("verdict")
    ran_at = utcnow()
    host = urlsplit(str(config.get("base_url") or "")).hostname or "target"

    with db.get_conn() as conn:
        current = conn.execute(
            "SELECT evidence_level, proof_packets_json FROM audit_findings WHERE id = ? AND project_id = ?",
            (finding_id, project_id),
        ).fetchone()
        if current is None:
            return {"status": "finding_not_found"}

        updates = {
            "replay_verdict": verdict,
            "replay_result_json": json.dumps(result, ensure_ascii=False),
            "replay_ran_at": ran_at,
        }
        evidence_level = current["evidence_level"]
        if verdict == "confirmed":
            packet = packet_from_result(result, host)
            if packet is not None:
                packets = _decode_list(current["proof_packets_json"])
                if not any(p.get("title") == packet["title"] and p.get("request") == packet["request"] for p in packets):
                    packets.append(packet)
                updates["proof_packets_json"] = json.dumps(packets, ensure_ascii=False)
            evidence_level = _max_level(current["evidence_level"], REPLAY_CONFIRMED_EVIDENCE_LEVEL)
            updates["evidence_level"] = evidence_level

        set_clause = ", ".join(f"{column} = ?" for column in updates)
        conn.execute(
            f"UPDATE audit_findings SET {set_clause} WHERE id = ? AND project_id = ?",
            (*updates.values(), finding_id, project_id),
        )

    return {
        "status": "ran",
        "verdict": verdict,
        "reason": result.get("reason"),
        "oracle": result.get("oracle"),
        "evidence_level": evidence_level,
        "checks": result.get("checks", []),
        "ran_at": ran_at,
    }


def _decode_list(raw: str | None) -> list:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []
