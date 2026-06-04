from __future__ import annotations

import re
from typing import Any

from cairn.dispatcher.output_parser import extract_json_object


BUSINESS_NODE_TYPES = {
    "feature",
    "role",
    "endpoint",
    "data_object",
    "state",
    "control",
    "asset",
    "risk",
    "external_system",
}
BUSINESS_NODE_TYPE_ALIASES = {
    "api": "endpoint",
    "api_endpoint": "endpoint",
    "route": "endpoint",
    "http_route": "endpoint",
    "controller": "endpoint",
    "actor": "role",
    "user": "role",
    "permission": "control",
    "auth": "control",
    "authorization": "control",
    "authentication": "control",
    "business_function": "feature",
    "business_logic": "feature",
    "business_process": "feature",
    "workflow": "feature",
    "module": "feature",
    "component": "feature",
    "service": "feature",
    "resource": "data_object",
    "entity": "data_object",
    "model": "data_object",
    "data": "data_object",
    "database": "data_object",
    "table": "data_object",
    "status": "state",
    "state_transition": "state",
    "trust_boundary": "control",
    "security_control": "control",
    "risk_point": "risk",
    "vulnerability": "risk",
    "threat": "risk",
    "third_party": "external_system",
    "external_service": "external_system",
    "integration": "external_system",
}

BUSINESS_EDGE_RELATIONS = {
    "contains",
    "exposes",
    "calls",
    "uses",
    "owns",
    "guards",
    "transitions_to",
    "depends_on",
    "risk_of",
    "relates_to",
}
BUSINESS_EDGE_RELATION_ALIASES = {
    "contain": "contains",
    "includes": "contains",
    "has": "contains",
    "part_of": "contains",
    "expose": "exposes",
    "exposed_by": "exposes",
    "entrypoint_for": "exposes",
    "route_to": "exposes",
    "routes_to": "exposes",
    "invoke": "calls",
    "invokes": "calls",
    "call": "calls",
    "use": "uses",
    "reads": "uses",
    "writes": "uses",
    "stores": "uses",
    "processes": "uses",
    "owner_of": "owns",
    "belongs_to": "owns",
    "protects": "guards",
    "validates": "guards",
    "checks": "guards",
    "authenticates": "guards",
    "authorizes": "guards",
    "requires": "depends_on",
    "depends": "depends_on",
    "impacts": "risk_of",
    "threatens": "risk_of",
    "vulnerable_to": "risk_of",
    "related_to": "relates_to",
    "maps_to": "relates_to",
    "implements": "relates_to",
    "supports": "relates_to",
}
BUSINESS_NODE_RISK_LEVELS = {"critical", "high", "medium", "low", "unknown"}
BUSINESS_NODE_REVIEW_STATUSES = {"unreviewed", "investigating", "covered", "blocked"}
BUSINESS_NODE_CONCLUSIONS = {"confirmed_finding", "rejected", "needs_more_evidence"}
BUSINESS_NODE_CONCLUSION_ALIASES = {
    "confirmed": "confirmed_finding",
    "finding": "confirmed_finding",
    "vulnerable": "confirmed_finding",
    "vulnerability": "confirmed_finding",
    "confirmed_vulnerability": "confirmed_finding",
    "no_finding": "rejected",
    "not_vulnerable": "rejected",
    "no_vulnerability": "rejected",
    "safe": "rejected",
    "not_exploitable": "rejected",
    "inconclusive": "needs_more_evidence",
    "unknown": "needs_more_evidence",
    "needs_evidence": "needs_more_evidence",
    "insufficient_evidence": "needs_more_evidence",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
AUDIT_CANDIDATE_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
AUDIT_CANDIDATE_STATUSES = {"confirmed", "rejected", "needs_more_evidence"}


def parse_json_output(stdout: str) -> dict[str, Any]:
    return extract_json_object(stdout)


def _unwrap_wrapped_payload(payload: dict[str, Any]) -> tuple[bool | None, dict[str, Any] | None]:
    accepted = payload.get("accepted")
    if accepted is False:
        return False, None
    if accepted is True:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return True, data
    return None, None


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _looks_like_reason_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys == {"complete"}:
        complete = payload["complete"]
        return isinstance(complete, dict) and "from" in complete and "description" in complete
    if keys == {"intents"}:
        return isinstance(payload["intents"], list)
    if keys == {"intent"}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    return False


def _looks_like_bootstrap_execute_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    optional = {"complete", "business_nodes", "business_edges"}
    if "fact" not in keys or not keys <= {"fact", *optional}:
        return False
    return _is_dict(payload.get("fact")) and (
        "complete" not in payload or _is_dict(payload.get("complete"))
    )


def _looks_like_bootstrap_conclude_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact"))


def _looks_like_explore_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    return "description" in keys and keys <= {
        "description",
        "tool_findings",
        "finding",
        "findings",
        "review",
        "reviews",
        "audit_candidates",
        "candidate_conclusions",
        "business_nodes",
        "business_edges",
        "business_node_conclusions",
    }


def _looks_like_report_enrichment_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    return bool(keys) and keys <= {
        "finding_id",
        "packet_templates",
        "reproduction_poc",
        "evidence_chain",
        "report_sections",
        "delivery_notes",
        "proof_packets",
    }


def _string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be an array")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field_name} at index {index} must be a non-empty string")
        text = item.strip()
        if text not in seen:
            result.append(text)
            seen.add(text)
    return result


def _normalize_business_node_type(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", "_").replace(" ", "_")
    if text in BUSINESS_NODE_TYPES:
        return text
    return BUSINESS_NODE_TYPE_ALIASES.get(text)


def _normalize_business_edge_relation(value: Any) -> str:
    if not isinstance(value, str):
        return "relates_to"
    text = value.strip().lower().replace("-", "_").replace(" ", "_")
    if text in BUSINESS_EDGE_RELATIONS:
        return text
    return BUSINESS_EDGE_RELATION_ALIASES.get(text, "relates_to")


def _normalize_business_node_conclusion(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", "_").replace(" ", "_")
    if text in BUSINESS_NODE_CONCLUSIONS:
        return text
    return BUSINESS_NODE_CONCLUSION_ALIASES.get(text)


def _validate_business_nodes(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("business_nodes must be an array")
    nodes: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"business node at index {index} must be an object")
        node_type = _normalize_business_node_type(item.get("node_type", item.get("type")))
        if node_type not in BUSINESS_NODE_TYPES:
            raise ValueError(f"business node at index {index} has invalid node_type")
        title = item.get("title")
        if not isinstance(title, str) or not title.strip():
            raise ValueError(f"business node at index {index} is missing title")
        description = item.get("description")
        if description is not None and not isinstance(description, str):
            raise ValueError(f"business node at index {index} description must be a string")
        risk_level = item.get("risk_level", "unknown")
        if risk_level not in BUSINESS_NODE_RISK_LEVELS:
            raise ValueError(f"business node at index {index} has invalid risk_level")
        review_status = item.get("review_status", "unreviewed")
        if review_status not in BUSINESS_NODE_REVIEW_STATUSES:
            raise ValueError(f"business node at index {index} has invalid review_status")
        coverage_note = item.get("coverage_note")
        if coverage_note is not None and not isinstance(coverage_note, str):
            raise ValueError(f"business node at index {index} coverage_note must be a string")
        last_intent_id = item.get("last_intent_id")
        if last_intent_id is not None and not isinstance(last_intent_id, str):
            raise ValueError(f"business node at index {index} last_intent_id must be a string")
        ref = item.get("ref")
        if ref is not None and (not isinstance(ref, str) or not ref.strip()):
            raise ValueError(f"business node at index {index} ref must be a non-empty string")
        node = {
            "node_type": node_type,
            "title": title.strip(),
            "description": description.strip() if isinstance(description, str) and description.strip() else None,
            "risk_level": risk_level,
            "review_status": review_status,
            "coverage_note": coverage_note.strip() if isinstance(coverage_note, str) and coverage_note.strip() else None,
            "last_intent_id": last_intent_id.strip() if isinstance(last_intent_id, str) and last_intent_id.strip() else None,
            "risk_tags": _string_list(item.get("risk_tags"), f"business node {index} risk_tags"),
            "evidence": _string_list(item.get("evidence"), f"business node {index} evidence"),
        }
        if isinstance(ref, str):
            node["ref"] = ref.strip()
        nodes.append(node)
    return nodes


def _validate_business_edges(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("business_edges must be an array")
    edges: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"business edge at index {index} must be an object")
        from_ref = item.get("from", item.get("from_node_id"))
        to_ref = item.get("to", item.get("to_node_id"))
        if not isinstance(from_ref, str) or not from_ref.strip():
            raise ValueError(f"business edge at index {index} is missing from")
        if not isinstance(to_ref, str) or not to_ref.strip():
            raise ValueError(f"business edge at index {index} is missing to")
        relation = _normalize_business_edge_relation(item.get("relation", "relates_to"))
        description = item.get("description")
        if description is not None and not isinstance(description, str):
            raise ValueError(f"business edge at index {index} description must be a string")
        edges.append(
            {
                "from": from_ref.strip(),
                "to": to_ref.strip(),
                "relation": relation,
                "description": description.strip() if isinstance(description, str) and description.strip() else None,
            }
        )
    return edges


def _validate_business_node_conclusions(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("business_node_conclusions must be an array")
    conclusions: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"business node conclusion at index {index} must be an object")
        business_node_id = item.get("business_node_id", item.get("node_id"))
        business_node_ref = item.get("business_node_ref", item.get("node_ref"))
        if business_node_id is not None and (
            not isinstance(business_node_id, str) or not business_node_id.strip()
        ):
            raise ValueError(
                f"business node conclusion at index {index} business_node_id must be a non-empty string"
            )
        if business_node_ref is not None and (
            not isinstance(business_node_ref, str) or not business_node_ref.strip()
        ):
            raise ValueError(
                f"business node conclusion at index {index} business_node_ref must be a non-empty string"
            )
        if business_node_id is None and business_node_ref is None:
            raise ValueError(
                f"business node conclusion at index {index} requires business_node_id or business_node_ref"
            )
        conclusion = _normalize_business_node_conclusion(item.get("conclusion", item.get("decision")))
        if conclusion not in BUSINESS_NODE_CONCLUSIONS:
            raise ValueError(f"business node conclusion at index {index} has invalid conclusion")
        summary = item.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError(f"business node conclusion at index {index} is missing summary")
        evidence = item.get("evidence")
        if evidence is not None and not isinstance(evidence, str):
            raise ValueError(f"business node conclusion at index {index} evidence must be a string")
        audit_finding_id = item.get("audit_finding_id", item.get("finding_id"))
        if audit_finding_id is not None and (
            not isinstance(audit_finding_id, str) or not audit_finding_id.strip()
        ):
            raise ValueError(
                f"business node conclusion at index {index} audit_finding_id must be a non-empty string"
            )
        if conclusion == "confirmed_finding" and not audit_finding_id:
            raise ValueError(
                f"business node conclusion at index {index} confirmed_finding requires audit_finding_id"
            )
        if conclusion in ("rejected", "needs_more_evidence") and (
            not isinstance(evidence, str) or not evidence.strip()
        ):
            raise ValueError(f"business node conclusion at index {index} {conclusion} requires evidence")
        conclusion_item = {
            "conclusion": conclusion,
            "summary": summary.strip(),
            "evidence": evidence.strip() if isinstance(evidence, str) and evidence.strip() else None,
            "audit_finding_id": audit_finding_id.strip() if isinstance(audit_finding_id, str) else None,
        }
        if isinstance(business_node_id, str):
            conclusion_item["business_node_id"] = business_node_id.strip()
        if isinstance(business_node_ref, str):
            conclusion_item["business_node_ref"] = business_node_ref.strip()
        conclusions.append(conclusion_item)
    return conclusions


def _validate_tool_findings(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("tool_findings must be an array")
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"tool finding at index {index} must be an object")
        required = ("tool_name", "title", "description")
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required):
            raise ValueError(f"tool finding at index {index} is missing required fields")
        if item.get("severity") is not None and item.get("severity") not in SEVERITIES:
            raise ValueError(f"tool finding at index {index} severity is invalid")
    return value


def _validate_one_finding(item: Any, index: int | None = None) -> dict[str, Any]:
    label = "finding" if index is None else f"finding at index {index}"
    if not isinstance(item, dict):
        raise ValueError(f"{label} must be an object")
    required = ("title", "category", "severity", "description")
    if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required):
        raise ValueError(f"{label} title, category, severity, and description are required")
    if item.get("severity") not in SEVERITIES:
        raise ValueError(f"{label} severity is invalid")
    proof_packets = _validate_proof_packets(item.get("proof_packets"), label)
    reproduction_poc = _validate_reproduction_poc(item.get("reproduction_poc"), label)
    item = {**item, "proof_packets": proof_packets, "reproduction_poc": reproduction_poc}
    if item["severity"] in ("critical", "high"):
        if not isinstance(item.get("file_path"), str) or not item["file_path"].strip():
            raise ValueError(f"high or critical {label} requires file_path")
        if not isinstance(item.get("line_start"), int) and (
            not isinstance(item.get("symbol"), str) or not item["symbol"].strip()
        ):
            raise ValueError(f"high or critical {label} requires line_start or symbol")
        for key in ("entry_point", "impact", "evidence"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"high or critical {label} requires {key}")
        if not (
            _has_complete_proof_packet(proof_packets)
            or _has_complete_reproduction_poc(reproduction_poc)
        ):
            raise ValueError(
                f"high or critical {label} requires complete proof_packets or reproduction_poc"
            )
    return item


_PROOF_PLACEHOLDER_RE = re.compile(
    r"(\.\.\.|未记录|待补充|需复测|placeholder|todo|example\.com|target\.local|"
    r"<\s*(?:target|host|hostname|payload|url|path|port|项目事实[^>]*|[^>]{0,20}待补充[^>]*)\s*>)",
    re.IGNORECASE,
)
_HTTP_REQUEST_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?",
    re.IGNORECASE | re.MULTILINE,
)
_HTTP_HOST_RE = re.compile(r"^Host:\s*\S+", re.IGNORECASE | re.MULTILINE)
_HTTP_RESPONSE_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+\d{3}\b", re.IGNORECASE | re.MULTILINE)


def _validate_proof_packets(value: Any, field_name: str) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field_name}.proof_packets must be an array")
    packets: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{field_name}.proof_packets at index {index} must be an object")
        normalized = {
            str(key): str(raw).strip()
            for key, raw in item.items()
            if raw is not None and str(raw).strip()
        }
        if normalized:
            packets.append(normalized)
    return packets


def _has_complete_proof_packet(proof_packets: list[dict[str, str]]) -> bool:
    return any(_is_complete_proof_packet(packet) for packet in proof_packets)


def _is_complete_proof_packet(packet: dict[str, str]) -> bool:
    title = str(packet.get("title") or "").strip()
    request = str(packet.get("request") or "").strip()
    response = str(packet.get("response") or "").strip()
    payload = str(packet.get("payload") or "").strip()
    note = str(packet.get("note") or packet.get("verification") or "").strip()
    if not title or not request or not response or not payload:
        return False
    combined = "\n".join([title, request, response, payload, note])
    if _PROOF_PLACEHOLDER_RE.search(combined):
        return False
    is_http_request = _HTTP_REQUEST_RE.search(request) is not None
    is_command = request.lstrip().startswith(("curl ", "python ", "python3 "))
    if not is_http_request and not is_command:
        return False
    if is_http_request and (_HTTP_HOST_RE.search(request) is None or _HTTP_RESPONSE_RE.search(response) is None):
        return False
    return True


def _validate_reproduction_poc(value: Any, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field_name}.reproduction_poc must be an object")
    normalized: dict[str, Any] = {}
    for key, raw in value.items():
        name = str(key).strip()
        if not name or raw is None:
            continue
        if isinstance(raw, list):
            items = [str(item).strip() for item in raw if str(item).strip()]
            if items:
                normalized[name] = items
            continue
        text = str(raw).strip()
        if text:
            normalized[name] = text
    return normalized


_STATIC_POC_PLACEHOLDER_RE = re.compile(r"(\.\.\.|未记录|待补充|placeholder|todo)", re.IGNORECASE)


def _has_complete_reproduction_poc(poc: dict[str, Any]) -> bool:
    payload = _poc_text(poc, "payload")
    request_template = (
        _poc_text(poc, "request_template")
        or _poc_text(poc, "curl")
        or _poc_text(poc, "command")
    )
    expected_result = _poc_text(poc, "expected_result") or _poc_text(poc, "expected_response")
    steps = _poc_list(poc, "steps")
    verification = _poc_text(poc, "verification")
    combined = "\n".join([payload, request_template, expected_result, verification, *steps])
    if _STATIC_POC_PLACEHOLDER_RE.search(combined):
        return False
    return bool(payload and request_template and expected_result and (steps or verification))


def _poc_text(poc: dict[str, Any], key: str) -> str:
    value = poc.get(key)
    return value.strip() if isinstance(value, str) else ""


def _poc_list(poc: dict[str, Any], key: str) -> list[str]:
    value = poc.get(key)
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _validate_findings(singular: Any, plural: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if singular is not None:
        findings.append(_validate_one_finding(singular))
    if plural is not None:
        if not isinstance(plural, list):
            raise ValueError("findings must be an array")
        for index, item in enumerate(plural):
            findings.append(_validate_one_finding(item, index))
    return findings


def _validate_one_review(item: Any, index: int | None = None) -> dict[str, Any]:
    label = "review" if index is None else f"review at index {index}"
    if not isinstance(item, dict):
        raise ValueError(f"{label} must be an object")
    if not isinstance(item.get("finding_id"), str) or not item["finding_id"].strip():
        raise ValueError(f"{label}.finding_id is required")
    if item.get("decision") not in ("confirmed", "rejected", "needs_more_evidence"):
        raise ValueError(f"{label}.decision is invalid")
    return {
        "finding_id": item["finding_id"].strip(),
        "decision": item["decision"],
    }


def _validate_reviews(singular: Any, plural: Any) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []
    if singular is not None:
        reviews.append(_validate_one_review(singular))
    if plural is not None:
        if not isinstance(plural, list):
            raise ValueError("reviews must be an array")
        for index, item in enumerate(plural):
            reviews.append(_validate_one_review(item, index))
    return reviews


def _validate_audit_candidates(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("audit_candidates must be an array")
    candidates: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"audit candidate at index {index} must be an object")
        required = ("candidate_type", "title", "description")
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required):
            raise ValueError(f"audit candidate at index {index} is missing required fields")
        severity = item.get("severity", "unknown")
        if severity not in AUDIT_CANDIDATE_SEVERITIES:
            raise ValueError(f"audit candidate at index {index} severity is invalid")
        source = item.get("source", "model")
        if not isinstance(source, str) or not source.strip():
            raise ValueError(f"audit candidate at index {index} source must be a non-empty string")
        ref = item.get("ref")
        if ref is not None and (not isinstance(ref, str) or not ref.strip()):
            raise ValueError(f"audit candidate at index {index} ref must be a non-empty string")
        line_start = item.get("line_start")
        line_end = item.get("line_end")
        if line_start is not None and (not isinstance(line_start, int) or line_start < 1):
            raise ValueError(f"audit candidate at index {index} line_start must be positive")
        if line_end is not None and (not isinstance(line_end, int) or line_end < 1):
            raise ValueError(f"audit candidate at index {index} line_end must be positive")
        candidate = {
            "source": source.strip(),
            "candidate_type": item["candidate_type"].strip(),
            "severity": severity,
            "title": item["title"].strip(),
            "description": item["description"].strip(),
            "file_path": _optional_string(item.get("file_path")),
            "line_start": line_start,
            "line_end": line_end,
            "entry_point": _optional_string(item.get("entry_point")),
            "symbol": _optional_string(item.get("symbol")),
            "tool_finding_id": _optional_string(item.get("tool_finding_id")),
            "business_node_id": _optional_string(item.get("business_node_id")),
        }
        if isinstance(ref, str):
            candidate["ref"] = ref.strip()
        candidates.append(candidate)
    return candidates


def _validate_candidate_conclusions(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("candidate_conclusions must be an array")
    conclusions: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"candidate conclusion at index {index} must be an object")
        candidate_id = item.get("candidate_id")
        candidate_ref = item.get("candidate_ref")
        if candidate_id is not None and (not isinstance(candidate_id, str) or not candidate_id.strip()):
            raise ValueError(f"candidate conclusion at index {index} candidate_id must be a non-empty string")
        if candidate_ref is not None and (not isinstance(candidate_ref, str) or not candidate_ref.strip()):
            raise ValueError(f"candidate conclusion at index {index} candidate_ref must be a non-empty string")
        if candidate_id is None and candidate_ref is None:
            raise ValueError(f"candidate conclusion at index {index} requires candidate_id or candidate_ref")
        decision = item.get("decision", item.get("status"))
        if decision not in AUDIT_CANDIDATE_STATUSES:
            raise ValueError(f"candidate conclusion at index {index} decision is invalid")
        summary = item.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError(f"candidate conclusion at index {index} is missing summary")
        evidence = item.get("evidence")
        if evidence is not None and not isinstance(evidence, str):
            raise ValueError(f"candidate conclusion at index {index} evidence must be a string")
        audit_finding_id = item.get("audit_finding_id", item.get("finding_id"))
        if audit_finding_id is not None and (
            not isinstance(audit_finding_id, str) or not audit_finding_id.strip()
        ):
            raise ValueError(f"candidate conclusion at index {index} audit_finding_id must be a non-empty string")
        if decision == "confirmed" and not audit_finding_id:
            raise ValueError(f"candidate conclusion at index {index} confirmed requires audit_finding_id")
        if decision in ("rejected", "needs_more_evidence") and (
            not isinstance(evidence, str) or not evidence.strip()
        ):
            raise ValueError(f"candidate conclusion at index {index} {decision} requires evidence")
        conclusion = {
            "decision": decision,
            "summary": summary.strip(),
            "evidence": evidence.strip() if isinstance(evidence, str) and evidence.strip() else None,
            "audit_finding_id": audit_finding_id.strip() if isinstance(audit_finding_id, str) else None,
        }
        if isinstance(candidate_id, str):
            conclusion["candidate_id"] = candidate_id.strip()
        if isinstance(candidate_ref, str):
            conclusion["candidate_ref"] = candidate_ref.strip()
        conclusions.append(conclusion)
    return conclusions


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("optional string field must be a string")
    text = value.strip()
    return text or None


def validate_reason_payload(
    payload: dict[str, Any], open_intents_empty: bool, max_intents: int,
) -> tuple[str, dict[str, Any] | list[dict[str, Any]] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_reason_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    complete = data.get("complete")
    intents = data.get("intents")
    # backward compat: accept singular "intent" key from LLMs
    if intents is None:
        singular = data.get("intent")
        if isinstance(singular, dict):
            intents = [singular]
    if complete is not None:
        if intents is not None:
            raise ValueError("complete and intents cannot coexist")
        if not isinstance(complete, dict) or "from" not in complete or "description" not in complete:
            raise ValueError("invalid complete payload")
        return "complete", complete
    if intents is not None:
        if not isinstance(intents, list):
            raise ValueError("intents must be an array")
        for i, intent in enumerate(intents):
            if not isinstance(intent, dict) or "from" not in intent or "description" not in intent:
                raise ValueError(f"invalid intent at index {i}")
        if not intents and open_intents_empty:
            raise ValueError("intents must not be empty when open_intents is empty")
        intents = intents[:max_intents]
        if not intents:
            return "noop", None
        return "intents", intents
    if open_intents_empty:
        raise ValueError("intents is required when open_intents is empty")
    return "noop", None


def validate_bootstrap_execute_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_execute_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")

    result: dict[str, Any] = {
        "fact_description": fact_description.strip(),
        "business_nodes": _validate_business_nodes(data.get("business_nodes")),
        "business_edges": _validate_business_edges(data.get("business_edges")),
    }
    complete = data.get("complete")
    if complete is None:
        return "fact", result
    if not isinstance(complete, dict):
        raise ValueError("complete must be an object")
    complete_description = complete.get("description")
    if not isinstance(complete_description, str) or not complete_description.strip():
        raise ValueError("complete.description is required")
    result["complete_description"] = complete_description.strip()
    return "complete", result


def validate_report_enrichment_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_report_enrichment_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    allowed = {
        "finding_id",
        "packet_templates",
        "reproduction_poc",
        "evidence_chain",
        "report_sections",
        "delivery_notes",
    }
    if "proof_packets" in data:
        raise ValueError("report enrichment must not emit proof_packets")
    extra = set(data) - allowed
    if extra:
        raise ValueError(f"unexpected keys in report enrichment payload: {', '.join(sorted(extra))}")
    packet_templates = _validate_packet_templates(data.get("packet_templates"))
    reproduction_poc = _validate_reproduction_poc(data.get("reproduction_poc"), "report_enrichment")
    evidence_chain = _string_list(data.get("evidence_chain"), "evidence_chain")
    delivery_notes = _string_list(data.get("delivery_notes"), "delivery_notes")
    report_sections = _validate_report_sections(data.get("report_sections"))
    if not packet_templates and not _has_complete_reproduction_poc(reproduction_poc):
        raise ValueError("report enrichment requires packet_templates or complete reproduction_poc")
    result = {
        "packet_templates": packet_templates,
        "reproduction_poc": reproduction_poc,
        "evidence_chain": evidence_chain,
        "report_sections": report_sections,
        "delivery_notes": delivery_notes,
    }
    finding_id = data.get("finding_id")
    if isinstance(finding_id, str) and finding_id.strip():
        result["finding_id"] = finding_id.strip()
    return "complete", result


def _validate_packet_templates(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("packet_templates must be an array")
    packets: list[dict[str, str]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"packet_templates at index {index} must be an object")
        if "response" in item:
            raise ValueError(f"packet_templates at index {index} must not contain observed response")
        normalized = {
            str(key): str(raw).strip()
            for key, raw in item.items()
            if raw is not None and str(raw).strip()
        }
        missing = [
            key
            for key in ("title", "request", "expected_result")
            if not normalized.get(key)
        ]
        if missing:
            raise ValueError(f"packet_templates at index {index} missing: {', '.join(missing)}")
        packets.append(normalized)
    return packets


def _validate_report_sections(value: Any) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("report_sections must be an object")
    result: dict[str, object] = {}
    for key, raw in value.items():
        name = str(key).strip()
        if not name or raw is None:
            continue
        if isinstance(raw, list):
            items = [str(item).strip() for item in raw if str(item).strip()]
            if items:
                result[name] = items
            continue
        text = str(raw).strip()
        if text:
            result[name] = text
    return result


def validate_bootstrap_conclude_payload(payload: dict[str, Any]) -> tuple[str, str | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_conclude_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    extra_keys = set(data) - {"fact", "complete"}
    if extra_keys:
        raise ValueError("unexpected keys in conclude payload")
    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")
    return "fact", fact_description.strip()


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_explore_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    finding = data.get("finding")
    findings = data.get("findings")
    review = data.get("review")
    reviews = data.get("reviews")
    tool_findings = _validate_tool_findings(data.get("tool_findings"))
    structured_findings = _validate_findings(finding, findings)
    structured_reviews = _validate_reviews(review, reviews)
    audit_candidates = _validate_audit_candidates(data.get("audit_candidates"))
    candidate_conclusions = _validate_candidate_conclusions(data.get("candidate_conclusions"))
    business_nodes = _validate_business_nodes(data.get("business_nodes"))
    business_edges = _validate_business_edges(data.get("business_edges"))
    business_node_conclusions = _validate_business_node_conclusions(
        data.get("business_node_conclusions")
    )
    if structured_findings and structured_reviews:
        raise ValueError("findings and reviews cannot coexist")
    return "fact", {
        "description": description.strip(),
        "tool_findings": tool_findings,
        "finding": structured_findings[0] if structured_findings else None,
        "findings": structured_findings,
        "review": structured_reviews[0] if structured_reviews else None,
        "reviews": structured_reviews,
        "audit_candidates": audit_candidates,
        "candidate_conclusions": candidate_conclusions,
        "business_nodes": business_nodes,
        "business_edges": business_edges,
        "business_node_conclusions": business_node_conclusions,
    }
