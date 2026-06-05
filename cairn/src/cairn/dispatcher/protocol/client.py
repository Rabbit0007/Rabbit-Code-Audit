from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import logging
import threading

from pydantic import TypeAdapter
import requests
from requests.adapters import HTTPAdapter

from cairn.server.models import Intent, ProjectDetail, ProjectSummary, RuntimeInfo, Settings

LOG = logging.getLogger(__name__)


class ProtocolError(RuntimeError):
    def __init__(self, message: str, status_code: int, response_text: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


@dataclass(slots=True)
class ApiResult:
    status_code: int
    data: Any | None = None
    text: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class CairnClient:
    def __init__(self, base_url: str, timeout: float = 10.0):
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._summary_adapter = TypeAdapter(list[ProjectSummary])
        self._local = threading.local()
        self._sessions: dict[int, requests.Session] = {}
        self._sessions_lock = threading.Lock()

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()

    def list_projects(self) -> list[ProjectSummary]:
        response = self._session().get(self._url("/projects"), timeout=self._timeout)
        response.raise_for_status()
        return self._summary_adapter.validate_python(response.json())

    def get_project(self, project_id: str) -> ProjectDetail:
        response = self._session().get(self._url(f"/projects/{project_id}"), timeout=self._timeout)
        response.raise_for_status()
        return ProjectDetail.model_validate(response.json())

    def get_settings(self) -> Settings:
        response = self._session().get(self._url("/settings"), timeout=self._timeout)
        response.raise_for_status()
        return Settings.model_validate(response.json())

    def get_runtime_info(self) -> RuntimeInfo:
        response = self._session().get(self._url("/api/runtime"), timeout=self._timeout)
        response.raise_for_status()
        return RuntimeInfo.model_validate(response.json())

    def export_project(self, project_id: str, *, profile: str = "full", intent_id: str | None = None) -> str:
        params: dict[str, str] = {"format": "yaml", "profile": profile}
        if intent_id:
            params["intent_id"] = intent_id
        response = self._session().get(
            self._url(f"/projects/{project_id}/export"),
            params=params,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return response.text

    def heartbeat(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/heartbeat",
            json={"worker": worker},
        )

    def claim_reason(self, project_id: str, worker: str, trigger: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/claim",
            json={"worker": worker, "trigger": trigger},
        )

    def reason_heartbeat(self, project_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/heartbeat",
            json={"worker": worker},
        )

    def release_reason(self, project_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/reason/release",
            json={"worker": worker},
        )

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/release",
            json={"worker": worker},
        )

    def conclude(self, project_id: str, intent_id: str, worker: str, description: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents/{intent_id}/conclude",
            json={"worker": worker, "description": description},
        )

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/complete",
            json={"from": from_ids, "description": description, "worker": worker},
        )

    def create_intent(self, project_id: str, from_ids: list[str], description: str, creator: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/projects/{project_id}/intents",
            json={"from": from_ids, "description": description, "creator": creator, "worker": None},
        )

    def create_audit_finding(self, project_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/audit-findings",
            json=payload,
        )

    def list_audit_findings(self, project_id: str, status: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, str] = {}
        if status:
            params["status"] = status
        response = self._session().get(
            self._url(f"/api/projects/{project_id}/audit-findings"),
            params=params,
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def create_tool_finding(self, project_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/tool-findings",
            json=payload,
        )

    def create_audit_candidate(self, project_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/audit-candidates",
            json=payload,
        )

    def list_audit_candidates(self, project_id: str) -> list[dict[str, Any]]:
        response = self._session().get(
            self._url(f"/api/projects/{project_id}/audit-candidates"),
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def conclude_audit_candidate(
        self,
        project_id: str,
        candidate_id: str,
        reviewer: str,
        decision: str,
        summary: str,
        evidence: str | None = None,
        audit_finding_id: str | None = None,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/audit-candidates/{candidate_id}/conclude",
            json={
                "reviewer": reviewer,
                "decision": decision,
                "summary": summary,
                "evidence": evidence,
                "audit_finding_id": audit_finding_id,
            },
        )

    def create_business_node(self, project_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/business-graph/nodes",
            json=payload,
        )

    def create_business_edge(self, project_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/business-graph/edges",
            json=payload,
        )

    def create_business_node_conclusion(self, project_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/business-graph/conclusions",
            json=payload,
        )

    def review_audit_finding(
        self,
        project_id: str,
        finding_id: str,
        reviewer: str,
        decision: str,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/audit-findings/{finding_id}/review",
            json={"reviewer": reviewer, "decision": decision},
        )

    def record_worker_task_history(self, payload: dict[str, Any]) -> ApiResult:
        return self._request_json("POST", "/api/workers/history", json=payload)

    def list_pending_report_enrichments(self, project_id: str, limit: int = 10) -> list[dict[str, Any]]:
        response = self._session().get(
            self._url("/api/report-enrichments/pending"),
            params={"project_id": project_id, "limit": limit},
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def claim_report_enrichment(self, task_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/report-enrichments/{task_id}/claim",
            json={"worker": worker},
        )

    def report_enrichment_heartbeat(self, task_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/report-enrichments/{task_id}/heartbeat",
            json={"worker": worker},
        )

    def release_report_enrichment(self, task_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/report-enrichments/{task_id}/release",
            json={"worker": worker},
        )

    def complete_report_enrichment(self, task_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/report-enrichments/{task_id}/complete",
            json=payload,
        )

    def fail_report_enrichment(self, task_id: str, worker: str, error_message: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/report-enrichments/{task_id}/fail",
            json={"worker": worker, "error_message": error_message},
        )

    def get_report_enrichment_packet(self, task_id: str) -> dict[str, Any]:
        response = self._session().get(
            self._url(f"/api/report-enrichments/{task_id}/packet"),
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ProtocolError("report enrichment packet must be an object", response.status_code, response.text)
        return payload

    def list_tool_scan_tasks(
        self,
        project_id: str,
        *,
        snapshot_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, str] = {}
        if snapshot_id:
            params["snapshot_id"] = snapshot_id
        if status:
            params["status"] = status
        response = self._session().get(
            self._url(f"/api/projects/{project_id}/tool-scan-tasks"),
            params=params,
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def create_tool_scan_task(
        self,
        project_id: str,
        snapshot_id: str,
        *,
        created_by: str,
        tools: list[str],
        timeout_per_tool: int,
    ) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/projects/{project_id}/sources/{snapshot_id}/tool-scan-tasks",
            json={
                "created_by": created_by,
                "tools": tools,
                "timeout_per_tool": timeout_per_tool,
            },
        )

    def list_pending_tool_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        response = self._session().get(
            self._url("/api/tool-scans/pending"),
            params={"limit": limit},
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def claim_tool_scan(self, task_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/tool-scans/{task_id}/claim",
            json={"worker": worker},
        )

    def tool_scan_heartbeat(self, task_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/tool-scans/{task_id}/heartbeat",
            json={"worker": worker},
        )

    def release_tool_scan(self, task_id: str, worker: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/tool-scans/{task_id}/release",
            json={"worker": worker},
        )

    def complete_tool_scan(self, task_id: str, payload: dict[str, Any]) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/tool-scans/{task_id}/complete",
            json=payload,
        )

    def fail_tool_scan(self, task_id: str, worker: str, error_message: str) -> ApiResult:
        return self._request_json(
            "POST",
            f"/api/tool-scans/{task_id}/fail",
            json={"worker": worker, "error_message": error_message},
        )

    def get_tool_plan(self, project_id: str, snapshot_id: str) -> list[dict[str, Any]]:
        response = self._session().get(
            self._url(f"/api/projects/{project_id}/sources/{snapshot_id}/tool-plan"),
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def run_tool_scan(
        self,
        project_id: str,
        snapshot_id: str,
        *,
        timeout_per_tool: int,
        tools: list[str],
    ) -> list[dict[str, Any]]:
        response = self._session().post(
            self._url(f"/api/projects/{project_id}/sources/{snapshot_id}/tool-scan"),
            params={
                "timeout_per_tool": timeout_per_tool,
                "tools": ",".join(tools),
            },
            timeout=max(self._timeout, timeout_per_tool + 30),
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, list) else []

    def _request_json(self, method: str, path: str, json: dict[str, Any]) -> ApiResult:
        try:
            response = self._session().request(
                method,
                self._url(path),
                json=json,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            LOG.warning("request failed method=%s path=%s error=%s", method, path, exc)
            return ApiResult(status_code=0, text=str(exc))
        data: Any | None = None
        if response.headers.get("content-type", "").startswith("application/json"):
            data = response.json()
        return ApiResult(status_code=response.status_code, data=data, text=response.text)

    def _url(self, path: str) -> str:
        return f"{self._base_url}{path}"

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is not None:
            return session

        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=64, pool_maxsize=64, pool_block=False)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        self._local.session = session
        with self._sessions_lock:
            self._sessions[threading.get_ident()] = session
        return session
