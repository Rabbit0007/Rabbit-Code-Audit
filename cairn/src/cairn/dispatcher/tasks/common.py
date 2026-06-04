from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass

from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.models import TaskOutcome
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.heartbeat import HeartbeatLease
from cairn.dispatcher.runtime.process import ProcessResult
from cairn.server.models import ProjectDetail

HEALTHCHECK_COMMUNICATE_GRACE_SECONDS = 10
PROCESS_COMMUNICATE_GRACE_SECONDS = 15
LOG_PREVIEW_LIMIT = 1200
GRAPH_SNAPSHOT_ROOT = "/tmp/cairn-prompts"
RATE_LIMIT_RE = re.compile(
    r"(?:\b429\b|rate\s*limit|too\s*many\s*requests|quota|访问频率|频率过高|禁止访问|限流)",
    re.IGNORECASE,
)
LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class HealthcheckRun:
    result: ProcessResult
    duration_ms: int


@dataclass(slots=True)
class ConcludeWriteResult:
    status: str
    fact_id: str | None = None


@dataclass(slots=True)
class SourcePreflightResult:
    ok: bool
    source_path: str | None = None
    reason: str | None = None


def preview(text: str, limit: int = LOG_PREVIEW_LIMIT) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[:limit] + "..."


def is_rate_limited(*texts: str | None) -> bool:
    return any(text and RATE_LIMIT_RE.search(text) for text in texts)


def task_outcome(
    status: str,
    *,
    error_type: str | None = None,
    error_detail: str | None = None,
    result: ProcessResult | None = None,
    rate_limited: bool = False,
    used_fallback: bool = False,
) -> TaskOutcome:
    stdout_preview = preview(result.stdout) if result is not None and result.stdout else None
    stderr_preview = preview(result.stderr) if result is not None and result.stderr else None
    detail = preview(error_detail) if error_detail else None
    return TaskOutcome(
        status=status,
        error_type=error_type,
        error_detail=detail,
        rate_limited=rate_limited or is_rate_limited(detail, stdout_preview, stderr_preview),
        used_fallback=used_fallback,
        stdout_preview=stdout_preview,
        stderr_preview=stderr_preview,
    )


def did_timeout(result: ProcessResult) -> bool:
    return not result.cancelled and (result.timed_out or result.returncode in (124, 137))


def cancel_reason(result: ProcessResult, cancellation: TaskCancellation | None = None) -> str | None:
    if result.cancelled:
        return result.cancel_reason or "cancelled"
    if cancellation is not None:
        return cancellation.reason
    return None


def communicate_timeout(timeout_seconds: int, grace_seconds: int = PROCESS_COMMUNICATE_GRACE_SECONDS) -> int:
    return timeout_seconds + grace_seconds


def write_graph_snapshot_reference(
    container_manager: ContainerManager,
    container_name: str,
    graph_yaml: str,
    *,
    phase: str,
) -> str:
    path = f"{GRAPH_SNAPSHOT_ROOT}/{phase}-{uuid.uuid4().hex[:12]}/graph.yaml"
    container_manager.write_text_file(container_name, path, graph_yaml)
    return (
        "The graph YAML snapshot is stored in this file inside the current container:\n\n"
        f"{path}\n\n"
        "Before using the graph, read the entire file and treat its contents as the YAML snapshot "
        "for this Graph section."
    )


def latest_ready_source_path(project: ProjectDetail) -> str | None:
    ready = [source for source in project.sources if source.status == "ready"]
    if not ready:
        return None
    latest = ready[0]
    return f"/audit-data/artifacts/snapshots/{latest.id}/source"


def verify_latest_source_available(
    container_manager: ContainerManager,
    container_name: str,
    project: ProjectDetail,
    *,
    phase: str,
    worker_name: str,
) -> SourcePreflightResult:
    source_path = latest_ready_source_path(project)
    if source_path is None:
        reason = "no ready source snapshot is available"
        LOG.warning(
            "source preflight failed project=%s worker=%s phase=%s reason=%s",
            project.project.id,
            worker_name,
            phase,
            reason,
        )
        return SourcePreflightResult(ok=False, reason=reason)
    if container_manager.directory_exists(container_name, source_path):
        return SourcePreflightResult(ok=True, source_path=source_path)
    mount_detail = getattr(container_manager, "artifact_mount_description", lambda: "artifact mount unknown")()
    reason = (
        f"ready source snapshot is not readable in worker container at {source_path}; "
        f"check artifact_host_path/artifact_volume mount configuration ({mount_detail})"
    )
    LOG.warning(
        "source preflight failed project=%s worker=%s phase=%s source_path=%s reason=%s",
        project.project.id,
        worker_name,
        phase,
        source_path,
        reason,
    )
    return SourcePreflightResult(ok=False, source_path=source_path, reason=reason)


def run_healthcheck(
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    command: list[str],
    *,
    timeout_seconds: int,
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
) -> HealthcheckRun:
    process = container_manager.build_exec_process(
        container_name,
        dict(worker.env),
        command,
        timeout_seconds=timeout_seconds,
    )
    process.start()
    if lease is not None:
        lease.attach_process(process)
    if cancellation is not None:
        cancellation.attach_process(process)
    started = time.perf_counter()
    try:
        result = process.communicate(timeout=communicate_timeout(timeout_seconds, HEALTHCHECK_COMMUNICATE_GRACE_SECONDS))
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return HealthcheckRun(result=result, duration_ms=duration_ms)


def run_worker_process(
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    argv: list[str],
    *,
    phase: str,
    timeout_seconds: int,
    lease: HeartbeatLease | None = None,
    cancellation: TaskCancellation | None = None,
) -> ProcessResult:
    LOG.info(
        "starting container exec container=%s worker=%s phase=%s timeout=%ss",
        container_name,
        worker.name,
        phase,
        timeout_seconds,
    )
    process = container_manager.build_exec_process(
        container_name,
        dict(worker.env),
        argv,
        timeout_seconds=timeout_seconds,
    )
    process.start()
    if lease is not None:
        lease.attach_process(process)
    if cancellation is not None:
        cancellation.attach_process(process)
    try:
        return process.communicate(timeout=communicate_timeout(timeout_seconds))
    finally:
        if lease is not None:
            lease.attach_process(None)
        if cancellation is not None:
            cancellation.attach_process(None)


def project_allows_conclude_fallback(client: CairnClient, project_id: str, *, worker_name: str, intent_id: str) -> bool:
    project = client.get_project(project_id)
    if project.project.status == "active":
        return True
    LOG.info(
        "skip conclude fallback because project is no longer active project=%s intent=%s worker=%s status=%s",
        project_id,
        intent_id,
        worker_name,
        project.project.status,
    )
    return False


def best_effort_release_reason(client: CairnClient, project_id: str, worker_name: str) -> None:
    response = client.release_reason(project_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "reason release failed project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released reason project=%s worker=%s", project_id, worker_name)
    else:
        LOG.info(
            "reason release skipped project=%s worker=%s status=%s",
            project_id,
            worker_name,
            response.status_code,
        )


def write_conclude_result(
    client: CairnClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
) -> str:
    return write_conclude_result_with_fact_id(
        client,
        project_id,
        intent_id,
        worker_name,
        description,
        source=source,
        phase_ms=phase_ms,
        total_ms=total_ms,
    ).status


def write_conclude_result_with_fact_id(
    client: CairnClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    description: str,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
) -> ConcludeWriteResult:
    response = client.conclude(project_id, intent_id, worker_name, description)
    if response.ok:
        fact_id: str | None = None
        if isinstance(response.data, dict):
            fact = response.data.get("fact")
            if isinstance(fact, dict):
                candidate = fact.get("id")
                if isinstance(candidate, str) and candidate:
                    fact_id = candidate
        if total_ms is None:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
            )
        else:
            LOG.info(
                "intent concluded project=%s intent=%s worker=%s source=%s phase_ms=%s total_ms=%s",
                project_id,
                intent_id,
                worker_name,
                source,
                phase_ms,
                total_ms,
            )
        return ConcludeWriteResult(status="success", fact_id=fact_id)
    if response.status_code == 403:
        LOG.info(
            "project became inactive during conclude project=%s intent=%s worker=%s",
            project_id,
            intent_id,
            worker_name,
        )
    else:
        LOG.warning(
            "conclude write failed project=%s intent=%s worker=%s status=%s body=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
            response.text,
        )
    best_effort_release(client, project_id, intent_id, worker_name)
    return ConcludeWriteResult(status="failed", fact_id=None)


def write_business_graph(
    client: CairnClient,
    project_id: str,
    worker_name: str,
    result_data: dict | None,
    *,
    source: str,
    last_intent_id: str | None = None,
) -> dict[str, str]:
    if not result_data:
        return {}

    ref_to_id: dict[str, str] = {}
    for node in result_data.get("business_nodes") or []:
        payload = {
            "node_type": node["node_type"],
            "title": node["title"],
            "description": node.get("description"),
            "risk_level": node.get("risk_level") or "unknown",
            "review_status": node.get("review_status") or "unreviewed",
            "coverage_note": node.get("coverage_note"),
            "last_intent_id": node.get("last_intent_id") or last_intent_id,
            "risk_tags": node.get("risk_tags") or [],
            "evidence": node.get("evidence") or [],
            "created_by": worker_name,
        }
        response = client.create_business_node(project_id, payload)
        if not response.ok:
            LOG.warning(
                "business node write failed project=%s worker=%s source=%s status=%s body=%s",
                project_id,
                worker_name,
                source,
                response.status_code,
                response.text,
            )
            continue
        node_id = response.data.get("id") if isinstance(response.data, dict) else None
        ref = node.get("ref")
        if isinstance(node_id, str) and isinstance(ref, str) and ref:
            ref_to_id[ref] = node_id

    for edge in result_data.get("business_edges") or []:
        from_node_id = ref_to_id.get(edge["from"], edge["from"])
        to_node_id = ref_to_id.get(edge["to"], edge["to"])
        payload = {
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "relation": edge["relation"],
            "description": edge.get("description"),
            "created_by": worker_name,
        }
        response = client.create_business_edge(project_id, payload)
        if not response.ok:
            LOG.warning(
                "business edge write failed project=%s worker=%s source=%s from=%s to=%s status=%s body=%s",
                project_id,
                worker_name,
                source,
                from_node_id,
                to_node_id,
                response.status_code,
                response.text,
            )
    return ref_to_id


def write_business_node_conclusions(
    client: CairnClient,
    project_id: str,
    worker_name: str,
    result_data: dict | None,
    ref_to_id: dict[str, str],
    *,
    source: str,
) -> None:
    if not result_data:
        return
    for conclusion in result_data.get("business_node_conclusions") or []:
        business_node_id = conclusion.get("business_node_id")
        business_node_ref = conclusion.get("business_node_ref")
        if isinstance(business_node_ref, str):
            business_node_id = ref_to_id.get(business_node_ref, business_node_id)
        if not isinstance(business_node_id, str) or not business_node_id:
            LOG.warning(
                "business node conclusion skipped without resolved node project=%s worker=%s source=%s ref=%s",
                project_id,
                worker_name,
                source,
                business_node_ref,
            )
            continue
        payload = {
            "business_node_id": business_node_id,
            "conclusion": conclusion["conclusion"],
            "summary": conclusion["summary"],
            "evidence": conclusion.get("evidence"),
            "audit_finding_id": conclusion.get("audit_finding_id"),
            "created_by": worker_name,
        }
        response = client.create_business_node_conclusion(project_id, payload)
        if not response.ok:
            LOG.warning(
                "business node conclusion write failed project=%s worker=%s source=%s node=%s status=%s body=%s",
                project_id,
                worker_name,
                source,
                business_node_id,
                response.status_code,
                response.text,
            )


def best_effort_release(client: CairnClient, project_id: str, intent_id: str, worker_name: str) -> None:
    response = client.release(project_id, intent_id, worker_name)
    if not response.ok and response.status_code not in (403, 409):
        LOG.warning(
            "release failed project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
    elif response.ok:
        LOG.info("released intent project=%s intent=%s worker=%s", project_id, intent_id, worker_name)
    else:
        LOG.info(
            "release skipped project=%s intent=%s worker=%s status=%s",
            project_id,
            intent_id,
            worker_name,
            response.status_code,
        )
