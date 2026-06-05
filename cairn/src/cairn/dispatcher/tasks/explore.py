from __future__ import annotations

import logging
import time

from cairn.dispatcher.config import DispatchConfig, WorkerConfig
from cairn.dispatcher.contracts import parse_json_output, validate_explore_payload
from cairn.dispatcher.prompting import load_prompt, render_prompt
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.heartbeat import HeartbeatLease
from cairn.dispatcher.models import TaskOutcome
from cairn.dispatcher.tasks.common import (
    best_effort_release,
    cancel_reason,
    did_timeout,
    project_allows_conclude_fallback,
    preview,
    run_healthcheck,
    run_worker_process,
    task_outcome,
    verify_latest_source_available,
    write_business_graph,
    write_business_node_conclusions,
    write_conclude_result,
    write_graph_snapshot_reference,
)
from cairn.dispatcher.workers.registry import get_driver
from cairn.server.models import Intent, ProjectDetail

LOG = logging.getLogger(__name__)


def run_explore_task(
    config: DispatchConfig,
    client: CairnClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    export_yaml: str,
    intent: Intent,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
) -> TaskOutcome:
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    healthcheck_timeout = config.runtime.healthcheck_timeout
    lease = HeartbeatLease.for_intent(client, project.project.id, intent.id, worker.name, config.runtime.interval)
    lease.start()
    try:
        container_name = container_manager.ensure_running(project.project.id)
        source_check = verify_latest_source_available(
            container_manager,
            container_name,
            project,
            phase="explore_preflight",
            worker_name=worker.name,
        )
        if not source_check.ok:
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return task_outcome("failed", error_type="source_preflight_failed", error_detail=source_check.reason)

        LOG.info(
            "starting container exec project=%s intent=%s worker=%s phase=explore_healthcheck timeout=%ss",
            project.project.id,
            intent.id,
            worker.name,
            healthcheck_timeout,
        )
        healthcheck = run_healthcheck(
            container_manager,
            container_name,
            worker,
            driver.build_healthcheck(worker),
            timeout_seconds=healthcheck_timeout,
            lease=lease,
            cancellation=cancellation,
        )
        cancelled = cancel_reason(healthcheck.result, cancellation)
        if cancelled is not None:
            LOG.info(
                "explore cancelled during healthcheck project=%s intent=%s worker=%s reason=%s",
                project.project.id,
                intent.id,
                worker.name,
                cancelled,
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=healthcheck.result)
        if lease.failure is not None:
            LOG.warning(
                "heartbeat lost during explore healthcheck project=%s intent=%s worker=%s status=%s",
                project.project.id,
                intent.id,
                worker.name,
                lease.failure.status_code,
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return task_outcome("failed", error_type="heartbeat_lost", error_detail=f"status={lease.failure.status_code}", result=healthcheck.result)
        healthcheck_error = driver.healthcheck_error(
            healthcheck.result.returncode,
            healthcheck.result.stdout,
            healthcheck.result.stderr,
        )
        if healthcheck_error is not None:
            LOG.warning(
                "worker unhealthy project=%s intent=%s worker=%s healthcheck_ms=%s error=%s",
                project.project.id,
                intent.id,
                worker.name,
                healthcheck.duration_ms,
                preview(healthcheck_error),
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return task_outcome("unhealthy", error_type="healthcheck_failed", error_detail=healthcheck_error, result=healthcheck.result)

        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "explore.md"),
            {
                "graph_yaml": write_graph_snapshot_reference(
                    container_manager,
                    container_name,
                    export_yaml.strip(),
                    phase="explore_execute",
                ),
                "intent_id": intent.id,
                "intent_description": intent.description,
            },
        )

        session = driver.prepare_session()
        execute = driver.build_execute(worker, prompt, session)
        session = execute.session
        execute_started = time.perf_counter()
        first = _run_process(
            container_manager,
            container_name,
            worker,
            execute.argv,
            phase="explore_execute",
            timeout=config.tasks.explore.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        session = driver.extract_session(session, first.stdout, first.stderr)
        cancelled = cancel_reason(first, cancellation)
        if cancelled is not None:
            LOG.info(
                "explore cancelled project=%s intent=%s worker=%s reason=%s execute_ms=%s",
                project.project.id,
                intent.id,
                worker.name,
                cancelled,
                execute_ms,
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=first)
        if lease.failure is not None:
            LOG.warning(
                "heartbeat lost during explore project=%s intent=%s worker=%s status=%s execute_ms=%s",
                project.project.id,
                intent.id,
                worker.name,
                lease.failure.status_code,
                execute_ms,
            )
            best_effort_release(client, project.project.id, intent.id, worker.name)
            return task_outcome("failed", error_type="heartbeat_lost", error_detail=f"status={lease.failure.status_code}", result=first)
        if not did_timeout(first) and first.returncode == 0:
            try:
                model_output = driver.extract_response_text(first.stdout, first.stderr)
                payload = parse_json_output(model_output)
                kind, result_data = validate_explore_payload(payload)
            except Exception as exc:
                LOG.warning(
                    "explore parse failed project=%s intent=%s worker=%s error=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                    project.project.id,
                    intent.id,
                    worker.name,
                    exc,
                    execute_ms,
                    int((time.perf_counter() - task_started) * 1000),
                    preview(first.stdout),
                    preview(first.stderr),
                )
                return _try_conclude_fallback(
                    config,
                    client,
                    container_manager,
                    container_name,
                    worker,
                    driver,
                    project.project.id,
                    intent,
                    export_yaml,
                    session,
                    lease,
                    cancellation,
                    cause_result=first,
                    cause_error_type="parse_failed",
                    cause_error_detail=str(exc),
                )
            if kind == "rejected":
                LOG.warning(
                    "explore rejected project=%s intent=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s",
                    project.project.id,
                    intent.id,
                    worker.name,
                    execute_ms,
                    int((time.perf_counter() - task_started) * 1000),
                    preview(first.stdout),
                )
                best_effort_release(client, project.project.id, intent.id, worker.name)
                return task_outcome("rejected", error_type="model_rejected", result=first)
            return _write_explore_result(
                client,
                project.project.id,
                intent.id,
                worker.name,
                result_data,
                source="explore_execute",
                phase_ms=execute_ms,
                total_ms=int((time.perf_counter() - task_started) * 1000),
            )
        if did_timeout(first):
            LOG.warning(
                "explore timed out project=%s intent=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                intent.id,
                worker.name,
                execute_ms,
                int((time.perf_counter() - task_started) * 1000),
                preview(first.stdout),
                preview(first.stderr),
            )
            return _try_conclude_fallback(
                config,
                client,
                container_manager,
                container_name,
                worker,
                driver,
                project.project.id,
                intent,
                export_yaml,
                session,
                lease,
                cancellation,
                cause_result=first,
                cause_error_type="timeout",
            )
        LOG.warning(
            "explore command failed project=%s intent=%s worker=%s code=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
            project.project.id,
            intent.id,
            worker.name,
            first.returncode,
            execute_ms,
            int((time.perf_counter() - task_started) * 1000),
            preview(first.stdout),
            preview(first.stderr),
        )
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return task_outcome("failed", error_type="command_failed", error_detail=f"returncode={first.returncode}", result=first)
    except Exception:
        LOG.exception("explore task crashed project=%s intent=%s worker=%s", project.project.id, intent.id, worker.name)
        best_effort_release(client, project.project.id, intent.id, worker.name)
        return task_outcome("failed", error_type="task_crashed")
    finally:
        lease.stop()


def _try_conclude_fallback(
    config: DispatchConfig,
    client: CairnClient,
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    driver,
    project_id: str,
    intent: Intent,
    export_yaml: str,
    session: str | None,
    lease: HeartbeatLease,
    cancellation: TaskCancellation,
    cause_result=None,
    cause_error_type: str | None = None,
    cause_error_detail: str | None = None,
) -> TaskOutcome:
    if not driver.supports_conclude() or not session:
        LOG.info(
            "conclude fallback unavailable project=%s intent=%s worker=%s supports_conclude=%s has_session=%s",
            project_id,
            intent.id,
            worker.name,
            driver.supports_conclude(),
            bool(session),
        )
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome(
            "failed",
            error_type=cause_error_type or "fallback_unavailable",
            error_detail=cause_error_detail,
            result=cause_result,
        )
    if lease.failure is not None:
        LOG.warning("conclude fallback skipped because heartbeat already lost project=%s intent=%s worker=%s", project_id, intent.id, worker.name)
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("failed", error_type="heartbeat_lost", result=cause_result)
    if cancellation.is_cancelled:
        LOG.info(
            "conclude fallback skipped because task was cancelled project=%s intent=%s worker=%s reason=%s",
            project_id,
            intent.id,
            worker.name,
            cancellation.reason,
        )
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("cancelled", error_type="cancelled", error_detail=cancellation.reason, result=cause_result)

    if not project_allows_conclude_fallback(
        client,
        project_id,
        worker_name=worker.name,
        intent_id=intent.id,
    ):
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("failed", error_type="fallback_project_inactive", result=cause_result)

    container_name = container_manager.ensure_running(project_id)

    prompt = render_prompt(
        load_prompt(config.runtime.prompt_group, "explore_conclude.md"),
        {
            "graph_yaml": write_graph_snapshot_reference(
                container_manager,
                container_name,
                export_yaml.strip(),
                phase="explore_conclude",
            ),
            "intent_id": intent.id,
            "intent_description": intent.description,
        },
    )
    conclude_argv = driver.build_conclude(worker, prompt, session)
    LOG.info("starting conclude fallback project=%s intent=%s worker=%s", project_id, intent.id, worker.name)
    conclude_started = time.perf_counter()
    result = _run_process(
        container_manager,
        container_name,
        worker,
        conclude_argv,
        phase="explore_conclude",
        timeout=config.tasks.explore.conclude_timeout,
        lease=lease,
        cancellation=cancellation,
    )
    conclude_ms = int((time.perf_counter() - conclude_started) * 1000)
    cancelled = cancel_reason(result, cancellation)
    if cancelled is not None:
        LOG.info(
            "conclude cancelled project=%s intent=%s worker=%s reason=%s conclude_ms=%s",
            project_id,
            intent.id,
            worker.name,
            cancelled,
            conclude_ms,
        )
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=result, used_fallback=True)
    if lease.failure is not None:
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("failed", error_type="heartbeat_lost", result=result, used_fallback=True)
    if result.timed_out or result.returncode != 0:
        LOG.warning(
            "conclude failed project=%s intent=%s worker=%s code=%s timed_out=%s conclude_ms=%s stdout_preview=%s stderr_preview=%s",
            project_id,
            intent.id,
            worker.name,
            result.returncode,
            result.timed_out,
            conclude_ms,
            preview(result.stdout),
            preview(result.stderr),
        )
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome(
            "failed",
            error_type="fallback_command_failed",
            error_detail=f"returncode={result.returncode} timed_out={result.timed_out}",
            result=result,
            used_fallback=True,
        )
    try:
        model_output = driver.extract_response_text(result.stdout, result.stderr)
        payload = parse_json_output(model_output)
        kind, result_data = validate_explore_payload(payload)
    except Exception as exc:
        LOG.warning(
            "conclude parse failed project=%s intent=%s worker=%s error=%s conclude_ms=%s stdout_preview=%s stderr_preview=%s",
            project_id,
            intent.id,
            worker.name,
            exc,
            conclude_ms,
            preview(result.stdout),
            preview(result.stderr),
        )
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("failed", error_type="fallback_parse_failed", error_detail=str(exc), result=result, used_fallback=True)
    if kind == "rejected":
        LOG.warning(
            "conclude rejected project=%s intent=%s worker=%s conclude_ms=%s stdout_preview=%s",
            project_id,
            intent.id,
            worker.name,
            conclude_ms,
            preview(result.stdout),
        )
        best_effort_release(client, project_id, intent.id, worker.name)
        return task_outcome("rejected", error_type="fallback_rejected", result=result, used_fallback=True)
    return _write_explore_result(
        client,
        project_id,
        intent.id,
        worker.name,
        result_data,
        source="explore_conclude",
        phase_ms=conclude_ms,
        used_fallback=True,
    )


def _write_explore_result(
    client: CairnClient,
    project_id: str,
    intent_id: str,
    worker_name: str,
    result_data: dict | None,
    *,
    source: str,
    phase_ms: int,
    total_ms: int | None = None,
    used_fallback: bool = False,
) -> TaskOutcome:
    if not result_data:
        return task_outcome("failed", error_type="empty_result", used_fallback=used_fallback)
    status = write_conclude_result(
        client,
        project_id,
        intent_id,
        worker_name,
        result_data["description"],
        source=source,
        phase_ms=phase_ms,
        total_ms=total_ms,
    )
    if status != "success":
        return task_outcome(status, error_type="conclude_write_failed", used_fallback=used_fallback)
    ref_to_id = write_business_graph(
        client,
        project_id,
        worker_name,
        result_data,
        source=source,
        last_intent_id=intent_id,
    )

    finding = result_data.get("finding")
    findings = result_data.get("findings") or ([finding] if finding else [])
    review = result_data.get("review")
    reviews = result_data.get("reviews") or ([review] if review else [])
    tool_findings = result_data.get("tool_findings") or []
    audit_candidates = result_data.get("audit_candidates") or []
    candidate_conclusions = result_data.get("candidate_conclusions") or []
    snapshot = None
    if findings or tool_findings or audit_candidates:
        project = client.get_project(project_id)
        snapshot = next((item for item in project.sources if item.status == "ready"), None)
        if snapshot is None:
            LOG.warning("skip findings without ready snapshot project=%s worker=%s", project_id, worker_name)
            return task_outcome(status, used_fallback=used_fallback)

    candidate_ref_to_id: dict[str, str] = {}
    for candidate in audit_candidates:
        ref = candidate.get("ref")
        payload = _strip_internal_refs(_resolve_business_node_ref(candidate, ref_to_id))
        response = client.create_audit_candidate(
            project_id,
            {
                **payload,
                "snapshot_id": snapshot.id,
                "created_by": worker_name,
            },
        )
        if response.ok:
            candidate_id = _response_id(response.data)
            if isinstance(ref, str) and candidate_id:
                candidate_ref_to_id[ref] = candidate_id
        else:
            LOG.warning(
                "audit candidate write failed project=%s worker=%s status=%s body=%s",
                project_id,
                worker_name,
                response.status_code,
                response.text,
            )

    for tool_finding in tool_findings:
        response = client.create_tool_finding(
            project_id,
            {
                **tool_finding,
                "snapshot_id": snapshot.id,
            },
        )
        if not response.ok:
            LOG.warning(
                "tool finding write failed project=%s worker=%s status=%s body=%s",
                project_id,
                worker_name,
                response.status_code,
                response.text,
            )
            continue
        tool_finding_id = _response_id(response.data)
        client.create_audit_candidate(
            project_id,
            {
                "snapshot_id": snapshot.id,
                "source": "tool",
                "candidate_type": "tool_finding",
                "severity": tool_finding.get("severity", "info"),
                "title": tool_finding["title"],
                "description": tool_finding["description"],
                "file_path": tool_finding.get("file_path"),
                "line_start": tool_finding.get("line_start"),
                "line_end": tool_finding.get("line_end"),
                "tool_finding_id": tool_finding_id,
                "created_by": worker_name,
            },
        )

    candidate_business_node_by_id: dict[str, str] = {}
    if findings:
        try:
            candidate_business_node_by_id = {
                item["id"]: item["business_node_id"]
                for item in client.list_audit_candidates(project_id)
                if isinstance(item.get("id"), str) and isinstance(item.get("business_node_id"), str)
            }
        except Exception:
            LOG.warning("failed to load audit candidate business links project=%s worker=%s", project_id, worker_name)

    for finding in findings:
        candidate_id = _resolve_candidate_ref(finding, candidate_ref_to_id)
        finding = _strip_internal_refs(_resolve_business_node_ref(finding, ref_to_id))
        if (
            candidate_id
            and not finding.get("business_node_id")
            and candidate_id in candidate_business_node_by_id
        ):
            finding = {**finding, "business_node_id": candidate_business_node_by_id[candidate_id]}
        response = client.create_audit_finding(
            project_id,
            {
                **finding,
                "snapshot_id": snapshot.id,
                "discovered_by": worker_name,
            },
        )
        if not response.ok:
            LOG.warning(
                "audit finding write failed project=%s worker=%s status=%s body=%s",
                project_id,
                worker_name,
                response.status_code,
                response.text,
            )
            continue
        finding_id = _response_id(response.data)
        if candidate_id and finding_id:
            client.conclude_audit_candidate(
                project_id,
                candidate_id,
                worker_name,
                "confirmed",
                finding.get("title") or "候选项已确认并生成审计 finding",
                evidence=finding.get("evidence"),
                audit_finding_id=finding_id,
            )

    for review in reviews:
        response = client.review_audit_finding(
            project_id,
            review["finding_id"],
            worker_name,
            review["decision"],
        )
        if not response.ok:
            LOG.warning(
                "audit finding review failed project=%s finding=%s worker=%s status=%s body=%s",
                project_id,
                review["finding_id"],
                worker_name,
                response.status_code,
                response.text,
            )
    for conclusion in candidate_conclusions:
        candidate_id = _resolve_candidate_ref(conclusion, candidate_ref_to_id)
        if not candidate_id:
            LOG.warning(
                "audit candidate conclusion skipped without resolvable candidate project=%s worker=%s",
                project_id,
                worker_name,
            )
            continue
        response = client.conclude_audit_candidate(
            project_id,
            candidate_id,
            worker_name,
            conclusion["decision"],
            conclusion["summary"],
            evidence=conclusion.get("evidence"),
            audit_finding_id=conclusion.get("audit_finding_id"),
        )
        if not response.ok:
            LOG.warning(
                "audit candidate conclusion failed project=%s candidate=%s worker=%s status=%s body=%s",
                project_id,
                candidate_id,
                worker_name,
                response.status_code,
                response.text,
            )
    write_business_node_conclusions(
        client,
        project_id,
        worker_name,
        result_data,
        ref_to_id,
        source=source,
    )
    return task_outcome(status, used_fallback=used_fallback)


def _response_id(data) -> str | None:
    if isinstance(data, dict):
        candidate = data.get("id")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None


def _strip_internal_refs(payload: dict) -> dict:
    result = dict(payload)
    result.pop("ref", None)
    result.pop("candidate_id", None)
    result.pop("candidate_ref", None)
    return result


def _resolve_candidate_ref(payload: dict, ref_to_id: dict[str, str]) -> str | None:
    candidate_id = payload.get("candidate_id")
    if isinstance(candidate_id, str) and candidate_id.strip():
        text = candidate_id.strip()
        return ref_to_id.get(text, text)
    candidate_ref = payload.get("candidate_ref")
    if isinstance(candidate_ref, str) and candidate_ref.strip():
        return ref_to_id.get(candidate_ref.strip())
    return None


def _resolve_business_node_ref(finding: dict, ref_to_id: dict[str, str]) -> dict:
    business_node_id = finding.get("business_node_id")
    if not isinstance(business_node_id, str):
        return finding
    resolved = ref_to_id.get(business_node_id)
    if resolved is None:
        return finding
    return {**finding, "business_node_id": resolved}


def _run_process(
    container_manager: ContainerManager,
    container_name: str,
    worker: WorkerConfig,
    argv: list[str],
    *,
    phase: str,
    timeout: int,
    lease: HeartbeatLease,
    cancellation: TaskCancellation,
):
    return run_worker_process(
        container_manager,
        container_name,
        worker,
        argv,
        phase=phase,
        timeout_seconds=timeout,
        lease=lease,
        cancellation=cancellation,
    )
