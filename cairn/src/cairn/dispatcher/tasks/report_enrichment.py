from __future__ import annotations

import json
import logging
import time

from cairn.dispatcher.config import DispatchConfig, WorkerConfig
from cairn.dispatcher.contracts import parse_json_output, validate_report_enrichment_payload
from cairn.dispatcher.models import TaskOutcome
from cairn.dispatcher.prompting import format_json_block, load_prompt, render_prompt
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.heartbeat import HeartbeatLease
from cairn.dispatcher.tasks.common import (
    cancel_reason,
    classify_worker_agent_error,
    did_timeout,
    is_rate_limited,
    preview,
    run_healthcheck,
    run_worker_process,
    task_outcome,
    write_report_evidence_packet_reference,
)
from cairn.dispatcher.workers.base import WorkerAgentError
from cairn.dispatcher.workers.registry import get_driver
from cairn.server.models import ProjectDetail

LOG = logging.getLogger(__name__)


def run_report_enrichment_task(
    config: DispatchConfig,
    client: CairnClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    task: dict,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
) -> TaskOutcome:
    task_id = str(task["id"])
    finding_id = str(task["finding_id"])
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    lease = HeartbeatLease.for_report_enrichment(
        client,
        project.project.id,
        task_id,
        worker.name,
        config.runtime.interval,
    )
    lease.start()
    try:
        container_name = container_manager.ensure_running(
            project.project.id,
            [source.id for source in getattr(project, "sources", []) if source.status == "ready"],
        )
        healthcheck = run_healthcheck(
            container_manager,
            container_name,
            worker,
            driver.build_healthcheck(worker),
            timeout_seconds=config.runtime.healthcheck_timeout,
            lease=lease,
            cancellation=cancellation,
        )
        cancelled = cancel_reason(healthcheck.result, cancellation)
        if cancelled is not None:
            client.release_report_enrichment(task_id, worker.name)
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=healthcheck.result)
        if lease.failure is not None:
            client.release_report_enrichment(task_id, worker.name)
            return task_outcome("failed", error_type="heartbeat_lost", result=healthcheck.result)
        healthcheck_error = driver.healthcheck_error(
            healthcheck.result.returncode,
            healthcheck.result.stdout,
            healthcheck.result.stderr,
        )
        if healthcheck_error is not None:
            client.release_report_enrichment(task_id, worker.name)
            return task_outcome("unhealthy", error_type="healthcheck_failed", error_detail=healthcheck_error, result=healthcheck.result)

        evidence_packet = client.get_report_enrichment_packet(task_id)
        prompt_template = load_prompt(config.runtime.prompt_group, "report_enrichment.md")
        evidence_packet_json = format_json_block(evidence_packet)
        replacements = {
            "finding_id": finding_id,
            "evidence_packet_json": evidence_packet_json,
        }
        if "{evidence_packet_reference}" in prompt_template:
            replacements["evidence_packet_reference"] = write_report_evidence_packet_reference(
                container_manager,
                container_name,
                evidence_packet_json,
            )
        prompt = render_prompt(
            prompt_template,
            replacements,
        )
        execute = driver.build_execute(worker, prompt, driver.prepare_session())
        started = time.perf_counter()
        result = run_worker_process(
            container_manager,
            container_name,
            worker,
            execute.argv,
            phase="report_enrichment",
            timeout_seconds=config.tasks.report_enrichment.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - started) * 1000)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            client.release_report_enrichment(task_id, worker.name)
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=result)
        if lease.failure is not None:
            client.release_report_enrichment(task_id, worker.name)
            return task_outcome("failed", error_type="heartbeat_lost", result=result)
        if did_timeout(result):
            return _complete_static_fallback(
                client, task_id, finding_id, worker.name, evidence_packet, result, "model_timeout"
            )
        if result.returncode != 0:
            detail = f"returncode={result.returncode}"
            if is_rate_limited(detail, result.stdout, result.stderr):
                client.release_report_enrichment(task_id, worker.name)
                return task_outcome(
                    "released",
                    error_type="rate_limited",
                    error_detail=detail,
                    result=result,
                    rate_limited=True,
                )
            _fail_task(client, task_id, worker.name, detail)
            return task_outcome("failed", error_type="command_failed", error_detail=detail, result=result)

        try:
            model_output = driver.extract_response_text(result.stdout, result.stderr)
            payload = parse_json_output(model_output)
            kind, data = validate_report_enrichment_payload(payload)
        except WorkerAgentError as exc:
            detail = str(exc)
            error_type, cooldown = classify_worker_agent_error(detail, result.stdout, result.stderr)
            if cooldown:
                client.release_report_enrichment(task_id, worker.name)
                return task_outcome(
                    "released",
                    error_type=error_type,
                    error_detail=detail,
                    result=result,
                    rate_limited=True,
                )
            LOG.warning(
                "report enrichment agent error project=%s task=%s finding=%s worker=%s error=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                task_id,
                finding_id,
                worker.name,
                detail,
                preview(result.stdout),
                preview(result.stderr),
            )
            return _complete_static_fallback(
                client, task_id, finding_id, worker.name, evidence_packet, result, error_type
            )
        except Exception as exc:
            detail = str(exc)
            if is_rate_limited(detail, result.stdout, result.stderr):
                client.release_report_enrichment(task_id, worker.name)
                return task_outcome(
                    "released",
                    error_type="rate_limited",
                    error_detail=detail,
                    result=result,
                    rate_limited=True,
                )
            LOG.warning(
                "report enrichment parse failed project=%s task=%s finding=%s worker=%s error=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                task_id,
                finding_id,
                worker.name,
                detail,
                preview(result.stdout),
                preview(result.stderr),
            )
            return _complete_static_fallback(
                client, task_id, finding_id, worker.name, evidence_packet, result, "parse_failed"
            )
        if kind == "rejected":
            _fail_task(client, task_id, worker.name, "model rejected report enrichment")
            return task_outcome("rejected", error_type="model_rejected", result=result)
        assert data is not None
        if data.get("finding_id") and data["finding_id"] != finding_id:
            detail = "model returned a different finding_id"
            _fail_task(client, task_id, worker.name, detail)
            return task_outcome("failed", error_type="finding_mismatch", error_detail=detail, result=result)
        response = client.complete_report_enrichment(
            task_id,
            {
                "worker": worker.name,
                "packet_templates": data["packet_templates"],
                "reproduction_poc": data["reproduction_poc"],
                "evidence_chain": data["evidence_chain"],
                "report_sections": data["report_sections"],
                "delivery_notes": data["delivery_notes"],
            },
        )
        if not response.ok:
            return task_outcome(
                "failed",
                error_type="write_failed",
                error_detail=response.text,
                result=result,
            )
        LOG.info(
            "report enrichment completed project=%s task=%s finding=%s worker=%s execute_ms=%s total_ms=%s",
            project.project.id,
            task_id,
            finding_id,
            worker.name,
            execute_ms,
            int((time.perf_counter() - task_started) * 1000),
        )
        return task_outcome("success", result=result)
    except Exception as exc:
        LOG.exception(
            "report enrichment crashed project=%s task=%s finding=%s worker=%s",
            project.project.id,
            task_id,
            finding_id,
            worker.name,
        )
        _fail_task(client, task_id, worker.name, str(exc))
        return task_outcome("failed", error_type="task_crashed", error_detail=str(exc))
    finally:
        lease.stop()


def _fail_task(client: CairnClient, task_id: str, worker: str, error_message: str) -> None:
    try:
        client.fail_report_enrichment(task_id, worker, error_message)
    except Exception:
        LOG.warning("report enrichment fail write crashed task=%s worker=%s", task_id, worker, exc_info=True)


def _complete_static_fallback(
    client: CairnClient,
    task_id: str,
    finding_id: str,
    worker: str,
    evidence_packet: dict,
    result,
    reason: str,
) -> TaskOutcome:
    finding = evidence_packet.get("finding") if isinstance(evidence_packet, dict) else None
    if not isinstance(finding, dict):
        _fail_task(client, task_id, worker, f"{reason}: missing confirmed finding packet")
        return task_outcome("failed", error_type=reason, result=result, used_fallback=True)

    file_path = str(finding.get("file_path") or "").strip()
    entry_point = str(finding.get("entry_point") or "").strip()
    route = entry_point if entry_point.startswith("/") else f"/{file_path.lstrip('/')}"
    route = route.replace("\r", "").replace("\n", "") or "/"
    method = "GET"
    code_index = evidence_packet.get("code_index")
    if isinstance(code_index, dict):
        entrypoints = code_index.get("entrypoints")
        if isinstance(entrypoints, list) and entrypoints and isinstance(entrypoints[0], dict):
            candidate_method = str(entrypoints[0].get("method") or "").strip().upper()
            candidate_route = str(entrypoints[0].get("route") or "").strip()
            if candidate_method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                method = candidate_method
            if candidate_route.startswith("/"):
                route = candidate_route.replace("\r", "").replace("\n", "")

    line_start = finding.get("line_start")
    location = f"{file_path}:{line_start}" if file_path and isinstance(line_start, int) else file_path
    evidence = str(finding.get("evidence") or "").strip()
    description = str(finding.get("description") or "").strip()
    impact = str(finding.get("impact") or "").strip()
    title = str(finding.get("title") or finding_id).strip()
    verification = evidence or description or (f"源码位置 {location}" if location else "已确认漏洞记录")
    expected_result = impact or description or "观察请求是否触发已确认的风险代码路径"
    payload = {
        "worker": worker,
        "packet_templates": [
            {
                "title": f"{title} 静态复测请求模板",
                "request": f"{method} {route} HTTP/1.1\nHost: target\nAccept: */*\nConnection: close",
                "expected_result": expected_result,
                "verification": verification,
                "note": "由已确认源码证据生成的静态模板，不是实测抓包。",
            }
        ],
        "reproduction_poc": {},
        "evidence_chain": [item for item in (location, evidence) if item],
        "report_sections": {
            "proof_material_note": "模型报告结构化输出失败，系统已基于已确认漏洞证据生成保守静态材料。"
        },
        "delivery_notes": [
            "该请求模板未经动态发送，复测时需要替换 Host 并根据部署环境补充参数。",
            f"降级原因: {reason}",
        ],
    }
    response = client.complete_report_enrichment(task_id, payload)
    if not response.ok:
        _fail_task(client, task_id, worker, f"{reason}: static fallback write failed: {response.text}")
        return task_outcome(
            "failed",
            error_type="fallback_write_failed",
            error_detail=response.text,
            result=result,
            used_fallback=True,
        )
    LOG.warning(
        "report enrichment completed with static fallback task=%s finding=%s worker=%s reason=%s",
        task_id,
        finding_id,
        worker,
        reason,
    )
    return task_outcome("success", error_type=reason, result=result, used_fallback=True)
