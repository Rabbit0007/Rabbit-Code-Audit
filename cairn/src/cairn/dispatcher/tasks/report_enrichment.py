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
    did_timeout,
    is_rate_limited,
    preview,
    run_healthcheck,
    run_worker_process,
    task_outcome,
    write_report_evidence_packet_reference,
)
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
        container_name = container_manager.ensure_running(project.project.id)
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
            _fail_task(client, task_id, worker.name, "report enrichment timed out")
            return task_outcome("failed", error_type="timeout", result=result)
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
            _fail_task(client, task_id, worker.name, detail)
            return task_outcome("failed", error_type="parse_failed", error_detail=detail, result=result)
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
