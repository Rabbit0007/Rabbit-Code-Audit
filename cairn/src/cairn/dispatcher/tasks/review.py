from __future__ import annotations

import logging
import time

from cairn.dispatcher.config import DispatchConfig, WorkerConfig
from cairn.dispatcher.contracts import parse_json_output, validate_review_payload
from cairn.dispatcher.models import TaskOutcome
from cairn.dispatcher.prompting import format_json_block, load_prompt, render_prompt
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.heartbeat import HeartbeatLease
from cairn.dispatcher.tasks.common import (
    SOURCE_PREFLIGHT_ATTEMPTS,
    cancel_reason,
    classify_worker_agent_error,
    did_timeout,
    is_rate_limited,
    preview,
    run_healthcheck,
    run_worker_process,
    task_outcome,
    verify_latest_source_available,
    write_review_packet_reference,
)
from cairn.dispatcher.workers.base import WorkerAgentError
from cairn.dispatcher.workers.registry import get_driver
from cairn.server.models import ProjectDetail

LOG = logging.getLogger(__name__)


def run_review_task(
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
    lease = HeartbeatLease.for_review_task(
        client,
        project.project.id,
        task_id,
        worker.name,
        config.runtime.interval,
    )
    lease.start()
    try:
        container_name = container_manager.ensure_running(project.project.id)
        source_check = verify_latest_source_available(
            container_manager,
            container_name,
            project,
            phase="review_preflight",
            worker_name=worker.name,
            attempts=SOURCE_PREFLIGHT_ATTEMPTS,
        )
        if not source_check.ok:
            client.release_review_task(task_id, worker.name)
            return task_outcome("failed", error_type="source_preflight_failed", error_detail=source_check.reason)

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
            client.release_review_task(task_id, worker.name)
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=healthcheck.result)
        if lease.failure is not None:
            client.release_review_task(task_id, worker.name)
            return task_outcome("failed", error_type="heartbeat_lost", result=healthcheck.result)
        healthcheck_error = driver.healthcheck_error(
            healthcheck.result.returncode,
            healthcheck.result.stdout,
            healthcheck.result.stderr,
        )
        if healthcheck_error is not None:
            client.release_review_task(task_id, worker.name)
            return task_outcome("unhealthy", error_type="healthcheck_failed", error_detail=healthcheck_error, result=healthcheck.result)

        review_packet = client.get_review_task_packet(task_id)
        prompt_template = load_prompt(config.runtime.prompt_group, "review.md")
        review_packet_json = format_json_block(review_packet)
        replacements = {
            "finding_id": finding_id,
            "review_packet_json": review_packet_json,
        }
        if "{review_packet_reference}" in prompt_template:
            replacements["review_packet_reference"] = write_review_packet_reference(
                container_manager,
                container_name,
                review_packet_json,
            )
        prompt = render_prompt(prompt_template, replacements)
        execute = driver.build_execute(worker, prompt, driver.prepare_session())
        started = time.perf_counter()
        result = run_worker_process(
            container_manager,
            container_name,
            worker,
            execute.argv,
            phase="review",
            timeout_seconds=config.tasks.review.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - started) * 1000)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            client.release_review_task(task_id, worker.name)
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=result)
        if lease.failure is not None:
            client.release_review_task(task_id, worker.name)
            return task_outcome("failed", error_type="heartbeat_lost", result=result)
        if did_timeout(result):
            _fail_task(client, task_id, worker.name, "review timed out")
            return task_outcome("failed", error_type="timeout", result=result)
        if result.returncode != 0:
            detail = f"returncode={result.returncode}"
            if is_rate_limited(detail, result.stdout, result.stderr):
                client.release_review_task(task_id, worker.name)
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
            kind, data = validate_review_payload(payload)
        except WorkerAgentError as exc:
            detail = str(exc)
            error_type, cooldown = classify_worker_agent_error(detail, result.stdout, result.stderr)
            if cooldown:
                client.release_review_task(task_id, worker.name)
                return task_outcome(
                    "released",
                    error_type=error_type,
                    error_detail=detail,
                    result=result,
                    rate_limited=True,
                )
            LOG.warning(
                "review agent error project=%s task=%s finding=%s worker=%s error=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                task_id,
                finding_id,
                worker.name,
                detail,
                preview(result.stdout),
                preview(result.stderr),
            )
            _fail_task(client, task_id, worker.name, detail)
            return task_outcome("failed", error_type=error_type, error_detail=detail, result=result)
        except Exception as exc:
            detail = str(exc)
            if is_rate_limited(detail, result.stdout, result.stderr):
                client.release_review_task(task_id, worker.name)
                return task_outcome(
                    "released",
                    error_type="rate_limited",
                    error_detail=detail,
                    result=result,
                    rate_limited=True,
                )
            LOG.warning(
                "review parse failed project=%s task=%s finding=%s worker=%s error=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                task_id,
                finding_id,
                worker.name,
                detail,
                preview(result.stdout),
                preview(result.stderr),
            )
            return _fail_parse_review_task(client, task_id, worker.name, detail, result)
        if kind == "rejected":
            _fail_task(client, task_id, worker.name, "model rejected review task")
            return task_outcome("rejected", error_type="model_rejected", result=result)
        decision = _single_review_decision(data, finding_id)

        response = client.complete_review_task(task_id, worker.name, decision)
        if not response.ok:
            return task_outcome(
                "failed",
                error_type="write_failed",
                error_detail=response.text,
                result=result,
            )
        LOG.info(
            "review completed project=%s task=%s finding=%s decision=%s worker=%s execute_ms=%s total_ms=%s",
            project.project.id,
            task_id,
            finding_id,
            decision,
            worker.name,
            execute_ms,
            int((time.perf_counter() - task_started) * 1000),
        )
        return task_outcome("success", result=result)
    except Exception as exc:
        LOG.exception(
            "review crashed project=%s task=%s finding=%s worker=%s",
            project.project.id,
            task_id,
            finding_id,
            worker.name,
        )
        _fail_task(client, task_id, worker.name, str(exc))
        return task_outcome("failed", error_type="task_crashed", error_detail=str(exc))
    finally:
        lease.stop()


def _single_review_decision(data: dict | None, finding_id: str) -> str:
    if not data:
        raise ValueError("review data is required")
    reviews = data.get("reviews") or ([data["review"]] if data.get("review") else [])
    if len(reviews) != 1:
        raise ValueError("review task must return exactly one review")
    review = reviews[0]
    if review.get("finding_id") != finding_id:
        raise ValueError("model returned a different finding_id")
    decision = review.get("decision")
    if decision not in ("confirmed", "rejected", "needs_more_evidence"):
        raise ValueError("review decision is invalid")
    if data.get("findings") or data.get("finding"):
        raise ValueError("review task must not return findings")
    return decision


def _fail_parse_review_task(
    client: CairnClient,
    task_id: str,
    worker_name: str,
    detail: str,
    result,
) -> TaskOutcome:
    _fail_task(client, task_id, worker_name, detail)
    return task_outcome("failed", error_type="parse_failed", error_detail=detail, result=result)


def _fail_task(client: CairnClient, task_id: str, worker: str, error_message: str) -> None:
    try:
        client.fail_review_task(task_id, worker, error_message)
    except Exception:
        LOG.warning("review fail write crashed task=%s worker=%s", task_id, worker, exc_info=True)
