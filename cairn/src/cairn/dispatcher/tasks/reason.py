from __future__ import annotations

import logging
import time

import yaml

from cairn.dispatcher.config import DispatchConfig, WorkerConfig
from cairn.dispatcher.contracts import parse_json_output, validate_reason_payload
from cairn.dispatcher.prompting import (
    format_fact_ids,
    format_open_intents,
    load_prompt,
    render_prompt,
)
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.containers import ContainerManager
from cairn.dispatcher.runtime.heartbeat import HeartbeatLease
from cairn.dispatcher.tasks.common import (
    best_effort_release_reason,
    cancel_reason,
    classify_worker_agent_error,
    did_timeout,
    preview,
    run_healthcheck,
    run_worker_process,
    task_outcome,
    write_graph_snapshot_reference,
)
from cairn.dispatcher.workers.base import WorkerAgentError
from cairn.dispatcher.workers.registry import get_driver
from cairn.dispatcher.models import TaskOutcome
from cairn.server.models import ProjectDetail

LOG = logging.getLogger(__name__)


def run_reason_task(
    config: DispatchConfig,
    client: CairnClient,
    container_manager: ContainerManager,
    project: ProjectDetail,
    export_yaml: str,
    worker: WorkerConfig,
    cancellation: TaskCancellation,
) -> TaskOutcome:
    driver = get_driver(worker.type)
    task_started = time.perf_counter()
    healthcheck_timeout = config.runtime.healthcheck_timeout
    lease = HeartbeatLease.for_reason(client, project.project.id, worker.name, config.runtime.interval)
    lease.start()
    try:
        container_name = container_manager.ensure_running(project.project.id)

        LOG.info(
            "starting container exec project=%s worker=%s phase=reason_healthcheck timeout=%ss",
            project.project.id,
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
                "reason cancelled during healthcheck project=%s worker=%s reason=%s",
                project.project.id,
                worker.name,
                cancelled,
            )
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=healthcheck.result)
        if lease.failure is not None:
            LOG.warning(
                "heartbeat lost during reason healthcheck project=%s worker=%s status=%s",
                project.project.id,
                worker.name,
                lease.failure.status_code,
            )
            return task_outcome("failed", error_type="heartbeat_lost", error_detail=f"status={lease.failure.status_code}", result=healthcheck.result)
        healthcheck_error = driver.healthcheck_error(
            healthcheck.result.returncode,
            healthcheck.result.stdout,
            healthcheck.result.stderr,
        )
        if healthcheck_error is not None:
            LOG.warning(
                "worker unhealthy project=%s worker=%s healthcheck_ms=%s error=%s",
                project.project.id,
                worker.name,
                healthcheck.duration_ms,
                preview(healthcheck_error),
            )
            return task_outcome("unhealthy", error_type="healthcheck_failed", error_detail=healthcheck_error, result=healthcheck.result)
        open_intents = [
            {
                "id": intent.id,
                "from": intent.from_,
                "description": intent.description,
                "worker": intent.worker,
            }
            for intent in project.intents
            if intent.to is None
        ]
        allowed_fact_ids = [fact.id for fact in project.facts if fact.id != "goal"]
        LOG.debug(
            "reason context prepared project=%s worker=%s facts=%s allowed_fact_ids=%s hints=%s open_intents=%s",
            project.project.id,
            worker.name,
            len(project.facts),
            len(allowed_fact_ids),
            len(project.hints),
            len(open_intents),
        )
        prompt = render_prompt(
            load_prompt(config.runtime.prompt_group, "reason.md"),
            {
                "graph_yaml": write_graph_snapshot_reference(
                    container_manager,
                    container_name,
                    export_yaml.strip(),
                    phase="reason_execute",
                ),
                "fact_ids": format_fact_ids(allowed_fact_ids),
                "open_intents": format_open_intents(open_intents),
                "max_intents": str(config.tasks.reason.max_intents),
            },
        )

        session = driver.prepare_session()
        command = driver.build_execute(worker, prompt, session)
        execute_started = time.perf_counter()
        result = run_worker_process(
            container_manager,
            container_name,
            worker,
            command.argv,
            phase="reason_execute",
            timeout_seconds=config.tasks.reason.timeout,
            lease=lease,
            cancellation=cancellation,
        )
        execute_ms = int((time.perf_counter() - execute_started) * 1000)
        total_ms = int((time.perf_counter() - task_started) * 1000)
        session = driver.extract_session(session, result.stdout, result.stderr)
        cancelled = cancel_reason(result, cancellation)
        if cancelled is not None:
            LOG.info(
                "reason cancelled project=%s worker=%s reason=%s execute_ms=%s",
                project.project.id,
                worker.name,
                cancelled,
                execute_ms,
            )
            return task_outcome("cancelled", error_type="cancelled", error_detail=cancelled, result=result)
        if lease.failure is not None:
            LOG.warning(
                "heartbeat lost during reason project=%s worker=%s status=%s execute_ms=%s",
                project.project.id,
                worker.name,
                lease.failure.status_code,
                execute_ms,
            )
            return task_outcome("failed", error_type="heartbeat_lost", error_detail=f"status={lease.failure.status_code}", result=result)
        if did_timeout(result):
            LOG.warning(
                "reason timed out project=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return task_outcome("failed", error_type="timeout", result=result)
        if result.returncode != 0:
            LOG.warning(
                "reason command failed project=%s worker=%s code=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                result.returncode,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return task_outcome("failed", error_type="command_failed", error_detail=f"returncode={result.returncode}", result=result)
        try:
            model_output = driver.extract_response_text(result.stdout, result.stderr)
            payload = parse_json_output(model_output)
            kind, data = validate_reason_payload(
                payload, open_intents_empty=not open_intents, max_intents=config.tasks.reason.max_intents,
            )
        except WorkerAgentError as exc:
            detail = str(exc)
            error_type, cooldown = classify_worker_agent_error(detail, result.stdout, result.stderr)
            LOG.warning(
                "reason agent error project=%s worker=%s error=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                detail,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            return task_outcome(
                "failed",
                error_type=error_type,
                error_detail=detail,
                result=result,
                rate_limited=cooldown,
            )
        except Exception as exc:
            LOG.warning(
                "reason parse failed project=%s worker=%s error=%s execute_ms=%s total_ms=%s stdout_preview=%s stderr_preview=%s",
                project.project.id,
                worker.name,
                exc,
                execute_ms,
                total_ms,
                preview(result.stdout),
                preview(result.stderr),
            )
            fallback_intents = _fallback_intents_from_graph(
                export_yaml,
                allowed_fact_ids,
                max_intents=config.tasks.reason.max_intents,
            )
            if fallback_intents:
                return _create_reason_intents(
                    client,
                    project.project.id,
                    worker.name,
                    fallback_intents,
                    execute_ms=execute_ms,
                    total_ms=total_ms,
                    source="parse_fallback",
                )
            return task_outcome("failed", error_type="parse_failed", error_detail=str(exc), result=result)
        if kind == "rejected":
            LOG.warning(
                "reason rejected project=%s worker=%s execute_ms=%s total_ms=%s stdout_preview=%s",
                project.project.id,
                worker.name,
                execute_ms,
                total_ms,
                preview(result.stdout),
            )
            return task_outcome("rejected", error_type="model_rejected", result=result)
        if kind == "complete":
            response = client.complete(project.project.id, data["from"], data["description"], worker.name)
            if response.status_code == 403:
                LOG.info("project became inactive during reason complete project=%s worker=%s", project.project.id, worker.name)
                return task_outcome("success")
            if not response.ok:
                LOG.warning(
                    "reason complete write failed project=%s worker=%s status=%s body=%s",
                    project.project.id,
                    worker.name,
                    response.status_code,
                    response.text,
                )
                return task_outcome("failed", error_type="complete_write_failed", error_detail=f"status={response.status_code}: {response.text}")
            LOG.info(
                "project completed project=%s worker=%s from=%s execute_ms=%s total_ms=%s",
                project.project.id,
                worker.name,
                data["from"],
                execute_ms,
                total_ms,
            )
            return task_outcome("success")
        if kind == "intents":
            return _create_reason_intents(
                client,
                project.project.id,
                worker.name,
                data,
                execute_ms=execute_ms,
                total_ms=total_ms,
                source="model",
            )
        LOG.info(
            "reason finished without graph change project=%s worker=%s execute_ms=%s total_ms=%s",
            project.project.id,
            worker.name,
            execute_ms,
            total_ms,
        )
        return task_outcome("success")
    finally:
        lease.stop()
        best_effort_release_reason(client, project.project.id, worker.name)


def _create_reason_intents(
    client: CairnClient,
    project_id: str,
    worker_name: str,
    intents: list[dict],
    *,
    execute_ms: int,
    total_ms: int,
    source: str,
) -> TaskOutcome:
    created = 0
    for intent_data in intents:
        response = client.create_intent(project_id, intent_data["from"], intent_data["description"], worker_name)
        if response.status_code == 403:
            LOG.info("project became inactive during reason intent create project=%s worker=%s created=%s", project_id, worker_name, created)
            return task_outcome("success")
        if response.status_code == 409:
            LOG.info("reason intent lost race project=%s worker=%s from=%s", project_id, worker_name, intent_data["from"])
            continue
        if not response.ok:
            LOG.warning(
                "reason intent write failed project=%s worker=%s status=%s body=%s",
                project_id,
                worker_name,
                response.status_code,
                response.text,
            )
            continue
        created += 1
        LOG.info(
            "reason created intent project=%s worker=%s source=%s from=%s description=%s",
            project_id,
            worker_name,
            source,
            intent_data["from"],
            intent_data["description"],
        )
    LOG.info(
        "reason finished project=%s worker=%s source=%s created_intents=%s/%s execute_ms=%s total_ms=%s",
        project_id,
        worker_name,
        source,
        created,
        len(intents),
        execute_ms,
        total_ms,
    )
    if created == 0:
        LOG.warning(
            "reason created no intents project=%s worker=%s source=%s attempted=%s execute_ms=%s total_ms=%s",
            project_id,
            worker_name,
            source,
            len(intents),
            execute_ms,
            total_ms,
        )
        return task_outcome("failed", error_type="intent_write_failed", error_detail="reason created no intents")
    return task_outcome("success")


def _fallback_intents_from_graph(export_yaml: str, allowed_fact_ids: list[str], *, max_intents: int) -> list[dict]:
    try:
        graph = yaml.safe_load(export_yaml) or {}
    except Exception:
        return []
    if not isinstance(graph, dict):
        return []
    from_facts = [allowed_fact_ids[-1]] if allowed_fact_ids else ["origin"]
    intents: list[dict] = []

    audit_coverage = _nested_dict(graph, "audit_candidates", "coverage")
    business_coverage = _nested_dict(graph, "business_graph", "coverage")
    business_items = (
        _item_list(business_coverage.get("high_or_unknown_without_conclusion"))
        or _item_list(business_coverage.get("high_or_unknown_open"))
        or _item_list(business_coverage.get("high_or_unknown_invalid_conclusion"))
    )
    if business_items:
        items = business_items[:3]
        node_ids = _ids(items, "business node")
        targets = _target_summary(items)
        intents.append(
            {
                "from": from_facts,
                "description": (
                    "补齐高/未知风险业务节点的源码审计结论。"
                    f" business_node_ids: {', '.join(node_ids)}。"
                    f" source_targets: {targets}。"
                    " 先读取可见源码目标；若图中缺少具体源码目标，先定位目标并输出 needs_more_evidence，"
                    "不要仅凭图谱生成结论。"
                ),
            }
        )

    if len(intents) >= max_intents:
        return intents[:max_intents]

    candidate_items = (
        _item_list(audit_coverage.get("high_risk_unresolved"))
        or _item_list(audit_coverage.get("open_required"))
        or _item_list(audit_coverage.get("invalid_conclusions"))
    )
    if candidate_items:
        items = candidate_items[:4]
        candidate_ids = _ids(items, "candidate")
        targets = _target_summary(items)
        intents.append(
            {
                "from": from_facts,
                "description": (
                    "闭环仍需证据的审计候选项。"
                    f" candidate_ids: {', '.join(candidate_ids)}。"
                    f" source_targets: {targets}。"
                    " 不得仅确认路由；必须读取实现链、认证/权限、对象查询、能力调用和后续加载/执行点。"
                    " 请读取源码后输出 findings 或 candidate_conclusions。"
                ),
            }
        )
    return intents[:max_intents]


def _nested_dict(root: dict, *keys: str) -> dict:
    current = root
    for key in keys:
        value = current.get(key) if isinstance(current, dict) else None
        if not isinstance(value, dict):
            return {}
        current = value
    return current


def _item_list(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _ids(items: list[dict], fallback_prefix: str) -> list[str]:
    ids: list[str] = []
    for index, item in enumerate(items, start=1):
        value = item.get("id") or item.get("finding_id") or item.get("candidate_id") or item.get("business_node_id")
        text = str(value).strip() if value is not None else ""
        ids.append(text or f"{fallback_prefix} #{index}")
    return ids


def _target_summary(items: list[dict]) -> str:
    targets: list[str] = []
    for item in items:
        matched = False
        for key in ("file_path", "entry_point", "symbol"):
            value = item.get(key)
            text = str(value).strip() if value is not None else ""
            if text:
                targets.append(text)
                matched = True
                break
        if matched:
            continue
        evidence = item.get("evidence")
        if isinstance(evidence, list):
            for value in evidence:
                text = str(value).strip()
                if text:
                    targets.append(text)
                    matched = True
                    break
        if matched:
            continue
        title = item.get("title")
        text = str(title).strip() if title is not None else ""
        if text:
            targets.append(text)
    return "; ".join(targets) if targets else "未在覆盖摘要中提供具体源码目标"
