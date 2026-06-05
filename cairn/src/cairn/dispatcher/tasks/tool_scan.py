from __future__ import annotations

import logging
import time
from typing import Any

from cairn.dispatcher.config import DispatchConfig
from cairn.dispatcher.models import TaskOutcome
from cairn.dispatcher.protocol.client import CairnClient
from cairn.dispatcher.runtime.cancellation import TaskCancellation


LOG = logging.getLogger(__name__)
TOOL_SCAN_WORKER_NAME = "dispatcher.tool_scan"


def run_tool_scan_task(
    config: DispatchConfig,
    client: CairnClient,
    task: dict[str, Any],
    cancellation: TaskCancellation,
) -> TaskOutcome:
    task_id = str(task["id"])
    project_id = str(task["project_id"])
    snapshot_id = str(task["snapshot_id"])
    worker = str(task.get("worker") or TOOL_SCAN_WORKER_NAME)
    timeout_per_tool = int(task.get("timeout_per_tool") or config.tasks.tool_scan.timeout_per_tool)
    task_started = time.perf_counter()
    summaries: list[dict[str, Any]] = []

    try:
        tools = _tool_names_for_task(task)
        if not tools:
            tools = _tool_names_from_plan(client.get_tool_plan(project_id, snapshot_id))
        if not tools:
            response = client.complete_tool_scan(task_id, {"worker": worker, "summaries": []})
            if not response.ok:
                client.fail_tool_scan(task_id, worker, response.text)
                return TaskOutcome(status="failed", error_type="write_failed", error_detail=response.text)
            return TaskOutcome(status="success")

        for tool_name in tools:
            if cancellation.is_cancelled:
                client.release_tool_scan(task_id, worker)
                return TaskOutcome(status="cancelled", error_type="cancelled", error_detail=cancellation.reason)
            heartbeat = client.tool_scan_heartbeat(task_id, worker)
            if not heartbeat.ok:
                client.release_tool_scan(task_id, worker)
                return TaskOutcome(status="failed", error_type="heartbeat_failed", error_detail=heartbeat.text)
            tool_started = time.perf_counter()
            result = client.run_tool_scan(
                project_id,
                snapshot_id,
                timeout_per_tool=timeout_per_tool,
                tools=[tool_name],
            )
            elapsed_ms = int((time.perf_counter() - tool_started) * 1000)
            for item in result:
                item = dict(item)
                item.setdefault("tool_name", tool_name)
                item["duration_ms"] = elapsed_ms
                summaries.append(item)

        response = client.complete_tool_scan(task_id, {"worker": worker, "summaries": summaries})
        if not response.ok:
            client.fail_tool_scan(task_id, worker, response.text)
            return TaskOutcome(status="failed", error_type="write_failed", error_detail=response.text)
        LOG.info(
            "tool scan completed project=%s task=%s snapshot=%s tools=%s summaries=%s total_ms=%s",
            project_id,
            task_id,
            snapshot_id,
            tools,
            len(summaries),
            int((time.perf_counter() - task_started) * 1000),
        )
        return TaskOutcome(status="success")
    except Exception as exc:
        LOG.warning(
            "tool scan task failed project=%s task=%s snapshot=%s error=%s",
            project_id,
            task_id,
            snapshot_id,
            exc,
            exc_info=True,
        )
        try:
            client.fail_tool_scan(task_id, worker, str(exc))
        except Exception:
            LOG.warning("tool scan fail write crashed task=%s worker=%s", task_id, worker, exc_info=True)
        return TaskOutcome(status="failed", error_type="tool_scan_failed", error_detail=str(exc))


def _tool_names_for_task(task: dict[str, Any]) -> list[str]:
    value = task.get("tools")
    if not isinstance(value, list):
        return []
    return _unique_texts(value)


def _tool_names_from_plan(plan: list[dict[str, Any]]) -> list[str]:
    names = [item.get("name") for item in plan if isinstance(item, dict)]
    return _unique_texts(names)


def _unique_texts(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
    return result
