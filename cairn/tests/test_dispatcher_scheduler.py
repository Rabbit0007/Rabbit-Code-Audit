from __future__ import annotations

import threading
import time
from concurrent.futures import Future
from types import SimpleNamespace

from cairn.dispatcher.models import RunningTask, TaskOutcome
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.scheduler.loop import (
    EXPLORE_PARSE_FAILURE_LIMIT,
    REASON_PARSE_FAILURE_LIMIT,
    DispatcherLoop,
)
from cairn.dispatcher.tasks.reason import _fallback_intents_from_graph


def _scheduler_loop() -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.reason_failure_state = {}
    loop.reason_checkpoints = {}
    loop.explore_failure_state = {}
    loop.explore_worker_retry_blocked_until = {}
    loop.explore_worker_parse_blocked_until = loop.explore_worker_retry_blocked_until
    loop._log_state = {}
    return loop


def _worker(name: str, *, priority: int = 0) -> WorkerConfig:
    return WorkerConfig.model_validate(
        {
            "name": name,
            "type": "mock",
            "task_types": ["report_enrichment", "explore"],
            "max_running": 1,
            "priority": priority,
            "env": {},
        }
    )


def test_explore_parse_failure_temporarily_avoids_same_worker():
    loop = _scheduler_loop()

    loop._record_explore_parse_failure("proj_1", "i001", "worker-a", "no JSON object found")

    assert loop._explore_parse_excluded_workers("proj_1", "i001") == {"worker-a"}
    assert loop._explore_parse_excluded_workers("proj_1", "i002") == set()


def test_explore_parse_failure_cools_down_repeated_bad_intent():
    loop = _scheduler_loop()

    for index in range(EXPLORE_PARSE_FAILURE_LIMIT):
        loop._record_explore_parse_failure(
            "proj_1",
            "i001",
            f"worker-{index}",
            "fallback parse failed",
        )

    assert loop._explore_parse_cooldown("proj_1", "i001") is True
    assert loop._explore_parse_cooldown("proj_1", "i002") is False


def test_successful_explore_clears_parse_failure_state():
    loop = _scheduler_loop()
    loop._record_explore_parse_failure("proj_1", "i001", "worker-a", "no JSON object found")

    loop._clear_explore_parse_failure("proj_1", "i001")

    assert loop._explore_parse_cooldown("proj_1", "i001") is False
    assert loop._explore_parse_excluded_workers("proj_1", "i001") == set()


def test_fallback_timeout_temporarily_avoids_same_worker():
    loop = _scheduler_loop()
    loop.futures = {}
    loop.task_history = None
    loop.client = SimpleNamespace(
        record_worker_task_history=lambda payload: SimpleNamespace(ok=True, status_code=200, text="")
    )
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_rate_limited_until = {}
    loop.source_preflight_blocked_until = {}

    future: Future = Future()
    future.set_result(
        TaskOutcome(
            status="failed",
            error_type="fallback_timeout",
            error_detail="returncode=124 timed_out=False",
        )
    )
    loop.futures[future] = RunningTask(
        "proj_1",
        "explore",
        "worker-a",
        TaskCancellation(),
        intent_id="i001",
    )

    loop._reap_futures()

    assert loop._explore_parse_excluded_workers("proj_1", "i001") == {"worker-a"}


def test_fallback_timeout_cools_down_repeated_bad_intent():
    loop = _scheduler_loop()

    for index in range(EXPLORE_PARSE_FAILURE_LIMIT):
        loop._record_explore_retryable_failure(
            "proj_1",
            "i001",
            f"worker-{index}",
            "returncode=124 timed_out=False",
        )

    assert loop._explore_parse_cooldown("proj_1", "i001") is True


def test_reason_parse_failure_limit_checkpoints_current_graph_state():
    loop = _scheduler_loop()
    for _ in range(REASON_PARSE_FAILURE_LIMIT - 1):
        assert loop._record_reason_parse_failure("proj_1", "facts:2->3") is False
    loop.futures = {}
    loop.task_history = None
    loop.client = SimpleNamespace(
        record_worker_task_history=lambda payload: SimpleNamespace(ok=True, status_code=200, text="")
    )
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_rate_limited_until = {}
    loop.source_preflight_blocked_until = {}

    future: Future = Future()
    future.set_result(TaskOutcome(status="failed", error_type="parse_failed"))
    loop.futures[future] = RunningTask(
        "proj_1",
        "reason",
        "worker-a",
        TaskCancellation(),
        fact_count=3,
        hint_count=0,
        open_intent_count=0,
        reason_trigger="facts:2->3",
    )

    loop._reap_futures()

    checkpoint = loop.reason_checkpoints["proj_1"]
    assert checkpoint.fact_count == 3
    assert checkpoint.hint_count == 0
    assert checkpoint.open_intent_count == 0
    assert loop._reason_trigger(
        SimpleNamespace(project=SimpleNamespace(id="proj_1"), facts=[1, 2, 3], hints=[], intents=[])
    ) is None


def test_reason_parse_fallback_derives_intents_from_coverage():
    intents = _fallback_intents_from_graph(
        """
audit_candidates:
  coverage:
    pending_high_findings:
      - id: finding_1
        title: pending SQL injection
        file_path: app/user.js
business_graph:
  coverage:
    high_or_unknown_without_conclusion:
      - id: biz_1
        title: user admin
        evidence:
          - app/user.js:10
""",
        ["origin", "f001"],
        max_intents=2,
    )

    assert len(intents) == 2
    assert intents[0]["from"] == ["f001"]
    assert "finding_1" in intents[0]["description"]
    assert "app/user.js" in intents[0]["description"]
    assert "biz_1" in intents[1]["description"]


def test_report_rate_limit_cooldown_blocks_only_that_task_type():
    loop = _scheduler_loop()
    loop.futures = {}
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_rate_limited_until = {
        ("report_enrichment", "worker-a"): time.time() + 60,
    }
    loop._config_lock = threading.RLock()
    loop.config = SimpleNamespace(workers=[_worker("worker-a", priority=0), _worker("worker-b", priority=1)])

    report_selection = loop._select_worker("proj_1", "report_enrichment")
    explore_selection = loop._select_worker("proj_1", "explore")

    assert report_selection.worker is not None
    assert report_selection.worker.name == "worker-b"
    assert report_selection.blocked_rate_limited
    assert report_selection.blocked_rate_limited[0].startswith("worker-a(")
    assert explore_selection.worker is not None
    assert explore_selection.worker.name == "worker-a"
