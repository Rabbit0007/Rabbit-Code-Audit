from __future__ import annotations

import threading
import time
from types import SimpleNamespace

from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.scheduler.loop import (
    EXPLORE_PARSE_FAILURE_LIMIT,
    DispatcherLoop,
)


def _scheduler_loop() -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.explore_failure_state = {}
    loop.explore_worker_parse_blocked_until = {}
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
