from __future__ import annotations

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
