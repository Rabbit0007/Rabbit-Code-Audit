from __future__ import annotations

import threading
import time
from concurrent.futures import Future
from types import SimpleNamespace

from cairn.dispatcher.models import RunningTask, TaskOutcome
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.scheduler.loop import (
    AUTO_COMPLETE_WORKER,
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


def _worker(
    name: str,
    *,
    priority: int = 0,
    task_types: list[str] | None = None,
    max_running: int = 1,
) -> WorkerConfig:
    return WorkerConfig.model_validate(
        {
            "name": name,
            "type": "mock",
            "task_types": task_types or ["report_enrichment", "explore"],
            "max_running": max_running,
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

    assert len(intents) == 1
    assert intents[0]["from"] == ["f001"]
    assert "app/user.js" in intents[0]["description"]
    assert "biz_1" in intents[0]["description"]


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


def test_dispatch_first_available_explore_skips_blocked_newer_intent():
    loop = _scheduler_loop()
    exported: list[str] = []
    attempted: list[str] = []
    loop.client = SimpleNamespace(
        export_project=lambda project_id, profile, intent_id: exported.append(intent_id) or f"yaml:{intent_id}"
    )

    def fake_dispatch_explore(project, export_yaml, intent):
        attempted.append(intent.id)
        return intent.id == "i009"

    loop._dispatch_explore = fake_dispatch_explore
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))
    intents = [
        SimpleNamespace(id="i008", created_at="2026-01-02T00:00:00Z"),
        SimpleNamespace(id="i009", created_at="2026-01-01T00:00:00Z"),
    ]

    assert loop._dispatch_first_available_explore(project, intents) is True
    assert exported == ["i008", "i009"]
    assert attempted == ["i008", "i009"]


class _FakeExecutor:
    def __init__(self):
        self.submissions: list[tuple] = []

    def submit(self, fn, *args):
        future: Future = Future()
        self.submissions.append((fn, args))
        return future


class _ReviewClient:
    def __init__(self):
        self.claims: list[tuple[str, str]] = []
        self.availability: list[tuple[str, str, str | None]] = []

    def claim_review_task(self, task_id: str, worker: str):
        self.claims.append((task_id, worker))
        return SimpleNamespace(
            ok=True,
            status_code=200,
            text="",
            data={"id": task_id, "project_id": "proj_1", "finding_id": "finding_1"},
        )

    def release_review_task(self, task_id: str, worker: str):
        return SimpleNamespace(ok=True, status_code=200, text="")

    def mark_review_task_availability(self, task_id: str, status: str, reason: str | None = None):
        self.availability.append((task_id, status, reason))
        return SimpleNamespace(ok=True, status_code=200, text="")


def _review_dispatch_loop(workers: list[WorkerConfig]) -> DispatcherLoop:
    loop = _scheduler_loop()
    loop.futures = {}
    loop.runtime_project_ids = set()
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_rate_limited_until = {}
    loop._config_lock = threading.RLock()
    loop.config = SimpleNamespace(workers=workers)
    loop.executor = _FakeExecutor()
    loop.client = _ReviewClient()
    loop.container_manager = SimpleNamespace()
    return loop


class _AutoCompleteClient:
    def __init__(self, project, *, active_report_statuses: set[str] | None = None):
        self.project = project
        self.active_report_statuses = active_report_statuses or set()
        self.completed: list[tuple[str, list[str], str, str]] = []

    def get_project(self, project_id: str):
        assert project_id == self.project.project.id
        return self.project

    def list_pending_review_tasks(self, project_id: str, limit: int = 10):
        return []

    def list_pending_report_enrichments(self, project_id: str, limit: int = 10):
        return []

    def list_report_enrichments(self, project_id: str, status: str | None = None):
        if status in self.active_report_statuses:
            return [{"id": f"rpt_{status}", "status": status}]
        return []

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str):
        self.completed.append((project_id, from_ids, description, worker))
        return SimpleNamespace(ok=True, status_code=200, text="")


def _auto_complete_loop(project, *, active_report_statuses: set[str] | None = None) -> DispatcherLoop:
    loop = _scheduler_loop()
    loop.futures = {}
    loop.runtime_project_ids = {project.project.id}
    loop._cleanup_pending = set()
    loop.config = SimpleNamespace(runtime=SimpleNamespace(max_project_workers=4))
    loop.container_manager = SimpleNamespace(container_name=lambda project_id: f"cairn-{project_id}")
    loop.client = _AutoCompleteClient(project, active_report_statuses=active_report_statuses)
    return loop


def _finished_project():
    return SimpleNamespace(
        project=SimpleNamespace(id="proj_1", status="active", reason=None),
        facts=[
            SimpleNamespace(id="origin"),
            SimpleNamespace(id="goal"),
            SimpleNamespace(id="f001"),
        ],
        hints=[],
        intents=[
            SimpleNamespace(
                id="i001",
                from_=["origin"],
                to="f001",
                description="done",
                creator="worker-a",
                worker="worker-a",
                created_at="2026-01-01T00:00:00Z",
            )
        ],
        sources=[SimpleNamespace(status="ready")],
    )


def test_idle_finished_project_auto_completes_without_reason_dispatch():
    project = _finished_project()
    loop = _auto_complete_loop(project)

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True

    assert loop.client.completed
    project_id, from_ids, description, worker = loop.client.completed[0]
    assert project_id == "proj_1"
    assert from_ids == ["origin", "f001"]
    assert description
    assert worker == AUTO_COMPLETE_WORKER
    assert "proj_1" not in loop.runtime_project_ids


def test_auto_complete_waits_for_active_report_enrichment_tasks():
    project = _finished_project()
    loop = _auto_complete_loop(project, active_report_statuses={"running"})

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is False

    assert loop.client.completed == []


def test_review_task_dispatch_excludes_discoverer_and_uses_review_worker():
    loop = _review_dispatch_loop(
        [
            _worker("worker-a", task_types=["review"], priority=0),
            _worker("review-gpt55-1", task_types=["review"], priority=1),
        ]
    )
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))
    task = {"id": "rev_1", "project_id": "proj_1", "finding_id": "finding_1", "discovered_by": "worker-a"}

    assert loop._dispatch_review_task(project, task) is True

    assert loop.client.claims == [("rev_1", "review-gpt55-1")]
    running = list(loop.futures.values())[0]
    assert running.task_type == "review"
    assert running.intent_id == "rev_1"


def test_review_task_marks_blocked_without_independent_worker():
    loop = _review_dispatch_loop([_worker("worker-a", task_types=["review"])])
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))
    task = {"id": "rev_1", "project_id": "proj_1", "finding_id": "finding_1", "discovered_by": "worker-a"}

    assert loop._dispatch_review_task(project, task) is False

    assert loop.client.claims == []
    assert loop.client.availability
    assert loop.client.availability[0][1] == "blocked_no_independent_worker"


def test_review_task_marks_waiting_when_independent_worker_is_temporarily_busy():
    loop = _review_dispatch_loop([_worker("review-gpt55-1", task_types=["review"], max_running=1)])
    loop.futures[Future()] = RunningTask(
        "proj_2",
        "review",
        "review-gpt55-1",
        TaskCancellation(),
        intent_id="rev_busy",
    )
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))
    task = {"id": "rev_1", "project_id": "proj_1", "finding_id": "finding_1", "discovered_by": "worker-a"}

    assert loop._dispatch_review_task(project, task) is False

    assert loop.client.claims == []
    assert loop.client.availability
    assert loop.client.availability[0][1] == "waiting_for_reviewer"
