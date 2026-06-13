from __future__ import annotations

import threading
import time
from concurrent.futures import Future
from types import SimpleNamespace

from cairn.dispatcher.models import ReasonCheckpoint, RunningTask, TaskOutcome
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.scheduler.loop import (
    COMPLETION_CHECK_TRIGGER,
    EXPLORE_PARSE_FAILURE_LIMIT,
    REASON_PARSE_FAILURE_LIMIT,
    DispatcherLoop,
)
from cairn.dispatcher.tasks.reason import _fallback_intents_from_graph


def _scheduler_loop() -> DispatcherLoop:
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.futures = {}
    loop.report_futures = {}
    loop.review_futures = {}
    loop.reason_failure_state = {}
    loop.reason_checkpoints = {}
    loop.completion_checkpoints = {}
    loop.explore_failure_state = {}
    loop.reason_worker_retry_blocked_until = {}
    loop.explore_worker_retry_blocked_until = {}
    loop.explore_worker_parse_blocked_until = loop.explore_worker_retry_blocked_until
    loop.worker_unhealthy_until = {}
    loop.worker_rejected_until = {}
    loop.worker_rate_limited_until = {}
    loop.source_preflight_blocked_until = {}
    loop._server_settings = None
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


def test_reason_parse_failure_limit_does_not_checkpoint_failed_graph_state():
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

    assert "proj_1" not in loop.reason_checkpoints
    assert loop._reason_trigger(
        SimpleNamespace(project=SimpleNamespace(id="proj_1"), facts=[1, 2, 3], hints=[], intents=[])
    ) == "initial"


def test_reason_timeout_temporarily_avoids_same_worker():
    loop = _scheduler_loop()
    loop._record_reason_retryable_failure("proj_1", "facts:2->3", "worker-a", "timeout")

    assert loop._reason_retry_excluded_workers("proj_1", "facts:2->3") == {"worker-a"}
    assert loop._reason_retry_excluded_workers("proj_1", "facts:3->4") == set()


def test_reason_worker_selection_uses_next_worker_after_timeout():
    loop = _scheduler_loop()
    loop._config_lock = threading.RLock()
    loop.config = SimpleNamespace(
        workers=[
            _worker("worker-a", task_types=["reason"], priority=0),
            _worker("worker-b", task_types=["reason"], priority=1),
        ]
    )
    loop._record_reason_retryable_failure("proj_1", "facts:2->3", "worker-a", "timeout")

    selection = loop._select_worker(
        "proj_1",
        "reason",
        excluded_workers=loop._reason_retry_excluded_workers("proj_1", "facts:2->3"),
    )

    assert selection.worker is not None
    assert selection.worker.name == "worker-b"


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


def test_reason_parse_fallback_prioritizes_high_risk_unresolved_candidates():
    intents = _fallback_intents_from_graph(
        """
audit_candidates:
  coverage:
    high_risk_unresolved:
      - id: cand_capability
        candidate_type: capability_chain
        title: "审计能力链: 归档解压/展开能力 apps/ops/api/playbook.py:14"
        file_path: apps/ops/api/playbook.py
        line_start: 14
        entry_point: /playbook/<uuid:pk>/file/
    open_required:
      - id: cand_generic
        title: generic route
        file_path: urls.py
business_graph:
  coverage:
    total_nodes: 0
""",
        ["origin", "f001"],
        max_intents=1,
    )

    assert len(intents) == 1
    assert "cand_capability" in intents[0]["description"]
    assert "cand_generic" not in intents[0]["description"]
    assert "不得仅确认路由" in intents[0]["description"]
    assert "apps/ops/api/playbook.py" in intents[0]["description"]


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


def test_worker_retry_cooldowns_use_server_settings():
    loop = _scheduler_loop()
    loop.task_history = None
    loop.client = SimpleNamespace(
        record_worker_task_history=lambda payload: SimpleNamespace(ok=True, status_code=200, text="")
    )
    loop._server_settings = SimpleNamespace(
        worker_unhealthy_retry_after_seconds=17,
        worker_rejected_retry_after_seconds=19,
    )

    unhealthy_future: Future = Future()
    unhealthy_future.set_result(TaskOutcome(status="unhealthy"))
    loop.futures[unhealthy_future] = RunningTask(
        "proj_1",
        "explore",
        "worker-a",
        TaskCancellation(),
        intent_id="i001",
    )

    rejected_future: Future = Future()
    rejected_future.set_result(TaskOutcome(status="rejected"))
    loop.futures[rejected_future] = RunningTask(
        "proj_1",
        "explore",
        "worker-b",
        TaskCancellation(),
        intent_id="i002",
    )

    now = time.time()
    loop._reap_futures()

    assert 15 <= loop.worker_unhealthy_until["worker-a"] - now <= 19
    assert 17 <= loop.worker_rejected_until[("proj_1", "explore", "worker-b")] - now <= 21


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
    loop.review_executor = _FakeExecutor()
    loop.client = _ReviewClient()
    loop.container_manager = SimpleNamespace()
    return loop


class _CompletionCheckClient:
    def __init__(self, project, *, pending_reports: list[dict] | None = None):
        self.project = project
        self.completed: list[tuple[str, list[str], str, str]] = []
        self.reason_claims: list[tuple[str, str, str]] = []
        self.report_claims: list[tuple[str, str]] = []
        self.pending_reports = pending_reports or []

    def get_project(self, project_id: str):
        assert project_id == self.project.project.id
        return self.project

    def list_pending_review_tasks(self, project_id: str, limit: int = 10):
        return []

    def list_pending_report_enrichments(self, project_id: str, limit: int = 10):
        return self.pending_reports[:limit]

    def export_project(self, project_id: str, profile: str, intent_id: str | None = None):
        assert project_id == self.project.project.id
        assert profile in {"reason", "explore"}
        return "facts: []"

    def claim_reason(self, project_id: str, worker: str, trigger: str):
        self.reason_claims.append((project_id, worker, trigger))
        return SimpleNamespace(ok=True, status_code=200, text="")

    def complete(self, project_id: str, from_ids: list[str], description: str, worker: str):
        self.completed.append((project_id, from_ids, description, worker))
        return SimpleNamespace(ok=True, status_code=200, text="")

    def record_worker_task_history(self, payload: dict):
        return SimpleNamespace(ok=True, status_code=200, text="")

    def claim_report_enrichment(self, task_id: str, worker: str):
        self.report_claims.append((task_id, worker))
        return SimpleNamespace(ok=True, status_code=200, text="", data={"id": task_id, "finding_id": "finding_1"})

    def release_report_enrichment(self, task_id: str, worker: str):
        return SimpleNamespace(ok=True, status_code=200, text="")


def _completion_check_loop(
    project,
    *,
    pending_reports: list[dict] | None = None,
    reason_checkpointed: bool = True,
) -> DispatcherLoop:
    loop = _scheduler_loop()
    if reason_checkpointed:
        loop.reason_checkpoints[project.project.id] = ReasonCheckpoint(
            fact_count=len(project.facts),
            hint_count=len(project.hints),
            open_intent_count=0,
        )
    loop.futures = {}
    loop.runtime_project_ids = {project.project.id}
    loop._cleanup_pending = set()
    loop.task_history = None
    loop._config_lock = threading.RLock()
    loop.config = SimpleNamespace(
        runtime=SimpleNamespace(max_project_workers=4),
        workers=[_worker("reason-worker", task_types=["reason"])],
    )
    loop.executor = _FakeExecutor()
    loop.review_executor = _FakeExecutor()
    loop.report_executor = _FakeExecutor()
    loop.container_manager = SimpleNamespace(container_name=lambda project_id: f"cairn-{project_id}")
    loop.client = _CompletionCheckClient(project, pending_reports=pending_reports)
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


def _project_with_open_intent():
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
                id="i002",
                from_=["f001"],
                to=None,
                description="audit upload flow",
                creator="reason-worker",
                worker=None,
                created_at="2026-01-02T00:00:00Z",
            )
        ],
        sources=[SimpleNamespace(status="ready")],
    )


def test_idle_finished_project_dispatches_reason_completion_check():
    project = _finished_project()
    loop = _completion_check_loop(project)

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True

    assert loop.client.completed == []
    assert loop.client.reason_claims == [("proj_1", "reason-worker", COMPLETION_CHECK_TRIGGER)]
    running = list(loop.futures.values())[0]
    assert running.task_type == "reason"
    assert running.reason_trigger == COMPLETION_CHECK_TRIGGER


def test_pending_report_enrichment_does_not_block_reason_completion_check():
    project = _finished_project()
    loop = _completion_check_loop(project, pending_reports=[{"id": "rpt_1", "finding_id": "finding_1"}])

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True

    assert loop.client.completed == []
    assert loop.client.reason_claims == [("proj_1", "reason-worker", COMPLETION_CHECK_TRIGGER)]


def test_running_report_enrichment_does_not_count_against_project_worker_limit():
    project = _project_with_open_intent()
    loop = _completion_check_loop(project)
    loop.config.runtime.max_project_workers = 1
    loop.report_futures[Future()] = RunningTask(
        "proj_1",
        "report_enrichment",
        "report-worker",
        TaskCancellation(),
        intent_id="rpt_1",
    )
    attempted: list[str] = []

    def fake_dispatch_explore(project_detail, export_yaml, intent):  # noqa: ARG001
        attempted.append(intent.id)
        return True

    loop._dispatch_explore = fake_dispatch_explore

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True
    assert attempted == ["i002"]


def test_report_enrichment_dispatch_uses_background_pool_not_core_futures():
    project = _finished_project()
    loop = _completion_check_loop(project, pending_reports=[{"id": "rpt_1", "finding_id": "finding_1"}])
    loop.config.workers = [_worker("report-worker", task_types=["report_enrichment"])]
    loop.runtime_project_ids = set()
    loop.reason_checkpoints[project.project.id] = ReasonCheckpoint(
        fact_count=len(project.facts),
        hint_count=len(project.hints),
        open_intent_count=0,
    )
    loop.completion_checkpoints[project.project.id] = ReasonCheckpoint(
        fact_count=len(project.facts),
        hint_count=len(project.hints),
        open_intent_count=0,
    )

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True

    assert loop.futures == {}
    assert len(loop.report_futures) == 1
    assert loop.runtime_project_ids == set()
    assert loop.client.report_claims == [("rpt_1", "report-worker")]


def test_successful_completion_check_does_not_repeat_for_same_graph_state():
    project = _finished_project()
    loop = _completion_check_loop(project)

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True
    future = next(iter(loop.futures))
    future.set_result(TaskOutcome(status="success"))
    loop._reap_futures()

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is False
    assert loop.client.reason_claims == [("proj_1", "reason-worker", COMPLETION_CHECK_TRIGGER)]

    project.facts.append(SimpleNamespace(id="f002"))
    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True
    assert loop.client.reason_claims[-1] == ("proj_1", "reason-worker", "facts:3->4")


def test_successful_initial_reason_with_no_open_intents_does_not_immediately_completion_check():
    project = _finished_project()
    loop = _completion_check_loop(project, reason_checkpointed=False)

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True
    assert loop.client.reason_claims == [("proj_1", "reason-worker", "initial")]

    future = next(iter(loop.futures))
    future.set_result(TaskOutcome(status="success"))
    loop._reap_futures()

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is False
    assert loop.client.reason_claims == [("proj_1", "reason-worker", "initial")]


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
    assert loop.futures == {}
    running = list(loop.review_futures.values())[0]
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
    loop.review_futures[Future()] = RunningTask(
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


def test_review_dispatch_uses_background_pool_not_core_futures():
    loop = _review_dispatch_loop([_worker("review-gpt55-1", task_types=["review"])])
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))
    task = {"id": "rev_1", "project_id": "proj_1", "finding_id": "finding_1", "discovered_by": "worker-a"}

    assert loop._dispatch_review_task(project, task) is True

    assert loop.futures == {}
    assert len(loop.review_futures) == 1


def test_core_worker_limit_does_not_block_review_dispatch():
    project = _project_with_open_intent()
    loop = _completion_check_loop(project)
    loop.config.runtime.max_project_workers = 1
    loop.config.workers = [
        _worker("core-worker", task_types=["explore"]),
        _worker("review-gpt55-1", task_types=["review"]),
    ]
    loop.futures[Future()] = RunningTask(
        "proj_1",
        "explore",
        "core-worker",
        TaskCancellation(),
        intent_id="i_busy",
    )
    loop.client.list_pending_review_tasks = lambda project_id, limit=10: [
        {"id": "rev_1", "project_id": project_id, "finding_id": "finding_1", "discovered_by": "worker-a"}
    ]
    loop.client.claim_review_task = lambda task_id, worker: SimpleNamespace(
        ok=True,
        status_code=200,
        text="",
        data={"id": task_id, "project_id": "proj_1", "finding_id": "finding_1", "discovered_by": "worker-a"},
    )
    loop.client.release_review_task = lambda task_id, worker: SimpleNamespace(ok=True, status_code=200, text="")
    loop.client.mark_review_task_availability = lambda task_id, status, reason=None: SimpleNamespace(
        ok=True,
        status_code=200,
        text="",
    )

    assert loop._try_dispatch_project(SimpleNamespace(id="proj_1", status="active")) is True
    assert len(loop.review_futures) == 1
