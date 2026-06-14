from __future__ import annotations

from cairn.dispatcher.protocol.client import ApiResult
from cairn.dispatcher.tasks.review import _fail_parse_review_task


class _ReviewClient:
    def __init__(self):
        self.completed: list[tuple[str, str, str]] = []
        self.failed: list[tuple[str, str, str]] = []

    def complete_review_task(self, task_id: str, worker: str, decision: str) -> ApiResult:
        self.completed.append((task_id, worker, decision))
        return ApiResult(status_code=200, data={"id": task_id})

    def fail_review_task(self, task_id: str, worker: str, error_message: str) -> ApiResult:
        self.failed.append((task_id, worker, error_message))
        return ApiResult(status_code=200, data={"id": task_id})


def test_review_parse_failure_fails_task_without_changing_finding_status():
    client = _ReviewClient()

    outcome = _fail_parse_review_task(
        client,
        "rev_1",
        "reviewer-a",
        "no JSON object found in output",
        result=None,
    )

    assert outcome.status == "failed"
    assert outcome.error_type == "parse_failed"
    assert client.completed == []
    assert client.failed == [("rev_1", "reviewer-a", "no JSON object found in output")]
