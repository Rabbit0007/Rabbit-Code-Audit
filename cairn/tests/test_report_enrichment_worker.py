from __future__ import annotations

import json
from types import SimpleNamespace

from cairn.dispatcher.config import DispatchConfig
from cairn.dispatcher.models import TaskOutcome
from cairn.dispatcher.protocol.client import ApiResult
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.process import ProcessResult
from cairn.dispatcher.tasks import report_enrichment
from cairn.dispatcher.workers.base import DriverResult, WorkerAgentError


def _config() -> DispatchConfig:
    return DispatchConfig.model_validate(
        {
            "server": "http://server",
            "runtime": {
                "max_workers": 1,
                "max_running_projects": 1,
                "max_project_workers": 1,
                "interval": 60,
                "healthcheck_timeout": 1,
                "prompt_group": "default",
            },
            "tasks": {
                "bootstrap": {"timeout": 1, "conclude_timeout": 1},
                "reason": {"timeout": 1, "max_intents": 1},
                "explore": {"timeout": 1, "conclude_timeout": 1},
                "report_enrichment": {"timeout": 1},
            },
            "container": {
                "image": "cairn-agent:latest",
                "network_mode": "bridge",
                "completed_action": "remove",
            },
            "workers": [
                {
                    "name": "reporter-1",
                    "type": "mock",
                    "task_types": ["report_enrichment"],
                    "max_running": 1,
                    "priority": 0,
                    "env": {},
                }
            ],
        }
    )


class _FakeDriver:
    def __init__(self) -> None:
        self.prompts: list[str] = []

    def build_healthcheck(self, worker):
        return ["healthcheck"]

    def healthcheck_error(self, returncode: int, stdout: str, stderr: str) -> str | None:
        return None

    def prepare_session(self) -> str | None:
        return None

    def build_execute(self, worker, prompt: str, session: str | None) -> DriverResult:
        self.prompts.append(prompt)
        return DriverResult(argv=["worker", "-p", prompt], session=session)

    def extract_response_text(self, stdout: str, stderr: str) -> str:
        return stdout


class _FakeProcess:
    def __init__(self, result: ProcessResult) -> None:
        self._result = result

    def start(self) -> None:
        return None

    def communicate(self, timeout: float | None) -> ProcessResult:
        return self._result

    def kill(self) -> None:
        return None

    def cancel(self, reason: str) -> None:
        return None


class _FakeContainerManager:
    def __init__(self, execute_stdout: str = "", execute_result: ProcessResult | None = None) -> None:
        self.commands: list[list[str]] = []
        self.writes: dict[str, str] = {}
        self._execute_stdout = execute_stdout
        self._execute_result = execute_result

    def ensure_running(self, project_id: str, snapshot_ids=None) -> str:
        return "container-1"

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        self.writes[path] = content

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
    ) -> _FakeProcess:
        self.commands.append(command)
        if command == ["healthcheck"]:
            return _FakeProcess(ProcessResult(returncode=0, stdout="", stderr=""))
        if self._execute_result is not None:
            return _FakeProcess(self._execute_result)
        return _FakeProcess(ProcessResult(returncode=0, stdout=self._execute_stdout, stderr=""))


class _FakeClient:
    def __init__(self, evidence_packet: dict) -> None:
        self.evidence_packet = evidence_packet
        self.completed_payload: dict | None = None
        self.failed: str | None = None
        self.released = False

    def report_enrichment_heartbeat(self, task_id: str, worker: str) -> ApiResult:
        return ApiResult(status_code=200, data={})

    def release_report_enrichment(self, task_id: str, worker: str) -> ApiResult:
        self.released = True
        return ApiResult(status_code=200, data={})

    def get_report_enrichment_packet(self, task_id: str) -> dict:
        return self.evidence_packet

    def complete_report_enrichment(self, task_id: str, payload: dict) -> ApiResult:
        self.completed_payload = payload
        return ApiResult(status_code=200, data=payload)

    def fail_report_enrichment(self, task_id: str, worker: str, error_message: str) -> ApiResult:
        self.failed = error_message
        return ApiResult(status_code=200, data={})


def test_report_enrichment_large_evidence_packet_is_written_to_file(monkeypatch):
    large_marker = "source evidence " + ("x" * 200_000)
    evidence_packet = {
        "finding": {
            "id": "finding_1",
            "status": "confirmed",
            "evidence": large_marker,
        }
    }
    worker_output = json.dumps(
        {
            "accepted": True,
            "data": {
                "finding_id": "finding_1",
                "packet_templates": [
                    {
                        "title": "static request",
                        "request": "GET / HTTP/1.1\nHost: target",
                        "expected_result": "source-backed behavior",
                        "verification": "source evidence",
                    }
                ],
                "evidence_chain": ["source evidence"],
                "report_sections": {"proof_material_note": "static source-inferred material"},
                "delivery_notes": ["not observed traffic"],
            },
        }
    )
    driver = _FakeDriver()
    monkeypatch.setattr(report_enrichment, "get_driver", lambda worker_type: driver)

    config = _config()
    client = _FakeClient(evidence_packet)
    container_manager = _FakeContainerManager(worker_output)
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))

    outcome: TaskOutcome = report_enrichment.run_report_enrichment_task(
        config,
        client,
        container_manager,
        project,
        {"id": "rpt_1", "finding_id": "finding_1"},
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome.status == "success"
    assert client.failed is None
    assert client.completed_payload is not None
    assert len(container_manager.writes) == 1
    assert large_marker in next(iter(container_manager.writes.values()))
    assert len(driver.prompts) == 1
    assert large_marker not in driver.prompts[0]
    assert "evidence_packet.json" in driver.prompts[0]
    assert max(len(arg) for command in container_manager.commands for arg in command) < 10_000


def test_report_enrichment_rate_limit_releases_task(monkeypatch):
    evidence_packet = {"finding": {"id": "finding_1", "status": "confirmed"}}
    driver = _FakeDriver()
    monkeypatch.setattr(report_enrichment, "get_driver", lambda worker_type: driver)

    config = _config()
    client = _FakeClient(evidence_packet)
    container_manager = _FakeContainerManager(
        execute_result=ProcessResult(returncode=1, stdout="", stderr="429 rate limit exceeded")
    )
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))

    outcome: TaskOutcome = report_enrichment.run_report_enrichment_task(
        config,
        client,
        container_manager,
        project,
        {"id": "rpt_1", "finding_id": "finding_1"},
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome.status == "released"
    assert outcome.error_type == "rate_limited"
    assert outcome.rate_limited is True
    assert client.released is True
    assert client.failed is None
    assert client.completed_payload is None


def test_report_enrichment_connection_error_releases_task(monkeypatch):
    evidence_packet = {"finding": {"id": "finding_1", "status": "confirmed"}}
    driver = _FakeDriver()

    def raise_connection_error(stdout: str, stderr: str) -> str:  # noqa: ARG001
        raise WorkerAgentError("Connection error.")

    driver.extract_response_text = raise_connection_error
    monkeypatch.setattr(report_enrichment, "get_driver", lambda worker_type: driver)

    config = _config()
    client = _FakeClient(evidence_packet)
    container_manager = _FakeContainerManager(execute_stdout="")
    project = SimpleNamespace(project=SimpleNamespace(id="proj_1"))

    outcome: TaskOutcome = report_enrichment.run_report_enrichment_task(
        config,
        client,
        container_manager,
        project,
        {"id": "rpt_1", "finding_id": "finding_1"},
        config.workers[0],
        TaskCancellation(),
    )

    assert outcome.status == "released"
    assert outcome.error_type == "model_connection_error"
    assert outcome.rate_limited is True
    assert client.released is True
    assert client.failed is None
    assert client.completed_payload is None


def test_report_enrichment_parse_failure_completes_with_static_fallback(monkeypatch):
    evidence_packet = {
        "finding": {
            "id": "finding_1",
            "title": "SQL 注入",
            "status": "confirmed",
            "file_path": "Less-1/index.php",
            "line_start": 29,
            "entry_point": "/Less-1/",
            "description": "id 参数进入 SQL 拼接",
            "impact": "攻击者可读取数据库内容",
            "evidence": "Less-1/index.php:29",
        },
        "code_index": {"entrypoints": [{"method": "GET", "route": "/Less-1/"}]},
    }
    driver = _FakeDriver()
    monkeypatch.setattr(report_enrichment, "get_driver", lambda worker_type: driver)
    client = _FakeClient(evidence_packet)

    outcome = report_enrichment.run_report_enrichment_task(
        _config(),
        client,
        _FakeContainerManager("analysis only; no final JSON"),
        SimpleNamespace(project=SimpleNamespace(id="proj_1")),
        {"id": "rpt_1", "finding_id": "finding_1"},
        _config().workers[0],
        TaskCancellation(),
    )

    assert outcome.status == "success"
    assert outcome.used_fallback is True
    assert client.failed is None
    assert client.completed_payload["packet_templates"][0]["request"].startswith("GET /Less-1/ HTTP/1.1")
