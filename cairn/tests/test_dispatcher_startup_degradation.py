from __future__ import annotations

from types import SimpleNamespace

import pytest

from cairn.dispatcher.config import WorkerConfig
from cairn.dispatcher.runtime import startup_healthcheck as healthcheck_module
from cairn.dispatcher.runtime.startup_healthcheck import StartupHealthcheckResult, run_startup_healthchecks
from cairn.dispatcher.scheduler import loop as loop_module
from cairn.dispatcher.scheduler.loop import DispatcherLoop


def _failure(worker_name: str) -> StartupHealthcheckResult:
    return StartupHealthcheckResult(
        worker_name=worker_name,
        ok=False,
        returncode=124,
        duration_ms=45_000,
        http_status=None,
        response_preview="timed out",
        stderr_preview="timed out",
        command="pi healthcheck",
    )


def _success(worker_name: str) -> StartupHealthcheckResult:
    return StartupHealthcheckResult(
        worker_name=worker_name,
        ok=True,
        returncode=0,
        duration_ms=100,
        http_status=None,
        response_preview="pong",
        stderr_preview="",
        command="pi healthcheck",
    )


def _loop() -> DispatcherLoop:
    dispatcher = DispatcherLoop.__new__(DispatcherLoop)
    dispatcher.config = SimpleNamespace()
    dispatcher.container_manager = SimpleNamespace()
    dispatcher.startup_unhealthy_workers = set()
    return dispatcher


def test_normal_dispatcher_startup_degrades_when_all_workers_are_offline(monkeypatch):
    dispatcher = _loop()
    monkeypatch.setattr(
        loop_module,
        "run_startup_healthchecks",
        lambda config, manager, show_commands=False: [_failure("worker-a"), _failure("worker-b")],
    )

    dispatcher._run_startup_healthchecks(show_commands=False)

    assert dispatcher.startup_unhealthy_workers == {"worker-a", "worker-b"}


def test_explicit_startup_healthcheck_command_remains_strict(monkeypatch):
    dispatcher = _loop()
    monkeypatch.setattr(
        loop_module,
        "run_startup_healthchecks",
        lambda config, manager, show_commands=False: [_failure("worker-a")],
    )

    with pytest.raises(RuntimeError, match="startup healthchecks failed for all workers"):
        dispatcher._run_startup_healthchecks(show_commands=True, strict=True)


def test_startup_healthcheck_recovers_transient_single_worker_failure(monkeypatch):
    dispatcher = _loop()
    worker = SimpleNamespace(name="worker-a")
    dispatcher.config = SimpleNamespace(workers=[worker])
    monkeypatch.setattr(
        loop_module,
        "run_startup_healthchecks",
        lambda config, manager, show_commands=False: [_failure("worker-a")],
    )
    monkeypatch.setattr(
        loop_module,
        "run_single_startup_healthcheck",
        lambda config, manager, worker: _success(worker.name),
    )

    dispatcher._run_startup_healthchecks(show_commands=False)

    assert dispatcher.startup_unhealthy_workers == set()


def test_startup_healthcheck_probes_shared_pi_connection_once(monkeypatch):
    workers = [
        WorkerConfig.model_validate(
            {
                "name": name,
                "type": "pi",
                "task_types": task_types,
                "max_running": 1,
                "priority": 0,
                "env": {
                    "PI_MODEL": "shared-model",
                    "PI_BASE_URL": "https://models.example.test/v1",
                    "PI_API_KEY": "secret",
                    "PI_PROVIDER_API": "openai-completions",
                },
            }
        )
        for name, task_types in [
            ("audit", ["explore"]),
            ("report", ["report_enrichment"]),
            ("retest", ["review"]),
        ]
    ]
    config = SimpleNamespace(
        workers=workers,
        runtime=SimpleNamespace(max_workers=3, shared_model_max_running=3, healthcheck_timeout=45),
    )
    calls: list[str] = []
    manager = SimpleNamespace(
        create_startup_container=lambda: "healthcheck-container",
        remove_container=lambda name, force=True: None,
    )

    def fake_healthcheck(manager, container, worker, timeout):  # noqa: ARG001
        calls.append(worker.name)
        return _success(worker.name)

    monkeypatch.setattr(healthcheck_module, "_run_worker_healthcheck", fake_healthcheck)

    results = run_startup_healthchecks(config, manager)

    assert calls == ["audit"]
    assert [result.worker_name for result in results] == ["audit", "report", "retest"]
    assert all(result.ok for result in results)
