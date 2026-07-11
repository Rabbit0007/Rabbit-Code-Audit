from __future__ import annotations

from types import SimpleNamespace

import pytest

from cairn.dispatcher.runtime.startup_healthcheck import StartupHealthcheckResult
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
