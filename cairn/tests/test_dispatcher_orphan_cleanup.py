from __future__ import annotations

from types import SimpleNamespace

from cairn.dispatcher.scheduler.loop import DispatcherLoop


class _CompletedFuture:
    def __init__(self, result: bool):
        self._result = result

    def done(self) -> bool:
        return True

    def result(self) -> bool:
        return self._result


class _ImmediateExecutor:
    def submit(self, function, *args):
        return _CompletedFuture(function(*args))


class _ContainerManager:
    def __init__(self):
        self.removed: list[str] = []

    @staticmethod
    def container_name(project_id: str) -> str:
        return f"worker-{project_id}"

    @staticmethod
    def managed_container_names() -> list[str]:
        return ["worker-proj_active", "worker-proj_deleted"]

    @staticmethod
    def needs_orphan_cleanup(name: str) -> bool:
        return True

    def cleanup_orphan(self, name: str) -> bool:
        self.removed.append(name)
        return True


def test_queue_container_cleanups_removes_deleted_project_container():
    loop = DispatcherLoop.__new__(DispatcherLoop)
    loop.container_manager = _ContainerManager()
    loop.cleanup_executor = _ImmediateExecutor()
    loop.cleanup_futures = {}
    loop._cleanup_pending = set()
    loop._inactive_cleanup_done = {}

    loop._queue_container_cleanups([SimpleNamespace(id="proj_active", status="active")])

    assert loop.container_manager.removed == ["worker-proj_deleted"]
    assert "worker-proj_deleted" in loop._cleanup_pending

    loop._reap_cleanup_futures()

    assert loop._cleanup_pending == set()
