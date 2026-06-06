from __future__ import annotations

import pytest

from cairn.dispatcher.config import ContainerConfig
from cairn.dispatcher.tasks.common import latest_ready_source_path, verify_latest_source_available
from cairn.server.models import ProjectDetail, ProjectMeta
from cairn.server.source_models import SourceSnapshot


def _project(sources: list[SourceSnapshot]) -> ProjectDetail:
    return ProjectDetail(
        project=ProjectMeta(
            id="proj_1",
            title="Audit",
            status="active",
            created_at="2026-01-01T00:00:00Z",
        ),
        facts=[],
        intents=[],
        hints=[],
        sources=sources,
    )


def _snapshot(snapshot_id: str = "snap_1", status: str = "ready") -> SourceSnapshot:
    return SourceSnapshot(
        id=snapshot_id,
        project_id="proj_1",
        source_type="zip",
        status=status,
        created_at="2026-01-01T00:00:00Z",
    )


class _FakeContainerManager:
    def __init__(self, exists: bool):
        self.exists = exists
        self.checked: list[tuple[str, str]] = []

    def directory_exists(self, container_name: str, path: str) -> bool:
        self.checked.append((container_name, path))
        return self.exists


class _FlakyContainerManager:
    def __init__(self, results: list[bool]):
        self.results = results
        self.checked: list[tuple[str, str]] = []

    def directory_exists(self, container_name: str, path: str) -> bool:
        self.checked.append((container_name, path))
        return self.results.pop(0)


def test_container_config_accepts_artifact_host_path():
    config = ContainerConfig(
        image="worker:latest",
        network_mode="bridge",
        completed_action="stop",
        artifact_host_path="/tmp/rabbit-code-audit-preview",
        artifact_mount_path="/audit-data",
    )

    assert config.artifact_host_path == "/tmp/rabbit-code-audit-preview"
    assert config.artifact_volume is None


def test_container_config_rejects_competing_artifact_mount_sources():
    with pytest.raises(ValueError, match="artifact_volume and artifact_host_path"):
        ContainerConfig(
            image="worker:latest",
            network_mode="bridge",
            completed_action="stop",
            artifact_volume="rabbit-code-audit-data",
            artifact_host_path="/tmp/rabbit-code-audit-preview",
        )


def test_latest_ready_source_path_uses_worker_container_location():
    project = _project([_snapshot("snap_ready")])

    assert latest_ready_source_path(project) == "/audit-data/artifacts/snapshots/snap_ready/source"


def test_source_preflight_fails_when_no_ready_snapshot():
    manager = _FakeContainerManager(exists=True)

    result = verify_latest_source_available(
        manager,
        "cairn-dispatch-proj_1",
        _project([_snapshot("snap_failed", status="failed")]),
        phase="bootstrap_preflight",
        worker_name="worker-1",
    )

    assert not result.ok
    assert result.source_path is None
    assert manager.checked == []


def test_source_preflight_fails_when_container_directory_is_missing():
    manager = _FakeContainerManager(exists=False)
    project = _project([_snapshot("snap_missing")])

    result = verify_latest_source_available(
        manager,
        "cairn-dispatch-proj_1",
        project,
        phase="bootstrap_preflight",
        worker_name="worker-1",
    )

    assert not result.ok
    assert result.source_path == "/audit-data/artifacts/snapshots/snap_missing/source"
    assert manager.checked == [
        ("cairn-dispatch-proj_1", "/audit-data/artifacts/snapshots/snap_missing/source")
    ]


def test_source_preflight_passes_when_container_directory_exists():
    manager = _FakeContainerManager(exists=True)
    project = _project([_snapshot("snap_ok")])

    result = verify_latest_source_available(
        manager,
        "cairn-dispatch-proj_1",
        project,
        phase="explore_preflight",
        worker_name="worker-1",
    )

    assert result.ok
    assert result.source_path == "/audit-data/artifacts/snapshots/snap_ok/source"


def test_source_preflight_retries_transient_missing_directory():
    manager = _FlakyContainerManager([False, False, True])
    project = _project([_snapshot("snap_eventual")])

    result = verify_latest_source_available(
        manager,
        "cairn-dispatch-proj_1",
        project,
        phase="bootstrap_preflight",
        worker_name="worker-1",
        attempts=5,
        retry_delay_seconds=0,
    )

    assert result.ok
    assert result.source_path == "/audit-data/artifacts/snapshots/snap_eventual/source"
    assert manager.checked == [
        ("cairn-dispatch-proj_1", "/audit-data/artifacts/snapshots/snap_eventual/source"),
        ("cairn-dispatch-proj_1", "/audit-data/artifacts/snapshots/snap_eventual/source"),
        ("cairn-dispatch-proj_1", "/audit-data/artifacts/snapshots/snap_eventual/source"),
    ]
