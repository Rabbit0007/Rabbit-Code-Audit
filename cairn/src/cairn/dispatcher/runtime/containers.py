from __future__ import annotations

import io
import logging
from pathlib import Path
from pathlib import PurePosixPath
import tarfile
import threading
import uuid
import re
import shlex

import docker
from docker.errors import APIError, DockerException, NotFound
from docker.models.containers import Container

from cairn.dispatcher.config import ContainerConfig
from cairn.dispatcher.runtime.process import ManagedProcess

LOG = logging.getLogger(__name__)


class ContainerManager:
    _PREFIX = "cairn-dispatch-"
    _STARTUP_PREFIX = "cairn-startup-healthcheck-"

    def __init__(self, config: ContainerConfig):
        self._config = config
        self._prefix = config.name_prefix
        self._startup_prefix = config.startup_name_prefix
        self._client = docker.from_env()
        self._ensure_running_locks: dict[str, threading.Lock] = {}
        self._ensure_running_locks_guard = threading.Lock()

    def close(self) -> None:
        self._client.close()

    def container_name(self, project_id: str) -> str:
        sanitized = project_id.replace("/", "-")
        return f"{self._prefix}{sanitized}"

    def ensure_running(self, project_id: str, snapshot_ids: list[str] | None = None) -> str:
        name = self.container_name(project_id)
        with self._ensure_running_lock(name):
            self._sync_project_artifacts(project_id, snapshot_ids or [])
            return self._ensure_running_locked(project_id, name)

    def _ensure_running_locked(self, project_id: str, name: str) -> str:
        state = self.inspect_state(name)
        if state is not None and not self._has_current_artifact_mount(name, project_id):
            LOG.info("recreating container with stale artifact mount project=%s container=%s state=%s", project_id, name, state)
            self.remove_container(name, force=True)
            state = None
        if state == "running":
            LOG.debug("container already running project=%s container=%s", project_id, name)
            return name
        if state is not None:
            LOG.info("starting existing container project=%s container=%s state=%s", project_id, name, state)
            self._start_existing(name)
            return name
        LOG.info("creating container project=%s container=%s image=%s", project_id, name, self._config.image)
        try:
            self._client.containers.run(
                self._config.image,
                ["sleep", "infinity"],
                detach=True,
                name=name,
                network_mode=self._config.network_mode,
                cap_add=self._config.cap_add or None,
                volumes=self._container_volumes(project_id),
            )
            LOG.info("created container project=%s container=%s", project_id, name)
            return name
        except APIError as exc:
            if not self._is_name_conflict(exc):
                raise RuntimeError(f"failed to create container {name}: {exc}") from exc
        LOG.info("container name conflict, reusing existing container project=%s container=%s", project_id, name)
        state = self.inspect_state(name)
        if state == "running":
            return name
        if state is not None:
            LOG.info("starting conflicted existing container project=%s container=%s state=%s", project_id, name, state)
            self._start_existing(name)
            return name
        raise RuntimeError(f"failed to create container {name}")

    def _ensure_running_lock(self, name: str) -> threading.Lock:
        with self._ensure_running_locks_guard:
            lock = self._ensure_running_locks.get(name)
            if lock is None:
                lock = threading.Lock()
                self._ensure_running_locks[name] = lock
            return lock

    def create_startup_container(self) -> str:
        name = f"{self._startup_prefix}{uuid.uuid4().hex[:12]}"
        LOG.debug("creating startup healthcheck container container=%s image=%s", name, self._config.image)
        try:
            self._client.containers.run(
                self._config.image,
                ["sleep", "infinity"],
                detach=True,
                name=name,
                network_mode=self._config.network_mode,
                cap_add=self._config.cap_add or None,
                volumes=None,
            )
        except DockerException as exc:
            raise RuntimeError(f"failed to create startup container {name}: {exc}") from exc
        return name

    def inspect_state(self, name: str) -> str | None:
        container = self._get_container(name)
        if container is None:
            return None
        try:
            container.reload()
        except DockerException as exc:
            raise RuntimeError(f"failed to inspect container {name}: {exc}") from exc
        state = container.attrs.get("State", {}).get("Status")
        return str(state) if state else None

    def cleanup_completed(self, project_id: str) -> bool:
        name = self.container_name(project_id)
        state = self.inspect_state(name)
        if state is None:
            return True
        container = self._require_container(name)
        if self._config.completed_action == "remove":
            LOG.info("removing completed project container project=%s container=%s", project_id, name)
            try:
                container.remove(force=True)
            except NotFound:
                return True
            except DockerException as exc:
                LOG.warning("failed to remove container=%s error=%s", name, exc)
                return False
            removed = self.inspect_state(name) is None
            if removed:
                self._remove_project_artifact_volume(project_id)
            return removed
        elif state == "running":
            LOG.info("stopping completed project container project=%s container=%s", project_id, name)
            try:
                container.stop(timeout=1)
            except NotFound:
                return True
            except DockerException as exc:
                LOG.warning("failed to stop container=%s error=%s", name, exc)
                return False
            return self.inspect_state(name) != "running"
        return True

    def cleanup_stopped(self, project_id: str) -> bool:
        name = self.container_name(project_id)
        state = self.inspect_state(name)
        if state != "running":
            return True
        LOG.info("stopping stopped project container project=%s container=%s", project_id, name)
        container = self._require_container(name)
        try:
            container.stop(timeout=1)
        except NotFound:
            return True
        except DockerException as exc:
            LOG.warning("failed to stop stopped project container=%s error=%s", name, exc)
            return False
        return self.inspect_state(name) != "running"

    def restart_for_dispatcher_recovery(self, project_id: str) -> bool:
        """Restart an active project container to terminate orphaned execs."""
        name = self.container_name(project_id)
        if self.inspect_state(name) != "running":
            return True
        LOG.warning(
            "restarting project container after dispatcher recovery project=%s container=%s",
            project_id,
            name,
        )
        container = self._require_container(name)
        try:
            container.restart(timeout=1)
        except NotFound:
            return True
        except DockerException as exc:
            LOG.warning("failed to restart recovered project container=%s error=%s", name, exc)
            return False
        return self.inspect_state(name) == "running"

    def cleanup_orphan(self, name: str) -> bool:
        state = self.inspect_state(name)
        if state is None:
            return True
        LOG.info("removing orphan project container container=%s state=%s", name, state)
        container = self._require_container(name)
        try:
            container.remove(force=True)
        except NotFound:
            return True
        except DockerException as exc:
            LOG.warning("failed to remove orphan container=%s error=%s", name, exc)
            return False
        removed = self.inspect_state(name) is None
        if removed and name.startswith(self._prefix):
            self._remove_project_artifact_volume(name[len(self._prefix) :])
        return removed

    def managed_container_names(self) -> list[str]:
        try:
            containers = self._client.containers.list(all=True)
        except DockerException as exc:
            LOG.warning("failed to list managed containers error=%s", exc)
            return []
        return sorted(container.name for container in containers if container.name.startswith(self._prefix))

    def project_id_for_ip(self, ip_address: str) -> str | None:
        if not ip_address:
            return None
        try:
            managed = self._client.containers.list(all=True)
        except DockerException:
            LOG.debug("failed to map worker container IP", exc_info=True)
            return None
        for container in managed:
            if not container.name.startswith(self._prefix):
                continue
            try:
                container.reload()
            except (NotFound, DockerException):
                continue
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {}) or {}
            if any(network.get("IPAddress") == ip_address for network in networks.values()):
                return container.name[len(self._prefix) :]
        return None

    def needs_completed_cleanup(self, project_id: str) -> bool:
        name = self.container_name(project_id)
        state = self.inspect_state(name)
        if state is None:
            return False
        if self._config.completed_action == "remove":
            return True
        return state == "running"

    def needs_orphan_cleanup(self, name: str) -> bool:
        return self.inspect_state(name) is not None

    def needs_stopped_cleanup(self, project_id: str) -> bool:
        return self.inspect_state(self.container_name(project_id)) == "running"

    def build_exec_process(
        self,
        container_name: str,
        env: dict[str, str],
        command: list[str],
        timeout_seconds: int | None = None,
        kill_after_seconds: int = 5,
    ) -> ManagedProcess:
        container = self._require_container(container_name)
        argv: list[str] = []
        if timeout_seconds is not None:
            argv.extend(
                [
                    "timeout",
                    "-k",
                    f"{kill_after_seconds}s",
                    f"{timeout_seconds}s",
                ]
            )
        argv.extend(command)
        return ManagedProcess(container, argv, env)

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        archive_path, archive = self._text_file_archive(path, content)
        container = self._require_container(container_name)
        try:
            ok = container.put_archive(archive_path, archive)
        except DockerException as exc:
            raise RuntimeError(f"failed to write container file {path}: {exc}") from exc
        if not ok:
            raise RuntimeError(f"failed to write container file {path}")

    def directory_exists(self, container_name: str, path: str) -> bool:
        self._validate_container_path(path)
        container = self._require_container(container_name)
        try:
            result = container.exec_run(["test", "-d", path], stdout=False, stderr=False)
        except DockerException as exc:
            raise RuntimeError(f"failed to check container directory {path}: {exc}") from exc
        exit_code = getattr(result, "exit_code", None)
        if exit_code is None and isinstance(result, tuple) and result:
            exit_code = result[0]
        return exit_code == 0

    def artifact_mount_description(self) -> str:
        expected = self._expected_artifact_mount()
        if expected is None:
            return f"no artifact mount configured; container_path={self._config.artifact_mount_path}"
        mount_type, source = expected
        return f"{mount_type}:{source}->{self._config.artifact_mount_path}"

    def remove_container(self, name: str, *, force: bool = True) -> None:
        container = self._get_container(name)
        if container is None:
            return
        try:
            container.remove(force=force)
        except NotFound:
            return
        except DockerException as exc:
            LOG.warning("failed to remove container=%s error=%s", name, exc)

    def _start_existing(self, name: str) -> None:
        LOG.debug("starting container=%s", name)
        container = self._require_container(name)
        try:
            container.start()
            return
        except DockerException as exc:
            if self.inspect_state(name) == "running":
                return
            raise RuntimeError(f"failed to start container {name}: {exc}") from exc

    def _get_container(self, name: str) -> Container | None:
        try:
            return self._client.containers.get(name)
        except NotFound:
            return None
        except DockerException as exc:
            raise RuntimeError(f"failed to get container {name}: {exc}") from exc

    def _require_container(self, name: str) -> Container:
        container = self._get_container(name)
        if container is None:
            raise RuntimeError(f"container not found: {name}")
        return container

    def _container_volumes(self, project_id: str) -> dict[str, dict[str, str]] | None:
        mount = self._expected_artifact_mount(project_id)
        if mount is None:
            return None
        mount_type, source = mount
        if mount_type == "bind" and not Path(source).exists():
            raise RuntimeError(f"artifact_host_path does not exist: {source}")
        return {
            source: {
                "bind": self._config.artifact_mount_path,
                "mode": "ro",
            }
        }

    def _has_current_artifact_mount(self, name: str, project_id: str) -> bool:
        expected = self._expected_artifact_mount(project_id)
        if expected is None:
            return True
        expected_type, expected_source = expected
        container = self._require_container(name)
        try:
            container.reload()
        except DockerException as exc:
            raise RuntimeError(f"failed to inspect container mounts {name}: {exc}") from exc
        for mount in container.attrs.get("Mounts", []) or []:
            if mount.get("Destination") != self._config.artifact_mount_path:
                continue
            if expected_type == "volume":
                return mount.get("Type") == "volume" and mount.get("Name") == expected_source
            if mount.get("Type") != "bind":
                return False
            current_source = mount.get("Source")
            if not isinstance(current_source, str) or not current_source:
                return False
            try:
                return Path(current_source).resolve() == Path(expected_source).resolve()
            except OSError:
                return current_source == expected_source
        return False

    def _expected_artifact_mount(self, project_id: str | None = None) -> tuple[str, str] | None:
        if self._config.artifact_host_path:
            if project_id is not None:
                raise RuntimeError(
                    "artifact_host_path cannot provide project-isolated worker mounts; use artifact_volume"
                )
            host_path = Path(self._config.artifact_host_path).expanduser().resolve()
            return ("bind", str(host_path))
        if self._config.artifact_volume:
            source = (
                self._project_artifact_volume_name(project_id)
                if project_id is not None
                else self._config.artifact_volume
            )
            return ("volume", source)
        return None

    def _project_artifact_volume_name(self, project_id: str) -> str:
        sanitized = re.sub(r"[^a-zA-Z0-9_.-]+", "-", project_id).strip("-.")
        if not sanitized:
            raise ValueError("project_id cannot produce an empty volume name")
        return f"{self._config.artifact_volume}-{sanitized}"

    def _sync_project_artifacts(self, project_id: str, snapshot_ids: list[str]) -> None:
        if not self._config.artifact_volume:
            if snapshot_ids:
                raise RuntimeError("project artifact isolation requires artifact_volume")
            return
        normalized: list[str] = []
        for snapshot_id in snapshot_ids:
            if not re.fullmatch(r"[a-zA-Z0-9_.-]+", snapshot_id):
                raise ValueError(f"invalid snapshot id: {snapshot_id}")
            if snapshot_id not in normalized:
                normalized.append(snapshot_id)
        project_volume = self._project_artifact_volume_name(project_id)
        self._client.volumes.create(name=project_volume)
        if not normalized:
            return
        copy_commands = ["mkdir -p /target/artifacts/snapshots"]
        for snapshot_id in normalized:
            quoted = shlex.quote(snapshot_id)
            copy_commands.append(
                f"rm -rf /target/artifacts/snapshots/{quoted} && "
                f"cp -a /source/artifacts/snapshots/{quoted} /target/artifacts/snapshots/{quoted}"
            )
        try:
            self._client.containers.run(
                self._config.image,
                ["sh", "-c", " && ".join(copy_commands)],
                remove=True,
                user="0:0",
                network_mode="none",
                volumes={
                    self._config.artifact_volume: {"bind": "/source", "mode": "ro"},
                    project_volume: {"bind": "/target", "mode": "rw"},
                },
            )
        except DockerException as exc:
            raise RuntimeError(
                f"failed to prepare isolated artifacts for project {project_id}: {exc}"
            ) from exc

    def _remove_project_artifact_volume(self, project_id: str) -> None:
        if not self._config.artifact_volume:
            return
        name = self._project_artifact_volume_name(project_id)
        try:
            volume = self._client.volumes.get(name)
            volume.remove(force=True)
        except NotFound:
            return
        except DockerException as exc:
            LOG.warning("failed to remove project artifact volume=%s error=%s", name, exc)

    @staticmethod
    def _is_name_conflict(exc: APIError) -> bool:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        explanation = str(getattr(exc, "explanation", "") or exc)
        return status_code == 409 or "is already in use" in explanation

    @staticmethod
    def _validate_container_path(path: str) -> PurePosixPath:
        target = PurePosixPath(path)
        if not target.is_absolute() or target.name in ("", ".", ".."):
            raise ValueError(f"container file path must be absolute: {path}")
        parts = target.parts[1:]
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise ValueError(f"invalid container file path: {path}")
        return target

    @staticmethod
    def _text_file_archive(path: str, content: str) -> tuple[str, bytes]:
        target = ContainerManager._validate_container_path(path)
        parts = target.parts[1:]
        if len(parts) == 1:
            archive_path = "/"
            archive_parts = parts
        else:
            archive_path = f"/{parts[0]}"
            archive_parts = parts[1:]

        payload = content.encode("utf-8")
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            parent = ""
            for part in archive_parts[:-1]:
                parent = f"{parent}/{part}" if parent else part
                info = tarfile.TarInfo(parent)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)

            file_name = "/".join(archive_parts)
            info = tarfile.TarInfo(file_name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
        return archive_path, stream.getvalue()
