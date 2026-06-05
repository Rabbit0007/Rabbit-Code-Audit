from __future__ import annotations

import fcntl
import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cairn.dispatcher.config import DispatchConfig


class DispatcherAlreadyRunning(RuntimeError):
    """Raised when another dispatcher is already holding the same instance lock."""


@dataclass(slots=True)
class DispatcherInstanceLock:
    path: Path
    owner: str
    _handle: object | None = None

    @classmethod
    def for_config(cls, config_path: Path, config: DispatchConfig) -> "DispatcherInstanceLock":
        resolved_config = config_path.resolve()
        identity = f"{resolved_config}|{config.server}"
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
        lock_dir = Path(tempfile.gettempdir()) / "cairn-dispatcher-locks"
        return cls(lock_dir / f"{digest}.lock", owner=f"server={config.server} config={resolved_config}")

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.seek(0)
            owner = handle.read().strip()
            handle.close()
            detail = f" ({owner})" if owner else ""
            raise DispatcherAlreadyRunning(f"Another dispatcher is already running for this config{detail}") from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} {self.owner}\n")
        handle.flush()
        self._handle = handle

    def release(self) -> None:
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()

    def __enter__(self) -> "DispatcherInstanceLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()
