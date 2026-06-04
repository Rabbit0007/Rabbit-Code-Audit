from __future__ import annotations

import time
from dataclasses import dataclass, field

from cairn.dispatcher.runtime.cancellation import TaskCancellation


@dataclass(slots=True)
class TaskOutcome:
    status: str
    error_type: str | None = None
    error_detail: str | None = None
    rate_limited: bool = False
    used_fallback: bool = False
    stdout_preview: str | None = None
    stderr_preview: str | None = None

    @property
    def storage_status(self) -> str:
        if self.status in {"success", "failed", "rejected", "released"}:
            return self.status
        return "failed"


@dataclass(slots=True)
class RunningTask:
    project_id: str
    task_type: str
    worker_name: str
    cancellation: TaskCancellation
    intent_id: str | None = None
    fact_count: int | None = None
    hint_count: int | None = None
    open_intent_count: int | None = None
    # Wall-clock start time, auto-populated at construction. Used only by the
    # optional read-only internal status API to compute task durations. This is
    # additive metadata and does not affect scheduling behavior.
    started_at: float = field(default_factory=time.time)


@dataclass(slots=True)
class ReasonCheckpoint:
    fact_count: int
    hint_count: int
    open_intent_count: int
