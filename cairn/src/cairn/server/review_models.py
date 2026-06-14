from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


ReviewTaskStatus = Literal[
    "pending",
    "running",
    "waiting_for_reviewer",
    "blocked_no_independent_worker",
    "completed",
    "failed",
]
ReviewDecision = Literal["confirmed", "rejected", "needs_more_evidence"]


class ReviewTask(BaseModel):
    id: str
    project_id: str
    finding_id: str
    status: ReviewTaskStatus
    created_by: str
    worker: str | None = None
    blocked_reason: str | None = None
    created_at: str
    started_at: str | None = None
    last_heartbeat_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    retry_count: int = 0
    discovered_by: str | None = None
    excluded_workers: list[str] = Field(default_factory=list)


class CreateReviewTaskRequest(BaseModel):
    finding_id: str
    created_by: str = "review.auto"

    @field_validator("finding_id", "created_by")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReviewTaskWorkerRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_worker(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompleteReviewTaskRequest(ReviewTaskWorkerRequest):
    decision: ReviewDecision


class FailReviewTaskRequest(ReviewTaskWorkerRequest):
    error_message: str

    @field_validator("error_message")
    @classmethod
    def validate_error_message(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ReviewTaskAvailabilityRequest(BaseModel):
    status: Literal["waiting_for_reviewer", "blocked_no_independent_worker"]
    reason: str | None = None

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None
