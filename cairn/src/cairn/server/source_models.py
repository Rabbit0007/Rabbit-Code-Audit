from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


SourceType = Literal["git", "zip"]
SourceStatus = Literal["importing", "ready", "failed"]


class GitSourceImportRequest(BaseModel):
    repository_url: str = Field(min_length=1)
    ref: str | None = None

    @field_validator("repository_url", "ref")
    @classmethod
    def strip_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        return text


class SourceSnapshot(BaseModel):
    id: str
    project_id: str
    source_type: SourceType
    original_name: str | None = None
    repository_url: str | None = None
    requested_ref: str | None = None
    resolved_commit: str | None = None
    archive_sha256: str | None = None
    snapshot_sha256: str | None = None
    status: SourceStatus
    file_count: int = 0
    total_bytes: int = 0
    detected_languages: dict[str, int] = Field(default_factory=dict)
    created_at: str
    error_message: str | None = None


class CodeFile(BaseModel):
    snapshot_id: str
    path: str
    size_bytes: int
    sha256: str
    language: str | None = None
    is_binary: bool = False


FindingStatus = Literal[
    "candidate",
    "investigating",
    "pending_review",
    "confirmed",
    "rejected",
    "needs_more_evidence",
]
Severity = Literal["critical", "high", "medium", "low", "info"]


class ToolFinding(BaseModel):
    id: str
    project_id: str
    snapshot_id: str
    tool_name: str
    rule_id: str | None = None
    severity: Severity = "info"
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    status: FindingStatus = "candidate"
    raw_artifact_path: str | None = None
    created_at: str


class AuditFinding(BaseModel):
    id: str
    project_id: str
    snapshot_id: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    cwe: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    description: str
    impact: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    discovered_by: str
    reviewed_by: str | None = None
    created_at: str
    reviewed_at: str | None = None


class CreateToolFindingRequest(BaseModel):
    snapshot_id: str
    tool_name: str
    rule_id: str | None = None
    severity: Severity = "info"
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    raw_artifact_path: str | None = None


class CreateAuditFindingRequest(BaseModel):
    snapshot_id: str
    title: str
    category: str
    severity: Severity
    cwe: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    description: str
    impact: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    discovered_by: str


class ReviewAuditFindingRequest(BaseModel):
    reviewer: str
    decision: Literal["confirmed", "rejected", "needs_more_evidence"]

