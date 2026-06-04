from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


ReportEnrichmentStatus = Literal["pending", "running", "completed", "failed"]


def _normalize_json_dict(value) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("must be an object")
    normalized: dict[str, object] = {}
    for key, item in value.items():
        name = str(key).strip()
        if not name or item is None:
            continue
        if isinstance(item, list):
            items = [str(part).strip() for part in item if str(part).strip()]
            if items:
                normalized[name] = items
            continue
        text = str(item).strip()
        if text:
            normalized[name] = text
    return normalized


def _normalize_json_list(value) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("must be an array")
    result = []
    for item in value:
        if isinstance(item, dict):
            normalized = {
                str(key).strip(): str(raw).strip()
                for key, raw in item.items()
                if str(key).strip() and raw is not None and str(raw).strip()
            }
            if normalized:
                result.append(normalized)
            continue
        text = str(item).strip()
        if text:
            result.append(text)
    return result


class ReportEnrichmentTask(BaseModel):
    id: str
    project_id: str
    finding_id: str
    status: ReportEnrichmentStatus
    created_by: str
    worker: str | None = None
    created_at: str
    started_at: str | None = None
    last_heartbeat_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    packet_templates: list[dict[str, str]] = Field(default_factory=list)
    reproduction_poc: dict[str, object] = Field(default_factory=dict)
    evidence_chain: list[str] = Field(default_factory=list)
    report_sections: dict[str, object] = Field(default_factory=dict)
    delivery_notes: list[str] = Field(default_factory=list)


class CreateReportEnrichmentRequest(BaseModel):
    finding_id: str
    created_by: str = "report_enrichment"

    @field_validator("finding_id", "created_by")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class ClaimReportEnrichmentRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_worker(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompleteReportEnrichmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    worker: str
    packet_templates: list[dict[str, str]] = Field(default_factory=list)
    reproduction_poc: dict[str, object] = Field(default_factory=dict)
    evidence_chain: list[str] = Field(default_factory=list)
    report_sections: dict[str, object] = Field(default_factory=dict)
    delivery_notes: list[str] = Field(default_factory=list)

    @field_validator("worker")
    @classmethod
    def validate_worker(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("packet_templates")
    @classmethod
    def normalize_packet_templates(cls, value) -> list[dict[str, str]]:
        normalized = _normalize_json_list(value)
        packets: list[dict[str, str]] = []
        for item in normalized:
            if not isinstance(item, dict):
                raise ValueError("packet_templates must contain objects")
            packets.append({str(key): str(raw) for key, raw in item.items()})
        return packets

    @field_validator("reproduction_poc", "report_sections")
    @classmethod
    def normalize_dict(cls, value) -> dict[str, object]:
        return _normalize_json_dict(value)

    @field_validator("evidence_chain", "delivery_notes")
    @classmethod
    def normalize_string_list(cls, value) -> list[str]:
        return [str(item) for item in _normalize_json_list(value) if not isinstance(item, dict)]


class FailReportEnrichmentRequest(BaseModel):
    worker: str
    error_message: str

    @field_validator("worker", "error_message")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text
