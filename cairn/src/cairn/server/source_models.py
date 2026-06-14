from __future__ import annotations

from typing import Any, Literal

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


class CodeSymbol(BaseModel):
    id: str
    snapshot_id: str
    path: str
    language: str | None = None
    kind: str
    name: str
    container: str | None = None
    signature: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    confidence: float = 0.8
    source: str = "heuristic"


class CodeEntrypoint(BaseModel):
    id: str
    snapshot_id: str
    path: str
    language: str | None = None
    kind: str
    framework: str | None = None
    method: str | None = None
    route: str
    handler: str | None = None
    line_start: int | None = None
    evidence: str | None = None
    confidence: float = 0.8
    source: str = "heuristic"


class CodeRelationship(BaseModel):
    id: str
    snapshot_id: str
    from_path: str
    from_symbol: str | None = None
    to_path: str
    to_symbol: str | None = None
    relation: str
    evidence: str | None = None
    confidence: float = 0.55
    source: str = "heuristic"
    line_start: int | None = None


class CodeCapability(BaseModel):
    id: str
    snapshot_id: str
    path: str
    symbol: str | None = None
    category: str
    title: str
    line_start: int | None = None
    line_end: int | None = None
    evidence: str | None = None
    risk_level: Literal["critical", "high", "medium", "low", "info", "unknown"] = "unknown"
    risk_tags: list[str] = Field(default_factory=list)
    confidence: float = 0.65
    source: str = "heuristic"


class DependencyManifest(BaseModel):
    id: str
    snapshot_id: str
    path: str
    manifest_type: str
    package_name: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    dev_dependencies: list[str] = Field(default_factory=list)


class SourceIndexSummary(BaseModel):
    symbol_count: int = 0
    entrypoint_count: int = 0
    relationship_count: int = 0
    manifest_count: int = 0


class SourceIndexQualityIssue(BaseModel):
    severity: Literal["info", "warning", "critical"] = "info"
    code: str
    title: str
    description: str
    count: int = 0


class SourceIndexQuality(BaseModel):
    snapshot_id: str
    score: int = Field(ge=0, le=100)
    grade: Literal["strong", "usable", "weak", "poor"]
    summary: SourceIndexSummary
    file_count: int = 0
    code_file_count: int = 0
    detected_languages: dict[str, int] = Field(default_factory=dict)
    framework_counts: dict[str, int] = Field(default_factory=dict)
    relationship_counts: dict[str, int] = Field(default_factory=dict)
    symbol_kind_counts: dict[str, int] = Field(default_factory=dict)
    confidence: dict[str, float] = Field(default_factory=dict)
    low_confidence: dict[str, int] = Field(default_factory=dict)
    orphan_entrypoints: list[CodeEntrypoint] = Field(default_factory=list)
    data_object_count: int = 0
    entrypoints_with_data_paths: int = 0
    candidate_count: int = 0
    high_impact_candidate_count: int = 0
    candidate_status_counts: dict[str, int] = Field(default_factory=dict)
    candidate_type_counts: dict[str, int] = Field(default_factory=dict)
    candidate_file_count: int = 0
    candidate_density_per_code_file: float = 0.0
    business_graph_node_count: int = 0
    business_graph_edge_count: int = 0
    business_module_count: int = 0
    business_module_island_count: int = 0
    entrypoints_with_business_flows: int = 0
    entrypoints_with_capability_paths: int = 0
    language_coverage: dict[str, dict[str, object]] = Field(default_factory=dict)
    graph_compression: dict[str, object] = Field(default_factory=dict)
    audit_readiness: dict[str, object] = Field(default_factory=dict)
    issues: list[SourceIndexQualityIssue] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


FindingStatus = Literal[
    "candidate",
    "investigating",
    "pending_review",
    "confirmed",
    "rejected",
    "needs_more_evidence",
]
Severity = Literal["critical", "high", "medium", "low", "info"]
EvidenceLevel = Literal["L0", "L1", "L2", "L3", "L4", "L5"]
CandidateSeverity = Literal["critical", "high", "medium", "low", "info", "unknown"]
CandidateStatus = Literal[
    "candidate",
    "investigating",
    "confirmed",
    "rejected",
    "needs_more_evidence",
]


def _normalize_reproduction_poc(value) -> dict[str, object]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("reproduction_poc must be an object")
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
    cluster_key: str | None = None
    title: str
    category: str
    severity: Severity
    status: FindingStatus
    evidence_level: EvidenceLevel = "L0"
    cwe: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    symbol: str | None = None
    entry_point: str | None = None
    business_node_id: str | None = None
    description: str
    impact: str | None = None
    evidence: str | None = None
    proof_packets: list[dict[str, str]] = Field(default_factory=list)
    reproduction_poc: dict[str, object] = Field(default_factory=dict)
    remediation: str | None = None
    discovered_by: str
    reviewed_by: str | None = None
    created_at: str
    reviewed_at: str | None = None


class AuditCandidate(BaseModel):
    id: str
    project_id: str
    snapshot_id: str
    source: str
    candidate_type: str
    severity: CandidateSeverity = "unknown"
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    entry_point: str | None = None
    symbol: str | None = None
    tool_finding_id: str | None = None
    business_node_id: str | None = None
    status: CandidateStatus = "candidate"
    conclusion_summary: str | None = None
    evidence: str | None = None
    audit_finding_id: str | None = None
    created_by: str
    created_at: str
    updated_at: str
    concluded_by: str | None = None
    concluded_at: str | None = None


ToolScanTaskStatus = Literal["pending", "running", "completed", "failed"]


class ToolScanTask(BaseModel):
    id: str
    project_id: str
    snapshot_id: str
    status: ToolScanTaskStatus
    created_by: str
    worker: str | None = None
    created_at: str
    started_at: str | None = None
    last_heartbeat_at: str | None = None
    completed_at: str | None = None
    error_message: str | None = None
    tools: list[str] = Field(default_factory=list)
    timeout_per_tool: int = 180
    summaries: list[dict[str, Any]] = Field(default_factory=list)


class CreateToolScanTaskRequest(BaseModel):
    created_by: str = "tool_scan"
    tools: list[str] = Field(default_factory=list)
    timeout_per_tool: int = Field(default=180, ge=10, le=1800)

    @field_validator("created_by")
    @classmethod
    def validate_created_by(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("tools")
    @classmethod
    def normalize_tools(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        tools: list[str] = []
        for item in value or []:
            text = str(item).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            tools.append(text)
        return tools


class ClaimToolScanTaskRequest(BaseModel):
    worker: str

    @field_validator("worker")
    @classmethod
    def validate_worker(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


class CompleteToolScanTaskRequest(ClaimToolScanTaskRequest):
    summaries: list[dict[str, Any]] = Field(default_factory=list)


class FailToolScanTaskRequest(ClaimToolScanTaskRequest):
    error_message: str

    @field_validator("error_message")
    @classmethod
    def validate_error_message(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


DynamicValidationStatus = Literal["static_only", "ready", "blocked"]
DynamicValidationRisk = Literal["low", "medium", "high"]


class DynamicValidationPlan(BaseModel):
    id: str | None = None
    project_id: str
    snapshot_id: str
    status: DynamicValidationStatus
    mode: Literal["plan_only"] = "plan_only"
    execution_default: Literal["disabled"] = "disabled"
    recommended_strategy: str
    risk_level: DynamicValidationRisk
    large_project: bool
    summary: str
    launch_indicators: list[dict[str, Any]] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    created_by: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class CreateDynamicValidationPlanRequest(BaseModel):
    created_by: str = "dynamic_validation_planner"

    @field_validator("created_by")
    @classmethod
    def validate_created_by(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text


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
    symbol: str | None = None
    entry_point: str | None = None
    business_node_id: str | None = None
    description: str
    impact: str | None = None
    evidence: str | None = None
    proof_packets: list[dict[str, str]] = Field(default_factory=list)
    reproduction_poc: dict[str, object] = Field(default_factory=dict)
    remediation: str | None = None
    discovered_by: str

    @field_validator("snapshot_id", "title", "category", "description", "discovered_by")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator(
        "cwe",
        "file_path",
        "symbol",
        "entry_point",
        "business_node_id",
        "impact",
        "evidence",
        "remediation",
    )
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None

    @field_validator("line_start", "line_end")
    @classmethod
    def validate_line(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("line number must be positive")
        return value

    @field_validator("proof_packets")
    @classmethod
    def normalize_proof_packets(cls, value: list[dict[str, str]]) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for packet in value or []:
            if not isinstance(packet, dict):
                raise ValueError("proof packet must be an object")
            normalized = {
                str(key): str(item).strip()
                for key, item in packet.items()
                if item is not None and str(item).strip()
            }
            if normalized:
                result.append(normalized)
        return result

    @field_validator("reproduction_poc")
    @classmethod
    def normalize_reproduction_poc(cls, value) -> dict[str, object]:
        return _normalize_reproduction_poc(value)


class CreateAuditCandidateRequest(BaseModel):
    snapshot_id: str
    source: str = "model"
    candidate_type: str
    severity: CandidateSeverity = "unknown"
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    entry_point: str | None = None
    symbol: str | None = None
    tool_finding_id: str | None = None
    business_node_id: str | None = None
    created_by: str

    @field_validator("snapshot_id", "source", "candidate_type", "title", "description", "created_by")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator(
        "file_path",
        "entry_point",
        "symbol",
        "tool_finding_id",
        "business_node_id",
    )
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None

    @field_validator("line_start", "line_end")
    @classmethod
    def validate_line(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("line number must be positive")
        return value


class ReviewAuditFindingRequest(BaseModel):
    reviewer: str
    decision: Literal["confirmed", "rejected", "needs_more_evidence"]


class ConcludeAuditCandidateRequest(BaseModel):
    reviewer: str
    decision: Literal["confirmed", "rejected", "needs_more_evidence"]
    summary: str
    evidence: str | None = None
    audit_finding_id: str | None = None

    @field_validator("reviewer", "summary")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("evidence", "audit_finding_id")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None
