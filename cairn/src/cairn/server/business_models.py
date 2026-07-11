from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


BusinessNodeType = Literal[
    "feature",
    "role",
    "endpoint",
    "data_object",
    "state",
    "control",
    "asset",
    "risk",
    "external_system",
]

BusinessEdgeRelation = Literal[
    "contains",
    "exposes",
    "calls",
    "uses",
    "extends",
    "extended_by",
    "owns",
    "guards",
    "transitions_to",
    "depends_on",
    "risk_of",
    "evidenced_by",
    "relates_to",
]

BusinessNodeRiskLevel = Literal["critical", "high", "medium", "low", "unknown"]
BusinessNodeReviewStatus = Literal["unreviewed", "investigating", "covered", "blocked"]
BusinessNodeConclusionType = Literal["confirmed_finding", "rejected", "needs_more_evidence"]
BusinessGraphLayer = Literal["evidence", "semantic", "audit"]
BusinessSourceKind = Literal["static_index", "model", "human", "mixed"]
BusinessEvidenceStatus = Literal["source_backed", "inferred", "unverified"]


class BusinessNode(BaseModel):
    id: str
    project_id: str
    node_type: BusinessNodeType
    title: str
    description: str | None = None
    risk_level: BusinessNodeRiskLevel = "unknown"
    review_status: BusinessNodeReviewStatus = "unreviewed"
    coverage_note: str | None = None
    last_intent_id: str | None = None
    risk_tags: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    source_snapshot_id: str | None = None
    confidence: float = 0.7
    semantic_key: str | None = None
    graph_layer: BusinessGraphLayer = "semantic"
    source_kind: BusinessSourceKind = "model"
    evidence_status: BusinessEvidenceStatus = "unverified"
    contributors: list[str] = Field(default_factory=list)
    revision: int = 1
    created_by: str
    created_at: str
    updated_at: str


class BusinessEdge(BaseModel):
    id: str
    project_id: str
    from_node_id: str
    to_node_id: str
    relation: BusinessEdgeRelation
    description: str | None = None
    confidence: float = 0.7
    graph_layer: BusinessGraphLayer = "semantic"
    source_kind: BusinessSourceKind = "model"
    contributors: list[str] = Field(default_factory=list)
    revision: int = 1
    created_by: str
    created_at: str


class BusinessNodeConclusion(BaseModel):
    id: str
    project_id: str
    business_node_id: str
    conclusion: BusinessNodeConclusionType
    summary: str
    evidence: str | None = None
    audit_finding_id: str | None = None
    is_current: bool = True
    superseded_at: str | None = None
    created_by: str
    created_at: str


class BusinessGraph(BaseModel):
    nodes: list[BusinessNode] = Field(default_factory=list)
    edges: list[BusinessEdge] = Field(default_factory=list)


class CreateBusinessNodeRequest(BaseModel):
    node_type: BusinessNodeType = "feature"
    title: str
    description: str | None = None
    risk_level: BusinessNodeRiskLevel = "unknown"
    review_status: BusinessNodeReviewStatus = "unreviewed"
    coverage_note: str | None = None
    last_intent_id: str | None = None
    risk_tags: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    semantic_key: str | None = None
    graph_layer: BusinessGraphLayer = "semantic"
    source_snapshot_id: str | None = None
    confidence: float = Field(default=0.7, ge=0, le=1)
    created_by: str

    @field_validator("title", "created_by")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("description", "coverage_note", "last_intent_id", "semantic_key", "source_snapshot_id")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None

    @field_validator("risk_tags", "evidence")
    @classmethod
    def normalize_string_list(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for item in value:
            text = str(item).strip()
            if not text or text in seen:
                continue
            cleaned.append(text)
            seen.add(text)
        return cleaned


class UpdateBusinessNodeRequest(BaseModel):
    node_type: BusinessNodeType | None = None
    title: str | None = None
    description: str | None = None
    risk_level: BusinessNodeRiskLevel | None = None
    review_status: BusinessNodeReviewStatus | None = None
    coverage_note: str | None = None
    last_intent_id: str | None = None
    risk_tags: list[str] | None = None
    evidence: list[str] | None = None

    @field_validator("title")
    @classmethod
    def normalize_title(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("description", "coverage_note", "last_intent_id")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None

    @field_validator("risk_tags", "evidence")
    @classmethod
    def normalize_optional_string_list(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return CreateBusinessNodeRequest.normalize_string_list(value)


class CreateBusinessEdgeRequest(BaseModel):
    from_node_id: str
    to_node_id: str
    relation: BusinessEdgeRelation = "relates_to"
    description: str | None = None
    graph_layer: BusinessGraphLayer = "semantic"
    confidence: float = Field(default=0.7, ge=0, le=1)
    created_by: str

    @field_validator("from_node_id", "to_node_id", "created_by")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        return text

    @field_validator("description")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        return text or None


class CreateBusinessNodeConclusionRequest(BaseModel):
    business_node_id: str
    conclusion: BusinessNodeConclusionType
    summary: str
    evidence: str | None = None
    audit_finding_id: str | None = None
    created_by: str

    @field_validator("business_node_id", "summary", "created_by")
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

    @model_validator(mode="after")
    def validate_conclusion_requirements(self) -> "CreateBusinessNodeConclusionRequest":
        if self.conclusion == "confirmed_finding" and not self.audit_finding_id:
            raise ValueError("confirmed_finding requires audit_finding_id")
        if self.conclusion in ("rejected", "needs_more_evidence") and not self.evidence:
            raise ValueError(f"{self.conclusion} requires evidence")
        return self
