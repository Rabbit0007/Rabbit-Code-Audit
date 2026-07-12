from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class BenchmarkExpectation(BaseModel):
    id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    category: str | None = None
    cwe: str | None = None
    file_path: str | None = None
    entry_point: str | None = None
    required: bool = True


class BenchmarkRunRequest(BaseModel):
    suite_name: str = Field(min_length=1, max_length=120)
    snapshot_id: str | None = None
    expectations: list[BenchmarkExpectation] = Field(min_length=1, max_length=5000)
    expected_business_entrypoints: list[str] = Field(default_factory=list, max_length=5000)


class BenchmarkMatch(BaseModel):
    expectation_id: str
    finding_id: str
    score: float
    matched_on: list[str] = Field(default_factory=list)


class BenchmarkMiss(BaseModel):
    id: str
    title: str
    reason: str


class BenchmarkRunResult(BaseModel):
    id: str
    project_id: str
    snapshot_id: str | None = None
    suite_name: str
    created_at: str
    status: Literal["pass", "warning", "fail"]
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    required_recall: float
    business_entrypoint_coverage: float
    matches: list[BenchmarkMatch] = Field(default_factory=list)
    misses: list[BenchmarkMiss] = Field(default_factory=list)
    unexpected_finding_ids: list[str] = Field(default_factory=list)
    missing_business_entrypoints: list[str] = Field(default_factory=list)

