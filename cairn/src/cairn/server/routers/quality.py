from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from cairn.server.quality_models import BenchmarkRunRequest, BenchmarkRunResult
from cairn.server.quality_service import list_quality_benchmarks, run_quality_benchmark


router = APIRouter(prefix="/api/projects/{project_id}/quality", tags=["quality"])


@router.post("/benchmarks", response_model=BenchmarkRunResult, status_code=201)
def create_benchmark(project_id: str, body: BenchmarkRunRequest) -> BenchmarkRunResult:
    try:
        return run_quality_benchmark(project_id, body)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/benchmarks", response_model=list[BenchmarkRunResult])
def get_benchmarks(project_id: str, limit: int = Query(default=50, ge=1, le=200)) -> list[BenchmarkRunResult]:
    return list_quality_benchmarks(project_id, limit=limit)

