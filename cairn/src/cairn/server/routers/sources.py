from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from cairn.server.source_models import (
    CodeCapability,
    CodeEntrypoint,
    CodeFile,
    CodeRelationship,
    CodeSymbol,
    CreateDynamicValidationPlanRequest,
    DependencyManifest,
    DynamicValidationPlan,
    GitSourceImportRequest,
    SourceBootstrapBrief,
    SourceIndexQuality,
    SourceIndexSummary,
    SourceImpactAnalysis,
    SourceSnapshot,
)
from cairn.server.source_service import (
    get_snapshot,
    get_source_bootstrap_brief,
    get_source_index_quality,
    get_source_index_summary,
    import_git_source,
    import_zip_source,
    list_code_capabilities,
    list_code_entrypoints,
    list_code_files,
    list_code_relationships,
    list_code_symbols,
    list_dependency_manifests,
    list_snapshots,
    analyze_source_impact,
    reindex_source_snapshot,
    snapshot_container_path,
)
from cairn.server.audit_tools import build_tool_plan
from cairn.server.audit_tool_runner import run_audit_tools_for_project
from cairn.server.dynamic_validation import build_dynamic_validation_plan, persist_dynamic_validation_plan


router = APIRouter(prefix="/api/projects/{project_id}/sources", tags=["sources"])


@router.get("", response_model=list[SourceSnapshot])
def get_sources(project_id: str):
    return list_snapshots(project_id)


@router.post("/git", response_model=SourceSnapshot, status_code=201)
def create_git_source(project_id: str, body: GitSourceImportRequest):
    try:
        return import_git_source(project_id, body.repository_url, body.ref)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(422, f"Git import failed: {exc}") from exc


@router.post("/zip", response_model=SourceSnapshot, status_code=201)
def create_zip_source(project_id: str, archive: UploadFile = File(...)):
    filename = archive.filename or "source.zip"
    if not filename.lower().endswith(".zip"):
        raise HTTPException(400, "Only ZIP archives are supported")
    try:
        return import_zip_source(project_id, filename, archive.file)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(422, f"ZIP import failed: {exc}") from exc
    finally:
        archive.file.close()


@router.get("/{snapshot_id}/files", response_model=list[CodeFile])
def get_source_files(project_id: str, snapshot_id: str, limit: int = 5000):
    if limit < 1 or limit > 20_000:
        raise HTTPException(400, "limit must be between 1 and 20000")
    try:
        return list_code_files(project_id, snapshot_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/index-summary", response_model=SourceIndexSummary)
def get_source_index(project_id: str, snapshot_id: str):
    try:
        return get_source_index_summary(project_id, snapshot_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/index-quality", response_model=SourceIndexQuality)
def get_source_quality(project_id: str, snapshot_id: str):
    try:
        return get_source_index_quality(project_id, snapshot_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/changes", response_model=SourceImpactAnalysis)
def get_source_changes(project_id: str, snapshot_id: str, base_snapshot_id: str | None = None):
    try:
        return analyze_source_impact(project_id, snapshot_id, base_snapshot_id=base_snapshot_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/bootstrap-brief", response_model=SourceBootstrapBrief)
def get_bootstrap_brief(project_id: str, snapshot_id: str):
    try:
        return get_source_bootstrap_brief(project_id, snapshot_id)
    except ValueError as exc:
        if "not ready" in str(exc).lower():
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(404, str(exc)) from exc


@router.post("/{snapshot_id}/reindex", response_model=SourceIndexSummary)
def reindex_source(project_id: str, snapshot_id: str):
    try:
        return reindex_source_snapshot(project_id, snapshot_id)
    except ValueError as exc:
        if "not ready" in str(exc).lower():
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/symbols", response_model=list[CodeSymbol])
def get_source_symbols(project_id: str, snapshot_id: str, limit: int = 1000):
    if limit < 1 or limit > 20_000:
        raise HTTPException(400, "limit must be between 1 and 20000")
    try:
        return list_code_symbols(project_id, snapshot_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/entrypoints", response_model=list[CodeEntrypoint])
def get_source_entrypoints(project_id: str, snapshot_id: str, limit: int = 1000):
    if limit < 1 or limit > 20_000:
        raise HTTPException(400, "limit must be between 1 and 20000")
    try:
        return list_code_entrypoints(project_id, snapshot_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/relationships", response_model=list[CodeRelationship])
def get_source_relationships(project_id: str, snapshot_id: str, limit: int = 1000):
    if limit < 1 or limit > 20_000:
        raise HTTPException(400, "limit must be between 1 and 20000")
    try:
        return list_code_relationships(project_id, snapshot_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/capabilities", response_model=list[CodeCapability])
def get_source_capabilities(project_id: str, snapshot_id: str, limit: int = 1000):
    if limit < 1 or limit > 20_000:
        raise HTTPException(400, "limit must be between 1 and 20000")
    try:
        return list_code_capabilities(project_id, snapshot_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/manifests", response_model=list[DependencyManifest])
def get_source_manifests(project_id: str, snapshot_id: str, limit: int = 1000):
    if limit < 1 or limit > 20_000:
        raise HTTPException(400, "limit must be between 1 and 20000")
    try:
        return list_dependency_manifests(project_id, snapshot_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/{snapshot_id}/tool-plan")
def get_tool_plan(project_id: str, snapshot_id: str):
    try:
        snapshot = get_snapshot(project_id, snapshot_id)
        files = list_code_files(project_id, snapshot_id, limit=20_000)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    if snapshot.status != "ready":
        raise HTTPException(409, "Source snapshot is not ready")
    source_path = snapshot_container_path(snapshot_id)
    return [item.as_dict() for item in build_tool_plan(snapshot, files, source_path)]


@router.post("/{snapshot_id}/tool-scan")
def run_tool_scan(
    project_id: str,
    snapshot_id: str,
    timeout_per_tool: int = 180,
    tools: str | None = None,
):
    if timeout_per_tool < 10 or timeout_per_tool > 1800:
        raise HTTPException(400, "timeout_per_tool must be between 10 and 1800")
    selected = {item.strip() for item in tools.split(",") if item.strip()} if tools else None
    try:
        summaries = run_audit_tools_for_project(
            project_id,
            snapshot_id=snapshot_id,
            timeout_per_tool=timeout_per_tool,
            selected_tools=selected,
        )
    except ValueError as exc:
        if "not ready" in str(exc).lower():
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(404, str(exc)) from exc
    return [summary.__dict__ for summary in summaries]


@router.get("/{snapshot_id}/dynamic-validation-plan", response_model=DynamicValidationPlan)
def get_dynamic_validation_plan(project_id: str, snapshot_id: str):
    try:
        return build_dynamic_validation_plan(project_id, snapshot_id)
    except ValueError as exc:
        if "not ready" in str(exc).lower():
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(404, str(exc)) from exc


@router.post("/{snapshot_id}/dynamic-validation-plan", response_model=DynamicValidationPlan, status_code=201)
def create_dynamic_validation_plan(
    project_id: str,
    snapshot_id: str,
    body: CreateDynamicValidationPlanRequest,
):
    try:
        return persist_dynamic_validation_plan(project_id, snapshot_id, created_by=body.created_by)
    except ValueError as exc:
        if "not ready" in str(exc).lower():
            raise HTTPException(409, str(exc)) from exc
        raise HTTPException(404, str(exc)) from exc
