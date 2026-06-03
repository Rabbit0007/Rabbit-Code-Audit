from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from cairn.server.source_models import CodeFile, GitSourceImportRequest, SourceSnapshot
from cairn.server.source_service import (
    get_snapshot,
    import_git_source,
    import_zip_source,
    list_code_files,
    list_snapshots,
    snapshot_container_path,
)
from cairn.server.audit_tools import build_tool_plan


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
