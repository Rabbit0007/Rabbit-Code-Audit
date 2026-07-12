from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query

from cairn.server.maintenance_models import BackupRecord, BackupRestoreResult, CreateBackupRequest
from cairn.server.maintenance_service import (
    create_database_backup,
    list_database_backups,
    restore_database_backup,
    verify_database_backup,
)


router = APIRouter(prefix="/api/maintenance", tags=["maintenance"])


@router.post("/backups", response_model=BackupRecord, status_code=201)
def create_backup(body: CreateBackupRequest) -> BackupRecord:
    return create_database_backup(body.label)


@router.get("/backups", response_model=list[BackupRecord])
def list_backups(limit: int = Query(default=100, ge=1, le=500)) -> list[BackupRecord]:
    return list_database_backups(limit)


@router.post("/backups/{backup_id}/verify", response_model=BackupRecord)
def verify_backup(backup_id: str) -> BackupRecord:
    try:
        return verify_database_backup(backup_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/backups/{backup_id}/restore", response_model=BackupRestoreResult)
def restore_backup(backup_id: str) -> BackupRestoreResult:
    try:
        return restore_database_backup(backup_id)
    except ValueError as exc:
        status = 409 if "stopped" in str(exc) or "integrity" in str(exc) else 404
        raise HTTPException(status, str(exc)) from exc

