from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CreateBackupRequest(BaseModel):
    label: str | None = Field(default=None, max_length=120)


class BackupRecord(BaseModel):
    id: str
    filename: str
    sha256: str
    size_bytes: int
    label: str | None = None
    integrity_status: Literal["ok", "failed"]
    created_at: str
    verified_at: str | None = None


class BackupRestoreResult(BaseModel):
    restored_backup_id: str
    safety_backup_id: str
    restored_at: str
    integrity_status: Literal["ok"] = "ok"

