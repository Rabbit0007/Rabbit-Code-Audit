from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import sqlite3
import uuid

from cairn.server import db
from cairn.server.maintenance_models import BackupRecord, BackupRestoreResult
from cairn.server.source_service import artifact_root


_BACKUP_ID_RE = re.compile(r"^backup_[a-f0-9]{16}$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _backup_root() -> Path:
    root = artifact_root() / "backups"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _integrity(path: Path) -> bool:
    try:
        with sqlite3.connect(str(path)) as conn:
            row = conn.execute("PRAGMA quick_check").fetchone()
            return bool(row and row[0] == "ok")
    except sqlite3.DatabaseError:
        return False


def create_database_backup(label: str | None = None) -> BackupRecord:
    backup_id = f"backup_{uuid.uuid4().hex[:16]}"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"cairn-{timestamp}-{backup_id}.sqlite3"
    path = _backup_root() / filename
    with sqlite3.connect(str(db.current_path())) as source, sqlite3.connect(str(path)) as destination:
        source.backup(destination)
    path.chmod(0o600)
    integrity_status = "ok" if _integrity(path) else "failed"
    created_at = _now()
    sha256 = _sha256(path)
    size_bytes = path.stat().st_size
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO backup_records (
                id, filename, path, sha256, size_bytes, label,
                integrity_status, created_at, verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                backup_id,
                filename,
                str(path),
                sha256,
                size_bytes,
                label,
                integrity_status,
                created_at,
                created_at if integrity_status == "ok" else None,
            ),
        )
    return BackupRecord(
        id=backup_id,
        filename=filename,
        sha256=sha256,
        size_bytes=size_bytes,
        label=label,
        integrity_status=integrity_status,
        created_at=created_at,
        verified_at=created_at if integrity_status == "ok" else None,
    )


def _record(backup_id: str) -> tuple[BackupRecord, Path]:
    if not _BACKUP_ID_RE.fullmatch(backup_id):
        raise ValueError("invalid backup id")
    with db.get_conn() as conn:
        row = conn.execute("SELECT * FROM backup_records WHERE id = ?", (backup_id,)).fetchone()
    if row is None:
        raise ValueError("backup not found")
    path = Path(row["path"])
    try:
        path.resolve().relative_to(_backup_root().resolve())
    except ValueError as exc:
        raise ValueError("backup path is outside backup root") from exc
    return (
        BackupRecord(
            id=row["id"],
            filename=row["filename"],
            sha256=row["sha256"],
            size_bytes=row["size_bytes"],
            label=row["label"],
            integrity_status=row["integrity_status"],
            created_at=row["created_at"],
            verified_at=row["verified_at"],
        ),
        path,
    )


def _persist_record(record: BackupRecord, path: Path) -> None:
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO backup_records (
                id, filename, path, sha256, size_bytes, label,
                integrity_status, created_at, verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.id,
                record.filename,
                str(path),
                record.sha256,
                record.size_bytes,
                record.label,
                record.integrity_status,
                record.created_at,
                record.verified_at,
            ),
        )


def list_database_backups(limit: int = 100) -> list[BackupRecord]:
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT id FROM backup_records ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    records: list[BackupRecord] = []
    for row in rows:
        try:
            record, _path = _record(row["id"])
        except ValueError:
            continue
        records.append(record)
    return records


def verify_database_backup(backup_id: str) -> BackupRecord:
    record, path = _record(backup_id)
    ok = path.is_file() and _sha256(path) == record.sha256 and _integrity(path)
    verified_at = _now()
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE backup_records SET integrity_status = ?, verified_at = ? WHERE id = ?",
            ("ok" if ok else "failed", verified_at, backup_id),
        )
    return record.model_copy(
        update={"integrity_status": "ok" if ok else "failed", "verified_at": verified_at}
    )


def restore_database_backup(backup_id: str) -> BackupRestoreResult:
    record = verify_database_backup(backup_id)
    if record.integrity_status != "ok":
        raise ValueError("backup integrity verification failed")
    with db.get_conn() as conn:
        active = int(conn.execute("SELECT COUNT(*) FROM projects WHERE status = 'active'").fetchone()[0])
    if active:
        raise ValueError("all projects must be stopped before database restore")
    safety = create_database_backup(label=f"pre-restore:{backup_id}")
    restored_record, backup_path = _record(backup_id)
    safety_record, safety_path = _record(safety.id)
    with sqlite3.connect(str(backup_path)) as source, sqlite3.connect(str(db.current_path())) as destination:
        source.backup(destination)
    if not _integrity(db.current_path()):
        raise RuntimeError("restored database failed integrity verification")
    _persist_record(restored_record, backup_path)
    _persist_record(safety_record, safety_path)
    return BackupRestoreResult(
        restored_backup_id=backup_id,
        safety_backup_id=safety.id,
        restored_at=_now(),
    )
