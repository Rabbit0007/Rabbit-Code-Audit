from fastapi import APIRouter

from cairn.server import db
from cairn.server.db import get_conn
from cairn.server.models import RuntimeInfo, Settings
from cairn.server.source_service import artifact_root

router = APIRouter(tags=["settings"])


@router.get("/settings", response_model=Settings)
def get_settings():
    with get_conn() as conn:
        row = conn.execute("SELECT intent_timeout, reason_timeout FROM settings WHERE rowid = 1").fetchone()
        return Settings(intent_timeout=row["intent_timeout"], reason_timeout=row["reason_timeout"])


@router.put("/settings", response_model=Settings)
def update_settings(body: Settings):
    with get_conn() as conn:
        conn.execute(
            "UPDATE settings SET intent_timeout = ?, reason_timeout = ? WHERE rowid = 1",
            (body.intent_timeout, body.reason_timeout),
        )
        return body


@router.get("/api/runtime", response_model=RuntimeInfo)
def get_runtime_info():
    return RuntimeInfo(
        db_path=str(db.current_path().expanduser().resolve()),
        artifact_root=str(artifact_root().expanduser().resolve()),
        source_container_root="/audit-data/artifacts",
    )
