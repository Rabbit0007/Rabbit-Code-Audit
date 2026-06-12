from fastapi import APIRouter

from cairn.server.db import get_conn
from cairn.server.models import CreateHintRequest, Hint
from cairn.server.services import check_project_hint_writable, next_hint_id, utcnow

router = APIRouter(tags=["hints"])


@router.post(
    "/projects/{project_id}/hints",
    response_model=Hint,
    status_code=201,
)
def create_hint(project_id: str, body: CreateHintRequest):
    with get_conn() as conn:
        check_project_hint_writable(conn, project_id)

        now = utcnow()
        hid = next_hint_id(conn, project_id)
        conn.execute(
            """
            INSERT INTO hints (
                id, project_id, content, creator, created_at,
                hint_type, target, priority, expires_at, max_uses
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hid,
                project_id,
                body.content,
                body.creator,
                now,
                body.hint_type,
                body.target,
                body.priority,
                body.expires_at,
                body.max_uses,
            ),
        )
        return Hint(
            id=hid,
            content=body.content,
            creator=body.creator,
            created_at=now,
            hint_type=body.hint_type,
            target=body.target,
            priority=body.priority,
            expires_at=body.expires_at,
            max_uses=body.max_uses,
        )
