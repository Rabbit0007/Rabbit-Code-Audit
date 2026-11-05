"""Security-relevant git history becomes variant-analysis hints.

The extractor is pure (fed synthetic ``git log`` text) so it needs no git
binary; the recorder is checked against a temp database.
"""

from __future__ import annotations

from cairn.server import db
from cairn.server.services import utcnow
from cairn.server.source_service import (
    MAX_SECURITY_COMMIT_HINTS,
    _record_security_commit_hints,
    extract_security_relevant_commits,
)

SEP = "\x1f"


def _log(*pairs: tuple[str, str]) -> str:
    return "\n".join(f"{sha}{SEP}{subject}" for sha, subject in pairs)


def test_extractor_keeps_security_commits_and_drops_noise():
    text = _log(
        ("a1b2c3d4e5f6", "Fix SQL injection in search handler"),
        ("0000000000aa", "Bump version to 2.1.0"),
        ("1111111111bb", "Update README"),
        ("2222222222cc", "patch XSS in profile page"),
        ("3333333333dd", "refactor logging"),
        ("4444444444ee", "修复越权访问漏洞"),
    )
    found = extract_security_relevant_commits(text)
    subjects = [subject for _sha, subject in found]
    assert "Fix SQL injection in search handler" in subjects
    assert "patch XSS in profile page" in subjects
    assert "修复越权访问漏洞" in subjects
    assert "Update README" not in subjects
    assert "refactor logging" not in subjects
    assert found[0][0] == "a1b2c3d4e5f6"  # short sha preserved, newest first


def test_extractor_dedupes_and_caps():
    pairs = [("f" * 12, "fix security issue")] * 5
    pairs += [(f"{i:012d}", f"CVE-2026-{i} buffer overflow") for i in range(30)]
    found = extract_security_relevant_commits(_log(*pairs))
    assert len(found) <= MAX_SECURITY_COMMIT_HINTS
    assert sum(1 for _sha, s in found if s == "fix security issue") == 1


def test_extractor_ignores_malformed_lines():
    assert extract_security_relevant_commits("no separator here\nanother line") == []
    assert extract_security_relevant_commits("") == []


def _make_project(project_id: str) -> None:
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, title, status, created_at) VALUES (?, ?, 'active', ?)",
            (project_id, "demo", utcnow()),
        )


def test_recorder_inserts_focus_hints(temp_db):
    _make_project("proj_hist")
    _record_security_commit_hints(
        "proj_hist",
        [("a1b2c3d4", "Fix SQL injection in search"), ("b2c3d4e5", "修复越权")],
    )
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT content, creator, hint_type FROM hints WHERE project_id = ? ORDER BY content",
            ("proj_hist",),
        ).fetchall()
    assert len(rows) == 2
    assert all(row["creator"] == "git_history" for row in rows)
    assert all(row["hint_type"] == "focus" for row in rows)
    assert any("变体分析" in row["content"] for row in rows)
    assert any("a1b2c3d4" in row["content"] for row in rows)


def test_recorder_is_noop_on_empty(temp_db):
    _make_project("proj_empty")
    _record_security_commit_hints("proj_empty", [])
    with db.get_conn() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM hints WHERE project_id = ?", ("proj_empty",)
        ).fetchone()["c"]
    assert count == 0
