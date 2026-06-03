from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import socket
import stat
import subprocess
import tempfile
from typing import BinaryIO
from urllib.parse import urlparse
import uuid
import zipfile

from cairn.server import db
from cairn.server.services import get_project_or_404, utcnow
from cairn.server.source_models import CodeFile, SourceSnapshot


MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 5 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_FILE_COUNT = 200_000
COPY_CHUNK_BYTES = 1024 * 1024

LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
}


def artifact_root() -> Path:
    configured = os.getenv("CAIRN_ARTIFACT_ROOT")
    root = Path(configured).expanduser() if configured else db.current_path().parent / "artifacts"
    root.mkdir(parents=True, exist_ok=True)
    return root


def snapshot_path(snapshot_id: str) -> Path:
    return artifact_root() / "snapshots" / snapshot_id / "source"


def snapshot_container_path(snapshot_id: str) -> str:
    return f"/audit-data/artifacts/snapshots/{snapshot_id}/source"


def import_git_source(project_id: str, repository_url: str, requested_ref: str | None) -> SourceSnapshot:
    _validate_public_git_url(repository_url)
    snapshot_id = _new_snapshot_id()
    created_at = utcnow()
    _insert_importing_snapshot(
        snapshot_id,
        project_id,
        source_type="git",
        repository_url=repository_url,
        requested_ref=requested_ref,
        original_name=None,
        created_at=created_at,
    )
    destination = snapshot_path(snapshot_id)
    try:
        with tempfile.TemporaryDirectory(prefix="rabbit-audit-git-") as temp_dir:
            checkout = Path(temp_dir) / "source"
            _run_git(["clone", "--no-local", "--no-hardlinks", repository_url, str(checkout)])
            if requested_ref:
                _run_git(["-C", str(checkout), "checkout", "--detach", requested_ref])
            else:
                _run_git(["-C", str(checkout), "checkout", "--detach"])
            resolved_commit = _run_git(["-C", str(checkout), "rev-parse", "HEAD"]).strip()
            shutil.rmtree(checkout / ".git", ignore_errors=True)
            _move_snapshot(checkout, destination)
        return _finalize_snapshot(snapshot_id, resolved_commit=resolved_commit)
    except Exception as exc:
        _mark_snapshot_failed(snapshot_id, str(exc))
        shutil.rmtree(destination.parent, ignore_errors=True)
        raise


def import_zip_source(project_id: str, original_name: str, stream: BinaryIO) -> SourceSnapshot:
    snapshot_id = _new_snapshot_id()
    created_at = utcnow()
    _insert_importing_snapshot(
        snapshot_id,
        project_id,
        source_type="zip",
        repository_url=None,
        requested_ref=None,
        original_name=original_name,
        created_at=created_at,
    )
    destination = snapshot_path(snapshot_id)
    try:
        with tempfile.TemporaryDirectory(prefix="rabbit-audit-zip-") as temp_dir:
            archive_path = Path(temp_dir) / "upload.zip"
            archive_sha256 = _copy_limited(stream, archive_path, MAX_ARCHIVE_BYTES)
            extracted = Path(temp_dir) / "source"
            extracted.mkdir()
            _safe_extract_zip(archive_path, extracted)
            source_root = _single_root_or_self(extracted)
            _move_snapshot(source_root, destination)
        return _finalize_snapshot(snapshot_id, archive_sha256=archive_sha256)
    except Exception as exc:
        _mark_snapshot_failed(snapshot_id, str(exc))
        shutil.rmtree(destination.parent, ignore_errors=True)
        raise


def list_snapshots(project_id: str) -> list[SourceSnapshot]:
    with db.get_conn() as conn:
        get_project_or_404(conn, project_id)
        rows = conn.execute(
            "SELECT * FROM source_snapshots WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ).fetchall()
    return [_snapshot_from_row(row) for row in rows]


def get_snapshot(project_id: str, snapshot_id: str) -> SourceSnapshot:
    with db.get_conn() as conn:
        get_project_or_404(conn, project_id)
        row = conn.execute(
            "SELECT * FROM source_snapshots WHERE id = ? AND project_id = ?",
            (snapshot_id, project_id),
        ).fetchone()
    if row is None:
        raise ValueError("Source snapshot not found")
    return _snapshot_from_row(row)


def list_code_files(project_id: str, snapshot_id: str, limit: int = 5000) -> list[CodeFile]:
    get_snapshot(project_id, snapshot_id)
    with db.get_conn() as conn:
        rows = conn.execute(
            """
            SELECT snapshot_id, path, size_bytes, sha256, language, is_binary
            FROM code_files
            WHERE snapshot_id = ?
            ORDER BY path
            LIMIT ?
            """,
            (snapshot_id, limit),
        ).fetchall()
    return [
        CodeFile(
            snapshot_id=row["snapshot_id"],
            path=row["path"],
            size_bytes=row["size_bytes"],
            sha256=row["sha256"],
            language=row["language"],
            is_binary=bool(row["is_binary"]),
        )
        for row in rows
    ]


def _validate_public_git_url(repository_url: str) -> None:
    parsed = urlparse(repository_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("repository_url must be a public http or https Git URL")
    if parsed.username or parsed.password:
        raise ValueError("repository_url must not contain credentials")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("repository_url must include a hostname")
    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise ValueError("repository_url hostname could not be resolved") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("repository_url must resolve only to public network addresses")


def _run_git(args: list[str]) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"git exited with {result.returncode}"
        raise RuntimeError(detail)
    return result.stdout


def _copy_limited(stream: BinaryIO, destination: Path, limit: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with destination.open("wb") as handle:
        while True:
            chunk = stream.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"ZIP archive exceeds {limit} bytes")
            digest.update(chunk)
            handle.write(chunk)
    if total == 0:
        raise ValueError("ZIP archive is empty")
    return digest.hexdigest()


def _safe_extract_zip(archive_path: Path, destination: Path) -> None:
    total_bytes = 0
    file_count = 0
    seen_paths: set[str] = set()
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            relative = _safe_zip_path(info.filename)
            if relative is None:
                continue
            normalized = relative.as_posix().casefold()
            if normalized in seen_paths:
                raise ValueError(f"ZIP contains a duplicate path: {relative.as_posix()}")
            seen_paths.add(normalized)
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type == stat.S_IFLNK:
                raise ValueError(f"ZIP contains a symbolic link: {relative.as_posix()}")
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError(f"ZIP contains a special file: {relative.as_posix()}")
            if info.is_dir():
                (destination / relative).mkdir(parents=True, exist_ok=True)
                continue
            file_count += 1
            total_bytes += info.file_size
            if file_count > MAX_FILE_COUNT:
                raise ValueError(f"ZIP contains more than {MAX_FILE_COUNT} files")
            if info.file_size > MAX_FILE_BYTES:
                raise ValueError(f"ZIP file exceeds {MAX_FILE_BYTES} bytes: {relative.as_posix()}")
            if total_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError(f"ZIP expands beyond {MAX_EXTRACTED_BYTES} bytes")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as source, target.open("xb") as output:
                while True:
                    chunk = source.read(COPY_CHUNK_BYTES)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > info.file_size or written > MAX_FILE_BYTES:
                        raise ValueError(f"ZIP file size mismatch: {relative.as_posix()}")
                    output.write(chunk)


def _safe_zip_path(name: str) -> PurePosixPath | None:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise ValueError(f"ZIP contains an absolute path: {name}")
    parts = [part for part in path.parts if part not in ("", ".")]
    if not parts:
        return None
    if any(part == ".." for part in parts):
        raise ValueError(f"ZIP path escapes the archive root: {name}")
    return PurePosixPath(*parts)


def _single_root_or_self(path: Path) -> Path:
    entries = [entry for entry in path.iterdir() if entry.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return path


def _move_snapshot(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError(f"snapshot destination already exists: {destination}")
    shutil.move(str(source), str(destination))


def _finalize_snapshot(
    snapshot_id: str,
    *,
    resolved_commit: str | None = None,
    archive_sha256: str | None = None,
) -> SourceSnapshot:
    files, snapshot_sha256, languages, total_bytes = _index_snapshot(snapshot_id)
    with db.get_conn() as conn:
        conn.executemany(
            """
            INSERT INTO code_files (snapshot_id, path, size_bytes, sha256, language, is_binary)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    item.snapshot_id,
                    item.path,
                    item.size_bytes,
                    item.sha256,
                    item.language,
                    int(item.is_binary),
                )
                for item in files
            ],
        )
        conn.execute(
            """
            UPDATE source_snapshots
            SET status = 'ready',
                resolved_commit = ?,
                archive_sha256 = ?,
                snapshot_sha256 = ?,
                file_count = ?,
                total_bytes = ?,
                detected_languages_json = ?,
                error_message = NULL
            WHERE id = ?
            """,
            (
                resolved_commit,
                archive_sha256,
                snapshot_sha256,
                len(files),
                total_bytes,
                json.dumps(languages, ensure_ascii=True, sort_keys=True),
                snapshot_id,
            ),
        )
        row = conn.execute("SELECT * FROM source_snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    assert row is not None
    return _snapshot_from_row(row)


def _index_snapshot(snapshot_id: str) -> tuple[list[CodeFile], str, dict[str, int], int]:
    root = snapshot_path(snapshot_id)
    files: list[CodeFile] = []
    languages: dict[str, int] = {}
    manifest_digest = hashlib.sha256()
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            relative = path.relative_to(root).as_posix()
            raise ValueError(f"Source snapshot contains a symbolic link: {relative}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        if len(files) >= MAX_FILE_COUNT:
            raise ValueError(f"Source snapshot contains more than {MAX_FILE_COUNT} files")
        if size > MAX_FILE_BYTES:
            raise ValueError(f"Source file exceeds {MAX_FILE_BYTES} bytes: {relative}")
        if total_bytes + size > MAX_EXTRACTED_BYTES:
            raise ValueError(f"Source snapshot exceeds {MAX_EXTRACTED_BYTES} bytes")
        digest, is_binary = _hash_file(path)
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language:
            languages[language] = languages.get(language, 0) + 1
        total_bytes += size
        manifest_digest.update(f"{relative}\0{size}\0{digest}\n".encode("utf-8"))
        files.append(
            CodeFile(
                snapshot_id=snapshot_id,
                path=relative,
                size_bytes=size,
                sha256=digest,
                language=language,
                is_binary=is_binary,
            )
        )
    return files, manifest_digest.hexdigest(), languages, total_bytes


def _hash_file(path: Path) -> tuple[str, bool]:
    digest = hashlib.sha256()
    first = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            if not first:
                first = chunk[:8192]
            digest.update(chunk)
    return digest.hexdigest(), b"\0" in first


def _new_snapshot_id() -> str:
    return f"snap_{uuid.uuid4().hex[:16]}"


def _insert_importing_snapshot(
    snapshot_id: str,
    project_id: str,
    *,
    source_type: str,
    repository_url: str | None,
    requested_ref: str | None,
    original_name: str | None,
    created_at: str,
) -> None:
    with db.get_conn() as conn:
        get_project_or_404(conn, project_id)
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, original_name, repository_url,
                requested_ref, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, 'importing', ?)
            """,
            (
                snapshot_id,
                project_id,
                source_type,
                original_name,
                repository_url,
                requested_ref,
                created_at,
            ),
        )


def _mark_snapshot_failed(snapshot_id: str, error_message: str) -> None:
    with db.get_conn() as conn:
        conn.execute(
            "UPDATE source_snapshots SET status = 'failed', error_message = ? WHERE id = ?",
            (error_message[:2000], snapshot_id),
        )


def _snapshot_from_row(row) -> SourceSnapshot:
    try:
        languages = json.loads(row["detected_languages_json"] or "{}")
    except json.JSONDecodeError:
        languages = {}
    return SourceSnapshot(
        id=row["id"],
        project_id=row["project_id"],
        source_type=row["source_type"],
        original_name=row["original_name"],
        repository_url=row["repository_url"],
        requested_ref=row["requested_ref"],
        resolved_commit=row["resolved_commit"],
        archive_sha256=row["archive_sha256"],
        snapshot_sha256=row["snapshot_sha256"],
        status=row["status"],
        file_count=row["file_count"],
        total_bytes=row["total_bytes"],
        detected_languages=languages if isinstance(languages, dict) else {},
        created_at=row["created_at"],
        error_message=row["error_message"],
    )
