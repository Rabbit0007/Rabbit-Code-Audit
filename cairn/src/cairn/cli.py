import json
from pathlib import Path

import click
import uvicorn

from cairn.dispatcher.logging import configure_logging
from cairn.dispatcher.runtime.instance_lock import DispatcherAlreadyRunning, DispatcherInstanceLock
from cairn.dispatcher.scheduler.loop import DispatcherLoop
from cairn.server import db, product_db


@click.group()
def main():
    """Cairn - Fact-graph based collaborative exploration protocol."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8000, show_default=True, help="Bind port")
@click.option(
    "--db-path",
    type=click.Path(),
    default=str(db.DEFAULT_DB),
    show_default=True,
    help="SQLite database path",
)
@click.option("--log-level", default="info", show_default=True, help="Uvicorn log level")
@click.option("--access-log/--no-access-log", default=True, show_default=True, help="Enable Uvicorn access log")
def serve(host: str, port: int, db_path: str, log_level: str, access_log: bool):
    """Start the Cairn API server."""
    db.configure(Path(db_path))
    from cairn.server.app import app

    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Dispatcher config path",
)
@click.option("--once", is_flag=True, help="Run one scheduling iteration and exit")
@click.option(
    "--startup-healthcheck-only",
    is_flag=True,
    help="Run startup worker healthchecks and exit",
)
@click.option("--log-level", default="INFO", show_default=True, help="Log level")
def dispatch(config_path: Path, once: bool, startup_healthcheck_only: bool, log_level: str):
    """Run the Cairn dispatcher."""
    configure_logging(log_level, bare=startup_healthcheck_only)
    loop = DispatcherLoop(config_path)
    try:
        if startup_healthcheck_only:
            loop.run_startup_healthchecks_only()
            return
        lock = DispatcherInstanceLock.for_config(config_path, loop.config)
        with lock:
            loop.run(once=once)
    except DispatcherAlreadyRunning as exc:
        loop.close()
        raise click.ClickException(str(exc)) from exc
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


@main.command("audit-quality")
@click.option(
    "--db-path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
    help="SQLite database path",
)
@click.option("--project-id", required=True, help="Project id to summarize")
@click.option("--expected-entrypoints", type=int, help="Fail if indexed entrypoints are below this value")
@click.option("--expected-confirmed-findings", type=int, help="Fail if confirmed audit findings are below this value")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format",
)
def audit_quality(
    db_path: Path,
    project_id: str,
    expected_entrypoints: int | None,
    expected_confirmed_findings: int | None,
    output_format: str,
):
    """Summarize audit discovery coverage for regression checks."""
    db.configure(db_path)
    product_db.configure_product_db()
    summary = _build_audit_quality_summary(project_id)
    failures: list[str] = []
    if expected_entrypoints is not None and summary["code_index"]["entrypoint_count"] < expected_entrypoints:
        failures.append(
            f"entrypoints {summary['code_index']['entrypoint_count']} < expected {expected_entrypoints}"
        )
    if (
        expected_confirmed_findings is not None
        and summary["audit_findings"]["by_status"].get("confirmed", 0) < expected_confirmed_findings
    ):
        failures.append(
            "confirmed findings "
            f"{summary['audit_findings']['by_status'].get('confirmed', 0)} "
            f"< expected {expected_confirmed_findings}"
        )
    summary["threshold_failures"] = failures
    if output_format == "json":
        click.echo(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        click.echo(f"project: {summary['project']['id']} ({summary['project']['status']})")
        click.echo(f"ready snapshot: {summary['source']['ready_snapshot_id'] or '-'}")
        click.echo(f"entrypoints: {summary['code_index']['entrypoint_count']}")
        click.echo(f"audit candidates: {summary['audit_candidates']['total']}")
        click.echo(f"  open required: {summary['audit_candidates']['open_required']}")
        click.echo(f"  needs more evidence: {summary['audit_candidates']['by_status'].get('needs_more_evidence', 0)}")
        click.echo(f"audit findings confirmed: {summary['audit_findings']['by_status'].get('confirmed', 0)}")
        click.echo(f"audit findings pending review: {summary['audit_findings']['by_status'].get('pending_review', 0)}")
        if failures:
            click.echo("threshold failures:")
            for failure in failures:
                click.echo(f"  - {failure}")
    if failures:
        raise click.ClickException("audit quality thresholds not met")


@main.command("run-audit-tools")
@click.option(
    "--db-path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=db.DEFAULT_DB,
    show_default=True,
    help="SQLite database path",
)
@click.option("--project-id", required=True, help="Project id to scan")
@click.option("--snapshot-id", help="Ready source snapshot id; defaults to the latest ready snapshot")
@click.option("--tool", "tools", multiple=True, help="Run only this tool name; may be repeated")
@click.option("--timeout-per-tool", type=int, default=180, show_default=True, help="Per-tool timeout in seconds")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format",
)
def run_audit_tools(
    db_path: Path,
    project_id: str,
    snapshot_id: str | None,
    tools: tuple[str, ...],
    timeout_per_tool: int,
    output_format: str,
):
    """Run installed audit tools and store results as candidates only."""
    db.configure(db_path)
    product_db.configure_product_db()
    from cairn.server.audit_tool_runner import run_audit_tools_for_project

    summaries = run_audit_tools_for_project(
        project_id,
        snapshot_id=snapshot_id,
        timeout_per_tool=timeout_per_tool,
        selected_tools=set(tools) if tools else None,
    )
    payload = [summary.__dict__ for summary in summaries]
    if output_format == "json":
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    for summary in summaries:
        detail = f" ({summary.detail})" if summary.detail else ""
        click.echo(f"{summary.tool_name}: {summary.status}, findings={summary.finding_count}{detail}")


def _build_audit_quality_summary(project_id: str) -> dict:
    with db.get_conn() as conn:
        project = conn.execute(
            "SELECT id, title, status, created_at FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if project is None:
            raise click.ClickException(f"project not found: {project_id}")
        ready_source = conn.execute(
            """
            SELECT id, file_count, total_bytes, detected_languages_json
            FROM source_snapshots
            WHERE project_id = ? AND status = 'ready'
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (project_id,),
        ).fetchone()
        ready_snapshot_id = ready_source["id"] if ready_source is not None else None
        entrypoint_count = 0
        if ready_snapshot_id is not None:
            entrypoint_count = conn.execute(
                "SELECT COUNT(*) AS count FROM code_entrypoints WHERE snapshot_id = ?",
                (ready_snapshot_id,),
            ).fetchone()["count"]
        candidate_status = _count_by(conn, "audit_candidates", project_id, "status")
        candidate_type = _count_by(conn, "audit_candidates", project_id, "candidate_type")
        candidate_severity = _count_by(conn, "audit_candidates", project_id, "severity")
        finding_status = _count_by(conn, "audit_findings", project_id, "status")
        finding_severity = _count_by(conn, "audit_findings", project_id, "severity")
        open_required = conn.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_candidates
            WHERE project_id = ?
              AND severity IN ('critical', 'high', 'unknown')
              AND status IN ('candidate', 'investigating')
            """,
            (project_id,),
        ).fetchone()["count"]
    return {
        "project": dict(project),
        "source": {
            "ready_snapshot_id": ready_snapshot_id,
            "file_count": ready_source["file_count"] if ready_source is not None else 0,
            "total_bytes": ready_source["total_bytes"] if ready_source is not None else 0,
            "detected_languages": _decode_json_object(
                ready_source["detected_languages_json"] if ready_source is not None else None
            ),
        },
        "code_index": {"entrypoint_count": entrypoint_count},
        "audit_candidates": {
            "total": sum(candidate_status.values()),
            "open_required": open_required,
            "by_status": candidate_status,
            "by_type": candidate_type,
            "by_severity": candidate_severity,
        },
        "audit_findings": {
            "total": sum(finding_status.values()),
            "by_status": finding_status,
            "by_severity": finding_severity,
        },
    }


def _count_by(conn, table: str, project_id: str, field: str) -> dict[str, int]:
    rows = conn.execute(
        f"SELECT {field} AS key, COUNT(*) AS count FROM {table} WHERE project_id = ? GROUP BY {field}",
        (project_id,),
    ).fetchall()
    return {row["key"]: row["count"] for row in rows}


def _decode_json_object(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}
