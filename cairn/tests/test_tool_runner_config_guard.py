"""The in-process tool runner must not execute scanners that load repository config.

ESLint, Psalm and PHPStan execute configuration found inside the audited source.
Running them in the server process would let an untrusted repository run code on
the server host, so they are skipped unless explicitly allowed.  No real scanner
is ever started: ``subprocess.run`` and ``shutil.which`` are replaced.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from cairn.server import audit_tool_runner
from cairn.server.audit_tool_runner import (
    ALLOW_PROJECT_CONFIG_TOOLS_ENV,
    PROJECT_CONFIG_EXECUTING_TOOLS,
    _run_one_tool,
)
from cairn.server.audit_tools import AuditToolPlan


def _plan(name: str, executable: str | None = None) -> AuditToolPlan:
    return AuditToolPlan(
        name=name,
        category="sast",
        command=[executable or name, "--json", "/src"],
        reason="test",
        output_format="json",
    )


@pytest.fixture
def spy(monkeypatch, tmp_path):
    """Pretend every binary exists, record every process launch, persist nothing."""
    launches: list[list[str]] = []

    monkeypatch.delenv(ALLOW_PROJECT_CONFIG_TOOLS_ENV, raising=False)
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setattr(audit_tool_runner.shutil, "which", lambda name: f"/fake/bin/{name}")

    def fake_run(command, **kwargs):
        launches.append(list(command))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(audit_tool_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(audit_tool_runner, "_persist_tool_findings", lambda *a, **k: None)
    monkeypatch.setattr(audit_tool_runner, "parse_tool_output", lambda *a, **k: [])
    return launches


def _run(plan: AuditToolPlan):
    return _run_one_tool("proj_1", "snap_1", Path("/nonexistent-source-root"), [], plan, 30)


@pytest.mark.parametrize("tool", sorted(PROJECT_CONFIG_EXECUTING_TOOLS))
def test_config_loading_tools_are_skipped_by_default(spy, tool):
    summary = _run(_plan(tool))

    assert summary.status == "skipped"
    assert ALLOW_PROJECT_CONFIG_TOOLS_ENV in (summary.detail or "")
    assert spy == [], "the scanner process must never be started"


@pytest.mark.parametrize("tool", sorted(PROJECT_CONFIG_EXECUTING_TOOLS))
@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_non_truthy_values_do_not_enable_config_loading_tools(spy, monkeypatch, tool, value):
    monkeypatch.setenv(ALLOW_PROJECT_CONFIG_TOOLS_ENV, value)

    assert _run(_plan(tool)).status == "skipped"
    assert spy == []


@pytest.mark.parametrize("tool", sorted(PROJECT_CONFIG_EXECUTING_TOOLS))
@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_explicit_opt_in_runs_config_loading_tools(spy, monkeypatch, tool, value):
    monkeypatch.setenv(ALLOW_PROJECT_CONFIG_TOOLS_ENV, value)

    summary = _run(_plan(tool))

    assert summary.status == "success"
    assert len(spy) == 1


@pytest.mark.parametrize("tool", ["semgrep", "gitleaks", "osv-scanner", "trivy", "bandit"])
def test_scanners_that_ignore_repository_config_still_run(spy, tool):
    summary = _run(_plan(tool))

    assert summary.status == "success"
    assert len(spy) == 1


def test_guarded_tool_set_is_exactly_the_config_loading_scanners():
    # Guards against the set silently drifting from build_tool_plan().
    assert PROJECT_CONFIG_EXECUTING_TOOLS == {"eslint-security", "psalm", "phpstan"}


def test_plan_names_match_guarded_names():
    from cairn.server.audit_tools import build_tool_plan
    from cairn.server.source_models import SourceSnapshot

    snapshot = SourceSnapshot(
        id="snap_1",
        project_id="proj_1",
        source_type="zip",
        status="ready",
        detected_languages={"PHP": 1, "JavaScript": 1},
        created_at="2026-01-01T00:00:00Z",
    )
    names = {plan.name for plan in build_tool_plan(snapshot, [], "/src")}

    assert PROJECT_CONFIG_EXECUTING_TOOLS <= names
