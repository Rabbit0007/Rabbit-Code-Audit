"""Regression tests for Git import hardening.

* ``ref`` is passed to ``git checkout`` as a positional argument.  It used to be
  only stripped, so a value such as ``--pathspec-from-file=/etc/hosts`` reached
  git as an option.  It is now validated against an allow-list before any git
  command runs.
* ``subprocess.TimeoutExpired`` used to escape ``_run_git`` and surface the full
  command line in the API error; it is now a ``RuntimeError`` with a short
  message.

The tests never invoke a real ``git`` binary.
"""

from __future__ import annotations

import subprocess

import pytest

from cairn.server import source_service
from cairn.server.source_service import _validate_git_ref, _run_git


@pytest.mark.parametrize(
    "ref",
    [
        None,
        "main",
        "master",
        "v1.2.3",
        "release/2026-07",
        "feature/login_fix",
        "HEAD~2",
        "HEAD^",
        "origin/main",
        "9fceb02d0ae598e95dc970b74767f19372d61af8",
        "refs/tags/v2.0.0",
    ],
)
def test_ordinary_refs_are_accepted(ref):
    _validate_git_ref(ref)


@pytest.mark.parametrize(
    "ref",
    [
        "--pathspec-from-file=/etc/hosts",
        "--orphan",
        "-f",
        "-b",
        "--help",
        "--detach",
        "--conflict=diff3",
        "--",
        "-",
    ],
)
def test_option_like_refs_are_rejected(ref):
    with pytest.raises(ValueError):
        _validate_git_ref(ref)


@pytest.mark.parametrize(
    "ref",
    [
        "main branch",
        "main;rm -rf /",
        "main\nHEAD",
        "$(whoami)",
        "`id`",
        "a|b",
        "a&b",
        "ref with space",
        "",
        "x" * 300,
        "分支",
    ],
)
def test_shell_and_whitespace_refs_are_rejected(ref):
    with pytest.raises(ValueError):
        _validate_git_ref(ref)


def test_import_git_source_rejects_bad_ref_before_running_git(monkeypatch):
    calls = []

    def fail_if_git_runs(args):
        calls.append(args)
        raise AssertionError("git must not run for an invalid ref")

    monkeypatch.setattr(source_service, "_validate_public_git_url", lambda url: None)
    monkeypatch.setattr(source_service, "_run_git", fail_if_git_runs)

    with pytest.raises(ValueError):
        source_service.import_git_source("proj_x", "https://example.com/r.git", "--orphan")

    assert calls == []


def test_checkout_passes_ref_after_end_of_options(monkeypatch, tmp_path):
    recorded = []

    def record(args):
        recorded.append(list(args))
        if args[:1] == ["clone"]:
            checkout = args[-1]
            import os

            os.makedirs(os.path.join(checkout, ".git"), exist_ok=True)
            return ""
        if "rev-parse" in args:
            return "0123456789abcdef0123456789abcdef01234567\n"
        return ""

    monkeypatch.setattr(source_service, "_validate_public_git_url", lambda url: None)
    monkeypatch.setattr(source_service, "_run_git", record)
    monkeypatch.setattr(source_service, "import_staging_root", lambda: tmp_path)
    monkeypatch.setattr(source_service, "_insert_importing_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(source_service, "_move_snapshot", lambda *a, **k: None)
    monkeypatch.setattr(source_service, "_finalize_snapshot", lambda *a, **k: "finalized")
    monkeypatch.setattr(source_service, "snapshot_path", lambda snapshot_id: tmp_path / "dest" / "source")

    result = source_service.import_git_source("proj_x", "https://example.com/r.git", "release/1.0")

    assert result == "finalized"
    checkout_call = next(call for call in recorded if "checkout" in call)
    assert checkout_call[-2:] == ["--end-of-options", "release/1.0"]


def test_run_git_converts_timeout_into_short_runtime_error(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["git", "clone", "https://example.com/secret-token"], timeout=900)

    monkeypatch.setattr(source_service.subprocess, "run", raise_timeout)

    with pytest.raises(RuntimeError) as excinfo:
        _run_git(["clone", "https://example.com/secret-token"])

    message = str(excinfo.value)
    assert "timed out" in message
    # The command line (which can contain the repository URL) must not leak.
    assert "secret-token" not in message
