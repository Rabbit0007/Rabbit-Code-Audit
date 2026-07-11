from __future__ import annotations

from types import SimpleNamespace

from cairn.dispatcher.protocol.client import ApiResult
from cairn.dispatcher.runtime.cancellation import TaskCancellation
from cairn.dispatcher.runtime.process import ProcessResult
from cairn.dispatcher.tasks import explore as explore_tasks
from cairn.dispatcher.tasks.explore import _write_explore_result
from cairn.server.models import Intent


def _proof_packet(path: str, payload: str) -> dict[str, str]:
    return {
        "title": "SQL injection proof",
        "payload": payload,
        "request": (
            f"GET {path} HTTP/1.1\n"
            "Host: audit.local\n"
            "Accept: */*\n"
            "Connection: close"
        ),
        "response": (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/plain\n\n"
            "database rows returned for injected predicate"
        ),
        "note": "Test fixture proof packet",
    }


def _reproduction_poc(path: str, payload: str) -> dict:
    return {
        "payload": payload,
        "request_template": f"curl 'http://target{path}'",
        "steps": ["替换 target 为测试环境地址", "发送请求并观察响应差异"],
        "expected_result": "响应返回额外数据或出现 SQL 错误差异",
        "verification": "源码中参数被拼接进 SQL 查询",
        "limitations": ["该 PoC 为源码静态推导，未包含真实抓包响应"],
    }


class _FakeClient:
    def __init__(self):
        self.audit_candidates: list[dict] = []
        self.tool_findings: list[dict] = []
        self.audit_findings: list[dict] = []
        self.candidate_conclusions: list[dict] = []
        self.reviews: list[dict] = []
        self.intents: list[dict] = []
        self.fail_audit_finding = False

    def conclude(self, project_id: str, intent_id: str, worker: str, description: str) -> ApiResult:
        return ApiResult(status_code=200, data={"fact": {"id": "f001"}})

    def get_project(self, project_id: str):
        return SimpleNamespace(sources=[SimpleNamespace(id="snap_1", status="ready")])

    def create_audit_candidate(self, project_id: str, payload: dict) -> ApiResult:
        self.audit_candidates.append(payload)
        return ApiResult(status_code=201, data={"id": f"cand_created_{len(self.audit_candidates)}"})

    def create_tool_finding(self, project_id: str, payload: dict) -> ApiResult:
        self.tool_findings.append(payload)
        return ApiResult(status_code=201, data={"id": f"tool_{len(self.tool_findings)}"})

    def create_audit_finding(self, project_id: str, payload: dict) -> ApiResult:
        if self.fail_audit_finding:
            return ApiResult(status_code=422, text="missing business_node_id")
        self.audit_findings.append(payload)
        return ApiResult(status_code=201, data={"id": f"finding_{len(self.audit_findings)}"})

    def create_intent(
        self,
        project_id: str,
        from_ids: list[str],
        description: str,
        creator: str,
        *,
        target_kind: str | None = None,
        target_id: str | None = None,
        objective: str | None = None,
        evidence_gap: str | None = None,
    ) -> ApiResult:
        self.intents.append(
            {
                "project_id": project_id,
                "from": from_ids,
                "description": description,
                "creator": creator,
                "target_kind": target_kind,
                "target_id": target_id,
                "objective": objective,
                "evidence_gap": evidence_gap,
            }
        )
        return ApiResult(status_code=201, data={"id": f"i_repair_{len(self.intents)}"})

    def conclude_audit_candidate(
        self,
        project_id: str,
        candidate_id: str,
        reviewer: str,
        decision: str,
        summary: str,
        evidence: str | None = None,
        audit_finding_id: str | None = None,
    ) -> ApiResult:
        self.candidate_conclusions.append(
            {
                "candidate_id": candidate_id,
                "reviewer": reviewer,
                "decision": decision,
                "summary": summary,
                "evidence": evidence,
                "audit_finding_id": audit_finding_id,
            }
        )
        return ApiResult(status_code=200, data={"id": candidate_id})

    def review_audit_finding(
        self,
        project_id: str,
        finding_id: str,
        reviewer: str,
        decision: str,
    ) -> ApiResult:
        self.reviews.append({"finding_id": finding_id, "reviewer": reviewer, "decision": decision})
        return ApiResult(status_code=200, data={"id": finding_id})


class _FallbackClient:
    def __init__(self):
        self.released: list[tuple[str, str, str]] = []

    def get_project(self, project_id: str):
        return SimpleNamespace(project=SimpleNamespace(status="active"))

    def release(self, project_id: str, intent_id: str, worker: str) -> ApiResult:
        self.released.append((project_id, intent_id, worker))
        return ApiResult(status_code=200, data={})


class _FallbackContainerManager:
    def ensure_running(self, project_id: str, snapshot_ids=None) -> str:
        return f"container-{project_id}"

    def write_text_file(self, container_name: str, path: str, content: str) -> None:
        assert container_name
        assert path
        assert content


class _FallbackDriver:
    def supports_conclude(self) -> bool:
        return True

    def build_conclude(self, worker, prompt: str, session: str) -> list[str]:
        assert prompt
        assert session == "session-1"
        return ["pi", "resume"]


def test_conclude_fallback_returncode_124_is_reported_as_timeout(monkeypatch):
    def fake_run_process(*args, **kwargs):
        return ProcessResult(returncode=124, stdout="partial", stderr="", timed_out=False)

    monkeypatch.setattr(explore_tasks, "_run_process", fake_run_process)

    client = _FallbackClient()
    outcome = explore_tasks._try_conclude_fallback(
        SimpleNamespace(
            runtime=SimpleNamespace(prompt_group="default"),
            tasks=SimpleNamespace(explore=SimpleNamespace(conclude_timeout=90)),
        ),
        client,
        _FallbackContainerManager(),
        "container-proj_1",
        SimpleNamespace(name="worker-a"),
        _FallbackDriver(),
        "proj_1",
        Intent.model_validate(
            {
                "id": "i001",
                "from": ["f001"],
                "description": "audit user flow",
                "creator": "tester",
                "created_at": "2026-06-06T00:00:00Z",
            }
        ),
        "facts: []",
        "session-1",
        SimpleNamespace(failure=None),
        TaskCancellation(),
    )

    assert outcome.status == "failed"
    assert outcome.error_type == "fallback_timeout"
    assert outcome.used_fallback is True
    assert client.released == [("proj_1", "i001", "worker-a")]


def test_write_explore_result_persists_batch_findings_and_candidate_closure():
    client = _FakeClient()

    outcome = _write_explore_result(
        client,
        "proj_1",
        "i001",
        "worker-a",
        {
            "description": "发现并闭环多个审计对象",
            "audit_candidates": [
                {
                    "ref": "login_candidate",
                    "candidate_type": "web_entrypoint",
                    "severity": "unknown",
                    "title": "审计 Web 脚本: login.php",
                    "description": "需要审计登录入口",
                    "file_path": "login.php",
                    "line_start": 1,
                    "entry_point": "/login.php",
                }
            ],
            "tool_findings": [
                {
                    "tool_name": "semgrep",
                    "severity": "medium",
                    "title": "scanner candidate",
                    "description": "scanner output",
                    "file_path": "search.php",
                    "line_start": 7,
                }
            ],
            "findings": [
                {
                    "candidate_ref": "login_candidate",
                    "title": "login SQL injection",
                    "category": "injection",
                    "severity": "high",
                    "file_path": "login.php",
                    "line_start": 12,
                    "entry_point": "/login.php",
                    "description": "password reaches query construction",
                    "impact": "authentication bypass",
                    "evidence": "$_POST['pass'] is concatenated into SELECT",
                    "reproduction_poc": _reproduction_poc(
                        "/login.php?pass=%27%20OR%201%3D1",
                        "' OR 1=1",
                    ),
                },
                {
                    "candidate_id": "cand_existing",
                    "title": "search SQL injection",
                    "category": "injection",
                    "severity": "high",
                    "file_path": "search.php",
                    "line_start": 7,
                    "entry_point": "/search.php",
                    "description": "query reaches SQL construction",
                    "impact": "data extraction",
                    "evidence": "$_GET['q'] is concatenated into SELECT",
                    "proof_packets": [_proof_packet("/search.php?q=1%27%20OR%201%3D1", "1' OR 1=1")],
                },
            ],
            "candidate_conclusions": [
                {
                    "candidate_id": "cand_safe",
                    "decision": "rejected",
                    "summary": "uses parameter binding",
                    "evidence": "profile.php uses bind_param()",
                }
            ],
        },
        source="explore_execute",
        phase_ms=10,
    )

    assert outcome.status == "success"
    assert len(client.audit_findings) == 2
    assert all("candidate_id" not in item for item in client.audit_findings)
    assert client.audit_findings[0]["snapshot_id"] == "snap_1"
    assert client.audit_findings[0]["reproduction_poc"]["payload"] == "' OR 1=1"
    assert len(client.audit_candidates) == 2
    assert client.audit_candidates[1]["candidate_type"] == "tool_finding"
    assert client.audit_candidates[1]["tool_finding_id"] == "tool_1"
    assert client.candidate_conclusions == [
        {
            "candidate_id": "cand_created_1",
            "reviewer": "worker-a",
            "decision": "confirmed",
            "summary": "login SQL injection",
            "evidence": "$_POST['pass'] is concatenated into SELECT",
            "audit_finding_id": "finding_1",
        },
        {
            "candidate_id": "cand_existing",
            "reviewer": "worker-a",
            "decision": "confirmed",
            "summary": "search SQL injection",
            "evidence": "$_GET['q'] is concatenated into SELECT",
            "audit_finding_id": "finding_2",
        },
        {
            "candidate_id": "cand_safe",
            "reviewer": "worker-a",
            "decision": "rejected",
            "summary": "uses parameter binding",
            "evidence": "profile.php uses bind_param()",
            "audit_finding_id": None,
        },
    ]


def test_write_explore_result_filters_unsupported_fallback_candidate_conclusions():
    client = _FakeClient()

    outcome = _write_explore_result(
        client,
        "proj_1",
        "i001",
        "worker-a",
        {
            "description": "fallback summarized only source-backed closures",
            "candidate_conclusions": [
                {
                    "candidate_id": "cand_safe",
                    "decision": "rejected",
                    "summary": "uses parameter binding",
                    "evidence": "profile.php uses bind_param()",
                },
                {
                    "candidate_id": "cand_guess",
                    "decision": "rejected",
                    "summary": "looks safe from graph",
                    "evidence": "仅凭索引看起来有权限控制",
                },
            ],
        },
        source="explore_conclude",
        phase_ms=10,
        used_fallback=True,
    )

    assert outcome.status == "success"
    assert client.candidate_conclusions == [
        {
            "candidate_id": "cand_safe",
            "reviewer": "worker-a",
            "decision": "rejected",
            "summary": "uses parameter binding",
            "evidence": "profile.php uses bind_param()",
            "audit_finding_id": None,
        }
    ]


def test_write_explore_result_creates_repair_intent_when_finding_write_fails():
    client = _FakeClient()
    client.fail_audit_finding = True

    outcome = _write_explore_result(
        client,
        "proj_1",
        "i001",
        "worker-a",
        {
            "description": "发现了一个高危漏洞，但落库需要补齐结构化字段",
            "findings": [
                {
                    "title": "upload chain RCE",
                    "category": "file_upload",
                    "severity": "high",
                    "file_path": "app/upload.py",
                    "line_start": 42,
                    "entry_point": "POST /upload",
                    "description": "upload reaches execution",
                    "impact": "remote command execution",
                    "evidence": "uploaded file is executed by worker",
                    "reproduction_poc": _reproduction_poc(
                        "/upload",
                        "payload.php",
                    ),
                }
            ],
        },
        source="explore_execute",
        phase_ms=10,
    )

    assert outcome.status == "failed"
    assert outcome.error_type == "structured_output_write_failed"
    assert len(client.audit_findings) == 0
    assert len(client.audit_candidates) == 1
    assert client.audit_candidates[0]["source"] == "model_write_failed"
    assert client.audit_candidates[0]["candidate_type"] == "finding_write_failed"
    assert client.intents == [
        {
            "project_id": "proj_1",
            "from": ["f001"],
            "description": client.intents[0]["description"],
            "creator": "repair:worker-a",
            "target_kind": "structured_output_write_failure",
            "target_id": "i001",
            "objective": "repair_structured_output",
            "evidence_gap": "server_write_validation",
        }
    ]
    assert "missing business_node_id" in client.intents[0]["description"]
