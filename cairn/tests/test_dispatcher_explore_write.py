from __future__ import annotations

from types import SimpleNamespace

from cairn.dispatcher.protocol.client import ApiResult
from cairn.dispatcher.tasks.explore import _write_explore_result


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
        self.audit_findings.append(payload)
        return ApiResult(status_code=201, data={"id": f"finding_{len(self.audit_findings)}"})

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
