from __future__ import annotations

import io
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from cairn.dispatcher.contracts import validate_explore_payload
from cairn.server import db
from cairn.server.routers import business_graph, export, findings, projects, sources, vulnerabilities


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    app.include_router(business_graph.router)
    app.include_router(export.router)
    app.include_router(vulnerabilities.router)
    return app


def _client(temp_db) -> TestClient:
    return TestClient(_app(temp_db))


def _create_project(client: TestClient) -> str:
    response = client.post(
        "/projects",
        json={
            "title": "audit",
            "origin": "source audit",
            "goal": "review scope",
            "hints": [],
        },
    )
    assert response.status_code == 201
    return response.json()["project"]["id"]


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _proof_packet(
    path: str = "/app.php?x=%3Cscript%3Ealert(1)%3C/script%3E",
    payload: str = "<script>alert(1)</script>",
) -> dict[str, str]:
    return {
        "title": "HTTP proof",
        "payload": payload,
        "request": (
            f"GET {path} HTTP/1.1\n"
            "Host: audit.local\n"
            "Accept: */*\n"
            "Connection: close"
        ),
        "response": (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n\n"
            f"{payload}"
        ),
        "note": "Test fixture proof packet",
    }


def _reproduction_poc(payload: str = "<script>alert(1)</script>") -> dict:
    return {
        "payload": payload,
        "request_template": (
            "curl 'http://target/app.php?x=%3Cscript%3Ealert(1)%3C/script%3E'"
        ),
        "steps": [
            "替换 target 为测试环境地址",
            "发送请求并观察响应中是否回显 payload",
        ],
        "expected_result": "响应体回显脚本内容，浏览器环境可触发脚本执行",
        "verification": "源码中 app.php 直接 echo $_GET['x']，未做 HTML 转义",
        "limitations": ["该 PoC 为源码静态推导，未包含真实抓包响应"],
    }


def test_explore_payload_accepts_structured_finding_and_review():
    kind, finding_result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "confirmed code evidence",
                "tool_findings": [
                    {
                        "tool_name": "semgrep",
                        "title": "candidate",
                        "description": "scanner output",
                    }
                ],
                "finding": {
                    "title": "authorization bypass",
                    "category": "authorization",
                    "severity": "high",
                    "file_path": "app/controllers/refund.py",
                    "line_start": 42,
                    "entry_point": "POST /api/refund",
                    "description": "resource ownership is not checked",
                    "impact": "attacker can refund another user's order",
                    "evidence": "RefundController.update_order_status does not compare owner_id",
                    "reproduction_poc": {
                        "payload": "order_id=1002&status=refunded",
                        "request_template": (
                            "curl -X POST -d 'order_id=1002&status=refunded' "
                            "http://target/api/refund"
                        ),
                        "steps": ["替换 target 为测试环境地址", "发送越权退款请求"],
                        "expected_result": "订单状态被更新为 refunded",
                        "verification": "RefundController.update_order_status does not compare owner_id",
                    },
                },
            },
        }
    )
    assert kind == "fact"
    assert finding_result["finding"]["severity"] == "high"
    assert finding_result["findings"][0]["severity"] == "high"
    assert finding_result["tool_findings"][0]["tool_name"] == "semgrep"

    _, batch_result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "covered two audit objects",
                "findings": [
                    {
                        "title": "SQL injection in search",
                        "category": "injection",
                        "severity": "high",
                        "file_path": "search.php",
                        "line_start": 12,
                        "entry_point": "/search.php",
                        "candidate_id": "cand_1",
                        "description": "user input reaches query construction",
                        "impact": "attacker can read arbitrary rows",
                        "evidence": "$_GET['q'] is concatenated into SELECT",
                        "proof_packets": [
                            _proof_packet(
                                "/search.php?q=1%27%20OR%20%271%27%3D%271",
                                "1' OR '1'='1",
                            )
                        ],
                    },
                    {
                        "title": "SQL injection in login",
                        "category": "injection",
                        "severity": "high",
                        "file_path": "login.php",
                        "line_start": 20,
                        "entry_point": "/login.php",
                        "candidate_id": "cand_2",
                        "description": "password parameter reaches query construction",
                        "impact": "attacker can bypass authentication",
                        "evidence": "$_POST['pass'] is concatenated into SELECT",
                        "proof_packets": [
                            _proof_packet(
                                "/login.php?pass=%27%20OR%20%271%27%3D%271",
                                "' OR '1'='1",
                            )
                        ],
                    },
                ],
                "audit_candidates": [
                    {
                        "ref": "profile_flow",
                        "candidate_type": "data_flow",
                        "severity": "unknown",
                        "title": "profile update flow",
                        "description": "needs authorization review",
                        "file_path": "profile.php",
                        "line_start": 1,
                    }
                ],
                "candidate_conclusions": [
                    {
                        "candidate_id": "cand_3",
                        "decision": "rejected",
                        "summary": "query uses parameter binding",
                        "evidence": "profile.php calls prepare() and bind_param()",
                    }
                ],
            },
        }
    )
    assert len(batch_result["findings"]) == 2
    assert batch_result["audit_candidates"][0]["ref"] == "profile_flow"
    assert batch_result["candidate_conclusions"][0]["decision"] == "rejected"

    _, review_result = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "independent review completed",
                "reviews": [{"finding_id": "finding_1", "decision": "confirmed"}],
            },
        }
    )
    assert review_result["review"]["finding_id"] == "finding_1"
    assert review_result["reviews"][0]["finding_id"] == "finding_1"


def test_zip_source_import_creates_immutable_snapshot_and_file_index(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app.py": b"print('hello')\n",
            "demo/composer.json": b'{"require": {}}\n',
            "demo/public/index.php": b"<?php echo 'ok';\n",
        }
    )
    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    )

    assert response.status_code == 201
    snapshot = response.json()
    assert snapshot["status"] == "ready"
    assert snapshot["source_type"] == "zip"
    assert snapshot["file_count"] == 3
    assert snapshot["detected_languages"] == {"PHP": 1, "Python": 1}
    assert len(snapshot["archive_sha256"]) == 64
    assert len(snapshot["snapshot_sha256"]) == 64

    files = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/files").json()
    assert [item["path"] for item in files] == ["app.py", "composer.json", "public/index.php"]
    assert {item["language"] for item in files} == {None, "PHP", "Python"}

    project = client.get(f"/projects/{project_id}").json()
    assert project["sources"][0]["id"] == snapshot["id"]


def test_source_import_builds_lightweight_code_structure_index(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app.py": b"""
from fastapi import FastAPI

app = FastAPI()

@app.post("/orders/{order_id}/refund")
def refund_order(order_id: str):
    return {"ok": True}

class RefundService:
    def approve(self, order_id: str):
        return order_id
""",
            "demo/routes.js": b"""
const router = require("express").Router();
router.get("/health", healthHandler);
function healthHandler(req, res) { res.send("ok"); }
""",
            "demo/package.json": b'{"name":"demo","dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"^29.0.0"}}',
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    summary = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/index-summary")
    assert summary.status_code == 200
    assert summary.json()["symbol_count"] >= 3
    assert summary.json()["entrypoint_count"] == 2
    assert summary.json()["manifest_count"] == 1

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    assert {item["route"] for item in entrypoints} == {"/orders/{order_id}/refund", "/health"}
    assert {item["method"] for item in entrypoints} == {"POST", "GET"}

    symbols = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/symbols").json()
    assert {"refund_order", "RefundService", "healthHandler"} <= {item["name"] for item in symbols}

    manifests = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/manifests").json()
    assert manifests[0]["manifest_type"] == "npm"
    assert manifests[0]["dependencies"] == ["express"]
    assert manifests[0]["dev_dependencies"] == ["jest"]

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    data = yaml.safe_load(exported.text)
    assert data["code_index"]["summary"]["entrypoint_count"] == 2
    assert {item["route"] for item in data["code_index"]["entrypoints"]} == {"/orders/{order_id}/refund", "/health"}


def test_source_import_creates_generic_audit_candidates(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/public/index.php": b"<?php echo $_GET['id'];\n",
            "demo/routes.js": b"""
const router = require("express").Router();
router.post("/login", loginHandler);
function loginHandler(req, res) { res.send("ok"); }
""",
            "demo/vendor/package/ignored.php": b"<?php echo 'lib';\n",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    candidate_types = {item["candidate_type"] for item in candidates}
    assert {"entrypoint", "web_entrypoint"} <= candidate_types
    assert all(item["severity"] == "unknown" for item in candidates)
    assert "vendor/package/ignored.php" not in {item["file_path"] for item in candidates}

    manual = client.post(
        f"/api/projects/{project_id}/audit-candidates",
        json={
            "snapshot_id": snapshot["id"],
            "source": "model",
            "candidate_type": "data_flow",
            "severity": "high",
            "title": "login password flow",
            "description": "password input requires authentication bypass review",
            "file_path": "routes.js",
            "line_start": 2,
            "entry_point": "POST /login",
            "created_by": "worker-a",
        },
    )
    assert manual.status_code == 201

    missing_evidence = client.post(
        f"/api/projects/{project_id}/audit-candidates/{manual.json()['id']}/conclude",
        json={"reviewer": "worker-a", "decision": "rejected", "summary": "safe"},
    )
    assert missing_evidence.status_code == 422

    concluded = client.post(
        f"/api/projects/{project_id}/audit-candidates/{manual.json()['id']}/conclude",
        json={
            "reviewer": "worker-a",
            "decision": "rejected",
            "summary": "login handler does not query the database",
            "evidence": "routes.js loginHandler returns a static response in this test fixture",
        },
    )
    assert concluded.status_code == 200
    assert concluded.json()["status"] == "rejected"

    exported = client.get(f"/projects/{project_id}/export?format=yaml")
    data = yaml.safe_load(exported.text)
    assert data["audit_candidates"]["coverage"]["total"] == len(candidates) + 1
    assert data["audit_candidates"]["coverage"]["open_required"]
    assert any(item["id"] == manual.json()["id"] for item in data["audit_candidates"]["items"])


def test_zip_source_import_rejects_path_escape(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"../escape.php": b"<?php echo 'bad';"})

    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("escape.zip", payload, "application/zip")},
    )

    assert response.status_code == 400
    assert "escapes the archive root" in response.json()["detail"]
    snapshots = client.get(f"/api/projects/{project_id}/sources").json()
    assert snapshots[0]["status"] == "failed"


def test_zip_source_import_rejects_symbolic_link(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        link = zipfile.ZipInfo("app-link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "/etc/passwd")

    response = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("link.zip", buffer.getvalue(), "application/zip")},
    )

    assert response.status_code == 400
    assert "symbolic link" in response.json()["detail"]


def test_git_source_import_rejects_private_network_url(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)

    response = client.post(
        f"/api/projects/{project_id}/sources/git",
        json={"repository_url": "http://127.0.0.1/private.git"},
    )

    assert response.status_code == 400
    assert "public network addresses" in response.json()["detail"]


def test_high_severity_finding_requires_quality_evidence_and_business_node(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"app.php": b"<?php echo $_GET['x'];"})
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    weak = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "weak claim",
            "category": "authorization",
            "severity": "high",
            "description": "looks bad",
            "discovered_by": "worker-a",
        },
    )
    assert weak.status_code == 422
    assert "file_path" in weak.json()["detail"]
    assert "complete_proof_packet_or_static_poc" in weak.json()["detail"]

    node = client.post(
        f"/api/projects/{project_id}/business-graph/nodes",
        json={
            "node_type": "endpoint",
            "title": "GET /app.php",
            "risk_level": "high",
            "created_by": "worker-a",
        },
    ).json()

    missing_business_node = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "reflected xss",
            "category": "xss",
            "severity": "high",
            "file_path": "app.php",
            "line_start": 1,
            "entry_point": "GET /app.php?x=",
            "description": "reflected output reaches the response without escaping",
            "impact": "attacker can execute script in a victim browser",
            "evidence": "app.php echoes $_GET['x'] directly",
            "proof_packets": [_proof_packet()],
            "discovered_by": "worker-a",
        },
    )
    assert missing_business_node.status_code == 422
    assert "business_node_id" in missing_business_node.json()["detail"]

    valid = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "reflected xss",
            "category": "xss",
            "severity": "high",
            "file_path": "app.php",
            "line_start": 1,
            "entry_point": "GET /app.php?x=",
            "business_node_id": node["id"],
            "description": "reflected output reaches the response without escaping",
            "impact": "attacker can execute script in a victim browser",
            "evidence": "app.php echoes $_GET['x'] directly",
            "proof_packets": [_proof_packet()],
            "discovered_by": "worker-a",
        },
    )
    assert valid.status_code == 201
    assert valid.json()["business_node_id"] == node["id"]

    static_poc = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "reflected xss static poc",
            "category": "xss",
            "severity": "high",
            "file_path": "app.php",
            "line_start": 1,
            "entry_point": "GET /app.php?x=",
            "business_node_id": node["id"],
            "description": "reflected output reaches the response without escaping",
            "impact": "attacker can execute script in a victim browser",
            "evidence": "app.php echoes $_GET['x'] directly",
            "reproduction_poc": _reproduction_poc(),
            "discovered_by": "worker-a",
        },
    )
    assert static_poc.status_code == 201
    assert static_poc.json()["reproduction_poc"]["payload"] == "<script>alert(1)</script>"


def test_high_severity_finding_requires_different_reviewer(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"app.php": b"<?php echo $_GET['x'];"})
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    created = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "candidate",
            "category": "authorization",
            "severity": "high",
            "file_path": "app.php",
            "line_start": 1,
            "entry_point": "GET /app.php?x=",
            "description": "reflected output reaches the response without escaping",
            "impact": "attacker can execute script in a victim browser",
            "evidence": "app.php echoes $_GET['x'] directly",
            "proof_packets": [_proof_packet()],
            "discovered_by": "worker-a",
        },
    )
    assert created.status_code == 201
    finding = created.json()
    assert finding["status"] == "pending_review"
    assert client.get("/api/vulnerabilities").json() == []

    same_worker = client.post(
        f"/api/projects/{project_id}/audit-findings/{finding['id']}/review",
        json={"reviewer": "worker-a", "decision": "confirmed"},
    )
    assert same_worker.status_code == 409

    reviewed = client.post(
        f"/api/projects/{project_id}/audit-findings/{finding['id']}/review",
        json={"reviewer": "worker-b", "decision": "confirmed"},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "confirmed"
    assert reviewed.json()["reviewed_by"] == "worker-b"

    report = client.get("/api/vulnerabilities").json()
    assert len(report) == 1
    assert report[0]["fact_id"] == finding["id"]
    assert report[0]["source_worker"] == "worker-a"

    with db.get_conn() as conn:
        tasks = conn.execute(
            "SELECT finding_id, status, created_by FROM report_enrichment_tasks WHERE project_id = ?",
            (project_id,),
        ).fetchall()
    assert len(tasks) == 1
    assert tasks[0]["finding_id"] == finding["id"]
    assert tasks[0]["status"] == "pending"
    assert tasks[0]["created_by"] == "review:worker-b"

    reviewed_again = client.post(
        f"/api/projects/{project_id}/audit-findings/{finding['id']}/review",
        json={"reviewer": "worker-b", "decision": "confirmed"},
    )
    assert reviewed_again.status_code == 200
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM report_enrichment_tasks WHERE project_id = ?",
            (project_id,),
        ).fetchone()
    assert row["count"] == 1
