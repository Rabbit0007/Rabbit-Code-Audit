from __future__ import annotations

import io
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from cairn.dispatcher.contracts import validate_explore_payload
from cairn.server import db
from cairn.server.routers import business_graph, export, findings, intents, projects, sources, vulnerabilities
from cairn.server.services import utcnow
from cairn.server.source_service import rebuild_source_index


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(intents.router)
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
                "description": "confirmation completed",
                "reviews": [{"finding_id": "finding_1", "decision": "confirmed"}],
            },
        }
    )
    assert review_result["review"]["finding_id"] == "finding_1"
    assert review_result["reviews"][0]["finding_id"] == "finding_1"


def test_candidate_confirmed_without_finding_id_does_not_fail_whole_payload():
    _, missing_evidence = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "candidate review",
                "candidate_conclusions": [
                    {
                        "candidate_id": "cand_1",
                        "decision": "confirmed",
                        "summary": "model asserted vulnerability but did not bind finding",
                    }
                ],
            },
        }
    )
    assert missing_evidence["candidate_conclusions"] == []

    _, with_evidence = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "candidate review",
                "candidate_conclusions": [
                    {
                        "candidate_id": "cand_1",
                        "decision": "confirmed",
                        "summary": "source path looks vulnerable but no finding id was emitted",
                        "evidence": "app/search.php:12 concatenates q into SQL; finding object missing",
                    }
                ],
            },
        }
    )
    conclusion = with_evidence["candidate_conclusions"][0]
    assert conclusion["decision"] == "needs_more_evidence"
    assert conclusion["audit_finding_id"] is None
    assert conclusion["evidence"] == "app/search.php:12 concatenates q into SQL; finding object missing"


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


def test_source_import_indexes_common_python_java_go_routes(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/api.py": b"""
from fastapi import APIRouter, FastAPI
from django.urls import include, path
from . import views

app = FastAPI()
router = APIRouter(prefix="/api/v1")
scoped_router = APIRouter(prefix="/users")
app.include_router(scoped_router, prefix="/api/v2")

@router.get("/users/{user_id}")
def get_user(user_id: str):
    return {"id": user_id}

@scoped_router.post("/{user_id}/lock")
def lock_user(user_id: str):
    return {"id": user_id}

urlpatterns = [
    path("health/", views.health),
    path("api/", include("users.urls")),
]
""",
            "demo/UserController.java": b"""
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {
    @GetMapping("/{id}")
    public User getUser() {
        return null;
    }

    @RequestMapping(value = "/search", method = RequestMethod.POST)
    public List<User> search() {
        return List.of();
    }

    @RequestMapping(
        path = {"/bulk", "/lookup"},
        method = RequestMethod.POST
    )
    public List<User> bulk() {
        return List.of();
    }
}

@Path("/legacy")
class LegacyResource {
    @GET
    @Path("/{id}")
    public Response getLegacy() {
        return null;
    }
}

@RestController
class AdminController {
    @GetMapping("/admin")
    public String admin() {
        return "ok";
    }
}
""",
            "demo/main.go": b"""
package main

func main() {
    http.HandleFunc("/ready", ready)
    r.HandleFunc("/users/{id}", getUser).Methods("GET")
    r.HandleFunc("/reports/{id}", reports.Show).Methods(http.MethodPost)
    chiRouter.Get("/orders/{id}", getOrder)
    app.Post("/fiber", createFiber)
    e.GET("/echo", echoHandler)
    router.GET("/gin", ginHandler)
    router.Handle("GET", "/handle", handleRoot)
    api := router.Group("/api")
    api.GET("/grouped", handlers.Grouped)
    v1 := api.Group("/v1")
    v1.Post("/nested", handlers.Nested)
}

func ready(w http.ResponseWriter, r *http.Request) {}
func getUser(w http.ResponseWriter, r *http.Request) {}
func getOrder(w http.ResponseWriter, r *http.Request) {}
func createFiber(c *fiber.Ctx) error { return nil }
func echoHandler(c echo.Context) error { return nil }
func ginHandler(c *gin.Context) {}
func handleRoot(w http.ResponseWriter, r *http.Request) {}
""",
            "demo/UsersController.cs": b"""
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Get(string id) {
        return Ok();
    }

    [Route("search")]
    [HttpPost]
    public IActionResult Search() {
        return Ok();
    }
}
""",
            "demo/routes/web.php": b"""<?php
use App\\Http\\Controllers\\UserController;

Route::prefix('api')->group(function () {
    Route::get('/profile', [UserController::class, 'profile']);
    Route::post('/profile', 'UserController@update');
});
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("polyglot.zip", payload, "application/zip")},
    ).json()

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    route_methods = {(item["route"], item["method"]) for item in entrypoints}
    assert {
        ("/api/v1/users/{user_id}", "GET"),
        ("/api/v2/users/{user_id}/lock", "POST"),
        ("/health/", None),
        ("/api/", None),
        ("/api/{id}", "GET"),
        ("/api/search", "POST"),
        ("/api/bulk", "POST"),
        ("/api/lookup", "POST"),
        ("/legacy/{id}", "GET"),
        ("/admin", "GET"),
        ("/ready", None),
        ("/users/{id}", "GET"),
        ("/reports/{id}", "POST"),
        ("/orders/{id}", "GET"),
        ("/fiber", "POST"),
        ("/echo", "GET"),
        ("/gin", "GET"),
        ("/handle", "GET"),
        ("/api/grouped", "GET"),
        ("/api/v1/nested", "POST"),
        ("/api/Users/{id}", "GET"),
        ("/api/Users/search", "POST"),
        ("/api/profile", "GET"),
        ("/api/profile", "POST"),
    } <= route_methods

    frameworks = {item["framework"] for item in entrypoints}
    assert {"python", "django", "spring", "jaxrs", "net/http", "mux", "go-router", "gin", "aspnet", "laravel"} <= frameworks

    symbols = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/symbols").json()
    assert {"get_user", "lock_user", "UserController", "AdminController", "UsersController", "ready", "getUser"} <= {item["name"] for item in symbols}


def test_source_index_builds_relationships_and_business_graph_chain(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app/api.py": b"""
from fastapi import APIRouter
from .services import UserService

router = APIRouter(prefix="/api")
service = UserService()

@router.post("/users/{user_id}/lock")
def lock_user(user_id: str):
    return service.lock_user(user_id)
""",
            "demo/app/services.py": b"""
from flask import request
from .models import User

class UserService:
    def lock_user(self, user_id):
        request_user_id = request.args["id"]
        cursor.execute("UPDATE users SET locked = 1 WHERE id = %s" % request_user_id)
        return User(id=user_id)
""",
            "demo/app/models.py": b"""
from django.db import models

class User(models.Model):
    locked = models.BooleanField(default=False)
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("business-chain.zip", payload, "application/zip")},
    ).json()

    summary = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/index-summary").json()
    assert summary["entrypoint_count"] == 1
    assert summary["relationship_count"] >= 4

    quality = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/index-quality").json()
    assert quality["score"] >= 70
    assert quality["grade"] in {"strong", "usable"}
    assert quality["entrypoints_with_data_paths"] >= 1
    assert quality["relationship_counts"]["calls"] >= 1
    assert quality["data_object_count"] >= 1

    relationships = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/relationships").json()
    relationship_pairs = {
        (item["from_path"], item["relation"], item["to_path"], item["to_symbol"])
        for item in relationships
    }
    assert ("app/api.py", "imports", "app/services.py", None) in relationship_pairs
    assert ("app/api.py", "calls", "app/services.py", "UserService") in relationship_pairs
    assert ("app/services.py", "imports", "app/models.py", None) in relationship_pairs
    assert ("app/services.py", "calls", "app/models.py", "User") in relationship_pairs
    assert all(0 < item["confidence"] <= 1 for item in relationships)

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    node_types = {item["node_type"] for item in graph["nodes"]}
    assert {"feature", "endpoint", "control", "data_object", "risk"} <= node_types
    assert any(item["title"] == "业务功能 users" for item in graph["nodes"])
    assert any(item["title"] == "处理逻辑 lock_user" for item in graph["nodes"])
    assert any(item["title"] == "处理逻辑 UserService" for item in graph["nodes"])
    assert any(item["title"] == "数据对象 User" for item in graph["nodes"])
    assert any(item["source_snapshot_id"] == snapshot["id"] for item in graph["nodes"])
    assert all(0 < item["confidence"] <= 1 for item in graph["nodes"])
    assert {"exposes", "calls", "uses", "risk_of"} <= {item["relation"] for item in graph["edges"]}

    reindexed = client.post(f"/api/projects/{project_id}/sources/{snapshot['id']}/reindex")
    assert reindexed.status_code == 200
    assert reindexed.json()["relationship_count"] >= 4
    graph_after = client.get(f"/api/projects/{project_id}/business-graph").json()
    node_ids = [item["id"] for item in graph_after["nodes"]]
    edge_ids = [item["id"] for item in graph_after["edges"]]
    assert len(node_ids) == len(set(node_ids))
    assert len(edge_ids) == len(set(edge_ids))


def test_source_import_indexes_satrda_routes_and_seeds_business_graph(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/server/plugins/erp/util.js": b"""
(function(root) {
  root.ApiPre = "/erp";
})(typeof window !== "undefined" ? window : null);
""",
            "demo/server/plugins/erp/erp.js": b"""
let fileSvr = {
  _all(ctx, r, w, key) {
    ctx.serveContent("myfile/" + key);
  }
};
satrda.Router.all(ApiPre + "/file", fileSvr);
""",
            "demo/server/plugins/erp/h5dw.js": b"""
let dw = {
  saveReport(ctx, r, w) {
    const param = r.jsonBody;
    const { key, filename, dw } = param;
    const filepath = `./plugins/data/${filename}`;
    satrda.writeFile(filepath, JSON.stringify(dw));
    w.write({ status: 0, msg: "ok" });
  }
};
satrda.Router.all(ApiPre + "/h5dw", dw);
""",
            "demo/server/plugins/erp/user.js": b"""
let profile = {
  query(ctx, r, w) {
    const session = ctx.getSession();
    w.write({ code: 200, userId: session.get("userId") });
  }
};
satrda.Router.all(ApiPre + "/system/user/profile", profile);
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("satrda.zip", payload, "application/zip")},
    ).json()

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    assert {item["route"] for item in entrypoints} >= {
        "/erp/file",
        "/erp/h5dw",
        "/erp/system/user/profile",
    }
    assert {item["framework"] for item in entrypoints} == {"satrda"}

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    assert any(item["entry_point"] == "/erp/file" for item in candidates)
    file_write = next(
        item
        for item in candidates
        if item["candidate_type"] == "data_flow"
        and item["file_path"] == "server/plugins/erp/h5dw.js"
        and "文件/包含操作面" in item["title"]
    )
    assert file_write["business_node_id"]

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    endpoint_titles = {node["title"] for node in graph["nodes"] if node["node_type"] == "endpoint"}
    assert {"入口 /erp/file", "入口 /erp/h5dw", "入口 /erp/system/user/profile"} <= endpoint_titles
    risk_nodes = [node for node in graph["nodes"] if node["node_type"] == "risk"]
    assert any("文件/包含操作面" in node["title"] for node in risk_nodes)
    assert any(node["risk_level"] == "unknown" for node in risk_nodes)
    assert graph["edges"]


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
    assert {"entrypoint", "data_flow"} <= candidate_types
    assert all(item["severity"] == "unknown" for item in candidates)
    assert "vendor/package/ignored.php" not in {item["file_path"] for item in candidates}
    assert any(
        item["candidate_type"] == "data_flow"
        and item["file_path"] == "public/index.php"
        and "不代表已确认漏洞" in item["description"]
        for item in candidates
    )

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    assert any(
        item["framework"] == "web_script"
        and item["route"] == "/public/index.php"
        for item in entrypoints
    )

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


def test_source_index_filters_php_include_noise_and_control_symbols(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/public/index.php": b"""<?php
$id = $_GET['id'];
echo $id;
""",
            "demo/includes/functions.php": b"""<?php
function render_value($value) {
    if ($value) {
        echo $value;
    }
}
""",
            "demo/includes/sql-connect.php": b"""<?php
$conn = mysql_connect("localhost", "root", "");
mysql_select_db("security", $conn);
""",
            "demo/sql-connections/setup-db.php": b"""<?php
$sql = "DROP DATABASE IF EXISTS security";
mysql_query($sql);
echo "done";
""",
            "demo/config/db-creds.inc": b"<?php $host = 'localhost';\n",
            "demo/README.md": b"# Demo\n",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("php-noise.zip", payload, "application/zip")},
    ).json()

    assert snapshot["detected_languages"]["PHP"] == 5
    assert "Markdown" not in snapshot["detected_languages"]

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    assert {item["route"] for item in entrypoints} == {
        "/public/index.php",
        "/sql-connections/setup-db.php",
    }
    assert "includes/functions.php" not in {item["path"] for item in entrypoints}
    assert "includes/sql-connect.php" not in {item["path"] for item in entrypoints}

    symbols = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/symbols").json()
    assert "render_value" in {item["name"] for item in symbols}
    assert "if" not in {item["name"] for item in symbols}

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    entrypoint_paths = {
        item["file_path"]
        for item in candidates
        if item["candidate_type"] in {"entrypoint", "web_entrypoint"}
    }
    assert entrypoint_paths == {"public/index.php", "sql-connections/setup-db.php"}


def test_source_import_creates_data_flow_candidates_for_sql_sinks(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/Less-1/index.php": b"""<?php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id='$id' LIMIT 0,1";
$result=mysql_query($sql);
echo "ok";
""",
            "demo/Less-2/index.php": b"""<?php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id=$id LIMIT 0,1";
$result=mysql_query($sql);
echo "ok";
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("sqli.zip", payload, "application/zip")},
    ).json()

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    assert {item["route"] for item in entrypoints} == {"/Less-1/index.php", "/Less-2/index.php"}

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    sql_candidates = [
        item
        for item in candidates
        if item["candidate_type"] == "data_flow" and "SQL 注入面" in item["title"]
    ]
    assert len(sql_candidates) == 2
    assert {item["file_path"] for item in sql_candidates} == {"Less-1/index.php", "Less-2/index.php"}
    assert {item["symbol"] for item in sql_candidates} == {"id"}
    assert all(item["status"] == "candidate" for item in sql_candidates)


def test_source_index_does_not_tie_far_same_name_input_to_sink(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    filler = "\n".join("$noop = 1;" for _ in range(85))

    payload = _zip_bytes(
        {
            "demo/app.php": (
                "<?php\n"
                "$id=$_GET['id'];\n"
                f"{filler}\n"
                "$sql=\"SELECT * FROM users WHERE id=$id\";\n"
                "$result=mysql_query($sql);\n"
            ).encode(),
        }
    )
    client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("far.zip", payload, "application/zip")},
    )

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    assert not [
        item
        for item in candidates
        if item["candidate_type"] == "data_flow" and "SQL 注入面" in item["title"]
    ]


def test_rebuild_source_index_closes_new_candidates_for_completed_project(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app.php": b"""<?php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id=$id";
$result=mysql_query($sql);
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("legacy.zip", payload, "application/zip")},
    ).json()

    with db.get_conn() as conn:
        conn.execute("DELETE FROM audit_candidates WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM business_nodes WHERE project_id = ?", (project_id,))
        conn.execute("UPDATE projects SET status = 'completed' WHERE id = ?", (project_id,))

    rebuild_source_index(snapshot["id"])

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    assert candidates
    assert {item["status"] for item in candidates} == {"needs_more_evidence"}
    assert all(item["conclusion_summary"] for item in candidates)
    assert all(item["evidence"] for item in candidates)
    assert all(item["business_node_id"] for item in candidates if item["candidate_type"] == "data_flow")


def test_export_profiles_focus_graph_context_and_validation_strategy(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/docker-compose.yml": b"services:\n  app:\n    image: php:8.2-apache\n",
            "demo/Less-1/index.php": b"""<?php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id='$id'";
$result=mysql_query($sql);
""",
            "demo/Less-2/index.php": b"""<?php
$id=$_GET['id'];
$sql="SELECT * FROM users WHERE id=$id";
$result=mysql_query($sql);
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("focus.zip", payload, "application/zip")},
    ).json()
    assert snapshot["status"] == "ready"

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    focused = next(
        item for item in candidates if item["candidate_type"] == "data_flow" and item["file_path"] == "Less-1/index.php"
    )
    intent = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": f"审计候选 {focused['id']} 对应的 SQL 数据流，只关闭这个候选。",
            "creator": "reason-worker",
            "worker": None,
        },
    ).json()

    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "explore", "intent_id": intent["id"]},
    )
    data = yaml.safe_load(exported.text)
    assert data["context_profile"]["profile"] == "explore"
    assert data["context_profile"]["focused_candidate_ids"] == [focused["id"]]
    assert data["validation_strategy"]["default_mode"] == "static_first"
    assert data["validation_strategy"]["dynamic_mode"] == "targeted_optional"
    assert data["validation_strategy"]["has_compose"] is True
    included_ids = {item["id"] for item in data["audit_candidates"]["items"]}
    assert focused["id"] in included_ids
    assert all(
        item["file_path"] == "Less-1/index.php"
        for item in data["audit_candidates"]["items"]
        if item["candidate_type"] == "data_flow"
    )

    reason_export = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "reason"},
    )
    reason_data = yaml.safe_load(reason_export.text)
    assert reason_data["context_profile"]["profile"] == "reason"
    assert reason_data["audit_candidates"]["coverage"]["open_required"]
    assert reason_data["audit_candidates"]["view"]["profile"] == "reason"


def test_completion_blocks_ready_index_without_business_graph_seed(temp_db):
    client = _client(temp_db)
    project_id = _create_project(client)
    now = utcnow()

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO source_snapshots (
                id, project_id, source_type, original_name, status,
                file_count, total_bytes, detected_languages_json, created_at
            )
            VALUES ('snap_missing_biz', ?, 'zip', 'fixture.zip', 'ready', 1, 10, '{}', ?)
            """,
            (project_id, now),
        )
        conn.execute(
            """
            INSERT INTO code_entrypoints (
                id, snapshot_id, path, language, kind, framework, method,
                route, handler, line_start, evidence
            )
            VALUES (
                'entry_missing_biz', 'snap_missing_biz', 'app.js', 'JavaScript',
                'http_route', 'satrda', NULL, '/erp/file', 'fileSvr', 1,
                'satrda.Router.all(ApiPre + "/file", fileSvr)'
            )
            """
        )

    blocked = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "reason"},
    )
    assert blocked.status_code == 409
    assert blocked.json()["detail"]["message"] == "Ready source index requires business graph seed before completion"

    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO business_nodes (
                id, project_id, node_type, title, description, risk_level,
                review_status, coverage_note, last_intent_id, risk_tags_json,
                evidence_json, created_by, created_at, updated_at
            )
            VALUES (
                'biz_existing', ?, 'endpoint', '入口 /erp/file', NULL, 'medium',
                'unreviewed', 'seeded', NULL, '[]', '[]', 'source_index', ?, ?
            )
            """,
            (project_id, now, now),
        )

    completed = client.post(
        f"/projects/{project_id}/complete",
        json={"from": ["origin"], "description": "done", "worker": "reason"},
    )
    assert completed.status_code == 200


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


def test_high_severity_finding_requires_quality_evidence_and_infers_business_node(temp_db, monkeypatch, tmp_path):
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

    inferred_business_node = client.post(
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
    assert inferred_business_node.status_code == 201
    assert inferred_business_node.json()["business_node_id"]

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
