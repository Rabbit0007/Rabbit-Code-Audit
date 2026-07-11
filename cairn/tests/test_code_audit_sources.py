from __future__ import annotations

import io
import json
import sqlite3
import time
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient
import yaml

from cairn.dispatcher.contracts import validate_explore_payload
from cairn.server.code_index import CodeSymbolRecord, _call_relationships
from cairn.server import db, source_service
from cairn.server.routers import business_graph, export, findings, intents, projects, review_tasks, sources, vulnerabilities
from cairn.server.services import utcnow
from cairn.server.source_models import CodeFile
from cairn.server.source_service import rebuild_source_index, _select_capability_chain_candidate_rows


def _app(temp_db) -> FastAPI:
    app = FastAPI()
    app.include_router(projects.router)
    app.include_router(intents.router)
    app.include_router(sources.router)
    app.include_router(findings.router)
    app.include_router(review_tasks.router)
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

    _, incomplete_review = validate_explore_payload(
        {
            "accepted": True,
            "data": {
                "description": "confirmation produced a prose-only review",
                "reviews": [{"decision": "confirmed"}],
            },
        }
    )
    assert incomplete_review["review"] is None
    assert incomplete_review["reviews"] == []


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


def test_source_import_indexes_additional_framework_routes_and_quality_readiness(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/server.ts": b"""
import fastify from 'fastify'
import Hapi from '@hapi/hapi'

const app = fastify()
app.get('/fast/users/:id', getUser)
app.route({ method: 'POST', url: '/fast/users', handler: createUser })

const server = new Hapi.Server({})
server.route({ method: 'GET', path: '/hapi/status', handler: status })
""",
            "demo/config/routes.rb": b"""
Rails.application.routes.draw do
  namespace :admin do
    resources :users
    post '/login', to: 'sessions#create'
  end
end
""",
            "demo/app.rb": b"""
require 'sinatra'

get '/health' do
  'ok'
end
""",
            "demo/src/main.rs": b"""
use actix_web::{get, post};
use axum::{routing::{get, post}, Router};

#[get("/actix/users/{id}")]
async fn get_user() -> String { String::new() }

#[post("/actix/users")]
async fn create_user() -> String { String::new() }

fn app() -> Router {
    Router::new()
        .route("/axum/users", get(list_users))
        .route("/axum/users", post(create_axum_user))
}
""",
            "demo/src/rocket.rs": b"""
use rocket::get;

#[get("/rocket/ping")]
fn ping() -> &'static str { "pong" }
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("frameworks.zip", payload, "application/zip")},
    ).json()

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    route_methods = {(item["route"], item["method"], item["framework"]) for item in entrypoints}
    assert {
        ("/fast/users/:id", "GET", "fastify"),
        ("/fast/users", "POST", "fastify"),
        ("/hapi/status", "GET", "hapi"),
        ("/admin/users", "GET", "rails"),
        ("/admin/users", "POST", "rails"),
        ("/admin/users/:id", "GET", "rails"),
        ("/admin/login", "POST", "rails"),
        ("/health", "GET", "sinatra"),
        ("/actix/users/{id}", "GET", "actix"),
        ("/actix/users", "POST", "actix"),
        ("/axum/users", "GET", "axum"),
        ("/axum/users", "POST", "axum"),
        ("/rocket/ping", "GET", "rocket"),
    } <= route_methods

    quality = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/index-quality").json()
    assert quality["audit_readiness"]["score"] > 0
    assert quality["graph_compression"]["module_count"] > 0
    assert quality["language_coverage"]["Ruby"]["entrypoints"] >= 4
    assert quality["language_coverage"]["Rust"]["entrypoints"] >= 5
    assert quality["language_coverage"]["TypeScript"]["entrypoints"] >= 3

    exported = client.get(f"/projects/{project_id}/export?format=yaml&profile=explore").text
    data = yaml.safe_load(exported)
    audit_context = data["code_index"]["audit_context"]
    assert audit_context["compressed_business_graph"]["module_count"] > 0
    assert audit_context["compressed_business_graph"]["top_modules"]


def test_call_relationship_extraction_is_bounded_for_large_symbol_sets():
    snapshot_id = "snap_perf"
    file = CodeFile(
        snapshot_id=snapshot_id,
        path="app/handler.js",
        size_bytes=1_000_000,
        sha256="0" * 64,
        language="JavaScript",
        is_binary=False,
    )
    text = "const payload = '" + ("x" * 1_000_000) + "';\n"
    unique_symbols = {
        f"Generated{i}": CodeSymbolRecord(
            id=f"sym_{i}",
            snapshot_id=snapshot_id,
            path=f"lib/generated_{i}.js",
            language="JavaScript",
            kind="function",
            name=f"Generated{i}",
        )
        for i in range(5000)
    }

    started = time.perf_counter()
    relationships = _call_relationships(snapshot_id, file, text, unique_symbols)

    assert relationships == []
    assert time.perf_counter() - started < 1.5


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
    assert quality["entrypoints_with_business_flows"] >= 1
    assert quality["business_module_count"] >= 1
    assert quality["business_module_island_count"] == 0
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
    assert any(item["title"] == "业务模块 services" for item in graph["nodes"])
    assert any(item["title"] == "业务功能 users" for item in graph["nodes"])
    assert any(item["title"] == "处理逻辑 lock_user" for item in graph["nodes"])
    assert any(item["title"] == "处理逻辑 UserService" for item in graph["nodes"])
    assert any(item["title"] == "数据对象 User" for item in graph["nodes"])
    assert not any(item["title"] == "数据对象 flask" for item in graph["nodes"])
    assert any(item["source_snapshot_id"] == snapshot["id"] for item in graph["nodes"])
    assert all(0 < item["confidence"] <= 1 for item in graph["nodes"])
    assert {"contains", "exposes", "calls", "uses", "risk_of"} <= {item["relation"] for item in graph["edges"]}

    data_flow = next(
        item
        for item in client.get(f"/api/projects/{project_id}/audit-candidates").json()
        if item["candidate_type"] == "data_flow" and item["file_path"] == "app/services.py"
    )
    intent = client.post(
        f"/projects/{project_id}/intents",
        json={
            "from": ["origin"],
            "description": f"审计候选 {data_flow['id']} 的跨文件 SQL 数据流。",
            "creator": "reason-worker",
            "worker": None,
        },
    ).json()
    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "explore", "intent_id": intent["id"]},
    )
    data = yaml.safe_load(exported.text)
    audit_context = data["code_index"]["audit_context"]
    assert "业务理解索引上下文" in audit_context["purpose"]
    assert any(
        summary["title"] == "业务模块 services"
        and summary["child_counts"].get("control", 0) >= 1
        and summary["risk_threads"]
        for summary in audit_context["module_summaries"]
    )
    assert any(
        trace["entry_point"] == "POST /api/users/{user_id}/lock"
        and trace["path_chain"][:2] == ["app/api.py", "app/services.py"]
        for trace in audit_context["business_flow_traces"]
    )
    assert any(
        summary["entry_point"] == "POST /api/users/{user_id}/lock"
        and "app/models.py" in summary["reachable_paths"]
        and any(item["name"] == "User" for item in summary["data_objects"])
        for summary in audit_context["entrypoint_summaries"]
    )
    focus_packs = audit_context["planner_focus_packs"]
    assert focus_packs
    assert any(
        data_flow["id"] in pack["candidate_ids"]
        and pack["pack_id"].startswith("pack_")
        and pack["objective"]
        and "app/api.py" in pack["reading_order"]
        and "app/services.py" in pack["reading_order"]
        and pack["audit_focus"]
        for pack in focus_packs
    )
    traces = audit_context["entrypoint_traces"]
    assert any(
        trace["candidate_id"] == data_flow["id"]
        and trace["path_chain"][:2] == ["app/api.py", "app/services.py"]
        for trace in traces
    )

    reindexed = client.post(f"/api/projects/{project_id}/sources/{snapshot['id']}/reindex")
    assert reindexed.status_code == 200
    assert reindexed.json()["relationship_count"] >= 4
    graph_after = client.get(f"/api/projects/{project_id}/business-graph").json()
    node_ids = [item["id"] for item in graph_after["nodes"]]
    edge_ids = [item["id"] for item in graph_after["edges"]]
    assert len(node_ids) == len(set(node_ids))
    assert len(edge_ids) == len(set(edge_ids))


def test_data_object_index_keeps_sql_identifiers_and_rejects_prose(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app.php": b"""<?php
// update the counter in database
echo "Read records from only random table from Database";
$query = "SELECT * FROM `security`.`users` WHERE id = 1";
$update = "UPDATE accounts SET locked = 1 WHERE id = 1";
$insert = "INSERT INTO `audit`.`events` (`name`) VALUES ('login')";
""",
            "demo/readme.md": b"Use git from within your project and update the database.",
            "demo/index.html": b"<title>Dump into Outfile</title>",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("data-object-quality.zip", payload, "application/zip")},
    ).json()

    symbols = client.get(
        f"/api/projects/{project_id}/sources/{snapshot['id']}/symbols"
    ).json()
    names = {
        item["name"]
        for item in symbols
        if item["kind"] == "data_object"
    }
    assert {"security.users", "accounts", "audit.events"} <= names
    assert not names & {
        "Database",
        "Outfile",
        "database",
        "only",
        "the",
        "within",
        "your",
    }


def test_source_index_uses_import_scope_for_object_method_business_flow(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app/api.py": b"""
from fastapi import APIRouter
from .services.users import UserService
from .services.audit import UserService as AuditUserService

router = APIRouter(prefix="/api")
svc = UserService()

@router.post("/users/{user_id}/lock")
def lock_user(user_id: str):
    return svc.lock_user(user_id)
""",
            "demo/app/services/users.py": b"""
from ..repositories.users import UserRepository

class UserService:
    def lock_user(self, user_id):
        return UserRepository().lock(user_id)
""",
            "demo/app/services/audit.py": b"""
class UserService:
    def write_audit(self, message):
        return message
""",
            "demo/app/repositories/users.py": b"""
from ..models import User

class UserRepository:
    def lock(self, user_id):
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
        files={"archive": ("scoped-flow.zip", payload, "application/zip")},
    ).json()
    quality = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/index-quality").json()
    assert quality["entrypoints_with_business_flows"] >= 1
    assert quality["business_module_count"] >= 1

    relationships = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/relationships").json()
    call_pairs = {
        (item["from_path"], item["relation"], item["to_path"], item["to_symbol"], item["source"])
        for item in relationships
        if item["relation"] == "calls"
    }
    assert (
        "app/api.py",
        "calls",
        "app/services/users.py",
        "lock_user",
        "heuristic:object_method_call",
    ) in call_pairs
    assert not any(
        item["from_path"] == "app/api.py"
        and item["relation"] == "calls"
        and item["to_path"] == "app/services/audit.py"
        for item in relationships
    )
    assert any(
        item["from_path"] == "app/services/users.py"
        and item["relation"] == "calls"
        and item["to_path"] == "app/repositories/users.py"
        for item in relationships
    )
    assert any(
        item["from_path"] == "app/repositories/users.py"
        and item["relation"] == "calls"
        and item["to_path"] == "app/models.py"
        for item in relationships
    )

    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "explore"},
    )
    data = yaml.safe_load(exported.text)
    traces = data["code_index"]["audit_context"]["business_flow_traces"]
    assert any(
        trace["entry_point"] == "POST /api/users/{user_id}/lock"
        and trace["path_chain"][:3] == [
            "app/api.py",
            "app/services/users.py",
            "app/repositories/users.py",
        ]
        for trace in traces
    )
    summaries = data["code_index"]["audit_context"]["entrypoint_summaries"]
    assert any(
        summary["entry_point"] == "POST /api/users/{user_id}/lock"
        and "app/repositories/users.py" in summary["reachable_paths"]
        and any(item["name"] == "User" for item in summary["data_objects"])
        for summary in summaries
    )


def test_source_index_links_interface_implementation_business_flow(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/src/main/java/demo/UserController.java": b"""
package demo;

import demo.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
class UserController {
    private final UserService userService;

    UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/{id}/lock")
    public User lockUser(String id) {
        return userService.lockUser(id);
    }
}
""",
            "demo/src/main/java/demo/UserService.java": b"""
package demo;

interface UserService {
    User lockUser(String id);
}
""",
            "demo/src/main/java/demo/UserServiceImpl.java": b"""
package demo;

import demo.UserRepository;

class UserServiceImpl implements UserService {
    private final UserRepository repository;

    UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    public User lockUser(String id) {
        return repository.lock(id);
    }
}
""",
            "demo/src/main/java/demo/UserRepository.java": b"""
package demo;

class UserRepository {
    public User lock(String id) {
        return new User(id);
    }
}
""",
            "demo/src/main/java/demo/User.java": b"""
package demo;

@Entity
class User {
    private String id;
    User(String id) {
        this.id = id;
    }
}
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("spring-interface-flow.zip", payload, "application/zip")},
    ).json()

    relationships = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/relationships").json()
    assert any(
        item["from_path"] == "src/main/java/demo/UserService.java"
        and item["relation"] == "implemented_by"
        and item["to_path"] == "src/main/java/demo/UserServiceImpl.java"
        for item in relationships
    )
    assert any(
        item["from_path"] == "src/main/java/demo/UserController.java"
        and item["relation"] == "calls"
        and item["to_path"] == "src/main/java/demo/UserService.java"
        and item["to_symbol"] == "lockUser"
        for item in relationships
    )
    assert any(
        item["from_path"] == "src/main/java/demo/UserServiceImpl.java"
        and item["relation"] == "calls"
        and item["to_path"] == "src/main/java/demo/UserRepository.java"
        and item["to_symbol"] == "lock"
        for item in relationships
    )
    symbols = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/symbols").json()
    assert not any(
        item["path"] == "src/main/java/demo/UserRepository.java"
        and item["kind"] == "function"
        and item["name"] == "User"
        for item in symbols
    )
    assert not any(
        item["path"] == "src/main/java/demo/UserRepository.java"
        and item["kind"] == "data_object"
        and item["name"] == "UserRepository"
        for item in symbols
    )

    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "explore"},
    )
    data = yaml.safe_load(exported.text)
    traces = data["code_index"]["audit_context"]["business_flow_traces"]
    assert any(
        trace["entry_point"] == "POST /api/users/{id}/lock"
        and trace["path_chain"][:4]
        == [
            "src/main/java/demo/UserController.java",
            "src/main/java/demo/UserService.java",
            "src/main/java/demo/UserServiceImpl.java",
            "src/main/java/demo/UserRepository.java",
        ]
        for trace in traces
    )
    summaries = data["code_index"]["audit_context"]["entrypoint_summaries"]
    assert any(
        summary["entry_point"] == "POST /api/users/{id}/lock"
        and "src/main/java/demo/UserServiceImpl.java" in summary["reachable_paths"]
        and any(item["name"] == "User" for item in summary["data_objects"])
        for summary in summaries
    )


def test_source_index_understands_framework_semantic_layers(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/src/main/java/demo/UserController.java": b"""
package demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
class UserController {
    private final UserService userService;

    UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/{id}")
    public User getUser(String id) {
        return userService.find(id);
    }
}
""",
            "demo/src/main/java/demo/UserService.java": b"""
package demo;

import org.springframework.stereotype.Service;

@Service
class UserService {
    private final UserMapper userMapper;

    UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public User find(String id) {
        return userMapper.findById(id);
    }
}
""",
            "demo/src/main/java/demo/UserMapper.java": b"""
package demo;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

@Mapper
interface UserMapper {
    @Select("select * from users where id = #{id}")
    User findById(String id);
}
""",
            "demo/src/main/java/demo/User.java": b"""
package demo;

import jakarta.persistence.Entity;

@Entity
class User {
    private String id;
}
""",
            "demo/src/app/users.controller.ts": b"""
import { Controller, Get, Param } from '@nestjs/common';
import { UserService } from './users.service';

@Controller('api/nest-users')
export class UsersController {
  constructor(private readonly service: UserService) {}

  @Get(':id')
  getUser(@Param('id') id: string) {
    return this.service.findOne(id);
  }
}
""",
            "demo/src/app/users.service.ts": b"""
export class UserService {
  findOne(id: string) {
    return { id };
  }
}
""",
            "demo/routes/web.php": b"""<?php
use App\\Http\\Controllers\\ProfileController;

Route::get('/web/profile', [ProfileController::class, 'show']);
""",
            "demo/app/Http/Controllers/ProfileController.php": b"""<?php
namespace App\\Http\\Controllers;

class ProfileController {
    public function show() {
        return 'ok';
    }
}
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("framework-semantics.zip", payload, "application/zip")},
    ).json()

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    route_methods = {(item["route"], item["method"], item["framework"]) for item in entrypoints}
    assert ("/api/users/{id}", "GET", "spring") in route_methods
    assert ("/api/nest-users/:id", "GET", "nestjs") in route_methods
    assert ("/web/profile", "GET", "laravel") in route_methods

    relationships = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/relationships").json()
    assert any(
        item["from_path"] == "src/main/java/demo/UserController.java"
        and item["relation"] == "calls"
        and item["to_path"] == "src/main/java/demo/UserService.java"
        and item["to_symbol"] == "find"
        for item in relationships
    )
    assert any(
        item["from_path"] == "src/main/java/demo/UserService.java"
        and item["relation"] == "calls"
        and item["to_path"] == "src/main/java/demo/UserMapper.java"
        and item["to_symbol"] == "findById"
        for item in relationships
    )
    assert any(
        item["from_path"] == "src/main/java/demo/UserMapper.java"
        and item["relation"] == "uses"
        and item["to_path"] == "src/main/java/demo/User.java"
        and item["to_symbol"] == "User"
        for item in relationships
    )
    assert any(
        item["from_path"] == "src/app/users.controller.ts"
        and item["relation"] == "calls"
        and item["to_path"] == "src/app/users.service.ts"
        for item in relationships
    )
    assert any(
        item["from_path"] == "routes/web.php"
        and item["relation"] == "calls"
        and item["to_path"] == "app/Http/Controllers/ProfileController.php"
        and item["to_symbol"] == "show"
        for item in relationships
    )

    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "explore"},
    )
    data = yaml.safe_load(exported.text)
    summaries = data["code_index"]["audit_context"]["entrypoint_summaries"]
    assert any(
        summary["entry_point"] == "GET /api/users/{id}"
        and "src/main/java/demo/UserMapper.java" in summary["reachable_paths"]
        and any(item["name"] == "User" for item in summary["data_objects"])
        for summary in summaries
    )
    assert any(
        summary["entry_point"] == "GET /api/nest-users/:id"
        and "src/app/users.service.ts" in summary["reachable_paths"]
        for summary in summaries
    )
    assert any(
        summary["entry_point"] == "GET /web/profile"
        and "app/Http/Controllers/ProfileController.php" in summary["reachable_paths"]
        for summary in summaries
    )


def test_source_index_understands_drf_viewset_business_layers(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/users/urls.py": b"""
from django.urls import include, path
from rest_framework.routers import DefaultRouter
from .views import UserViewSet

router = DefaultRouter()
router.register(r"users", UserViewSet, basename="user")

urlpatterns = [
    path("api/", include(router.urls)),
    path("direct/users/", UserViewSet.as_view({"get": "list", "post": "create"})),
]
""",
            "demo/users/views.py": b"""
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import User

class UserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = User.objects.all()

    def list(self, request):
        return Response({"count": self.queryset.count()})

    def create(self, request):
        return Response({"ok": True})

    @action(detail=True, methods=["post"], url_path="lock")
    def lock(self, request, pk=None):
        user = User.objects.get(pk=pk)
        return Response({"id": user.id})
""",
            "demo/users/models.py": b"""
from django.db import models

class User(models.Model):
    owner_id = models.CharField(max_length=64)
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("drf-viewset.zip", payload, "application/zip")},
    ).json()

    entrypoints = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/entrypoints").json()
    route_methods = {(item["route"], item["method"], item["handler"], item["framework"]) for item in entrypoints}
    assert ("/api/users", "GET", "UserViewSet.list", "drf") in route_methods
    assert ("/api/users", "POST", "UserViewSet.create", "drf") in route_methods
    assert ("/api/users/{pk}", "GET", "UserViewSet.retrieve", "drf") in route_methods
    assert ("/direct/users/", "GET", "UserViewSet.list", "drf") in route_methods

    relationships = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/relationships").json()
    assert any(
        item["from_path"] == "users/urls.py"
        and item["relation"] == "calls"
        and item["to_path"] == "users/views.py"
        and item["to_symbol"] == "list"
        for item in relationships
    )
    assert any(
        item["from_path"] == "users/views.py"
        and item["relation"] == "uses"
        and item["to_path"] == "users/models.py"
        and item["to_symbol"] == "User"
        for item in relationships
    )

    capabilities = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/capabilities").json()
    assert any(
        item["path"] == "users/views.py" and item["category"] == "auth_guard"
        for item in capabilities
    )
    exported = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "explore"},
    )
    data = yaml.safe_load(exported.text)
    summaries = data["code_index"]["audit_context"]["entrypoint_summaries"]
    assert any(
        summary["entry_point"] == "GET /api/users"
        and "users/views.py" in summary["reachable_paths"]
        and "users/models.py" in summary["reachable_paths"]
        and any(item["name"] == "User" for item in summary["data_objects"])
        and any(item["category"] == "auth_guard" for item in summary["semantic_boundaries"])
        for summary in summaries
    )


def test_source_index_builds_control_plane_capability_chains(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/apps/ops/__init__.py": b"",
            "demo/apps/ops/urls/api_urls.py": b"""
from django.urls import path
from .. import api

urlpatterns = [
    path("playbook/<uuid:pk>/file/", api.PlaybookFileBrowserAPIView.as_view(), name="playbook-file"),
]
""",
            "demo/apps/ops/api/__init__.py": b"""
from .playbook import PlaybookFileBrowserAPIView, PlaybookViewSet
""",
            "demo/apps/ops/api/playbook.py": b"""
import os
import shutil
import zipfile
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView

from apps.ops.models.playbook import Playbook

def safe_join(*parts):
    return os.path.join(*parts)

def unzip_playbook(src, dist):
    fz = zipfile.ZipFile(src, 'r')
    for file in fz.namelist():
        fz.extract(file, dist)

class PlaybookViewSet(APIView):
    def perform_create(self, serializer):
        instance = serializer.save()
        if 'multipart/form-data' in self.request.headers['Content-Type']:
            src_path = safe_join(settings.MEDIA_ROOT, instance.path.name)
            dest_path = safe_join(settings.DATA_DIR, "ops", "playbook", instance.id.__str__())
            unzip_playbook(src_path, dest_path)

class PlaybookFileBrowserAPIView(APIView):
    permission_classes = (object,)
    rbac_perms = {'GET': 'ops.change_playbook', 'POST': 'ops.change_playbook'}

    def get(self, request, **kwargs):
        playbook_id = kwargs.get('pk')
        file_key = request.query_params.get('key')
        playbook = get_object_or_404(Playbook, id=playbook_id)
        file_path = safe_join(settings.DATA_DIR, "ops", "playbook", str(playbook.id), file_key)
        with open(file_path, 'r') as f:
            return f.read()

    def post(self, request, **kwargs):
        playbook_id = kwargs.get('pk')
        file_key = request.data.get('key')
        content = request.data.get('content')
        new_file_path = safe_join(settings.DATA_DIR, "ops", "playbook", str(playbook_id), file_key)
        with open(new_file_path, 'w') as f:
            f.write(content)

    def delete(self, request, **kwargs):
        file_path = request.data.get('path')
        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        else:
            os.remove(file_path)
""",
            "demo/apps/ops/models/__init__.py": b"",
            "demo/apps/ops/models/playbook.py": b"""
class Playbook:
    entry = "main.yml"

    def check_dangerous_keywords(self):
        return True
""",
            "demo/apps/ops/models/job.py": b"""
from apps.ops.models.playbook import Playbook

class PlaybookRunner:
    def start(self):
        return True

class Job:
    def get_runner(self, playbook: Playbook):
        return PlaybookRunner(playbook.entry)
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("control-plane.zip", payload, "application/zip")},
    ).json()

    relationships = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/relationships").json()
    relationship_pairs = {
        (item["from_path"], item["relation"], item["to_path"], item["to_symbol"], item["source"])
        for item in relationships
    }
    assert (
        "apps/ops/urls/api_urls.py",
        "calls",
        "apps/ops/api/playbook.py",
        "PlaybookFileBrowserAPIView",
        "heuristic:django_handler",
    ) in relationship_pairs

    capabilities = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/capabilities").json()
    capability_categories = {item["category"] for item in capabilities}
    assert {"archive_extract", "file_write", "file_read", "task_execution"} <= capability_categories
    assert any(
        item["category"] == "archive_extract"
        and item["risk_level"] == "high"
        and "控制面" in item["risk_tags"]
        for item in capabilities
    )

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    capability_candidates = [item for item in candidates if item["candidate_type"] == "capability_chain"]
    assert capability_candidates
    assert any("归档解压/展开能力" in item["title"] for item in capability_candidates)
    assert any("文件写入/删除能力" in item["title"] for item in capability_candidates)
    assert all("不是漏洞类型判断" in item["description"] for item in capability_candidates)
    assert any(
        item["file_path"] == "apps/ops/api/playbook.py"
        and item["entry_point"] == "/playbook/<uuid:pk>/file/"
        for item in capability_candidates
    )

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    risk_nodes = [node for node in graph["nodes"] if node["node_type"] == "risk"]
    assert any("待审计能力链" in node["title"] and node["risk_level"] == "high" for node in risk_nodes)
    assert any(
        node["node_type"] == "control" and "权限边界" in node["title"]
        for node in graph["nodes"]
    )
    assert any(
        node["node_type"] == "asset" and "文件生命周期" in node["title"]
        for node in graph["nodes"]
    )
    assert any(
        edge["relation"] in {"guards", "uses", "risk_of"}
        for edge in graph["edges"]
    )

    def fail_on_lazy_index_ensure(snapshot):
        raise AssertionError("export must not rebuild or mutate source indexes")

    monkeypatch.setattr(source_service, "_ensure_code_index", fail_on_lazy_index_ensure)
    reason_export = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "reason"},
    )
    reason_data = yaml.safe_load(reason_export.text)
    assert any(
        item["capabilities"]
        for item in reason_data["code_index"]["audit_context"]["file_slices"]
    )
    high_risk_ids = {
        item["id"] for item in reason_data["audit_candidates"]["coverage"]["high_risk_unresolved"]
    }
    assert {item["id"] for item in capability_candidates} & high_risk_ids


def test_capability_chain_candidate_selection_balances_capability_families():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE code_capabilities (
            id TEXT PRIMARY KEY,
            snapshot_id TEXT NOT NULL,
            path TEXT NOT NULL,
            symbol TEXT,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            line_start INTEGER,
            line_end INTEGER,
            evidence TEXT,
            risk_level TEXT NOT NULL,
            risk_tags_json TEXT NOT NULL DEFAULT '[]',
            confidence REAL NOT NULL DEFAULT 0.65,
            source TEXT NOT NULL DEFAULT 'heuristic'
        )
        """
    )
    rows = []
    for index in range(40):
        rows.append(
            (
                f"cap_cred_{index}",
                "snap_1",
                f"aaa/secrets_{index}.py",
                "load_secret",
                "credential_access",
                "凭据/令牌访问能力",
                index + 1,
                index + 1,
                "token = settings.SECRET",
                "high",
                "[]",
                0.95,
                "test",
            )
        )
    rows.extend(
        [
            (
                "cap_upload",
                "snap_1",
                "zzz/upload.py",
                "upload",
                "file_upload",
                "文件上传入口/接收能力",
                10,
                10,
                "request.FILES['file']",
                "high",
                "[]",
                0.80,
                "test",
            ),
            (
                "cap_archive",
                "snap_1",
                "zzz/archive.py",
                "extract",
                "archive_extract",
                "归档解压/展开能力",
                20,
                20,
                "zipfile.ZipFile(src).extractall(dst)",
                "high",
                "[]",
                0.80,
                "test",
            ),
        ]
    )
    conn.executemany(
        """
        INSERT INTO code_capabilities (
            id, snapshot_id, path, symbol, category, title, line_start, line_end,
            evidence, risk_level, risk_tags_json, confidence, source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )

    selected = _select_capability_chain_candidate_rows(conn, "snap_1", limit=20)
    categories = [row["category"] for row in selected]

    assert "file_upload" in categories
    assert "archive_extract" in categories
    assert categories.index("file_upload") < 5
    assert categories.index("archive_extract") < 5


def test_source_index_extracts_multilanguage_upload_file_facts(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)

    payload = _zip_bytes(
        {
            "demo/app/views.py": b"""
from django.core.files.storage import default_storage

def upload_view(request):
    uploaded = request.FILES["file"]
    tenant_id = request.query_params.get("tenant_id")
    path = request.query_params.get("path")
    return default_storage.save(path, uploaded)
""",
            "demo/src/main/java/demo/UploadController.java": b"""
package demo;

import java.nio.file.Files;
import java.nio.file.Paths;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

class UploadController {
    void upload(HttpServletRequest request, @RequestParam MultipartFile file) {
        String name = request.getParameter("name");
        Files.copy(file.getInputStream(), Paths.get(name));
    }
}
""",
            "demo/server/upload.go": b"""
package main

func upload(c *gin.Context) {
    file, _ := c.FormFile("file")
    dst := c.Query("path")
    c.SaveUploadedFile(file, dst)
}
""",
        }
    )
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("uploads.zip", payload, "application/zip")},
    ).json()

    candidates = client.get(f"/api/projects/{project_id}/audit-candidates").json()
    file_flows = [
        item
        for item in candidates
        if item["candidate_type"] == "data_flow"
        and "外部输入到文件读写/加载能力" in item["title"]
    ]
    assert {item["file_path"] for item in file_flows} >= {
        "app/views.py",
        "src/main/java/demo/UploadController.java",
        "server/upload.go",
    }
    assert all("索引优先级" in item["description"] for item in file_flows)
    assert all("不是漏洞类型判断" in item["description"] for item in file_flows)

    quality = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/index-quality").json()
    assert quality["candidate_count"] >= len(file_flows)
    assert quality["high_impact_candidate_count"] >= len(file_flows)
    assert quality["candidate_type_counts"]["data_flow"] >= len(file_flows)

    capabilities = client.get(f"/api/projects/{project_id}/sources/{snapshot['id']}/capabilities").json()
    categories = {item["category"] for item in capabilities}
    assert {"file_upload", "file_write", "object_scope_guard"} <= categories

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    assert any(
        node["node_type"] == "asset" and "文件生命周期" in node["title"]
        for node in graph["nodes"]
    )
    assert any(
        node["node_type"] == "asset" and "对象边界" in node["title"]
        for node in graph["nodes"]
    )


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
        and "外部输入到文件读写/加载能力" in item["title"]
    )
    assert file_write["business_node_id"]
    assert file_write["severity"] == "high"
    assert "该候选是数据流事实，不是漏洞类型判断" in file_write["description"]
    assert "高影响能力提示" in file_write["description"]
    assert "局部代码切片" in file_write["description"]
    assert "filename" in file_write["description"]
    assert len(file_write["description"]) <= 1600

    graph = client.get(f"/api/projects/{project_id}/business-graph").json()
    endpoint_titles = {node["title"] for node in graph["nodes"] if node["node_type"] == "endpoint"}
    assert {"入口 /erp/file", "入口 /erp/h5dw", "入口 /erp/system/user/profile"} <= endpoint_titles
    risk_nodes = [node for node in graph["nodes"] if node["node_type"] == "risk"]
    file_risk = next(node for node in risk_nodes if "外部输入到文件读写/加载能力" in node["title"])
    assert file_risk["risk_level"] == "high"
    assert graph["edges"]

    reason_export = client.get(
        f"/projects/{project_id}/export",
        params={"format": "yaml", "profile": "reason"},
    )
    reason_data = yaml.safe_load(reason_export.text)
    open_required_ids = {
        item["id"] for item in reason_data["audit_candidates"]["coverage"]["open_required"]
    }
    assert file_write["id"] in open_required_ids


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
        and "不是漏洞类型判断" in item["description"]
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
        if item["candidate_type"] == "data_flow" and "外部输入到数据库执行能力" in item["title"]
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
        if item["candidate_type"] == "data_flow" and "外部输入到数据库执行能力" in item["title"]
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


def test_rebuild_source_index_refreshes_existing_index_candidate_without_resetting_conclusion(
    temp_db,
    monkeypatch,
    tmp_path,
):
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
    candidate = next(
        item
        for item in client.get(f"/api/projects/{project_id}/audit-candidates").json()
        if item["candidate_type"] == "data_flow"
    )

    concluded = client.post(
        f"/api/projects/{project_id}/audit-candidates/{candidate['id']}/conclude",
        json={
            "reviewer": "worker-a",
            "decision": "needs_more_evidence",
            "summary": "保留现有 worker 结论",
            "evidence": "worker 已读过源码但还缺运行时证据",
        },
    )
    assert concluded.status_code == 200
    with db.get_conn() as conn:
        conn.execute(
            """
            UPDATE audit_candidates
            SET title = '审计数据流: SQL 注入面 app.php:4',
                description = '旧版候选描述',
                updated_at = ?
            WHERE id = ?
            """,
            (utcnow(), candidate["id"]),
        )

    rebuild_source_index(snapshot["id"])

    refreshed = next(
        item
        for item in client.get(f"/api/projects/{project_id}/audit-candidates").json()
        if item["id"] == candidate["id"]
    )
    assert "外部输入到数据库执行能力" in refreshed["title"]
    assert "该候选是数据流事实，不是漏洞类型判断" in refreshed["description"]
    assert len(refreshed["description"]) <= 1600
    assert refreshed["status"] == "needs_more_evidence"
    assert refreshed["conclusion_summary"] == "保留现有 worker 结论"
    assert refreshed["evidence"] == "worker 已读过源码但还缺运行时证据"
    assert refreshed["concluded_by"] == "worker-a"


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
    audit_context = data["code_index"]["audit_context"]
    assert audit_context["focused_candidate_ids"] == [focused["id"]]
    assert audit_context["module_summaries"]
    assert audit_context["entrypoint_summaries"]
    assert "business_flow_traces" in audit_context
    assert audit_context["priority_candidates"][0]["id"] == focused["id"]
    assert audit_context["priority_candidates"][0]["risk_score"] >= 70
    assert audit_context["file_slices"]
    assert audit_context["file_slices"][0]["path"] == "Less-1/index.php"
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
    inferred_finding = inferred_business_node.json()

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
    assert valid.json()["id"] == inferred_finding["id"]
    assert valid.json()["business_node_id"] == inferred_finding["business_node_id"]

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


def test_duplicate_audit_findings_share_cluster_and_reuse_existing_record(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"app.php": b"<?php echo $_GET['x'];"})
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    first = client.post(
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
    second = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "same reflected xss with static poc",
            "category": "Cross-Site Scripting (XSS)",
            "severity": "high",
            "file_path": "app.php",
            "line_start": 1,
            "entry_point": "GET /app.php?x=",
            "description": "same source path and entry point",
            "impact": "attacker can execute script in a victim browser",
            "evidence": "same direct echo evidence",
            "reproduction_poc": _reproduction_poc(),
            "discovered_by": "worker-b",
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.json()["id"] == first.json()["id"]
    assert second.json()["category"] == "xss"
    assert second.json()["cluster_key"] == first.json()["cluster_key"]
    assert second.json()["reproduction_poc"]["payload"] == "<script>alert(1)</script>"
    findings = client.get(f"/api/projects/{project_id}/audit-findings").json()
    assert len(findings) == 1
    with db.get_conn() as conn:
        review_tasks = conn.execute(
            "SELECT finding_id, status, excluded_workers_json FROM review_tasks WHERE project_id = ?",
            (project_id,),
        ).fetchall()
    assert len(review_tasks) == 1
    assert review_tasks[0]["finding_id"] == first.json()["id"]
    assert json.loads(review_tasks[0]["excluded_workers_json"]) == ["worker-a", "worker-b"]


def test_finding_cluster_key_uses_root_location_before_route():
    first = findings.audit_finding_cluster_key(
        findings.CreateAuditFindingRequest(
            snapshot_id="snap_1",
            title="sso redirect",
            category="open_redirect",
            severity="high",
            cwe="CWE-601",
            file_path="apps/auth/sso.py",
            line_start=88,
            symbol="complete_login",
            entry_point="GET /api/v1/auth/sso/callback/",
            description="redirect target is controlled by request state",
            impact="account phishing and token relay",
            evidence="apps/auth/sso.py:88 returns redirect_url from request state",
            discovered_by="worker-a",
        )
    )
    second = findings.audit_finding_cluster_key(
        findings.CreateAuditFindingRequest(
            snapshot_id="snap_1",
            title="sso redirect alternate route",
            category="open_redirect",
            severity="high",
            cwe="CWE-601",
            file_path="apps/auth/sso.py",
            line_start=89,
            symbol="complete_login",
            entry_point="GET /api/v1/auth/sso/oidc/callback/",
            description="same root cause through an alternate route",
            impact="account phishing and token relay",
            evidence="apps/auth/sso.py:89 returns redirect_url from request state",
            discovered_by="worker-b",
        )
    )

    assert second == first


def test_high_severity_finding_creates_independent_review_task_queue(temp_db, monkeypatch, tmp_path):
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
    assert created.status_code == 201
    finding = created.json()
    assert finding["status"] == "pending_review"

    pending = client.get("/api/review-tasks/pending", params={"project_id": project_id}).json()
    assert len(pending) == 1
    task = pending[0]
    assert task["finding_id"] == finding["id"]
    assert task["status"] == "pending"
    assert task["discovered_by"] == "worker-a"

    same_worker = client.post(f"/api/review-tasks/{task['id']}/claim", json={"worker": "worker-a"})
    assert same_worker.status_code == 409

    claimed = client.post(f"/api/review-tasks/{task['id']}/claim", json={"worker": "worker-b"})
    assert claimed.status_code == 200
    assert claimed.json()["status"] == "running"
    assert claimed.json()["worker"] == "worker-b"

    completed = client.post(
        f"/api/review-tasks/{task['id']}/complete",
        json={"worker": "worker-b", "decision": "confirmed"},
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"

    reviewed = client.get(f"/api/projects/{project_id}/audit-findings").json()
    assert reviewed[0]["id"] == finding["id"]
    assert reviewed[0]["status"] == "confirmed"
    assert reviewed[0]["reviewed_by"] == "worker-b"

    pending_after = client.get("/api/review-tasks/pending", params={"project_id": project_id}).json()
    assert pending_after == []
    with db.get_conn() as conn:
        report_task = conn.execute(
            """
            SELECT finding_id, status, created_by
            FROM report_enrichment_tasks
            WHERE project_id = ?
            """,
            (project_id,),
        ).fetchone()
    assert report_task is not None
    assert report_task["finding_id"] == finding["id"]
    assert report_task["status"] == "pending"
    assert report_task["created_by"] == "review:worker-b"


def test_confirmed_finding_backfills_index_candidate_and_business_node(temp_db, monkeypatch, tmp_path):
    monkeypatch.setenv("CAIRN_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    client = _client(temp_db)
    project_id = _create_project(client)
    payload = _zip_bytes({"app.php": b"<?php echo $_GET['x'];"})
    snapshot = client.post(
        f"/api/projects/{project_id}/sources/zip",
        files={"archive": ("demo.zip", payload, "application/zip")},
    ).json()

    candidate = next(
        item
        for item in client.get(f"/api/projects/{project_id}/audit-candidates").json()
        if item["candidate_type"] == "data_flow" and item["business_node_id"]
    )
    blocked = client.post(
        f"/api/projects/{project_id}/audit-candidates/{candidate['id']}/conclude",
        json={
            "reviewer": "worker-a",
            "decision": "needs_more_evidence",
            "summary": "首次 worker 未完成源码审计",
            "evidence": "未读取目标源码，暂不能确认或排除",
        },
    )
    assert blocked.status_code == 200
    assert blocked.json()["status"] == "needs_more_evidence"

    now = utcnow()
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audit_candidates (
                id, project_id, snapshot_id, source, candidate_type, severity,
                title, description, file_path, line_start, entry_point, business_node_id,
                status, created_by, created_at, updated_at
            )
            VALUES (
                'cand_unrelated_same_node', ?, ?, 'index', 'data_flow', 'unknown',
                '审计数据流: 外部输入到响应渲染输出能力 app.php:100',
                '同业务节点下的另一条远距离数据流，不应被该 finding 自动闭合',
                'app.php', 100, 'GET /app.php?x=', ?, 'candidate',
                'source_index', ?, ?
            )
            """,
            (project_id, snapshot["id"], candidate["business_node_id"], now, now),
        )

    created = client.post(
        f"/api/projects/{project_id}/audit-findings",
        json={
            "snapshot_id": snapshot["id"],
            "title": "reflected xss",
            "category": "xss",
            "severity": "high",
            "file_path": "app.php",
            "line_start": 1,
            "entry_point": "GET /app.php?x=",
            "business_node_id": candidate["business_node_id"],
            "description": "reflected output reaches the response without escaping",
            "impact": "attacker can execute script in a victim browser",
            "evidence": "app.php echoes $_GET['x'] directly",
            "proof_packets": [_proof_packet()],
            "discovered_by": "worker-b",
        },
    )
    assert created.status_code == 201
    finding = created.json()

    reviewed = client.post(
        f"/api/projects/{project_id}/audit-findings/{finding['id']}/review",
        json={"reviewer": "worker-c", "decision": "confirmed"},
    )
    assert reviewed.status_code == 200

    updated_candidate = next(
        item
        for item in client.get(f"/api/projects/{project_id}/audit-candidates").json()
        if item["id"] == candidate["id"]
    )
    assert updated_candidate["status"] == "confirmed"
    assert updated_candidate["audit_finding_id"] == finding["id"]
    assert updated_candidate["concluded_by"] == "worker-c"
    unrelated_candidate = next(
        item
        for item in client.get(f"/api/projects/{project_id}/audit-candidates").json()
        if item["id"] == "cand_unrelated_same_node"
    )
    assert unrelated_candidate["status"] == "candidate"
    assert unrelated_candidate["audit_finding_id"] is None

    conclusions = client.get(
        f"/api/projects/{project_id}/business-graph/conclusions",
        params={"business_node_id": candidate["business_node_id"]},
    ).json()
    assert len(conclusions) == 1
    assert conclusions[0]["conclusion"] == "confirmed_finding"
    assert conclusions[0]["audit_finding_id"] == finding["id"]

    node = next(
        item
        for item in client.get(f"/api/projects/{project_id}/business-graph").json()["nodes"]
        if item["id"] == candidate["business_node_id"]
    )
    assert node["review_status"] == "covered"
    assert "已确认 finding 闭合该审计对象" in node["coverage_note"]


def test_relevance_compaction_preserves_focused_open_candidate_within_hard_budget():
    data = {
        "context_profile": {"focused_candidate_ids": ["cand_focus"]},
        "audit_candidates": {
            "items": [
                {
                    "id": "cand_focus",
                    "status": "investigating",
                    "severity": "high",
                    "description": "required evidence " + "x" * 2_000,
                },
                *[
                    {
                        "id": f"cand_done_{index}",
                        "status": "confirmed",
                        "severity": "medium",
                        "description": "historical " + "x" * 4_000,
                    }
                    for index in range(80)
                ],
            ]
        },
        "business_graph": {"nodes": []},
        "audit_findings": [
            {
                "id": f"finding_{index}",
                "status": "confirmed",
                "description": "known issue " + "x" * 4_000,
            }
            for index in range(80)
        ],
        "facts": [{"id": "origin"}, {"id": "goal"}],
        "intents": [],
    }

    text = export._fit_context_to_budget(data, "explore", 480 * 1024)
    compacted = yaml.safe_load(text)

    assert len(text.encode("utf-8")) <= 480 * 1024
    assert any(
        item["id"] == "cand_focus"
        for item in compacted["audit_candidates"]["items"]
    )
