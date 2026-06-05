from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cairn.server import db
from cairn.server.services import utcnow
from cairn.server.source_models import CodeFile, DynamicValidationPlan
from cairn.server.source_service import get_snapshot, list_code_files, snapshot_path


LARGE_PROJECT_FILE_COUNT = 50_000
LARGE_PROJECT_BYTES = 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024

COMPOSE_FILES = {
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
}
PACKAGE_JSON_SCRIPTS = ("start", "dev", "serve", "test", "e2e", "integration")


def build_dynamic_validation_plan(project_id: str, snapshot_id: str) -> DynamicValidationPlan:
    snapshot = get_snapshot(project_id, snapshot_id)
    if snapshot.status != "ready":
        raise ValueError("Source snapshot is not ready")
    files = list_code_files(project_id, snapshot_id, limit=20_000)
    paths = {item.path for item in files}
    root = snapshot_path(snapshot_id)
    large_project = snapshot.file_count > LARGE_PROJECT_FILE_COUNT or snapshot.total_bytes > LARGE_PROJECT_BYTES

    indicators: list[dict[str, Any]] = []
    indicators.extend(_docker_compose_indicators(paths))
    indicators.extend(_dockerfile_indicators(paths))
    indicators.extend(_node_indicators(root, files))
    indicators.extend(_python_indicators(paths))
    indicators.extend(_java_indicators(paths))
    indicators.extend(_go_indicators(paths))
    indicators.extend(_php_indicators(root, files))

    warnings = _warnings(large_project, indicators)
    allowed_actions = [
        "仅在隔离容器或测试环境中执行后续验证",
        "优先执行配置检查、依赖枚举、单元测试等低侵入动作",
        "只针对已确认候选的入口构造最小化请求，不做全站爬扫",
        "需要人工确认基础镜像、网络、凭据、数据脱敏和资源限制后再启动服务",
    ]
    blocked_actions = [
        "默认不执行 install/build/start/up 等会运行目标代码的命令",
        "不使用 host network、privileged、Docker socket 或宿主敏感目录挂载",
        "不自动接入生产数据库、生产密钥或真实第三方服务",
        "不把扫描器结果或动态探测结果直接转成已确认漏洞",
    ]

    if not indicators:
        status = "static_only"
        recommended_strategy = "static_only"
        risk_level = "low"
        summary = "未识别到可靠的沙箱启动入口，保持静态审计和报告补全为主。"
    elif large_project:
        status = "blocked"
        recommended_strategy = "static_first_targeted_manual"
        risk_level = "high"
        summary = "项目体量较大，动态验证仅建议对已确认候选做人工挑选后的定向沙箱验证。"
    else:
        status = "ready"
        recommended_strategy = _recommended_strategy(indicators)
        risk_level = _risk_level(indicators)
        summary = "已识别到可用于后续沙箱验证的启动/测试信号，但执行默认关闭。"

    return DynamicValidationPlan(
        project_id=project_id,
        snapshot_id=snapshot_id,
        status=status,
        recommended_strategy=recommended_strategy,
        risk_level=risk_level,
        large_project=large_project,
        summary=summary,
        launch_indicators=indicators,
        allowed_actions=allowed_actions,
        blocked_actions=blocked_actions,
        warnings=warnings,
    )


def persist_dynamic_validation_plan(
    project_id: str,
    snapshot_id: str,
    *,
    created_by: str = "dynamic_validation_planner",
) -> DynamicValidationPlan:
    plan = build_dynamic_validation_plan(project_id, snapshot_id)
    now = utcnow()
    plan_id = _stable_id("vplan", project_id, snapshot_id)
    payload = plan.model_dump(mode="json", exclude={"id", "created_by", "created_at", "updated_at"})
    with db.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO dynamic_validation_plans (
                id, project_id, snapshot_id, status, created_by, created_at,
                updated_at, summary, plan_json, warnings_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(project_id, snapshot_id) DO UPDATE SET
                status = excluded.status,
                created_by = excluded.created_by,
                updated_at = excluded.updated_at,
                summary = excluded.summary,
                plan_json = excluded.plan_json,
                warnings_json = excluded.warnings_json
            """,
            (
                plan_id,
                project_id,
                snapshot_id,
                plan.status,
                created_by,
                now,
                now,
                plan.summary,
                json.dumps(payload, ensure_ascii=False),
                json.dumps(plan.warnings, ensure_ascii=False),
            ),
        )
        row = conn.execute(
            """
            SELECT *
            FROM dynamic_validation_plans
            WHERE project_id = ? AND snapshot_id = ?
            """,
            (project_id, snapshot_id),
        ).fetchone()
    assert row is not None
    return dynamic_validation_plan_from_row(row)


def list_dynamic_validation_plans(project_id: str, snapshot_id: str | None = None) -> list[DynamicValidationPlan]:
    clauses = ["project_id = ?"]
    params: list[object] = [project_id]
    if snapshot_id:
        clauses.append("snapshot_id = ?")
        params.append(snapshot_id)
    with db.get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT *
            FROM dynamic_validation_plans
            WHERE {' AND '.join(clauses)}
            ORDER BY updated_at DESC, id DESC
            """,
            params,
        ).fetchall()
    return [dynamic_validation_plan_from_row(row) for row in rows]


def dynamic_validation_plan_from_row(row) -> DynamicValidationPlan:
    try:
        payload = json.loads(row["plan_json"] or "{}")
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.update(
        {
            "id": row["id"],
            "project_id": row["project_id"],
            "snapshot_id": row["snapshot_id"],
            "status": row["status"],
            "summary": row["summary"],
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
    )
    return DynamicValidationPlan.model_validate(payload)


def _docker_compose_indicators(paths: set[str]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for path in sorted(paths):
        if Path(path).name.lower() not in COMPOSE_FILES:
            continue
        indicators.append(
            {
                "type": "docker_compose",
                "path": path,
                "preflight_command": f"docker compose -f {path} config",
                "execution_command": f"docker compose -f {path} up",
                "risk": "high",
                "note": "只能在人工确认网络、卷挂载、凭据和资源限制后执行 up。",
            }
        )
    return indicators


def _dockerfile_indicators(paths: set[str]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for path in sorted(paths):
        if Path(path).name.lower() != "dockerfile":
            continue
        indicators.append(
            {
                "type": "dockerfile",
                "path": path,
                "preflight_command": f"docker build --network=none -f {path} .",
                "risk": "high",
                "note": "构建 Dockerfile 会执行目标项目指令，默认只记录计划不执行。",
            }
        )
    return indicators


def _node_indicators(root: Path, files: list[CodeFile]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for file in files:
        if Path(file.path).name != "package.json":
            continue
        payload = _read_json(root / file.path)
        if not isinstance(payload, dict):
            continue
        scripts = payload.get("scripts") if isinstance(payload.get("scripts"), dict) else {}
        dependencies = {}
        for key in ("dependencies", "devDependencies"):
            value = payload.get(key)
            if isinstance(value, dict):
                dependencies.update(value)
        frameworks = [
            name
            for name in ("express", "koa", "fastify", "next", "nuxt", "vite", "@nestjs/core")
            if name in dependencies
        ]
        for script in PACKAGE_JSON_SCRIPTS:
            command = scripts.get(script)
            if not isinstance(command, str) or not command.strip():
                continue
            indicators.append(
                {
                    "type": "node_script",
                    "path": file.path,
                    "script": script,
                    "command": f"npm run {script}",
                    "risk": "medium",
                    "frameworks": frameworks,
                    "note": "需要先在隔离环境安装依赖；默认不执行 npm install/npm run。",
                }
            )
    return indicators


def _python_indicators(paths: set[str]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    has_python_manifest = bool(paths.intersection({"requirements.txt", "pyproject.toml", "Pipfile", "poetry.lock"}))
    if "manage.py" in paths:
        indicators.append(
            {
                "type": "python_django",
                "path": "manage.py",
                "command": "python manage.py test",
                "optional_server_command": "python manage.py runserver 127.0.0.1:8000",
                "risk": "medium",
                "note": "仅建议先跑测试或针对已确认入口启动本地回环服务。",
            }
        )
    elif has_python_manifest:
        indicators.append(
            {
                "type": "python_project",
                "path": _first_path(paths, ("pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock")),
                "command": "pytest",
                "risk": "medium",
                "note": "需要人工确认测试不会访问外部服务或真实数据库。",
            }
        )
    return indicators


def _java_indicators(paths: set[str]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    if "pom.xml" in paths or "mvnw" in paths:
        indicators.append(
            {
                "type": "java_maven",
                "path": "mvnw" if "mvnw" in paths else "pom.xml",
                "command": "./mvnw test" if "mvnw" in paths else "mvn test",
                "risk": "medium",
                "note": "Maven 生命周期可能执行插件脚本，默认只记录计划。",
            }
        )
    if "build.gradle" in paths or "build.gradle.kts" in paths or "gradlew" in paths:
        indicators.append(
            {
                "type": "java_gradle",
                "path": "gradlew" if "gradlew" in paths else _first_path(paths, ("build.gradle", "build.gradle.kts")),
                "command": "./gradlew test" if "gradlew" in paths else "gradle test",
                "risk": "medium",
                "note": "Gradle 构建脚本本身会执行代码，默认只记录计划。",
            }
        )
    return indicators


def _go_indicators(paths: set[str]) -> list[dict[str, Any]]:
    if "go.mod" not in paths:
        return []
    return [
        {
            "type": "go_project",
            "path": "go.mod",
            "command": "go test ./...",
            "risk": "medium",
            "note": "仅建议在网络受限容器内运行定向测试。",
        }
    ]


def _php_indicators(root: Path, files: list[CodeFile]) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    for file in files:
        name = Path(file.path).name
        if name == "artisan":
            indicators.append(
                {
                    "type": "php_laravel",
                    "path": file.path,
                    "command": "php artisan test",
                    "optional_server_command": "php artisan serve --host=127.0.0.1",
                    "risk": "medium",
                    "note": "需要人工确认 .env、数据库和队列配置后才可启动服务。",
                }
            )
        if name != "composer.json":
            continue
        payload = _read_json(root / file.path)
        scripts = payload.get("scripts") if isinstance(payload, dict) and isinstance(payload.get("scripts"), dict) else {}
        for script in ("test", "serve", "start"):
            if script not in scripts:
                continue
            indicators.append(
                {
                    "type": "php_composer_script",
                    "path": file.path,
                    "script": script,
                    "command": f"composer {script}",
                    "risk": "medium",
                    "note": "Composer script 会执行项目命令，默认只记录计划。",
                }
            )
    return indicators


def _warnings(large_project: bool, indicators: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    if large_project:
        warnings.append("项目体量较大，不建议自动拉起完整系统，动态验证应按候选入口手动收敛。")
    if any(item.get("type") in {"docker_compose", "dockerfile"} for item in indicators):
        warnings.append("Docker/Compose 文件可能包含外部网络、宿主卷、特权模式或敏感环境变量。")
    if any(str(item.get("command") or item.get("execution_command") or "").strip() for item in indicators):
        warnings.append("所有命令目前只是计划材料，系统不会自动执行目标项目命令。")
    if not indicators:
        warnings.append("没有发现可靠启动入口，动态验证不可作为当前审计质量前置条件。")
    return warnings


def _recommended_strategy(indicators: list[dict[str, Any]]) -> str:
    types = {str(item.get("type") or "") for item in indicators}
    if "docker_compose" in types:
        return "manual_compose_preflight"
    if "dockerfile" in types:
        return "manual_container_build_preflight"
    if any(item_type.endswith("_script") for item_type in types):
        return "targeted_script_probe"
    return "targeted_test_probe"


def _risk_level(indicators: list[dict[str, Any]]) -> str:
    if any(item.get("risk") == "high" for item in indicators):
        return "high"
    if indicators:
        return "medium"
    return "low"


def _read_json(path: Path) -> Any | None:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _first_path(paths: set[str], candidates: tuple[str, ...]) -> str | None:
    for candidate in candidates:
        if candidate in paths:
            return candidate
    return None


def _stable_id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha1("\0".join("" if part is None else str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:16]}"
