from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tomllib

from cairn.server.source_models import CodeFile


MAX_TEXT_BYTES = 2 * 1024 * 1024
GENERIC_WEB_SCRIPT_SUFFIXES = {".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx"}
GENERIC_WEB_SCRIPT_EXCLUDED_PARTS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "spec",
    "target",
    "test",
    "tests",
    "vendor",
    "venv",
}


@dataclass(frozen=True)
class CodeSymbolRecord:
    id: str
    snapshot_id: str
    path: str
    language: str | None
    kind: str
    name: str
    container: str | None = None
    signature: str | None = None
    line_start: int | None = None
    line_end: int | None = None


@dataclass(frozen=True)
class CodeEntrypointRecord:
    id: str
    snapshot_id: str
    path: str
    language: str | None
    kind: str
    framework: str | None
    method: str | None
    route: str
    handler: str | None = None
    line_start: int | None = None
    evidence: str | None = None


@dataclass(frozen=True)
class DependencyManifestRecord:
    id: str
    snapshot_id: str
    path: str
    manifest_type: str
    package_name: str | None = None
    dependencies: list[str] = field(default_factory=list)
    dev_dependencies: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CodeIndexRecords:
    symbols: list[CodeSymbolRecord]
    entrypoints: list[CodeEntrypointRecord]
    manifests: list[DependencyManifestRecord]


def extract_code_index(snapshot_id: str, root: Path, files: list[CodeFile]) -> CodeIndexRecords:
    symbols: list[CodeSymbolRecord] = []
    entrypoints: list[CodeEntrypointRecord] = []
    manifests: list[DependencyManifestRecord] = []
    readable: list[tuple[CodeFile, str]] = []
    for file in files:
        if file.is_binary:
            continue
        path = root / file.path
        text = _read_text(path)
        if text is None:
            continue
        readable.append((file, text))

    js_constants = _collect_js_string_constants(
        text for file, text in readable if file.language in {"JavaScript", "TypeScript", "Vue"}
    )
    for file, text in readable:
        symbols.extend(_extract_symbols(snapshot_id, file, text))
        entrypoints.extend(_extract_entrypoints(snapshot_id, file, text, string_constants=js_constants))
        manifest = _extract_manifest(snapshot_id, file, text)
        if manifest is not None:
            manifests.append(manifest)
    return CodeIndexRecords(
        symbols=_dedupe_symbols(symbols),
        entrypoints=_dedupe_entrypoints(entrypoints),
        manifests=_dedupe_manifests(manifests),
    )


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _id(prefix: str, *parts: object) -> str:
    digest = hashlib.sha1("\0".join("" if part is None else str(part) for part in parts).encode("utf-8")).hexdigest()
    return f"{prefix}_{digest[:16]}"


def _extract_symbols(snapshot_id: str, file: CodeFile, text: str) -> list[CodeSymbolRecord]:
    if file.language == "Python":
        return _python_symbols(snapshot_id, file, text)
    return _regex_symbols(snapshot_id, file, text)


def _python_symbols(snapshot_id: str, file: CodeFile, text: str) -> list[CodeSymbolRecord]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    symbols: list[CodeSymbolRecord] = []

    def add(kind: str, name: str, node: ast.AST, container: str | None = None, signature: str | None = None) -> None:
        line_start = getattr(node, "lineno", None)
        symbols.append(
            CodeSymbolRecord(
                id=_id("sym", snapshot_id, file.path, kind, name, container, line_start),
                snapshot_id=snapshot_id,
                path=file.path,
                language=file.language,
                kind=kind,
                name=name,
                container=container,
                signature=signature,
                line_start=line_start,
                line_end=getattr(node, "end_lineno", None),
            )
        )

    def signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        names = [arg.arg for arg in node.args.posonlyargs + node.args.args]
        if node.args.vararg:
            names.append(f"*{node.args.vararg.arg}")
        names.extend(arg.arg for arg in node.args.kwonlyargs)
        if node.args.kwarg:
            names.append(f"**{node.args.kwarg.arg}")
        return f"{node.name}({', '.join(names)})"

    def visit(nodes: list[ast.stmt], container: str | None = None) -> None:
        for node in nodes:
            if isinstance(node, ast.ClassDef):
                add("class", node.name, node, container)
                visit(node.body, node.name if container is None else f"{container}.{node.name}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add("method" if container else "function", node.name, node, container, signature(node))
                visit(node.body, container)

    visit(tree.body)
    return symbols


SYMBOL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("class", re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)\b", re.MULTILINE)),
    ("interface", re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)\b", re.MULTILINE)),
    ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", re.MULTILINE)),
    ("function", re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(?[^=\n]*?\)?\s*=>", re.MULTILINE)),
    ("function", re.compile(r"^\s*function\s+([A-Za-z_][\w]*)\s*\(", re.MULTILINE)),
    ("class", re.compile(r"^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_][\w]*)\b", re.MULTILINE)),
    ("interface", re.compile(r"^\s*interface\s+([A-Za-z_][\w]*)\b", re.MULTILINE)),
    ("function", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)\s*\(", re.MULTILINE)),
    ("function", re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][\w]*)\s*\(", re.MULTILINE)),
    ("class", re.compile(r"^\s*(?:pub\s+)?(?:struct|enum)\s+([A-Za-z_][\w]*)\b", re.MULTILINE)),
    ("function", re.compile(r"^\s*def\s+([A-Za-z_][\w!?=]*)\b", re.MULTILINE)),
    ("class", re.compile(r"^\s*(?:class|module)\s+([A-Za-z_][\w:]*)(?:\s|$)", re.MULTILINE)),
    ("function", re.compile(r"^\s*(?:public|private|protected|static|final|async|\s)+[A-Za-z_<>\[\], ?]+\s+([A-Za-z_][\w]*)\s*\(", re.MULTILINE)),
)


def _regex_symbols(snapshot_id: str, file: CodeFile, text: str) -> list[CodeSymbolRecord]:
    symbols: list[CodeSymbolRecord] = []
    seen: set[tuple[str, str, int]] = set()
    for kind, pattern in SYMBOL_PATTERNS:
        for match in pattern.finditer(text):
            name = match.group(1)
            line_start = text.count("\n", 0, match.start()) + 1
            key = (kind, name, line_start)
            if key in seen:
                continue
            seen.add(key)
            line = _line_at(text, line_start)
            symbols.append(
                CodeSymbolRecord(
                    id=_id("sym", snapshot_id, file.path, kind, name, line_start),
                    snapshot_id=snapshot_id,
                    path=file.path,
                    language=file.language,
                    kind=kind,
                    name=name,
                    signature=line.strip()[:240],
                    line_start=line_start,
                )
            )
    return symbols


def _extract_entrypoints(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    *,
    string_constants: dict[str, str] | None = None,
) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    records.extend(_python_entrypoints(snapshot_id, file, text))
    records.extend(_js_entrypoints(snapshot_id, file, text, string_constants=string_constants))
    records.extend(_php_entrypoints(snapshot_id, file, text))
    records.extend(_java_entrypoints(snapshot_id, file, text))
    records.extend(_go_entrypoints(snapshot_id, file, text))
    records.extend(_generic_web_script_entrypoints(snapshot_id, file, text))
    return records


def _python_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "Python":
        return []
    records: list[CodeEntrypointRecord] = []
    pending: list[tuple[int, str | None, str, str]] = []
    route_pattern = re.compile(r"@\w+(?:\.\w+)*\.(get|post|put|delete|patch|options|head|route)\((.*)")
    def_pattern = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(")
    for lineno, line in enumerate(text.splitlines(), start=1):
        route_match = route_pattern.search(line)
        if route_match:
            method = route_match.group(1).upper()
            args = route_match.group(2)
            route = _first_string(args)
            if route:
                methods = _methods_from_args(args)
                if method != "ROUTE":
                    methods = [method]
                if not methods:
                    methods = [None]
                for item in methods:
                    pending.append((lineno, item, route, line.strip()))
            continue
        def_match = def_pattern.match(line)
        if def_match and pending:
            handler = def_match.group(1)
            for route_lineno, method, route, evidence in pending:
                records.append(_entrypoint(snapshot_id, file, "http_route", "python", method, route, handler, route_lineno, evidence))
            pending = []
        elif line.strip() and not line.lstrip().startswith("@") and pending:
            pending = []
    return records


def _js_entrypoints(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    *,
    string_constants: dict[str, str] | None = None,
) -> list[CodeEntrypointRecord]:
    if file.language not in {"JavaScript", "TypeScript", "Vue"}:
        return []
    records: list[CodeEntrypointRecord] = []
    constants = dict(string_constants or {})
    constants.update(_collect_js_string_constants([text]))
    express = re.compile(r"\b(?:app|router)\.(get|post|put|delete|patch|options|head|all)\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*([A-Za-z_$][\w$\.]*))?", re.IGNORECASE)
    for match in express.finditer(text):
        method = match.group(1).upper()
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "express",
                None if method == "ALL" else method,
                match.group(2),
                match.group(3),
                _line_no(text, match.start()),
                _line_at(text, _line_no(text, match.start())).strip(),
            )
        )
    satrda = re.compile(
        r"\bsatrda\.Router\.(get|post|put|delete|patch|options|head|all)\(\s*([^,\n]+?)\s*(?:,\s*([A-Za-z_$][\w$\.]*))?(?:,|\))",
        re.IGNORECASE,
    )
    for match in satrda.finditer(text):
        route = _resolve_js_string_expression(match.group(2), constants)
        if not route:
            continue
        method = match.group(1).upper()
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "satrda",
                None if method == "ALL" else method,
                route,
                match.group(3),
                _line_no(text, match.start()),
                _line_at(text, _line_no(text, match.start())).strip(),
            )
        )
    decorators = re.compile(r"@(Get|Post|Put|Delete|Patch|Options|Head)\(\s*['\"]?([^'\")]+)?['\"]?\s*\)\s*\n\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(", re.IGNORECASE)
    for match in decorators.finditer(text):
        method = match.group(1).upper()
        route = match.group(2) or "/"
        records.append(_entrypoint(snapshot_id, file, "http_route", "nestjs", method, route, match.group(3), _line_no(text, match.start()), match.group(0).splitlines()[0].strip()))
    return records


JS_STRING_ASSIGNMENT = re.compile(
    r"^\s*(?:(?:const|let|var)\s+)?(?:globalThis\.|global\.|window\.|root\.)?([A-Za-z_$][\w$]*)\s*=\s*(['\"])(.*?)\2\s*;?",
    re.MULTILINE,
)


def _collect_js_string_constants(texts: object) -> dict[str, str]:
    values: dict[str, set[str]] = {}
    for text in texts:
        if not isinstance(text, str):
            continue
        for match in JS_STRING_ASSIGNMENT.finditer(text):
            values.setdefault(match.group(1), set()).add(match.group(3))
    return {key: next(iter(items)) for key, items in values.items() if len(items) == 1}


def _resolve_js_string_expression(expr: str, constants: dict[str, str]) -> str | None:
    parts = [part.strip() for part in expr.strip().split("+")]
    if not parts:
        return None
    resolved: list[str] = []
    for part in parts:
        if not part:
            return None
        string_match = re.fullmatch(r"['\"]([^'\"]*)['\"]", part)
        if string_match:
            resolved.append(string_match.group(1))
            continue
        ident_match = re.fullmatch(r"(?:globalThis\.|global\.|window\.|root\.)?([A-Za-z_$][\w$]*)", part)
        if ident_match and ident_match.group(1) in constants:
            resolved.append(constants[ident_match.group(1)])
            continue
        return None
    route = "".join(resolved).strip()
    return route or None


def _php_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "PHP":
        return []
    records: list[CodeEntrypointRecord] = []
    pattern = re.compile(r"Route::(get|post|put|delete|patch|options|any)\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^)\n]+)", re.IGNORECASE)
    for match in pattern.finditer(text):
        method = match.group(1).upper()
        records.append(_entrypoint(snapshot_id, file, "http_route", "laravel", None if method == "ANY" else method, match.group(2), _handler_text(match.group(3)), _line_no(text, match.start()), _line_at(text, _line_no(text, match.start())).strip()))
    return records


def _java_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language not in {"Java", "Kotlin", "Scala", "C#"}:
        return []
    records: list[CodeEntrypointRecord] = []
    pattern = re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
    method_by_mapping = {
        "GETMAPPING": "GET",
        "POSTMAPPING": "POST",
        "PUTMAPPING": "PUT",
        "DELETEMAPPING": "DELETE",
        "PATCHMAPPING": "PATCH",
    }
    lines = text.splitlines()
    for match in pattern.finditer(text):
        mapping = match.group(1).upper()
        args = match.group(2) or ""
        route = _first_string(args) or "/"
        method = method_by_mapping.get(mapping) or _request_method(args)
        line_start = _line_no(text, match.start())
        handler = _next_java_like_method(lines, line_start)
        records.append(_entrypoint(snapshot_id, file, "http_route", "spring", method, route, handler, line_start, _line_at(text, line_start).strip()))
    return records


def _go_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "Go":
        return []
    records: list[CodeEntrypointRecord] = []
    patterns = (
        ("net/http", re.compile(r"http\.HandleFunc\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w]*)")),
        ("gin", re.compile(r"\b(?:router|r|group)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w]*)")),
    )
    for framework, pattern in patterns:
        for match in pattern.finditer(text):
            if framework == "net/http":
                method, route, handler = None, match.group(1), match.group(2)
            else:
                method, route, handler = match.group(1), match.group(2), match.group(3)
            line_start = _line_no(text, match.start())
            records.append(_entrypoint(snapshot_id, file, "http_route", framework, method, route, handler, line_start, _line_at(text, line_start).strip()))
    return records


def _generic_web_script_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    path = PurePosixPath(file.path)
    if path.suffix.lower() not in GENERIC_WEB_SCRIPT_SUFFIXES:
        return []
    if any(part in GENERIC_WEB_SCRIPT_EXCLUDED_PARTS for part in path.parts):
        return []
    return [
        _entrypoint(
            snapshot_id,
            file,
            "http_route",
            "web_script",
            None,
            f"/{file.path}",
            path.name,
            1,
            f"{file.path} is a web-executable script file",
        )
    ]


def _entrypoint(
    snapshot_id: str,
    file: CodeFile,
    kind: str,
    framework: str | None,
    method: str | None,
    route: str,
    handler: str | None,
    line_start: int | None,
    evidence: str | None,
) -> CodeEntrypointRecord:
    return CodeEntrypointRecord(
        id=_id("entry", snapshot_id, file.path, kind, framework, method, route, handler, line_start),
        snapshot_id=snapshot_id,
        path=file.path,
        language=file.language,
        kind=kind,
        framework=framework,
        method=method,
        route=route,
        handler=handler,
        line_start=line_start,
        evidence=evidence,
    )


def _extract_manifest(snapshot_id: str, file: CodeFile, text: str) -> DependencyManifestRecord | None:
    name = Path(file.path).name
    try:
        if name == "package.json":
            data = json.loads(text)
            return _manifest(snapshot_id, file, "npm", data.get("name"), _keys(data.get("dependencies")), _keys(data.get("devDependencies")))
        if name == "composer.json":
            data = json.loads(text)
            return _manifest(snapshot_id, file, "composer", data.get("name"), _keys(data.get("require")), _keys(data.get("require-dev")))
        if name == "pyproject.toml":
            data = tomllib.loads(text)
            project = data.get("project") or {}
            poetry = ((data.get("tool") or {}).get("poetry") or {})
            deps = _string_values(project.get("dependencies")) or _keys(poetry.get("dependencies"))
            dev = _flatten_optional_deps(project.get("optional-dependencies")) or _keys(((poetry.get("group") or {}).get("dev") or {}).get("dependencies"))
            return _manifest(snapshot_id, file, "pyproject", project.get("name") or poetry.get("name"), deps, dev)
        if name in {"requirements.txt", "requirements-dev.txt", "dev-requirements.txt"}:
            deps = _requirements(text)
            dev = deps if "dev" in name else []
            return _manifest(snapshot_id, file, "requirements", None, [] if dev else deps, dev)
        if name == "go.mod":
            return _manifest(snapshot_id, file, "go", _go_module(text), _go_requires(text), [])
        if name in {"pom.xml", "build.gradle", "build.gradle.kts", "Gemfile", "Cargo.toml"}:
            return _manifest(snapshot_id, file, name, None, _generic_manifest_deps(name, text), [])
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, TypeError, AttributeError):
        return None
    return None


def _manifest(
    snapshot_id: str,
    file: CodeFile,
    manifest_type: str,
    package_name: str | None,
    dependencies: list[str],
    dev_dependencies: list[str],
) -> DependencyManifestRecord:
    return DependencyManifestRecord(
        id=_id("manifest", snapshot_id, file.path, manifest_type),
        snapshot_id=snapshot_id,
        path=file.path,
        manifest_type=manifest_type,
        package_name=package_name.strip() if isinstance(package_name, str) and package_name.strip() else None,
        dependencies=sorted(set(dependencies)),
        dev_dependencies=sorted(set(dev_dependencies)),
    )


def _keys(value: object) -> list[str]:
    return [str(key) for key in value.keys()] if isinstance(value, dict) else []


def _string_values(value: object) -> list[str]:
    return [str(item) for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _flatten_optional_deps(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    result: list[str] = []
    for items in value.values():
        result.extend(_string_values(items))
    return result


def _requirements(text: str) -> list[str]:
    result: list[str] = []
    for line in text.splitlines():
        item = line.strip()
        if not item or item.startswith("#") or item.startswith("-"):
            continue
        result.append(item.split("#", 1)[0].strip())
    return result


def _go_module(text: str) -> str | None:
    match = re.search(r"^\s*module\s+(\S+)", text, re.MULTILINE)
    return match.group(1) if match else None


def _go_requires(text: str) -> list[str]:
    return re.findall(r"^\s*(?:require\s+)?([A-Za-z0-9_.\-/]+)\s+v[0-9]", text, re.MULTILINE)


def _generic_manifest_deps(name: str, text: str) -> list[str]:
    if name == "pom.xml":
        artifacts = re.findall(r"<artifactId>\s*([^<]+)\s*</artifactId>", text)
        return [item.strip() for item in artifacts if item.strip()]
    if name in {"build.gradle", "build.gradle.kts"}:
        return re.findall(r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s+['\"]([^'\"]+)['\"]", text)
    if name == "Gemfile":
        return re.findall(r"^\s*gem\s+['\"]([^'\"]+)['\"]", text, re.MULTILINE)
    if name == "Cargo.toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return []
        return _keys(data.get("dependencies"))
    return []


def _line_no(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _line_at(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def _first_string(value: str) -> str | None:
    match = re.search(r"['\"]([^'\"]+)['\"]", value)
    return match.group(1) if match else None


def _methods_from_args(value: str) -> list[str]:
    match = re.search(r"methods\s*=\s*\[([^\]]+)\]", value)
    if not match:
        return []
    return [item.upper() for item in re.findall(r"['\"]([A-Za-z]+)['\"]", match.group(1))]


def _request_method(value: str) -> str | None:
    match = re.search(r"RequestMethod\.([A-Z]+)", value)
    return match.group(1) if match else None


def _next_java_like_method(lines: list[str], line_start: int) -> str | None:
    method_pattern = re.compile(r"\b([A-Za-z_][\w]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{?\s*$")
    for line in lines[line_start : min(len(lines), line_start + 8)]:
        match = method_pattern.search(line.strip())
        if match and match.group(1) not in {"if", "for", "while", "switch", "catch"}:
            return match.group(1)
    return None


def _handler_text(value: str) -> str | None:
    text = value.strip().strip("[]")
    return text[:160] if text else None


def _dedupe_symbols(items: list[CodeSymbolRecord]) -> list[CodeSymbolRecord]:
    seen: set[tuple[str, str, str, int | None]] = set()
    result: list[CodeSymbolRecord] = []
    for item in items:
        key = (item.path, item.kind, item.name, item.line_start)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _dedupe_entrypoints(items: list[CodeEntrypointRecord]) -> list[CodeEntrypointRecord]:
    seen: set[tuple[str, str | None, str, str | None]] = set()
    result: list[CodeEntrypointRecord] = []
    for item in items:
        key = (item.path, item.method, item.route, item.handler)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _dedupe_manifests(items: list[DependencyManifestRecord]) -> list[DependencyManifestRecord]:
    seen: set[str] = set()
    result: list[DependencyManifestRecord] = []
    for item in items:
        if item.path in seen:
            continue
        seen.add(item.path)
        result.append(item)
    return result
