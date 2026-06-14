from __future__ import annotations

import ast
from dataclasses import dataclass, field
import hashlib
import json
import posixpath
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
SYMBOL_RESERVED_NAMES = {
    "case",
    "catch",
    "default",
    "do",
    "else",
    "elseif",
    "for",
    "foreach",
    "if",
    "return",
    "switch",
    "try",
    "while",
    "with",
}
CALL_RELATIONSHIP_LANGUAGES = {
    "Python",
    "JavaScript",
    "TypeScript",
    "Vue",
    "PHP",
    "Java",
    "Kotlin",
    "Scala",
    "C#",
    "Go",
    "Ruby",
    "Rust",
}
GENERATED_RELATIONSHIP_PARTS = {
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
}
GENERATED_RELATIONSHIP_STEMS = {
    "ace",
    "codemirror",
    "echarts",
    "element-ui",
    "exceljs",
    "jquery",
    "jspdf",
    "monaco",
    "vue",
}
CALL_TOKEN_RE = re.compile(r"\b(?:new\s+)?([A-Za-z_$][\w$]*)\s*(?:\(|\{)")
MAX_CALL_TOKENS_PER_FILE = 4000
PHP_DIRECT_SCRIPT_NAME_RE = re.compile(
    r"^(?:index|app|main|server|setup|install|upgrade|migrate|admin|login|logout|"
    r"callback|webhook|test)(?:[-_.][A-Za-z0-9_.-]+)?\.php$",
    re.IGNORECASE,
)
PHP_DECLARATION_START_RE = re.compile(
    r"^\s*(?:final\s+|abstract\s+)?(?:function|class|interface|trait)\b",
    re.IGNORECASE,
)
PHP_TOP_LEVEL_WEB_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|php://input"),
    re.compile(r"\b(?:echo|print|printf|header|setcookie|http_response_code)\b", re.IGNORECASE),
    re.compile(r"\b(?:session_start|move_uploaded_file)\s*\(", re.IGNORECASE),
    re.compile(r"\b(?:DROP\s+DATABASE|CREATE\s+DATABASE|CREATE\s+TABLE|INSERT\s+INTO)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:<!doctype\s+html|<html\b|<body\b|<form\b)", re.IGNORECASE),
)


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
    confidence: float = 0.8
    source: str = "heuristic"


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
    confidence: float = 0.8
    source: str = "heuristic"


@dataclass(frozen=True)
class CodeRelationshipRecord:
    id: str
    snapshot_id: str
    from_path: str
    from_symbol: str | None
    to_path: str
    to_symbol: str | None
    relation: str
    evidence: str | None = None
    confidence: float = 0.55
    source: str = "heuristic"
    line_start: int | None = None


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
    relationships: list[CodeRelationshipRecord]
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
    symbols = _dedupe_symbols(symbols)
    entrypoints = _dedupe_entrypoints(entrypoints)
    relationships = _extract_relationships(snapshot_id, readable, symbols, entrypoints)
    return CodeIndexRecords(
        symbols=symbols,
        entrypoints=entrypoints,
        relationships=_dedupe_relationships(relationships),
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
        symbols = _python_symbols(snapshot_id, file, text)
    else:
        symbols = _regex_symbols(snapshot_id, file, text)
    symbols.extend(_data_object_symbols(snapshot_id, file, text))
    return symbols


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
    ("class", re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*(?:class|enum|record)\s+([A-Za-z_][\w]*)\b", re.MULTILINE)),
    ("interface", re.compile(r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*interface\s+([A-Za-z_][\w]*)\b", re.MULTILINE)),
    ("function", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)\s*\(", re.MULTILINE)),
    ("function", re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][\w]*)\s*\(", re.MULTILINE)),
    ("class", re.compile(r"^\s*(?:pub\s+)?(?:struct|enum)\s+([A-Za-z_][\w]*)\b", re.MULTILINE)),
    ("function", re.compile(r"^\s*def\s+([A-Za-z_][\w!?=]*)\b", re.MULTILINE)),
    ("class", re.compile(r"^\s*(?:class|module)\s+([A-Za-z_][\w:]*)(?:\s|$)", re.MULTILINE)),
    (
        "function",
        re.compile(
            r"^\s*(?!return\b|throw\b|new\b|if\b|for\b|while\b|switch\b|catch\b)"
            r"(?:(?:public|private|protected|static|final|abstract|synchronized|async)\s+)*"
            r"[A-Za-z_][\w_<>\[\], ?]*\s+([A-Za-z_][\w]*)\s*\(",
            re.MULTILINE,
        ),
    ),
)


def _regex_symbols(snapshot_id: str, file: CodeFile, text: str) -> list[CodeSymbolRecord]:
    symbols: list[CodeSymbolRecord] = []
    seen: set[tuple[str, str, int]] = set()
    for kind, pattern in SYMBOL_PATTERNS:
        for match in pattern.finditer(text):
            name = match.group(1)
            if name.lower() in SYMBOL_RESERVED_NAMES:
                continue
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


DATA_OBJECT_SQL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`\"'\[]?([A-Za-z_][\w.$-]*)", re.IGNORECASE),
    re.compile(r"\b(?:FROM|JOIN|UPDATE|INTO)\s+[`\"'\[]?([A-Za-z_][\w.$-]*)", re.IGNORECASE),
)
DATA_OBJECT_RESERVED_NAMES = {
    "select",
    "where",
    "values",
    "set",
    "returning",
    "dual",
    "public",
}


def _data_object_symbols(snapshot_id: str, file: CodeFile, text: str) -> list[CodeSymbolRecord]:
    symbols: list[CodeSymbolRecord] = []
    seen: set[tuple[str, int | None]] = set()

    def add(name: str, offset: int, signature: str, confidence: float, source: str) -> None:
        cleaned = _clean_data_object_name(name)
        if cleaned is None:
            return
        line_start = _line_no(text, offset)
        key = (cleaned, line_start)
        if key in seen:
            return
        seen.add(key)
        symbols.append(
            CodeSymbolRecord(
                id=_id("sym", snapshot_id, file.path, "data_object", cleaned, line_start),
                snapshot_id=snapshot_id,
                path=file.path,
                language=file.language,
                kind="data_object",
                name=cleaned,
                signature=signature.strip()[:240],
                line_start=line_start,
                confidence=confidence,
                source=source,
            )
        )

    for pattern in DATA_OBJECT_SQL_PATTERNS:
        for match in pattern.finditer(text):
            line_start = _line_no(text, match.start())
            line = _line_at(text, line_start)
            if _looks_like_language_import_line(line):
                continue
            add(match.group(1), match.start(), line, 0.82, "heuristic:sql")

    for match in re.finditer(r"__tablename__\s*=\s*['\"]([^'\"]+)['\"]", text):
        add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.88, "heuristic:orm")
    for match in re.finditer(r"\bclass\s+([A-Za-z_][\w]*)\s*\([^)]*(?:models\.Model|Model)[^)]*\)", text):
        add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.82, "heuristic:orm")
    for match in re.finditer(r"@(?:Entity|Table)\s*(?:\(\s*(?:name\s*=\s*)?['\"]([^'\"]+)['\"])?", text):
        explicit = match.group(1)
        if explicit:
            add(explicit, match.start(), _line_at(text, _line_no(text, match.start())), 0.86, "heuristic:orm")
            continue
        class_match = re.search(r"\bclass\s+([A-Za-z_][\w]*)", text[match.end() : match.end() + 500])
        if class_match:
            add(class_match.group(1), match.end() + class_match.start(), class_match.group(0), 0.78, "heuristic:orm")
    for match in re.finditer(r"\[Table\(\s*['\"]([^'\"]+)['\"]\s*\)\]", text):
        add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.86, "heuristic:orm")
    for match in re.finditer(r"\bDbSet\s*<\s*([A-Za-z_][\w]*)\s*>\s+([A-Za-z_][\w]*)", text):
        add(match.group(2), match.start(), _line_at(text, _line_no(text, match.start())), 0.8, "heuristic:orm")
    for match in re.finditer(r"@Entity\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", text):
        add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.86, "heuristic:orm")
    for match in re.finditer(r"\bmodel\s*\(\s*['\"]([^'\"]+)['\"]", text):
        add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.76, "heuristic:orm")
    for match in re.finditer(r"\btype\s+([A-Za-z_][\w]*)\s+struct\s*\{", text):
        block = text[match.start() : match.start() + 800]
        if "gorm." in block or "`json:" in block or "`db:" in block:
            add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.64, "heuristic:model")
    for match in re.finditer(r"\bclass\s+([A-Za-z_][\w]*(?:Model|Entity|Record))\b", text):
        add(match.group(1), match.start(), _line_at(text, _line_no(text, match.start())), 0.62, "heuristic:model")
    return symbols


def _clean_data_object_name(value: str) -> str | None:
    text = value.strip().strip("`\"'[]")
    text = text.split()[0].strip("`\"'[]")
    if not text or text.lower() in DATA_OBJECT_RESERVED_NAMES:
        return None
    if text.startswith("$") or text.startswith(":"):
        return None
    return text[:120]


def _looks_like_language_import_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    lower = stripped.lower()
    if re.match(r"^(?:from\s+[a-zA-Z_][\w.]*\s+import\b|import\s+)", stripped):
        return True
    if re.match(r"^(?:import|export)\s+.+\s+from\s+['\"]", stripped):
        return True
    if lower.startswith(("package ", "using ", "require ", "include ")):
        return True
    return False


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
    records.extend(_csharp_entrypoints(snapshot_id, file, text))
    records.extend(_java_entrypoints(snapshot_id, file, text))
    records.extend(_go_entrypoints(snapshot_id, file, text))
    records.extend(_ruby_entrypoints(snapshot_id, file, text))
    records.extend(_rust_entrypoints(snapshot_id, file, text))
    records.extend(_generic_web_script_entrypoints(snapshot_id, file, text))
    return records


def _python_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "Python":
        return []
    records: list[CodeEntrypointRecord] = []
    pending: list[tuple[int, str | None, str, str]] = []
    router_prefixes = _python_router_prefixes(text)
    route_pattern = re.compile(r"@([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\.(get|post|put|delete|patch|options|head|route)\((.*)")
    def_pattern = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(")
    for lineno, line in enumerate(text.splitlines(), start=1):
        route_match = route_pattern.search(line)
        if route_match:
            target = route_match.group(1).split(".")[-1]
            method = route_match.group(2).upper()
            args = route_match.group(3)
            route = _first_string(args)
            if route:
                route = _join_routes(router_prefixes.get(target), route)
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
    records.extend(_python_django_entrypoints(snapshot_id, file, text))
    records.extend(_python_drf_entrypoints(snapshot_id, file, text))
    return records


def _python_router_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    router_pattern = re.compile(
        r"\b([A-Za-z_][\w]*)\s*=\s*(?:[A-Za-z_][\w]*\.)?(?:APIRouter|Blueprint)\(([^)\n]*)\)"
    )
    for match in router_pattern.finditer(text):
        prefix = _keyword_string(match.group(2), "prefix") or _keyword_string(match.group(2), "url_prefix")
        if prefix:
            prefixes[match.group(1)] = prefix
    register_pattern = re.compile(
        r"\bregister_blueprint\(\s*([A-Za-z_][\w]*)\s*,[^)\n]*url_prefix\s*=\s*['\"]([^'\"]+)['\"]"
    )
    for match in register_pattern.finditer(text):
        target = match.group(1)
        prefixes[target] = _join_routes(match.group(2), prefixes.get(target))
    include_pattern = re.compile(
        r"\binclude_router\(\s*([A-Za-z_][\w]*)\s*,[^)\n]*prefix\s*=\s*['\"]([^'\"]+)['\"]"
    )
    for match in include_pattern.finditer(text):
        target = match.group(1)
        prefixes[target] = _join_routes(match.group(2), prefixes.get(target))
    return prefixes


def _python_django_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    include_pattern = re.compile(r"\b(path|re_path)\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*include\(\s*['\"]([^'\"]+)['\"]\s*\)")
    for match in include_pattern.finditer(text):
        call, route, include_target = match.group(1), match.group(2), match.group(3)
        if call == "re_path":
            route = route.strip("^").rstrip("$")
        route = _join_routes(None, route)
        line_start = _line_no(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "django",
                None,
                route,
                f"include({include_target})",
                line_start,
                _line_at(text, line_start).strip(),
                0.7,
                "heuristic:django_include",
            )
        )
    pattern = re.compile(r"\b(path|re_path)\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*([^,\)\n]+)")
    for match in pattern.finditer(text):
        call, route, handler = match.group(1), match.group(2), match.group(3)
        if handler.strip().startswith("include("):
            continue
        if ".as_view" in handler and "{" in handler:
            continue
        if call == "re_path":
            route = route.strip("^").rstrip("$")
        route = _join_routes(None, route)
        line_start = _line_no(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "django",
                None,
                route,
                _handler_text(handler),
                line_start,
                _line_at(text, line_start).strip(),
            )
        )
    return records


DRF_STANDARD_ACTIONS: tuple[tuple[str, str, str], ...] = (
    ("GET", "", "list"),
    ("POST", "", "create"),
    ("GET", "{pk}", "retrieve"),
    ("PUT", "{pk}", "update"),
    ("PATCH", "{pk}", "partial_update"),
    ("DELETE", "{pk}", "destroy"),
)


def _python_drf_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    router_prefixes = _python_drf_router_prefixes(text)
    action_routes = _python_drf_action_routes(text)

    register_pattern = re.compile(
        r"\b([A-Za-z_][\w]*)\.register\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?)",
        re.MULTILINE,
    )
    for match in register_pattern.finditer(text):
        router_name, route, viewset = match.group(1), match.group(2), match.group(3)
        if not viewset.split(".")[-1].endswith("ViewSet"):
            continue
        base_route = _join_routes(router_prefixes.get(router_name), route)
        line_start = _line_no(text, match.start())
        evidence = _line_at(text, line_start).strip()
        for method, suffix, action in DRF_STANDARD_ACTIONS:
            records.append(
                _entrypoint(
                    snapshot_id,
                    file,
                    "http_route",
                    "drf",
                    method,
                    _join_routes(base_route, suffix),
                    f"{viewset}.{action}",
                    line_start,
                    evidence,
                    0.62,
                    "heuristic:drf_router",
                )
            )
        for custom in action_routes.get(viewset.split(".")[-1], []):
            detail, methods, url_path, action = custom
            suffix = _join_routes("{pk}" if detail else "", url_path)
            for method in methods:
                records.append(
                    _entrypoint(
                        snapshot_id,
                        file,
                        "http_route",
                        "drf",
                        method,
                        _join_routes(base_route, suffix),
                        f"{viewset}.{action}",
                        line_start,
                        evidence,
                        0.66,
                        "heuristic:drf_router_action",
                    )
                )

    as_view_pattern = re.compile(
        r"\b(path|re_path)\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?)\.as_view\(\s*\{([^}]*)\}",
        re.MULTILINE | re.DOTALL,
    )
    for match in as_view_pattern.finditer(text):
        call, route, viewset, mapping = match.group(1), match.group(2), match.group(3), match.group(4)
        if call == "re_path":
            route = route.strip("^").rstrip("$")
        line_start = _line_no(text, match.start())
        evidence = _line_at(text, line_start).strip()
        for method, action in _python_drf_action_map(mapping):
            records.append(
                _entrypoint(
                    snapshot_id,
                    file,
                    "http_route",
                    "drf",
                    method,
                    _join_routes(None, route),
                    f"{viewset}.{action}",
                    line_start,
                    evidence,
                    0.7,
                    "heuristic:drf_as_view",
                )
            )
    return records


def _python_drf_router_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    pattern = re.compile(
        r"\b(?:path|re_path)\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*include\(\s*([A-Za-z_][\w]*)\.urls",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        route, router_name = match.group(1), match.group(2)
        prefixes[router_name] = _join_routes(prefixes.get(router_name), route)
    return prefixes


def _python_drf_action_routes(text: str) -> dict[str, list[tuple[bool, list[str], str, str]]]:
    result: dict[str, list[tuple[bool, list[str], str, str]]] = {}
    class_pattern = re.compile(r"^\s*class\s+([A-Za-z_][\w]*)\s*\([^)]*(?:ViewSet|GenericViewSet|ModelViewSet)[^)]*\)\s*:", re.MULTILINE)
    for class_match in class_pattern.finditer(text):
        class_name = class_match.group(1)
        class_start = class_match.end()
        next_class = re.search(r"^\s*class\s+[A-Za-z_][\w]*\s*\(", text[class_start:], re.MULTILINE)
        class_end = class_start + next_class.start() if next_class else len(text)
        block = text[class_start:class_end]
        action_pattern = re.compile(
            r"@action\(([^)]*)\)\s*\n\s*def\s+([A-Za-z_][\w]*)\s*\(",
            re.MULTILINE,
        )
        for action_match in action_pattern.finditer(block):
            args = action_match.group(1)
            method_name = action_match.group(2)
            detail = _keyword_bool(args, "detail")
            methods = _methods_from_args(args) or ["GET"]
            url_path = _keyword_string(args, "url_path") or method_name.replace("_", "-")
            result.setdefault(class_name, []).append((detail, methods, url_path, method_name))
    return result


def _python_drf_action_map(value: str) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for match in re.finditer(r"['\"]([A-Za-z]+)['\"]\s*:\s*['\"]([A-Za-z_][\w]*)['\"]", value):
        items.append((match.group(1).upper(), match.group(2)))
    return items


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
    fastify_names = _js_fastify_names(text)
    hapi_names = _js_hapi_names(text)
    express = re.compile(r"\b(?:app|router)\.(get|post|put|delete|patch|options|head|all)\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*([A-Za-z_$][\w$\.]*))?", re.IGNORECASE)
    for match in express.finditer(text):
        target_match = re.search(r"\b([A-Za-z_$][\w$]*)\.", match.group(0))
        target = target_match.group(1) if target_match else ""
        if target in fastify_names or target in hapi_names:
            continue
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
    records.extend(_nestjs_entrypoints(snapshot_id, file, text))
    records.extend(_js_fastify_entrypoints(snapshot_id, file, text))
    records.extend(_js_hapi_entrypoints(snapshot_id, file, text))
    return records


def _js_fastify_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    method_pattern = re.compile(
        r"\b([A-Za-z_$][\w$]*)\.(get|post|put|delete|patch|options|head|all)\(\s*['\"]([^'\"]+)['\"]\s*(?:,\s*([A-Za-z_$][\w$\.]*))?",
        re.IGNORECASE,
    )
    fastify_names = _js_fastify_names(text)
    for match in method_pattern.finditer(text):
        target = match.group(1)
        if target not in fastify_names and target.lower() != "fastify":
            continue
        method = match.group(2).upper()
        line_start = _line_no(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "fastify",
                None if method == "ALL" else method,
                match.group(3),
                match.group(4),
                line_start,
                _line_at(text, line_start).strip(),
                0.78,
                "heuristic:fastify",
            )
        )
    route_pattern = re.compile(r"\b([A-Za-z_$][\w$]*)\.route\(\s*\{(?P<body>.*?)\}\s*\)", re.DOTALL)
    for match in route_pattern.finditer(text):
        target = match.group(1)
        if target not in fastify_names and target.lower() != "fastify":
            continue
        body = match.group("body")
        method = _js_object_string(body, "method")
        route = _js_object_string(body, "url") or _js_object_string(body, "path")
        if not route:
            continue
        handler = _js_object_identifier(body, "handler")
        line_start = _line_no(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "fastify",
                method.upper() if method else None,
                route,
                handler,
                line_start,
                _line_at(text, line_start).strip(),
                0.78,
                "heuristic:fastify_route",
            )
        )
    return records


def _js_fastify_names(text: str) -> set[str]:
    names = {"fastify"}
    for match in re.finditer(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:fastify|require\(['\"]fastify['\"]\))\s*\(",
        text,
    ):
        names.add(match.group(1))
    return names


def _js_hapi_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    hapi_names = _js_hapi_names(text)
    pattern = re.compile(r"\b([A-Za-z_$][\w$]*)\.route\(\s*(?:\[\s*)?\{(?P<body>.*?)\}\s*(?:\]\s*)?\)", re.DOTALL)
    for match in pattern.finditer(text):
        target = match.group(1)
        if target not in hapi_names and target.lower() not in {"server"}:
            continue
        line = _line_at(text, _line_no(text, match.start()))
        if "route" not in line and "method" not in match.group("body"):
            continue
        body = match.group("body")
        method = _js_object_string(body, "method")
        route = _js_object_string(body, "path")
        if not route:
            continue
        handler = _js_object_identifier(body, "handler")
        line_start = _line_no(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "hapi",
                method.upper() if method else None,
                route,
                handler,
                line_start,
                _line_at(text, line_start).strip(),
                0.74,
                "heuristic:hapi_route",
            )
        )
    return records


def _js_hapi_names(text: str) -> set[str]:
    names: set[str] = set()
    if "@hapi/hapi" in text or "require('hapi')" in text or 'require("hapi")' in text:
        names.add("server")
    for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?Hapi\.Server\b", text):
        names.add(match.group(1))
    return names


def _js_object_string(body: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*:\s*['\"]([^'\"]+)['\"]", body)
    return match.group(1) if match else None


def _js_object_identifier(body: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*:\s*([A-Za-z_$][\w$\.]*)", body)
    return match.group(1) if match else None


def _nestjs_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    class_pattern = re.compile(
        r"@Controller\s*(?:\(([^)]*)\))?\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)[^{]*\{",
        re.IGNORECASE,
    )
    for class_match in class_pattern.finditer(text):
        open_brace = text.find("{", class_match.start(), class_match.end())
        if open_brace < 0:
            continue
        close_brace = _find_matching_brace(text, open_brace)
        if close_brace is None:
            continue
        prefix = _first_string(class_match.group(1) or "") or ""
        block = text[open_brace + 1 : close_brace]
        for item in _nestjs_method_entrypoints(snapshot_id, file, text, block, open_brace + 1, prefix):
            records.append(item)

    if not records:
        for item in _nestjs_method_entrypoints(snapshot_id, file, text, text, 0, ""):
            records.append(item)
    return records


def _nestjs_method_entrypoints(
    snapshot_id: str,
    file: CodeFile,
    full_text: str,
    text: str,
    offset: int,
    prefix: str,
) -> list[CodeEntrypointRecord]:
    records: list[CodeEntrypointRecord] = []
    decorators = re.compile(
        r"@(Get|Post|Put|Delete|Patch|Options|Head|All)\s*(?:\(([^)]*)\))?"
        r"\s*(?:public|private|protected|async|static|\s)*([A-Za-z_$][\w$]*)\s*\(",
        re.IGNORECASE,
    )
    for match in decorators.finditer(text):
        raw_method = match.group(1).upper()
        method = None if raw_method == "ALL" else raw_method
        route = _join_routes(prefix, _first_string(match.group(2) or "") or "")
        line_start = _line_no(full_text, offset + match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "nestjs",
                method,
                route,
                match.group(3),
                line_start,
                _line_at(full_text, line_start).strip(),
            )
        )
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
    prefix_ranges = _php_laravel_prefix_ranges(text)
    pattern = re.compile(r"Route::(get|post|put|delete|patch|options|any)\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^)\n]+)", re.IGNORECASE)
    for match in pattern.finditer(text):
        method = match.group(1).upper()
        route = _join_routes(_php_route_prefix_at(prefix_ranges, match.start()), match.group(2))
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "laravel",
                None if method == "ANY" else method,
                route,
                _php_handler_text(match.group(3)),
                _line_no(text, match.start()),
                _line_at(text, _line_no(text, match.start())).strip(),
            )
        )
    return records


def _php_laravel_prefix_ranges(text: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    patterns = (
        re.compile(r"Route::prefix\(\s*['\"]([^'\"]+)['\"]\s*\)\s*->\s*group\s*\(\s*function\s*\([^)]*\)\s*\{", re.IGNORECASE),
        re.compile(
            r"Route::group\(\s*\[[^\]]*['\"]prefix['\"]\s*=>\s*['\"]([^'\"]+)['\"][^\]]*\]\s*,\s*function\s*\([^)]*\)\s*\{",
            re.IGNORECASE | re.DOTALL,
        ),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            open_brace = text.find("{", match.start(), match.end())
            if open_brace < 0:
                continue
            close_brace = _find_matching_brace(text, open_brace)
            if close_brace is not None:
                ranges.append((open_brace, close_brace, match.group(1)))
    return sorted(ranges)


def _php_route_prefix_at(ranges: list[tuple[int, int, str]], offset: int) -> str | None:
    prefix: str | None = None
    for start, end, value in ranges:
        if start <= offset <= end:
            prefix = _join_routes(prefix, value)
    return prefix


def _find_matching_brace(text: str, open_brace: int) -> int | None:
    depth = 0
    for index in range(open_brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _php_handler_text(value: str) -> str | None:
    text = _handler_text(value)
    if not text:
        return None
    class_method = re.search(
        r"([A-Za-z_][\w\\]*Controller)::class\s*,\s*['\"]([A-Za-z_][\w]*)['\"]",
        text,
    )
    if class_method:
        controller = class_method.group(1).split("\\")[-1]
        return f"{controller}@{class_method.group(2)}"
    string_handler = re.search(r"['\"]([A-Za-z_][\w\\]*Controller@[A-Za-z_][\w]*)['\"]", text)
    if string_handler:
        return string_handler.group(1).split("\\")[-1]
    return text


def _csharp_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "C#":
        return []
    records: list[CodeEntrypointRecord] = []
    lines = text.splitlines()
    pending: list[tuple[int, str | None, str | None, str]] = []
    class_prefix = ""
    class_name: str | None = None
    for lineno, line in enumerate(lines, start=1):
        pending.extend(_csharp_route_attributes(line, lineno))
        stripped = line.strip()
        class_match = re.search(r"\bclass\s+([A-Za-z_][\w]*)", stripped)
        if class_match:
            class_name = class_match.group(1)
            class_route = next((item[2] for item in reversed(pending) if item[1] is None and item[2] is not None), "")
            class_prefix = _csharp_route_tokens(class_route or "", class_name, None)
            pending = []
            continue
        handler = _csharp_method_name(stripped)
        if handler and pending:
            method_route = next((item[2] for item in reversed(pending) if item[2] is not None), "")
            has_method_attr = any(item[1] is not None for item in pending)
            for attr_lineno, method, route, evidence in pending:
                if method is None and has_method_attr:
                    continue
                full_route = _join_routes(class_prefix, _csharp_route_tokens(route if route is not None else method_route, class_name, handler))
                records.append(_entrypoint(snapshot_id, file, "http_route", "aspnet", method, full_route, handler, attr_lineno, evidence))
            pending = []
        elif stripped and not stripped.startswith("[") and pending:
            pending = []
    return records


def _java_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language not in {"Java", "Kotlin", "Scala"}:
        return []
    records: list[CodeEntrypointRecord] = []
    lines = text.splitlines()
    pending: list[tuple[int, str, str | None, str | None, str]] = []
    class_prefix = ""
    class_jax_prefix = ""
    annotation_lines: list[str] = []
    annotation_start = 0
    annotation_balance = 0
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if annotation_lines:
            annotation_lines.append(stripped)
            annotation_balance += stripped.count("(") - stripped.count(")")
            if annotation_balance <= 0:
                pending.extend(_java_mapping_annotations(" ".join(annotation_lines), annotation_start))
                annotation_lines = []
            continue
        if _is_java_route_annotation(stripped) and stripped.count("(") > stripped.count(")"):
            annotation_lines = [stripped]
            annotation_start = lineno
            annotation_balance = stripped.count("(") - stripped.count(")")
            continue
        pending.extend(_java_mapping_annotations(stripped, lineno))
        if re.search(r"\b(?:class|interface|record)\s+[A-Za-z_][\w]*", stripped):
            spring_routes = [item for item in pending if item[1] == "spring" and item[3] is not None]
            jax_routes = [item for item in pending if item[1] == "jaxrs" and item[3] is not None]
            class_prefix = spring_routes[-1][3] or "" if spring_routes else ""
            class_jax_prefix = jax_routes[-1][3] or "" if jax_routes else ""
            pending = []
            continue
        handler = _java_like_method_name(stripped)
        if handler and pending:
            method_route = next((item[3] for item in reversed(pending) if item[3] is not None), "")
            for anno_lineno, framework, method, route, evidence in pending:
                if framework == "jaxrs" and method is None:
                    continue
                if framework == "spring":
                    if route is None and method is None:
                        continue
                    full_route = _join_routes(class_prefix, route if route is not None else method_route)
                else:
                    full_route = _join_routes(class_jax_prefix, route if route is not None else method_route)
                records.append(_entrypoint(snapshot_id, file, "http_route", framework, method, full_route, handler, anno_lineno, evidence))
            pending = []
        elif stripped and not stripped.startswith("@") and pending:
            pending = []
    return records


def _go_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "Go":
        return []
    records: list[CodeEntrypointRecord] = []
    group_prefixes = _go_group_prefixes(text)
    router_frameworks = _go_router_frameworks(text)
    handler_name = r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)?)"
    patterns = (
        ("net/http", re.compile(rf"http\.HandleFunc\(\s*['\"]([^'\"]+)['\"]\s*,\s*{handler_name}")),
        ("net/http", re.compile(r"http\.Handle\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_][\w.]*(?:\([^)]*\))?)")),
        ("go-method-router", re.compile(rf"\b([A-Za-z_][\w]*)\.(?:Handle|HandleFunc|Method|MethodFunc)\(\s*['\"]([A-Za-z]+)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*,\s*{handler_name}")),
        ("gin", re.compile(rf"\b(router|r|group)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*['\"]([^'\"]+)['\"]\s*,\s*{handler_name}")),
        ("go-router", re.compile(rf"\b([A-Za-z_][\w]*)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*['\"]([^'\"]+)['\"]\s*,\s*{handler_name}")),
        ("go-router", re.compile(rf"\b([A-Za-z_][\w]*)\.(Get|Post|Put|Delete|Patch|Options|Head)\(\s*['\"]([^'\"]+)['\"]\s*,\s*{handler_name}")),
        ("mux", re.compile(rf"\b([A-Za-z_][\w]*)\.HandleFunc\(\s*['\"]([^'\"]+)['\"]\s*,\s*{handler_name}\s*\)\.Methods\(\s*([^)]+)\)")),
    )
    for framework, pattern in patterns:
        for match in pattern.finditer(text):
            entry_framework = framework
            if framework == "net/http":
                method, route, handler = None, match.group(1), match.group(2)
            elif framework == "go-method-router":
                entry_framework = router_frameworks.get(match.group(1), "go-router")
                method, route, handler = match.group(2).upper(), _join_routes(group_prefixes.get(match.group(1)), match.group(3)), match.group(4)
            elif framework == "mux":
                entry_framework = router_frameworks.get(match.group(1), "mux")
                method, route, handler = _go_http_method(match.group(4)), _join_routes(group_prefixes.get(match.group(1)), match.group(2)), match.group(3)
            else:
                entry_framework = router_frameworks.get(match.group(1), framework)
                method, route, handler = match.group(2).upper(), _join_routes(group_prefixes.get(match.group(1)), match.group(3)), match.group(4)
            line_start = _line_no(text, match.start())
            records.append(_entrypoint(snapshot_id, file, "http_route", entry_framework, method, route, handler, line_start, _line_at(text, line_start).strip()))
    return records


def _ruby_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "Ruby":
        return []
    records: list[CodeEntrypointRecord] = []
    scope_prefixes = _ruby_scope_prefixes(text)
    is_rails_routes = "Rails.application.routes" in text or re.search(
        r"^\s*(?:resources\s+:|namespace\s+:|scope\s+['\"]?:)",
        text,
        re.MULTILINE,
    )
    if is_rails_routes:
        rails_pattern = re.compile(
            r"^\s*(get|post|put|patch|delete|match)\s+['\"]([^'\"]+)['\"](?:\s*,\s*to:\s*['\"]([^'\"]+)['\"])?",
            re.IGNORECASE | re.MULTILINE,
        )
        for match in rails_pattern.finditer(text):
            method = match.group(1).upper()
            line_start = _line_no(text, match.start())
            route = _join_routes(_ruby_prefix_at(scope_prefixes, match.start()), match.group(2))
            records.append(
                _entrypoint(
                    snapshot_id,
                    file,
                    "http_route",
                    "rails",
                    None if method == "MATCH" else method,
                    route,
                    match.group(3),
                    line_start,
                    _line_at(text, line_start).strip(),
                    0.74,
                    "heuristic:rails_routes",
                )
            )
        resources_pattern = re.compile(r"^\s*resources\s+:([A-Za-z_][\w]*)", re.MULTILINE)
        for match in resources_pattern.finditer(text):
            base = _join_routes(_ruby_prefix_at(scope_prefixes, match.start()), match.group(1).replace("_", "-"))
            line_start = _line_no(text, match.start())
            evidence = _line_at(text, line_start).strip()
            controller = f"{match.group(1)}#"
            for method, suffix, action in (
                ("GET", "", "index"),
                ("POST", "", "create"),
                ("GET", ":id", "show"),
                ("PATCH", ":id", "update"),
                ("DELETE", ":id", "destroy"),
            ):
                records.append(
                    _entrypoint(
                        snapshot_id,
                        file,
                        "http_route",
                        "rails",
                        method,
                        _join_routes(base, suffix),
                        f"{controller}{action}",
                        line_start,
                        evidence,
                        0.62,
                        "heuristic:rails_resources",
                    )
                )
    sinatra_pattern = re.compile(
        r"^\s*(get|post|put|patch|delete|options|head)\s+['\"]([^'\"]+)['\"]\s+do\b",
        re.IGNORECASE | re.MULTILINE,
    )
    for match in sinatra_pattern.finditer(text):
        line_start = _line_no(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                "sinatra",
                match.group(1).upper(),
                match.group(2),
                None,
                line_start,
                _line_at(text, line_start).strip(),
                0.72,
                "heuristic:sinatra",
            )
        )
    return records


def _rust_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if file.language != "Rust":
        return []
    records: list[CodeEntrypointRecord] = []
    route_attr_pattern = re.compile(
        r"#\[(get|post|put|delete|patch|options|head)\s*\(\s*['\"]([^'\"]+)['\"](?:[^\]]*)\)\]\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][\w]*)",
        re.IGNORECASE | re.DOTALL,
    )
    for match in route_attr_pattern.finditer(text):
        line_start = _line_no(text, match.start())
        framework = _rust_attribute_framework(text, match.start())
        records.append(
            _entrypoint(
                snapshot_id,
                file,
                "http_route",
                framework,
                match.group(1).upper(),
                match.group(2),
                match.group(3),
                line_start,
                _line_at(text, line_start).strip(),
                0.76,
                f"heuristic:{framework}_attribute",
            )
        )
    axum_route_pattern = re.compile(
        r"\.route\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^)]+)\)",
        re.DOTALL,
    )
    for match in axum_route_pattern.finditer(text):
        route = match.group(1)
        body = match.group(2)
        line_start = _line_no(text, match.start())
        for method, handler in _rust_axum_methods(body):
            records.append(
                _entrypoint(
                    snapshot_id,
                    file,
                    "http_route",
                    "axum",
                    method,
                    route,
                    handler,
                    line_start,
                    _line_at(text, line_start).strip(),
                    0.74,
                    "heuristic:axum_route",
                )
            )
    return records


def _rust_attribute_framework(text: str, offset: int) -> str:
    local_context = text[max(0, offset - 500) : offset].lower()
    full_context = text[: min(len(text), offset + 2000)].lower()
    if "rocket::" in local_context or "#[macro_use] extern crate rocket" in full_context or "use rocket::" in full_context:
        return "rocket"
    if "actix_web" in full_context or "use actix" in full_context:
        return "actix"
    return "actix"


CSHARP_HTTP_METHOD_BY_ATTR = {
    "HTTPGET": "GET",
    "HTTPPOST": "POST",
    "HTTPPUT": "PUT",
    "HTTPDELETE": "DELETE",
    "HTTPPATCH": "PATCH",
    "HTTPOPTIONS": "OPTIONS",
    "HTTPHEAD": "HEAD",
}
CSHARP_ROUTE_ATTR_RE = re.compile(
    r"\[(Route|HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|HttpOptions|HttpHead)\s*(?:\((.*?)\))?\]",
    re.IGNORECASE,
)


def _csharp_route_attributes(line: str, lineno: int) -> list[tuple[int, str | None, str | None, str]]:
    items: list[tuple[int, str | None, str | None, str]] = []
    for match in CSHARP_ROUTE_ATTR_RE.finditer(line):
        attr = match.group(1).upper()
        args = match.group(2) or ""
        items.append((lineno, CSHARP_HTTP_METHOD_BY_ATTR.get(attr), _first_string(args), line.strip()))
    return items


def _csharp_method_name(line: str) -> str | None:
    method_pattern = re.compile(
        r"^(?:public|private|protected|internal|static|virtual|override|async|sealed|new|partial|\s)*"
        r"(?:[A-Za-z_][\w<>\[\],.?]*(?:\s*<[^>]+>)?\s+)+([A-Za-z_][\w]*)\s*\("
    )
    match = method_pattern.search(line)
    if not match:
        return None
    name = match.group(1)
    return None if name in {"if", "for", "while", "switch", "catch"} else name


def _csharp_route_tokens(route: str | None, class_name: str | None, handler: str | None) -> str:
    text = route or ""
    if class_name:
        controller = class_name.removesuffix("Controller")
        text = re.sub(r"\[controller\]", controller, text, flags=re.IGNORECASE)
    if handler:
        text = re.sub(r"\[action\]", handler, text, flags=re.IGNORECASE)
    return text


JAVA_SPRING_METHOD_BY_MAPPING = {
    "GETMAPPING": "GET",
    "POSTMAPPING": "POST",
    "PUTMAPPING": "PUT",
    "DELETEMAPPING": "DELETE",
    "PATCHMAPPING": "PATCH",
}
JAVA_HTTP_METHOD_ANNOTATIONS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
}
JAVA_SPRING_MAPPING_RE = re.compile(
    r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(([^)]*)\))?",
    re.IGNORECASE,
)
JAVA_JAX_METHOD_RE = re.compile(r"@(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b")
JAVA_JAX_PATH_RE = re.compile(r"@Path\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.IGNORECASE)


def _is_java_route_annotation(line: str) -> bool:
    return bool(JAVA_SPRING_MAPPING_RE.search(line) or JAVA_JAX_PATH_RE.search(line) or JAVA_JAX_METHOD_RE.search(line))


def _java_mapping_annotations(line: str, lineno: int) -> list[tuple[int, str, str | None, str | None, str]]:
    items: list[tuple[int, str, str | None, str | None, str]] = []
    for match in JAVA_SPRING_MAPPING_RE.finditer(line):
        mapping = match.group(1).upper()
        args = match.group(2) or ""
        routes = _java_route_strings(args) or [None]
        methods = [JAVA_SPRING_METHOD_BY_MAPPING[mapping]] if mapping in JAVA_SPRING_METHOD_BY_MAPPING else (_request_methods(args) or [None])
        for route in routes:
            for method in methods:
                items.append((lineno, "spring", method, route, line.strip()))
    path_match = JAVA_JAX_PATH_RE.search(line)
    if path_match:
        items.append((lineno, "jaxrs", None, path_match.group(1), line.strip()))
    for match in JAVA_JAX_METHOD_RE.finditer(line):
        method = match.group(1).upper()
        if method in JAVA_HTTP_METHOD_ANNOTATIONS:
            items.append((lineno, "jaxrs", method, None, line.strip()))
    return items


def _java_route_strings(value: str) -> list[str]:
    routes: list[str] = []
    for match in re.finditer(r"\b(?:value|path)\s*=\s*(?:\{([^}]*)\}|['\"]([^'\"]+)['\"])", value):
        if match.group(1):
            routes.extend(re.findall(r"['\"]([^'\"]+)['\"]", match.group(1)))
        elif match.group(2):
            routes.append(match.group(2))
    if routes:
        return routes
    first = _first_string(value)
    return [first] if first else []


def _java_like_method_name(line: str) -> str | None:
    method_pattern = re.compile(
        r"^(?:public|private|protected|static|final|suspend|async|\s)*"
        r"(?:[A-Za-z_<>\[\], ?]+\s+)?([A-Za-z_][\w]*)\s*\([^;{}]*\)"
    )
    match = method_pattern.search(line)
    if not match:
        return None
    name = match.group(1)
    return None if name in {"if", "for", "while", "switch", "catch"} else name


def _go_group_prefixes(text: str) -> dict[str, str]:
    prefixes: dict[str, str] = {}
    pattern = re.compile(r"\b([A-Za-z_][\w]*)\s*:?=\s*([A-Za-z_][\w]*)\.Group\(\s*['\"]([^'\"]+)['\"]")
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        target, parent, route = match.group(1), match.group(2), match.group(3)
        prefixes[target] = _join_routes(prefixes.get(parent), route)
    return prefixes


def _go_router_frameworks(text: str) -> dict[str, str]:
    frameworks: dict[str, str] = {}
    patterns = (
        ("gin", re.compile(r"\b([A-Za-z_][\w]*)\s*:?=\s*gin\.(?:Default|New)\s*\(")),
        ("chi", re.compile(r"\b([A-Za-z_][\w]*)\s*:?=\s*chi\.NewRouter\s*\(")),
        ("fiber", re.compile(r"\b([A-Za-z_][\w]*)\s*:?=\s*fiber\.New\s*\(")),
        ("echo", re.compile(r"\b([A-Za-z_][\w]*)\s*:?=\s*echo\.New\s*\(")),
        ("mux", re.compile(r"\b([A-Za-z_][\w]*)\s*:?=\s*mux\.NewRouter\s*\(")),
    )
    for framework, pattern in patterns:
        for match in pattern.finditer(text):
            frameworks[match.group(1)] = framework
    for child, parent, _route in re.findall(
        r"\b([A-Za-z_][\w]*)\s*:?=\s*([A-Za-z_][\w]*)\.Group\(\s*['\"]([^'\"]+)['\"]",
        text,
    ):
        if parent in frameworks:
            frameworks[child] = frameworks[parent]
    return frameworks


def _go_http_method(value: str) -> str | None:
    text = value.strip()
    string_match = re.search(r"['\"]([A-Za-z]+)['\"]", text)
    if string_match:
        return string_match.group(1).upper()
    const_match = re.search(r"\bMethod([A-Za-z]+)\b", text)
    if const_match:
        return const_match.group(1).upper()
    return None


def _ruby_scope_prefixes(text: str) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    pattern = re.compile(r"^\s*(?:scope|namespace)\s+['\"]?:?([^'\"\s]+)['\"]?\s+do\b", re.MULTILINE)
    for match in pattern.finditer(text):
        end = _ruby_block_end(text, match.end())
        if end is None:
            continue
        prefix = match.group(1).strip(":")
        ranges.append((match.start(), end, prefix))
    return ranges


def _ruby_block_end(text: str, start: int) -> int | None:
    depth = 1
    for match in re.finditer(r"^\s*(do|end)\b", text[start:], re.MULTILINE):
        token = match.group(1)
        if token == "do":
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return start + match.end()
    return None


def _ruby_prefix_at(ranges: list[tuple[int, int, str]], offset: int) -> str | None:
    prefix: str | None = None
    for start, end, value in ranges:
        if start <= offset <= end:
            prefix = _join_routes(prefix, value)
    return prefix


def _rust_axum_methods(body: str) -> list[tuple[str | None, str | None]]:
    items: list[tuple[str | None, str | None]] = []
    for match in re.finditer(
        r"\b(get|post|put|delete|patch|options|head)\s*\(\s*([A-Za-z_][\w:]*)?",
        body,
        re.IGNORECASE,
    ):
        items.append((match.group(1).upper(), match.group(2)))
    return items or [(None, None)]


def _extract_relationships(
    snapshot_id: str,
    readable: list[tuple[CodeFile, str]],
    symbols: list[CodeSymbolRecord],
    entrypoints: list[CodeEntrypointRecord],
) -> list[CodeRelationshipRecord]:
    relationships: list[CodeRelationshipRecord] = []
    paths = {file.path for file, _ in readable}
    module_map = _module_path_map(paths)
    symbols_by_name: dict[str, list[CodeSymbolRecord]] = {}
    for symbol in symbols:
        if len(symbol.name) < 3 or symbol.name.lower() in SYMBOL_RESERVED_NAMES:
            continue
        symbols_by_name.setdefault(symbol.name, []).append(symbol)
    unique_symbols = {
        name: items[0]
        for name, items in symbols_by_name.items()
        if len({item.path for item in items}) == 1
    }
    symbols_by_path: dict[str, list[CodeSymbolRecord]] = {}
    for symbol in symbols:
        symbols_by_path.setdefault(symbol.path, []).append(symbol)
    entrypoints_by_path: dict[str, list[CodeEntrypointRecord]] = {}
    for entrypoint in entrypoints:
        entrypoints_by_path.setdefault(entrypoint.path, []).append(entrypoint)
    data_objects_by_path: dict[str, list[CodeSymbolRecord]] = {}
    for symbol in symbols:
        if symbol.kind == "data_object":
            data_objects_by_path.setdefault(symbol.path, []).append(symbol)
    data_objects_by_name: dict[str, list[CodeSymbolRecord]] = {}
    for symbol in symbols:
        if symbol.kind == "data_object" and len(symbol.name) >= 3:
            data_objects_by_name.setdefault(symbol.name, []).append(symbol)
    unique_data_objects = {
        name: items[0]
        for name, items in data_objects_by_name.items()
        if len({item.path for item in items}) == 1
    }

    for file, text in readable:
        relationships.extend(
            _entrypoint_handler_relationships(
                snapshot_id,
                file,
                text,
                entrypoints_by_path.get(file.path, []),
                paths,
                module_map,
                symbols_by_name,
                symbols_by_path,
            )
        )
        relationships.extend(_import_relationships(snapshot_id, file, text, paths, module_map, unique_symbols))
        relationships.extend(_call_relationships(snapshot_id, file, text, unique_symbols))
        relationships.extend(_data_object_reference_relationships(snapshot_id, file, text, unique_data_objects))
        relationships.extend(
            _scoped_call_relationships(
                snapshot_id,
                file,
                text,
                paths,
                module_map,
                symbols_by_path,
            )
        )
        relationships.extend(
            _object_method_call_relationships(
                snapshot_id,
                file,
                text,
                paths,
                module_map,
                symbols_by_name,
                symbols_by_path,
            )
        )
        relationships.extend(
            _inheritance_relationships(
                snapshot_id,
                file,
                text,
                paths,
                module_map,
                symbols_by_name,
                symbols_by_path,
            )
        )
        relationships.extend(_data_object_use_relationships(snapshot_id, file, data_objects_by_path.get(file.path, [])))
    return relationships


def _entrypoint_handler_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    entrypoints: list[CodeEntrypointRecord],
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> list[CodeRelationshipRecord]:
    relationships: list[CodeRelationshipRecord] = []
    import_aliases = _python_import_aliases(file.path, text, paths, module_map) if file.language == "Python" else {}
    symbol_aliases = _import_symbol_aliases(file, text, paths, module_map, symbols_by_path)
    for entrypoint in entrypoints:
        if not entrypoint.handler:
            continue
        handler_text = entrypoint.handler.strip()
        if handler_text == PurePosixPath(entrypoint.path).name:
            continue
        handler = handler_text.split(".")[-1].strip()
        if not handler:
            continue
        resolved = _resolve_python_handler_target(
            entrypoint.path,
            handler_text,
            import_aliases,
            paths,
            module_map,
            symbols_by_name,
        )
        if resolved is not None:
            target_path, target_symbol = resolved
            relationships.append(
                _relationship(
                    snapshot_id,
                    from_path=entrypoint.path,
                    from_symbol=_entrypoint_label(entrypoint.method, entrypoint.route),
                    to_path=target_path,
                    to_symbol=target_symbol,
                    relation="calls",
                    evidence=entrypoint.evidence,
                    confidence=min(0.9, max(0.58, entrypoint.confidence)),
                    source="heuristic:django_handler",
                    line_start=entrypoint.line_start,
                )
            )
            continue
        resolved = _resolve_framework_handler_target(handler_text, symbol_aliases, symbols_by_name)
        if resolved is not None:
            target_path, target_symbol = resolved
            relationships.append(
                _relationship(
                    snapshot_id,
                    from_path=entrypoint.path,
                    from_symbol=_entrypoint_label(entrypoint.method, entrypoint.route),
                    to_path=target_path,
                    to_symbol=target_symbol,
                    relation="calls",
                    evidence=entrypoint.evidence,
                    confidence=min(0.86, max(0.52, entrypoint.confidence)),
                    source="heuristic:framework_handler",
                    line_start=entrypoint.line_start,
                )
            )
            continue
        relationships.append(
            _relationship(
                snapshot_id,
                from_path=entrypoint.path,
                from_symbol=_entrypoint_label(entrypoint.method, entrypoint.route),
                to_path=entrypoint.path,
                to_symbol=handler,
                relation="calls",
                evidence=entrypoint.evidence,
                confidence=min(0.88, max(0.5, entrypoint.confidence)),
                source="heuristic:entrypoint_handler",
                line_start=entrypoint.line_start,
            )
        )
    return relationships


def _python_import_aliases(
    current_path: str,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    from_pattern = re.compile(
        r"^\s*from\s+([.\w]+)\s+import\s+([A-Za-z_][\w]*(?:\s+as\s+[A-Za-z_][\w]*)?(?:\s*,\s*[A-Za-z_][\w]*(?:\s+as\s+[A-Za-z_][\w]*)?)*)",
        re.MULTILINE,
    )
    for match in from_pattern.finditer(text):
        module = match.group(1)
        imported_items = _python_import_items(match.group(2))
        module_path = _resolve_module_import(current_path, module, paths, module_map)
        for imported_name, alias in imported_items:
            target = None
            if module_path:
                target = _resolve_imported_child(module_path, imported_name, paths) or module_path
            if target is None:
                target = _resolve_module_import(current_path, f"{module}.{imported_name}", paths, module_map)
            if target:
                aliases[alias or imported_name] = target
    import_pattern = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)((?:\s+as\s+)([A-Za-z_][\w]*))?", re.MULTILINE)
    for match in import_pattern.finditer(text):
        module = match.group(1)
        target = _resolve_module_import(current_path, module, paths, module_map)
        if not target:
            continue
        alias = match.group(3) or module.split(".")[-1]
        aliases[alias] = target
    return aliases


def _python_import_items(value: str) -> list[tuple[str, str | None]]:
    items: list[tuple[str, str | None]] = []
    for part in value.split(","):
        text = part.strip()
        if not text:
            continue
        match = re.fullmatch(r"([A-Za-z_][\w]*)(?:\s+as\s+([A-Za-z_][\w]*))?", text)
        if match:
            items.append((match.group(1), match.group(2)))
    return items


def _resolve_imported_child(module_path: str, imported_name: str, paths: set[str]) -> str | None:
    pure_path = PurePosixPath(module_path)
    if pure_path.name == "__init__.py":
        base = pure_path.parent / imported_name
        return _resolve_path_candidates(base.as_posix(), paths)
    if pure_path.suffix == ".py":
        sibling = pure_path.parent / imported_name
        return _resolve_path_candidates(sibling.as_posix(), paths)
    return None


def _resolve_python_handler_target(
    current_path: str,
    handler_text: str,
    import_aliases: dict[str, str],
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
) -> tuple[str, str] | None:
    target = _python_handler_reference(handler_text)
    if not target:
        return None
    parts = [part for part in target.split(".") if part]
    if not parts:
        return None
    symbol_name = parts[-1]
    if symbol_name in {"as_view", "view"} and len(parts) >= 2:
        symbol_name = parts[-2]
    scope_path = None
    if len(parts) >= 2:
        alias = parts[0]
        scope_path = import_aliases.get(alias)
        if scope_path is None:
            scope_path = _resolve_module_import(current_path, ".".join(parts[:-1]), paths, module_map)
    return _find_symbol_target(symbol_name, scope_path, symbols_by_name)


def _resolve_framework_handler_target(
    handler_text: str,
    symbol_aliases: dict[str, tuple[str, str | None, str | None]],
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
) -> tuple[str, str] | None:
    text = handler_text.strip().strip("[]")
    if not text:
        return None
    class_method = re.search(
        r"([A-Za-z_$][\w$]*(?:\\[A-Za-z_$][\w$]*)*)\s*@\s*([A-Za-z_$][\w$]*)",
        text,
    )
    if class_method:
        class_name = class_method.group(1).rsplit("\\", 1)[-1]
        method_name = class_method.group(2)
        alias_target = symbol_aliases.get(class_name)
        scope_path = alias_target[0] if alias_target else None
        method_target = _find_symbol_target(method_name, scope_path, symbols_by_name)
        if method_target is not None:
            return method_target
        class_target = _find_symbol_target(class_name, scope_path, symbols_by_name)
        if class_target is not None:
            return class_target

    dotted = re.search(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)$", text)
    if dotted:
        parts = dotted.group(1).split(".")
        alias_target = symbol_aliases.get(parts[0])
        if alias_target is not None:
            target = _find_symbol_target(parts[-1], alias_target[0], symbols_by_name)
            if target is not None:
                return target
            return alias_target[0], alias_target[1] or parts[-1]

    simple = re.search(r"([A-Za-z_$][\w$]*)$", text)
    if simple:
        name = simple.group(1)
        alias_target = symbol_aliases.get(name)
        if alias_target is not None:
            return alias_target[0], alias_target[1] or name
        return _find_symbol_target(name, None, symbols_by_name)
    return None


def _python_handler_reference(handler_text: str) -> str | None:
    text = handler_text.strip()
    if not text:
        return None
    text = text.split("#", 1)[0].strip()
    as_view = re.search(r"\.as_view\s*\(", text)
    if as_view:
        text = text[: as_view.start()]
    else:
        call = text.find("(")
        if call >= 0:
            text = text[:call]
    text = text.strip().strip("'\"")
    match = re.search(r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)$", text)
    return match.group(1) if match else None


def _find_symbol_target(
    symbol_name: str,
    scope_path: str | None,
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
) -> tuple[str, str] | None:
    candidates = symbols_by_name.get(symbol_name) or []
    if not candidates:
        return None
    if scope_path:
        scoped = [symbol for symbol in candidates if symbol.path == scope_path]
        if len(scoped) == 1:
            return scoped[0].path, scoped[0].name
        scope = PurePosixPath(scope_path)
        if scope.name == "__init__.py":
            prefix = scope.parent.as_posix().rstrip("/") + "/"
            scoped = [symbol for symbol in candidates if symbol.path.startswith(prefix)]
            if len({symbol.path for symbol in scoped}) == 1:
                symbol = scoped[0]
                return symbol.path, symbol.name
        parent_prefix = scope.parent.as_posix().rstrip("/") + "/"
        scoped = [symbol for symbol in candidates if symbol.path.startswith(parent_prefix)]
        if len({symbol.path for symbol in scoped}) == 1:
            symbol = scoped[0]
            return symbol.path, symbol.name
        return None
    if len({symbol.path for symbol in candidates}) == 1:
        symbol = candidates[0]
        return symbol.path, symbol.name
    return None


def _import_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
    unique_symbols: dict[str, CodeSymbolRecord],
) -> list[CodeRelationshipRecord]:
    relationships: list[CodeRelationshipRecord] = []
    if file.language == "Python":
        pattern = re.compile(r"^\s*from\s+([.\w]+)\s+import\s+([A-Za-z_][\w]*(?:\s*,\s*[A-Za-z_][\w]*)*)", re.MULTILINE)
        for match in pattern.finditer(text):
            target = _resolve_module_import(file.path, match.group(1), paths, module_map)
            imported_names = [item.strip() for item in match.group(2).split(",")]
            if target is None:
                target_symbol = next((unique_symbols[name] for name in imported_names if name in unique_symbols), None)
                target = target_symbol.path if target_symbol is not None else None
            if target:
                relationships.append(_import_relationship(snapshot_id, file, text, match.start(), target, match.group(0).strip(), 0.72, "heuristic:python_import"))
        pattern = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)(?:\s+as\s+[A-Za-z_][\w]*)?", re.MULTILINE)
        for match in pattern.finditer(text):
            target = _resolve_module_import(file.path, match.group(1), paths, module_map)
            if target:
                relationships.append(_import_relationship(snapshot_id, file, text, match.start(), target, match.group(0).strip(), 0.68, "heuristic:python_import"))
    if file.language in {"JavaScript", "TypeScript", "Vue"}:
        pattern = re.compile(r"\b(?:import\s+(?:[^'\"]+\s+from\s+)?|require\()\s*['\"]([^'\"]+)['\"]", re.MULTILINE)
        for match in pattern.finditer(text):
            target = _resolve_relative_path(file.path, match.group(1), paths)
            if target:
                relationships.append(_import_relationship(snapshot_id, file, text, match.start(), target, _line_at(text, _line_no(text, match.start())).strip(), 0.74, "heuristic:js_import"))
    if file.language == "PHP":
        pattern = re.compile(r"\b(?:require|include)(?:_once)?\s*\(?\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
        for match in pattern.finditer(text):
            target = _resolve_relative_path(file.path, match.group(1), paths)
            if target:
                relationships.append(_import_relationship(snapshot_id, file, text, match.start(), target, _line_at(text, _line_no(text, match.start())).strip(), 0.76, "heuristic:php_include"))
    if file.language in {"Java", "Kotlin", "Scala"}:
        pattern = re.compile(r"^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*);", re.MULTILINE)
        for match in pattern.finditer(text):
            name = match.group(1).split(".")[-1]
            target_symbol = unique_symbols.get(name)
            if target_symbol and target_symbol.path != file.path:
                relationships.append(
                    _relationship(
                        snapshot_id,
                        from_path=file.path,
                        from_symbol=None,
                        to_path=target_symbol.path,
                        to_symbol=target_symbol.name,
                        relation="imports",
                        evidence=match.group(0).strip(),
                        confidence=0.68,
                        source="heuristic:java_import",
                        line_start=_line_no(text, match.start()),
                    )
                )
    return relationships


def _call_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    unique_symbols: dict[str, CodeSymbolRecord],
) -> list[CodeRelationshipRecord]:
    relationships: list[CodeRelationshipRecord] = []
    if file.language not in CALL_RELATIONSHIP_LANGUAGES or _is_generated_relationship_path(file.path):
        return relationships
    per_file_count = 0
    seen_names: set[str] = set()
    for match in CALL_TOKEN_RE.finditer(text):
        if per_file_count >= 80:
            break
        if len(seen_names) >= MAX_CALL_TOKENS_PER_FILE:
            break
        name = match.group(1)
        if name in seen_names:
            continue
        seen_names.add(name)
        target = unique_symbols.get(name)
        if target is None:
            continue
        if target.path == file.path or target.kind == "data_object":
            continue
        if _is_generated_relationship_path(target.path):
            continue
        line_start = _line_no(text, match.start())
        line = _line_at(text, line_start).strip()
        if _looks_like_symbol_declaration(line, name):
            continue
        relationships.append(
            _relationship(
                snapshot_id,
                from_path=file.path,
                from_symbol=None,
                to_path=target.path,
                to_symbol=target.name,
                relation="calls",
                evidence=line,
                confidence=0.58,
                source="heuristic:unique_symbol_call",
                line_start=line_start,
            )
        )
        per_file_count += 1
    return relationships


def _data_object_reference_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    unique_data_objects: dict[str, CodeSymbolRecord],
) -> list[CodeRelationshipRecord]:
    if file.language not in CALL_RELATIONSHIP_LANGUAGES or _is_generated_relationship_path(file.path):
        return []
    relationships: list[CodeRelationshipRecord] = []
    emitted = 0
    for name, target in sorted(unique_data_objects.items()):
        if emitted >= 60:
            break
        if target.path == file.path or name.lower() in SYMBOL_RESERVED_NAMES:
            continue
        pattern = re.compile(rf"\b{re.escape(name)}\b")
        for match in pattern.finditer(text):
            line_start = _line_no(text, match.start())
            line = _line_at(text, line_start).strip()
            if not line or _looks_like_language_import_line(line):
                continue
            if _looks_like_symbol_declaration(line, name):
                continue
            relationships.append(
                _relationship(
                    snapshot_id,
                    from_path=file.path,
                    from_symbol=None,
                    to_path=target.path,
                    to_symbol=target.name,
                    relation="uses",
                    evidence=line,
                    confidence=0.62,
                    source="heuristic:data_object_reference",
                    line_start=line_start,
                )
            )
            emitted += 1
            break
    return relationships


def _scoped_call_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> list[CodeRelationshipRecord]:
    if file.language not in CALL_RELATIONSHIP_LANGUAGES or _is_generated_relationship_path(file.path):
        return []
    aliases = _import_symbol_aliases(file, text, paths, module_map, symbols_by_path)
    if not aliases:
        return []
    relationships: list[CodeRelationshipRecord] = []
    emitted = 0
    direct_call_pattern = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
    member_call_pattern = re.compile(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if emitted >= 80:
            break
        stripped = line.strip()
        if not stripped or _looks_like_import_or_declaration(stripped):
            continue
        for match in member_call_pattern.finditer(stripped):
            if emitted >= 80:
                break
            alias, member = match.group(1), match.group(2)
            target = aliases.get(alias)
            if target is None:
                continue
            target_path, target_symbol, container = target
            resolved = _member_target_in_path(target_path, member, symbols_by_path, container=container)
            if resolved is None:
                resolved = (target_path, target_symbol or member)
            if resolved[0] == file.path:
                continue
            relationships.append(
                _relationship(
                    snapshot_id,
                    from_path=file.path,
                    from_symbol=None,
                    to_path=resolved[0],
                    to_symbol=resolved[1],
                    relation="calls",
                    evidence=stripped,
                    confidence=0.72,
                    source="heuristic:scoped_member_call",
                    line_start=lineno,
                )
            )
            emitted += 1
        for match in direct_call_pattern.finditer(stripped):
            if emitted >= 80:
                break
            alias = match.group(1)
            if alias in SYMBOL_RESERVED_NAMES:
                continue
            target = aliases.get(alias)
            if target is None:
                continue
            target_path, target_symbol, _container = target
            if target_path == file.path:
                continue
            relationships.append(
                _relationship(
                    snapshot_id,
                    from_path=file.path,
                    from_symbol=None,
                    to_path=target_path,
                    to_symbol=target_symbol or alias,
                    relation="calls",
                    evidence=stripped,
                    confidence=0.74,
                    source="heuristic:scoped_symbol_call",
                    line_start=lineno,
                )
            )
            emitted += 1
    return relationships


def _object_method_call_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> list[CodeRelationshipRecord]:
    if file.language not in CALL_RELATIONSHIP_LANGUAGES or _is_generated_relationship_path(file.path):
        return []
    variables = _object_variable_types(text)
    if not variables:
        return []
    aliases = _import_symbol_aliases(file, text, paths, module_map, symbols_by_path)
    relationships: list[CodeRelationshipRecord] = []
    emitted = 0
    method_call_pattern = re.compile(r"\b([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*\(")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if emitted >= 80:
            break
        stripped = line.strip()
        if not stripped or _looks_like_import_or_declaration(stripped):
            continue
        for match in method_call_pattern.finditer(stripped):
            variable, method_name = match.group(1), match.group(2)
            class_name = variables.get(variable)
            if not class_name:
                continue
            alias_target = aliases.get(class_name)
            if alias_target is not None:
                target_path, target_symbol, _container = alias_target
                target_class = (target_path, target_symbol or class_name)
            else:
                target_class = _find_symbol_target(class_name, None, symbols_by_name)
            if target_class is None or target_class[0] == file.path:
                continue
            target_path, target_symbol = target_class
            resolved = _member_target_in_path(target_path, method_name, symbols_by_path, container=target_symbol)
            if resolved is None:
                resolved = _member_target_in_path(target_path, method_name, symbols_by_path)
            if resolved is None:
                resolved = (target_path, target_symbol)
            relationships.append(
                _relationship(
                    snapshot_id,
                    from_path=file.path,
                    from_symbol=None,
                    to_path=resolved[0],
                    to_symbol=resolved[1],
                    relation="calls",
                    evidence=stripped,
                    confidence=0.7,
                    source="heuristic:object_method_call",
                    line_start=lineno,
                )
            )
            emitted += 1
            if emitted >= 80:
                break
    return relationships


def _import_symbol_aliases(
    file: CodeFile,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> dict[str, tuple[str, str | None, str | None]]:
    if file.language == "Python":
        return _python_import_symbol_aliases(file.path, text, paths, module_map, symbols_by_path)
    if file.language in {"JavaScript", "TypeScript", "Vue"}:
        return _js_import_symbol_aliases(file.path, text, paths, symbols_by_path)
    if file.language == "PHP":
        return _php_import_symbol_aliases(file.path, text, symbols_by_path)
    if file.language in {"Java", "Kotlin", "Scala", "C#"}:
        return _typed_import_symbol_aliases(file.path, text, symbols_by_path)
    return {}


def _python_import_symbol_aliases(
    current_path: str,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> dict[str, tuple[str, str | None, str | None]]:
    aliases: dict[str, tuple[str, str | None, str | None]] = {}
    from_pattern = re.compile(
        r"^\s*from\s+([.\w]+)\s+import\s+([A-Za-z_][\w]*(?:\s+as\s+[A-Za-z_][\w]*)?(?:\s*,\s*[A-Za-z_][\w]*(?:\s+as\s+[A-Za-z_][\w]*)?)*)",
        re.MULTILINE,
    )
    for match in from_pattern.finditer(text):
        module = match.group(1)
        module_path = _resolve_module_import(current_path, module, paths, module_map)
        for imported_name, alias in _python_import_items(match.group(2)):
            target_path = None
            if module_path:
                target_path = _resolve_imported_child(module_path, imported_name, paths) or module_path
            if target_path is None:
                target_path = _resolve_module_import(current_path, f"{module}.{imported_name}", paths, module_map)
            if target_path is None:
                continue
            target_symbol = _symbol_name_in_path(imported_name, target_path, symbols_by_path)
            aliases[alias or imported_name] = (target_path, target_symbol or imported_name, target_symbol or imported_name)
    import_pattern = re.compile(r"^\s*import\s+([A-Za-z_][\w.]*)((?:\s+as\s+)([A-Za-z_][\w]*))?", re.MULTILINE)
    for match in import_pattern.finditer(text):
        module = match.group(1)
        target_path = _resolve_module_import(current_path, module, paths, module_map)
        if not target_path:
            continue
        alias = match.group(3) or module.split(".")[-1]
        aliases[alias] = (target_path, None, None)
    return aliases


def _js_import_symbol_aliases(
    current_path: str,
    text: str,
    paths: set[str],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> dict[str, tuple[str, str | None, str | None]]:
    aliases: dict[str, tuple[str, str | None, str | None]] = {}
    named_import = re.compile(r"\bimport\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]")
    for match in named_import.finditer(text):
        target_path = _resolve_relative_path(current_path, match.group(2), paths)
        if not target_path:
            continue
        for imported_name, alias in _js_import_items(match.group(1)):
            symbol = _symbol_name_in_path(imported_name, target_path, symbols_by_path) or imported_name
            aliases[alias or imported_name] = (target_path, symbol, symbol)
    default_import = re.compile(r"\bimport\s+([A-Za-z_$][\w$]*)\s+from\s+['\"]([^'\"]+)['\"]")
    for match in default_import.finditer(text):
        target_path = _resolve_relative_path(current_path, match.group(2), paths)
        if not target_path:
            continue
        alias = match.group(1)
        symbol = _symbol_name_in_path(alias, target_path, symbols_by_path)
        aliases[alias] = (target_path, symbol or alias, symbol or alias)
    namespace_import = re.compile(r"\bimport\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"]([^'\"]+)['\"]")
    for match in namespace_import.finditer(text):
        target_path = _resolve_relative_path(current_path, match.group(2), paths)
        if target_path:
            aliases[match.group(1)] = (target_path, None, None)
    require_object = re.compile(r"\b(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
    for match in require_object.finditer(text):
        target_path = _resolve_relative_path(current_path, match.group(2), paths)
        if not target_path:
            continue
        for imported_name, alias in _js_import_items(match.group(1)):
            symbol = _symbol_name_in_path(imported_name, target_path, symbols_by_path) or imported_name
            aliases[alias or imported_name] = (target_path, symbol, symbol)
    require_module = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)")
    for match in require_module.finditer(text):
        target_path = _resolve_relative_path(current_path, match.group(2), paths)
        if target_path:
            aliases[match.group(1)] = (target_path, None, None)
    return aliases


def _js_import_items(value: str) -> list[tuple[str, str | None]]:
    items: list[tuple[str, str | None]] = []
    for part in value.split(","):
        text = part.strip()
        if not text:
            continue
        text = text.replace(":", " as ")
        match = re.fullmatch(r"([A-Za-z_$][\w$]*)(?:\s+as\s+([A-Za-z_$][\w$]*))?", text)
        if match:
            items.append((match.group(1), match.group(2)))
    return items


def _php_import_symbol_aliases(
    current_path: str,
    text: str,
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> dict[str, tuple[str, str | None, str | None]]:
    aliases: dict[str, tuple[str, str | None, str | None]] = {}
    for match in re.finditer(
        r"^\s*use\s+([A-Za-z_][\w\\]*)(?:\s+as\s+([A-Za-z_][\w]*))?\s*;",
        text,
        re.MULTILINE,
    ):
        class_name = match.group(1).rsplit("\\", 1)[-1]
        alias = match.group(2) or class_name
        for path, symbols in symbols_by_path.items():
            if path == current_path:
                continue
            symbol = next((item for item in symbols if item.name == class_name), None)
            if symbol:
                aliases[alias] = (symbol.path, symbol.name, symbol.name)
                break
    return aliases


def _typed_import_symbol_aliases(
    current_path: str,
    text: str,
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> dict[str, tuple[str, str | None, str | None]]:
    aliases: dict[str, tuple[str, str | None, str | None]] = {}
    for match in re.finditer(r"^\s*(?:import|using)\s+(?:static\s+)?([A-Za-z_][\w.]*);?", text, re.MULTILINE):
        name = match.group(1).split(".")[-1]
        for path, symbols in symbols_by_path.items():
            if path == current_path:
                continue
            symbol = next((item for item in symbols if item.name == name), None)
            if symbol:
                aliases[name] = (symbol.path, symbol.name, symbol.name)
                break
    return aliases


def _object_variable_types(text: str) -> dict[str, str]:
    variables: dict[str, str] = {}
    patterns = (
        re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?([A-Z][A-Za-z0-9_]*)\s*\("),
        re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:new\s+)?([A-Z][A-Za-z0-9_]*)\s*\("),
        re.compile(r"\b(?:private|protected|public|final|readonly|static|\s)*([A-Z][A-Za-z0-9_]*)\s+([a-z_][A-Za-z0-9_]*)\s*(?:[;=]|$)"),
        re.compile(r"\b(?:private|protected|public|readonly|\s)*([a-z_][A-Za-z0-9_]*)\s*:\s*([A-Z][A-Za-z0-9_]*)"),
        re.compile(r"\b([a-z_][A-Za-z0-9_]*)\s*:=\s*&?([A-Z][A-Za-z0-9_]*)\s*(?:\{|\()"),
    )
    for pattern in patterns:
        for match in pattern.finditer(text):
            first, second = match.group(1), match.group(2)
            if first[:1].isupper() and not second[:1].isupper():
                class_name, variable = first, second
            else:
                variable, class_name = first, second
            if variable and class_name and variable not in SYMBOL_RESERVED_NAMES:
                variables.setdefault(variable, class_name)
    return variables


def _member_target_in_path(
    target_path: str,
    member: str,
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
    *,
    container: str | None = None,
) -> tuple[str, str] | None:
    symbols = symbols_by_path.get(target_path, [])
    if container:
        scoped = [
            symbol
            for symbol in symbols
            if symbol.name == member
            and (symbol.container == container or (symbol.container or "").endswith(f".{container}"))
        ]
        if scoped:
            return target_path, scoped[0].name
    candidates = [
        symbol
        for symbol in symbols
        if symbol.name == member and symbol.kind in {"function", "method", "class", "interface"}
    ]
    if candidates:
        return target_path, candidates[0].name
    return None


def _symbol_name_in_path(
    name: str,
    target_path: str,
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> str | None:
    for symbol in symbols_by_path.get(target_path, []):
        if symbol.name == name and symbol.kind != "data_object":
            return symbol.name
    return None


def _looks_like_import_or_declaration(line: str) -> bool:
    if _looks_like_language_import_line(line):
        return True
    return bool(
        re.match(r"^(?:class|interface|trait|enum|record|struct|func|function|def)\b", line)
        or re.match(r"^package\s+", line)
    )


def _inheritance_relationships(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    paths: set[str],
    module_map: dict[str, str],
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
    symbols_by_path: dict[str, list[CodeSymbolRecord]],
) -> list[CodeRelationshipRecord]:
    if file.language not in {"Python", "JavaScript", "TypeScript", "Vue", "PHP", "Java", "Kotlin", "Scala", "C#"}:
        return []
    aliases = _import_symbol_aliases(file, text, paths, module_map, symbols_by_path)
    relationships: list[CodeRelationshipRecord] = []
    for item in _declared_type_edges(file.language, text):
        class_name, relation, target_name, line_start, evidence = item
        target = _resolve_type_target(target_name, aliases, symbols_by_name)
        if target is None or target[0] == file.path:
            continue
        target_path, target_symbol = target
        relationships.append(
            _relationship(
                snapshot_id,
                from_path=file.path,
                from_symbol=class_name,
                to_path=target_path,
                to_symbol=target_symbol,
                relation=relation,
                evidence=evidence,
                confidence=0.7,
                source="heuristic:type_hierarchy",
                line_start=line_start,
            )
        )
        reverse_relation = "implemented_by" if relation == "implements" else "extended_by"
        relationships.append(
            _relationship(
                snapshot_id,
                from_path=target_path,
                from_symbol=target_symbol,
                to_path=file.path,
                to_symbol=class_name,
                relation=reverse_relation,
                evidence=evidence,
                confidence=0.68,
                source="heuristic:type_hierarchy_reverse",
                line_start=line_start,
            )
        )
    return relationships


def _declared_type_edges(language: str | None, text: str) -> list[tuple[str, str, str, int, str]]:
    edges: list[tuple[str, str, str, int, str]] = []
    if language == "Python":
        pattern = re.compile(r"^\s*class\s+([A-Za-z_][\w]*)\s*\(([^)]*)\)\s*:", re.MULTILINE)
        for match in pattern.finditer(text):
            class_name = match.group(1)
            evidence = match.group(0).strip()
            for target_name in _type_names_from_list(match.group(2)):
                edges.append((class_name, "extends", target_name, _line_no(text, match.start()), evidence))
        return edges

    if language in {"JavaScript", "TypeScript", "Vue", "PHP", "Java", "Kotlin", "Scala"}:
        pattern = re.compile(
            r"^\s*(?:export\s+)?(?:abstract\s+|final\s+|public\s+|private\s+|protected\s+|sealed\s+|open\s+|data\s+)*"
            r"(?:class|record)\s+([A-Za-z_][\w]*)"
            r"(?:\s+extends\s+([A-Za-z_][\w.$\\<>]*))?"
            r"(?:\s+implements\s+([A-Za-z_][\w.$\\<>,\s]*))?",
            re.MULTILINE,
        )
        for match in pattern.finditer(text):
            class_name = match.group(1)
            evidence = match.group(0).strip()
            if match.group(2):
                edges.append((class_name, "extends", _simple_type_name(match.group(2)), _line_no(text, match.start()), evidence))
            for target_name in _type_names_from_list(match.group(3) or ""):
                edges.append((class_name, "implements", target_name, _line_no(text, match.start()), evidence))
        return edges

    if language == "C#":
        pattern = re.compile(
            r"^\s*(?:public|private|protected|internal|sealed|abstract|partial|\s)*"
            r"(?:class|record)\s+([A-Za-z_][\w]*)\s*:\s*([A-Za-z_][\w.<>,\s]*)",
            re.MULTILINE,
        )
        for match in pattern.finditer(text):
            class_name = match.group(1)
            evidence = match.group(0).strip()
            for target_name in _type_names_from_list(match.group(2)):
                relation = "implements" if target_name.startswith("I") and len(target_name) > 1 and target_name[1:2].isupper() else "extends"
                edges.append((class_name, relation, target_name, _line_no(text, match.start()), evidence))
        return edges

    return edges


def _resolve_type_target(
    target_name: str,
    aliases: dict[str, tuple[str, str | None, str | None]],
    symbols_by_name: dict[str, list[CodeSymbolRecord]],
) -> tuple[str, str] | None:
    clean_name = _simple_type_name(target_name)
    if not clean_name:
        return None
    alias_target = aliases.get(clean_name)
    if alias_target is not None:
        return alias_target[0], alias_target[1] or clean_name
    return _find_symbol_target(clean_name, None, symbols_by_name)


def _type_names_from_list(value: str) -> list[str]:
    names: list[str] = []
    for item in value.split(","):
        name = _simple_type_name(item)
        if name and name not in names and name not in {"object", "Object", "BaseModel"}:
            names.append(name)
    return names


def _simple_type_name(value: str) -> str:
    text = value.strip()
    if not text:
        return ""
    text = re.sub(r"<[^<>]*>", "", text)
    text = text.strip().strip("&*?")
    text = text.split()[0] if text.split() else text
    text = text.rsplit("\\", 1)[-1].rsplit(".", 1)[-1]
    return re.sub(r"[^A-Za-z0-9_$]", "", text)


def _is_generated_relationship_path(path: str) -> bool:
    pure_path = PurePosixPath(path)
    suffix = pure_path.suffix.lower()
    if suffix in {".map", ".min.js", ".min.css"}:
        return True
    if any(part.lower() in GENERATED_RELATIONSHIP_PARTS for part in pure_path.parts):
        return True
    name = pure_path.name.lower()
    if ".min." in name or name.endswith(".bundle.js"):
        return True
    stem = pure_path.stem.lower()
    return any(stem == item or stem.startswith(f"{item}.") or stem.startswith(f"{item}-") for item in GENERATED_RELATIONSHIP_STEMS)


def _data_object_use_relationships(
    snapshot_id: str,
    file: CodeFile,
    data_objects: list[CodeSymbolRecord],
) -> list[CodeRelationshipRecord]:
    relationships: list[CodeRelationshipRecord] = []
    for symbol in data_objects:
        relationships.append(
            _relationship(
                snapshot_id,
                from_path=file.path,
                from_symbol=None,
                to_path=symbol.path,
                to_symbol=symbol.name,
                relation="uses",
                evidence=symbol.signature,
                confidence=min(0.82, max(0.5, symbol.confidence)),
                source=symbol.source,
                line_start=symbol.line_start,
            )
        )
    return relationships


def _relationship(
    snapshot_id: str,
    *,
    from_path: str,
    from_symbol: str | None,
    to_path: str,
    to_symbol: str | None,
    relation: str,
    evidence: str | None,
    confidence: float,
    source: str,
    line_start: int | None,
) -> CodeRelationshipRecord:
    return CodeRelationshipRecord(
        id=_id("rel", snapshot_id, from_path, from_symbol, relation, to_path, to_symbol, line_start),
        snapshot_id=snapshot_id,
        from_path=from_path,
        from_symbol=from_symbol,
        to_path=to_path,
        to_symbol=to_symbol,
        relation=relation,
        evidence=evidence[:240] if isinstance(evidence, str) else None,
        confidence=confidence,
        source=source,
        line_start=line_start,
    )


def _import_relationship(
    snapshot_id: str,
    file: CodeFile,
    text: str,
    offset: int,
    target: str,
    evidence: str,
    confidence: float,
    source: str,
) -> CodeRelationshipRecord:
    return _relationship(
        snapshot_id,
        from_path=file.path,
        from_symbol=None,
        to_path=target,
        to_symbol=None,
        relation="imports",
        evidence=evidence,
        confidence=confidence,
        source=source,
        line_start=_line_no(text, offset),
    )


def _module_path_map(paths: set[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(paths):
        pure_path = PurePosixPath(path)
        suffix = pure_path.suffix.lower()
        if suffix not in {".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".java", ".kt", ".scala"}:
            continue
        stem_path = pure_path.with_suffix("").as_posix()
        module = stem_path.replace("/", ".")
        if module.endswith(".__init__"):
            module = module[: -len(".__init__")]
        result.setdefault(module, path)
        result.setdefault(pure_path.stem, path)
    return result


def _resolve_module_import(
    current_path: str,
    module: str,
    paths: set[str],
    module_map: dict[str, str],
) -> str | None:
    if module.startswith("."):
        dots = len(module) - len(module.lstrip("."))
        rest = module[dots:].replace(".", "/")
        base = PurePosixPath(current_path).parent
        for _ in range(max(0, dots - 1)):
            base = base.parent
        return _resolve_path_candidates((base / rest).as_posix(), paths)
    if module in module_map:
        return module_map[module]
    suffix = f".{module}"
    matches = [path for name, path in module_map.items() if name.endswith(suffix)]
    return matches[0] if len(set(matches)) == 1 else None


def _resolve_relative_path(current_path: str, target: str, paths: set[str]) -> str | None:
    if not target.startswith("."):
        return None
    base = (PurePosixPath(current_path).parent / target).as_posix()
    return _resolve_path_candidates(base, paths)


def _resolve_path_candidates(base: str, paths: set[str]) -> str | None:
    normalized = posixpath.normpath(PurePosixPath(base).as_posix())
    candidates = [normalized]
    candidates.extend(f"{normalized}{suffix}" for suffix in (".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".php", ".java", ".kt", ".scala", ".go"))
    candidates.extend(f"{normalized}/index{suffix}" for suffix in (".js", ".jsx", ".ts", ".tsx", ".php"))
    candidates.append(f"{normalized}/__init__.py")
    for candidate in candidates:
        if candidate in paths:
            return candidate
    return None


def _looks_like_symbol_declaration(line: str, name: str) -> bool:
    return bool(
        re.search(rf"\b(?:function|func|def|class|interface|struct|enum|record)\s+{re.escape(name)}\b", line)
        or re.search(rf"\b{re.escape(name)}\s*[:=]\s*(?:async\s*)?\(?", line)
    )


def _generic_web_script_entrypoints(snapshot_id: str, file: CodeFile, text: str) -> list[CodeEntrypointRecord]:
    if not is_likely_generic_web_script(file.path, text):
        return []
    path = PurePosixPath(file.path)
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
            0.72,
            "heuristic:web_script",
        )
    ]


def is_likely_generic_web_script(path: str, text: str | None = None) -> bool:
    pure_path = PurePosixPath(path)
    if pure_path.suffix.lower() not in GENERIC_WEB_SCRIPT_SUFFIXES:
        return False
    if any(part in GENERIC_WEB_SCRIPT_EXCLUDED_PARTS for part in pure_path.parts):
        return False
    if pure_path.suffix.lower() == ".php":
        return text is not None and _is_likely_direct_php_script(pure_path, text)
    return True


def _is_likely_direct_php_script(path: PurePosixPath, text: str) -> bool:
    """Heuristic for generic PHP entrypoints.

    PHP projects often place helper files such as ``functions.php`` or
    ``sql-connect.php`` under the web root. Treating every ``.php`` file as a
    route overwhelms the audit graph. This keeps direct scripts that have
    top-level request/response behavior, while leaving function-only include
    files out of the entrypoint set.
    """
    if path.name.lower() == "index.php":
        return True
    if not PHP_DIRECT_SCRIPT_NAME_RE.match(path.name):
        return _has_php_top_level_web_behavior(text)
    return _has_php_top_level_web_behavior(text)


def _has_php_top_level_web_behavior(text: str) -> bool:
    declaration_depth = 0
    pending_declaration = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("//", "#", "*")):
            continue
        if declaration_depth > 0:
            declaration_depth += _brace_delta(stripped)
            if declaration_depth <= 0:
                declaration_depth = 0
            continue
        if pending_declaration:
            if "{" in stripped:
                declaration_depth = max(1, _brace_delta(stripped))
                pending_declaration = False
            continue
        if PHP_DECLARATION_START_RE.match(stripped):
            if "{" in stripped:
                declaration_depth = max(1, _brace_delta(stripped))
            else:
                pending_declaration = True
            continue
        if any(pattern.search(stripped) for pattern in PHP_TOP_LEVEL_WEB_PATTERNS):
            return True
    return False


def _brace_delta(text: str) -> int:
    return text.count("{") - text.count("}")


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
    confidence: float = 0.82,
    source: str = "heuristic:route",
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
        confidence=confidence,
        source=source,
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


def _keyword_string(value: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*['\"]([^'\"]+)['\"]", value)
    return match.group(1) if match else None


def _keyword_bool(value: str, key: str) -> bool:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*(True|False|true|false)", value)
    return bool(match and match.group(1).lower() == "true")


def _join_routes(prefix: str | None, route: str | None) -> str:
    prefix_text = (prefix or "").strip()
    route_text = (route or "").strip()
    if route_text.startswith("^"):
        route_text = route_text[1:]
    if route_text.endswith("$"):
        route_text = route_text[:-1]
    if not prefix_text and not route_text:
        return "/"
    if not prefix_text:
        return route_text if route_text.startswith("/") else f"/{route_text}"
    if not route_text:
        return prefix_text if prefix_text.startswith("/") else f"/{prefix_text}"
    return f"/{prefix_text.strip('/')}/{route_text.strip('/')}"


def _methods_from_args(value: str) -> list[str]:
    match = re.search(r"methods\s*=\s*\[([^\]]+)\]", value)
    if not match:
        return []
    return [item.upper() for item in re.findall(r"['\"]([A-Za-z]+)['\"]", match.group(1))]


def _request_method(value: str) -> str | None:
    methods = _request_methods(value)
    return methods[0] if methods else None


def _request_methods(value: str) -> list[str]:
    return list(dict.fromkeys(re.findall(r"RequestMethod\.([A-Z]+)", value)))


def _entrypoint_label(method: str | None, route: str) -> str:
    return f"{method} {route}" if method else route


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


def _dedupe_relationships(items: list[CodeRelationshipRecord]) -> list[CodeRelationshipRecord]:
    seen: set[tuple[str, str | None, str, str, str | None]] = set()
    result: list[CodeRelationshipRecord] = []
    for item in items:
        key = (item.from_path, item.from_symbol, item.relation, item.to_path, item.to_symbol)
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
