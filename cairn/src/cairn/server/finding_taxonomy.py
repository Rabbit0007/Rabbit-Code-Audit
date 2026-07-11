from __future__ import annotations

import hashlib
import re


_CATEGORY_ALIASES = {
    "sql injection": "sql_injection",
    "sqli": "sql_injection",
    "sql注入": "sql_injection",
    "xss": "xss",
    "cross site scripting": "xss",
    "cross site scripting xss": "xss",
    "reflected xss": "xss",
    "xss reflected": "xss",
    "stored xss": "xss",
    "xss stored": "xss",
    "dom xss": "xss",
    "command injection": "command_injection",
    "os command injection": "command_injection",
    "命令注入": "command_injection",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "目录遍历": "path_traversal",
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    "open redirect": "open_redirect",
    "开放重定向": "open_redirect",
    "authorization": "authorization",
    "authorization bypass": "authorization",
    "idor": "authorization",
    "越权": "authorization",
    "csrf": "csrf",
    "cross site request forgery": "csrf",
}

_CWE_CATEGORIES = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-79": "xss",
    "CWE-89": "sql_injection",
    "CWE-352": "csrf",
    "CWE-601": "open_redirect",
    "CWE-639": "authorization",
    "CWE-918": "ssrf",
}


def canonical_cwe(value: str | None) -> str | None:
    text = (value or "").strip().upper().replace("_", "-").replace(" ", "-")
    if not text:
        return None
    match = re.fullmatch(r"(?:CWE-?)?(\d+)", text)
    return f"CWE-{match.group(1)}" if match else text


def canonical_finding_category(category: str, cwe: str | None = None) -> str:
    normalized_cwe = canonical_cwe(cwe)
    if normalized_cwe in _CWE_CATEGORIES:
        return _CWE_CATEGORIES[normalized_cwe]
    key = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", category.strip().lower()).strip()
    if key in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[key]
    return key.replace(" ", "_") or "unknown"


def finding_cluster_key(
    *,
    category: str,
    cwe: str | None,
    file_path: str | None,
    symbol: str | None,
    line_start: int | None,
    entry_point: str | None,
) -> str:
    family = canonical_cwe(cwe) or canonical_finding_category(category, cwe)
    locator = _normalize_text(symbol)
    if not locator and line_start:
        locator = f"line:{line_start}"
    if not locator:
        locator = _entry_route_key(entry_point or "") or "unknown_location"
    parts = [family.lower(), normalize_finding_path(file_path), locator]
    return hashlib.sha1("\0".join(parts).encode("utf-8")).hexdigest()[:20]


def normalize_finding_path(value: str | None) -> str:
    text = (value or "").strip().replace("\\", "/").strip("/")
    return text.lower() or "unknown_path"


def _normalize_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = " ".join(value.strip().lower().replace("-", "_").split())
    return text or None


def _entry_route_key(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    parts = text.split()
    route = parts[1] if len(parts) >= 2 and parts[0].isalpha() else parts[0]
    route = route.split("?", 1)[0].split("#", 1)[0].strip()
    return route.lower() or None
