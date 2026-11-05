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
    # --- Injection family ---
    "code injection": "code_injection",
    "eval injection": "code_injection",
    "代码注入": "code_injection",
    "远程代码执行": "code_injection",
    "rce": "command_injection",
    "远程命令执行": "command_injection",
    "ssti": "ssti",
    "template injection": "ssti",
    "server side template injection": "ssti",
    "模板注入": "ssti",
    "expression injection": "expression_injection",
    "expression language injection": "expression_injection",
    "ognl injection": "expression_injection",
    "spel injection": "expression_injection",
    "el injection": "expression_injection",
    "表达式注入": "expression_injection",
    "xxe": "xxe",
    "xml external entity": "xxe",
    "xml injection": "xml_injection",
    "xml注入": "xml_injection",
    "ldap injection": "ldap_injection",
    "ldap注入": "ldap_injection",
    "xpath injection": "xpath_injection",
    "xpath注入": "xpath_injection",
    "nosql injection": "nosql_injection",
    "mongo injection": "nosql_injection",
    "nosql注入": "nosql_injection",
    "crlf injection": "crlf_injection",
    "http response splitting": "crlf_injection",
    "响应拆分": "crlf_injection",
    "host header injection": "host_header_injection",
    "主机头注入": "host_header_injection",
    # --- Deserialization / file / upload ---
    "insecure deserialization": "deserialization",
    "unsafe deserialization": "deserialization",
    "deserialization": "deserialization",
    "反序列化": "deserialization",
    "反序列化漏洞": "deserialization",
    "unrestricted file upload": "file_upload",
    "arbitrary file upload": "file_upload",
    "file upload": "file_upload",
    "任意文件上传": "file_upload",
    "文件上传漏洞": "file_upload",
    "file inclusion": "file_inclusion",
    "local file inclusion": "file_inclusion",
    "remote file inclusion": "file_inclusion",
    "lfi": "file_inclusion",
    "rfi": "file_inclusion",
    "文件包含": "file_inclusion",
    "arbitrary file read": "path_traversal",
    "arbitrary file download": "path_traversal",
    "任意文件读取": "path_traversal",
    "任意文件下载": "path_traversal",
    "arbitrary file write": "file_write",
    "任意文件写入": "file_write",
    "任意文件删除": "file_write",
    # --- Auth / access control ---
    "broken authentication": "authentication",
    "improper authentication": "authentication",
    "authentication bypass": "authentication",
    "认证绕过": "authentication",
    "登录绕过": "authentication",
    "jwt": "authentication",
    "missing authentication": "missing_authentication",
    "unauthenticated access": "missing_authentication",
    "未授权访问": "missing_authentication",
    "未认证访问": "missing_authentication",
    "missing authorization": "authorization",
    "improper authorization": "authorization",
    "broken access control": "authorization",
    "session fixation": "session_fixation",
    "会话固定": "session_fixation",
    "cors misconfiguration": "cors_misconfig",
    "cors": "cors_misconfig",
    "跨域配置错误": "cors_misconfig",
    # --- Logic / misc web ---
    "mass assignment": "mass_assignment",
    "批量赋值": "mass_assignment",
    "prototype pollution": "prototype_pollution",
    "原型链污染": "prototype_pollution",
    "原型污染": "prototype_pollution",
    "race condition": "race_condition",
    "toctou": "race_condition",
    "条件竞争": "race_condition",
    "竞争条件": "race_condition",
    "business logic": "business_logic",
    "业务逻辑漏洞": "business_logic",
    "逻辑漏洞": "business_logic",
    "information disclosure": "information_disclosure",
    "sensitive data exposure": "information_disclosure",
    "信息泄露": "information_disclosure",
    "敏感信息泄露": "information_disclosure",
    "hardcoded credentials": "hardcoded_credentials",
    "硬编码凭据": "hardcoded_credentials",
    "硬编码密码": "hardcoded_credentials",
    "weak cryptography": "weak_crypto",
    "weak crypto": "weak_crypto",
    "弱加密": "weak_crypto",
    "redos": "redos",
    "regular expression denial of service": "redos",
    "正则拒绝服务": "redos",
}

_CWE_CATEGORIES = {
    "CWE-22": "path_traversal",
    "CWE-78": "command_injection",
    "CWE-79": "xss",
    "CWE-89": "sql_injection",
    "CWE-90": "ldap_injection",
    "CWE-91": "xml_injection",
    "CWE-94": "code_injection",
    "CWE-98": "file_inclusion",
    "CWE-113": "crlf_injection",
    "CWE-93": "crlf_injection",
    "CWE-200": "information_disclosure",
    "CWE-287": "authentication",
    "CWE-306": "missing_authentication",
    "CWE-327": "weak_crypto",
    "CWE-352": "csrf",
    "CWE-362": "race_condition",
    "CWE-384": "session_fixation",
    "CWE-434": "file_upload",
    "CWE-502": "deserialization",
    "CWE-601": "open_redirect",
    "CWE-611": "xxe",
    "CWE-639": "authorization",
    "CWE-643": "xpath_injection",
    "CWE-644": "host_header_injection",
    "CWE-798": "hardcoded_credentials",
    "CWE-840": "business_logic",
    "CWE-862": "authorization",
    "CWE-863": "authorization",
    "CWE-915": "mass_assignment",
    "CWE-917": "expression_injection",
    "CWE-918": "ssrf",
    "CWE-942": "cors_misconfig",
    "CWE-943": "nosql_injection",
    "CWE-1321": "prototype_pollution",
    "CWE-1333": "redos",
    "CWE-1336": "ssti",
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
