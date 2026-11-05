"""Server-side replay verification of web findings.

Why this exists
---------------
A finding written by a language model is a *claim*.  The proof packets and
reproduction steps it contains cannot be told apart from invented ones by
format checks, and the reviewer is another model that reads the same claim.
This module gives the system a verdict that does not depend on any model's
honesty: the **server** sends the HTTP requests itself, against a lab target
the operator configured, and a **program** decides whether the observed
responses prove the vulnerability.

Design rules
------------
* The model only proposes a *plan* (which requests, which oracle).  It never
  supplies results.  Results are produced here.
* Oracles that compute something use server-generated random nonces
  (``__A__``, ``__B__``, ``__M__``).  A model cannot know them in advance, so
  an expected value showing up in a response means the target really
  evaluated attacker-controlled input.
* A verdict is advisory evidence.  Nothing here rejects or confirms a finding
  by itself: ``not_reproduced`` does not prove safety.
* Requests are confined to the configured target: relative paths only, no
  redirects followed, no model-supplied credentials, a header allow-list, a
  request budget, size limits, and safe methods unless the operator opted in
  to state-changing requests.

No database or web-framework imports live here so the logic stays unit-testable.
"""

from __future__ import annotations

import http.server
import ipaddress
import re
import secrets
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qsl, unquote, urlsplit

import requests

# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

MAX_REQUESTS_PER_PLAN = 6
MAX_REQUEST_BODY_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
MAX_PATH_LENGTH = 2048
CONNECT_TIMEOUT_SECONDS = 3.0
READ_TIMEOUT_SECONDS = 10.0
CALLBACK_WAIT_SECONDS = 8.0
EVIDENCE_EXCERPT_CHARS = 700

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Headers a plan may set.  Credentials are deliberately absent: they come only
# from the operator's profiles, never from the model.
ALLOWED_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "accept-language",
        "content-type",
        "origin",
        "range",
        "referer",
        "user-agent",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-http-method-override",
        "x-original-url",
        "x-requested-with",
        "x-rewrite-url",
    }
)
SENSITIVE_HEADER_FRAGMENTS = ("cookie", "authorization", "token", "secret", "api-key", "apikey", "session")

VERDICT_CONFIRMED = "confirmed"
VERDICT_NOT_REPRODUCED = "not_reproduced"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_ERROR = "error"

STATUS_BY_VERDICT = {
    VERDICT_CONFIRMED: "replay_confirmed",
    VERDICT_NOT_REPRODUCED: "replay_not_reproduced",
    VERDICT_INCONCLUSIVE: "replay_inconclusive",
    VERDICT_ERROR: "replay_error",
}

ORACLE_NAMES = (
    "sql_error",
    "boolean_diff",
    "reflected_raw",
    "computed_marker",
    "file_signature",
    "redirect_host",
    "access_control",
    "ssrf_callback",
)

REDIRECT_HOST_SUFFIX = ".cairn-test.invalid"

SQL_ERROR_SIGNATURES = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"you have an error in your sql syntax",
        r"warning:\s*mysqli?_",
        r"mysql_fetch_",
        r"SQLSTATE\[[0-9A-Z]+\]",
        r"\bORA-\d{5}\b",
        r"PostgreSQL.{0,40}ERROR",
        r"pg_query\(\)",
        r"unterminated quoted string",
        r"sqlite3?\.(?:operationalerror|databaseerror)",
        r"SQLite3::",
        r"near \".{0,40}\": syntax error",
        r"unrecognized token:",
        r"Unclosed quotation mark",
        r"ODBC SQL Server Driver",
        r"Microsoft OLE DB Provider",
        r"java\.sql\.SQLException",
        r"org\.hibernate\.QueryException",
        r"com\.mysql\.jdbc",
        r"Syntax error in string in query expression",
    )
)

FILE_SIGNATURES: dict[str, re.Pattern[str]] = {
    "passwd": re.compile(r"\broot:[x*!]?:0:0:"),
    "win_ini": re.compile(r"\[(?:fonts|extensions|mci extensions|files)\]", re.IGNORECASE),
    "proc_version": re.compile(r"Linux version \d"),
    "hosts": re.compile(r"127\.0\.0\.1\s+localhost"),
}

_NONCE_PATTERN = re.compile(r"__(?:A|B|M|CALLBACK)__")
_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]+$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ReplayError(Exception):
    """Raised when a plan or target cannot be executed safely."""


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------


@dataclass
class ValidationTarget:
    base_url: str
    allow_state_changing: bool = False
    profiles: dict[str, dict[str, Any]] = field(default_factory=dict)
    callback: dict[str, Any] = field(default_factory=dict)


@dataclass
class Exchange:
    name: str
    method: str
    path: str
    auth: str | None
    request_headers: dict[str, str]
    request_body: str | None
    status: int = 0
    reason: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    truncated: bool = False
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0


@dataclass
class Nonces:
    a: int
    b: int
    m: str
    callback_url: str | None = None

    def substitute(self, text: str) -> str:
        replaced = text.replace("__A__", str(self.a)).replace("__B__", str(self.b)).replace("__M__", self.m)
        if self.callback_url is not None:
            replaced = replaced.replace("__CALLBACK__", self.callback_url)
        return replaced

    def public(self) -> dict[str, Any]:
        return {"A": self.a, "B": self.b, "M": self.m}


@dataclass
class OracleOutcome:
    verdict: str
    reason: str
    checks: list[dict[str, Any]] = field(default_factory=list)
    focus: dict[str, str] = field(default_factory=dict)

    def check(self, name: str, passed: bool, detail: str = "") -> bool:
        self.checks.append({"name": name, "passed": bool(passed), "detail": detail})
        return bool(passed)


def new_nonces() -> Nonces:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    token = "".join(secrets.choice(alphabet) for _ in range(10))
    return Nonces(a=secrets.randbelow(9000) + 1000, b=secrets.randbelow(9000) + 1000, m=f"cairn{token}")


# --------------------------------------------------------------------------
# Target and request safety
# --------------------------------------------------------------------------


def _addresses_for_host(hostname: str, port: int) -> set[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ReplayError(f"target host could not be resolved: {hostname}") from exc
    addresses: set[ipaddress._BaseAddress] = set()
    for info in infos:
        try:
            addresses.add(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not addresses:
        raise ReplayError(f"target host could not be resolved: {hostname}")
    return addresses


def validate_target_url(url: str) -> str:
    """Validate and normalise a validation-target base URL.

    Lab targets normally live on loopback or a private network, so those are
    allowed.  Link-local (cloud metadata), multicast, unspecified and reserved
    addresses never are.
    """
    if not isinstance(url, str) or not url.strip():
        raise ReplayError("base_url is required")
    text = url.strip()
    parsed = urlsplit(text)
    if parsed.scheme not in ("http", "https"):
        raise ReplayError("base_url must use http or https")
    if not parsed.hostname:
        raise ReplayError("base_url must include a host")
    if parsed.username or parsed.password:
        raise ReplayError("base_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ReplayError("base_url must not contain a query string or fragment")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    for address in _addresses_for_host(parsed.hostname, port):
        if (
            address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ReplayError(f"target address {address} is not allowed (link-local, multicast or reserved)")
    return text.rstrip("/")


def validate_request_path(path: Any) -> str:
    if not isinstance(path, str) or not path:
        raise ReplayError("request path is required")
    if len(path) > MAX_PATH_LENGTH:
        raise ReplayError("request path is too long")
    if not path.startswith("/") or path.startswith("//"):
        raise ReplayError("request path must be relative to the target and start with a single '/'")
    if "\\" in path or _CONTROL_RE.search(path) or " " in path:
        raise ReplayError("request path contains forbidden characters")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc:
        raise ReplayError("request path must not contain a scheme or host")
    return path


def validate_request_headers(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise ReplayError("request headers must be an object")
    clean: dict[str, str] = {}
    for name, value in headers.items():
        key = str(name).strip()
        if not _HEADER_NAME_RE.match(key):
            raise ReplayError(f"invalid header name: {key!r}")
        if key.lower() not in ALLOWED_REQUEST_HEADERS:
            raise ReplayError(f"header {key} is not allowed in a verification plan")
        text = str(value)
        if _CONTROL_RE.search(text) or len(text) > 1024:
            raise ReplayError(f"invalid value for header {key}")
        clean[key] = text
    return clean


@dataclass
class PlannedRequest:
    name: str
    method: str
    path: str
    headers: dict[str, str]
    body: str | None
    auth: str | None


def parse_plan_request(name: str, raw: Any, target: ValidationTarget) -> PlannedRequest:
    if not isinstance(raw, dict):
        raise ReplayError(f"request {name!r} must be an object")
    method = str(raw.get("method") or "GET").strip().upper()
    if method in STATE_CHANGING_METHODS:
        if not target.allow_state_changing:
            raise ReplayError(
                f"{method} is a state-changing method and the validation target does not allow it"
            )
    elif method not in SAFE_METHODS:
        raise ReplayError(f"method {method} is not supported")
    path = validate_request_path(raw.get("path"))
    headers = validate_request_headers(raw.get("headers"))
    body = raw.get("body")
    if body is not None:
        if method in SAFE_METHODS:
            raise ReplayError(f"{method} request must not have a body")
        body = str(body)
        if len(body.encode("utf-8")) > MAX_REQUEST_BODY_BYTES:
            raise ReplayError("request body is too large")
    auth = raw.get("auth")
    auth = None if auth in (None, "", "none") else str(auth)
    if auth is not None and auth not in target.profiles:
        raise ReplayError(f"unknown credential profile: {auth}")
    return PlannedRequest(name=name, method=method, path=path, headers=headers, body=body, auth=auth)


# --------------------------------------------------------------------------
# Sending
# --------------------------------------------------------------------------


def _session() -> requests.Session:
    session = requests.Session()
    # Never route lab traffic through whatever proxy the host environment has.
    session.trust_env = False
    return session


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        lowered = key.lower()
        redacted[key] = "***" if any(part in lowered for part in SENSITIVE_HEADER_FRAGMENTS) else value
    return redacted


def send_request(
    session: requests.Session,
    target: ValidationTarget,
    planned: PlannedRequest,
    nonces: Nonces,
) -> Exchange:
    path = nonces.substitute(planned.path)
    # Nonce substitution must not be able to smuggle the request off target.
    path = validate_request_path(path)
    body = nonces.substitute(planned.body) if planned.body is not None else None
    headers = {key: nonces.substitute(value) for key, value in planned.headers.items()}
    for key, value in headers.items():
        if _CONTROL_RE.search(value):
            raise ReplayError(f"invalid value for header {key} after substitution")

    profile_headers: dict[str, str] = {}
    if planned.auth is not None:
        raw_profile = target.profiles.get(planned.auth, {})
        profile_headers = {str(k): str(v) for k, v in (raw_profile.get("headers") or {}).items()}
    effective = {**headers, **profile_headers}
    effective.setdefault("User-Agent", "cairn-replay-verifier/1")

    url = target.base_url + path
    if urlsplit(url).netloc != urlsplit(target.base_url).netloc:
        raise ReplayError("request would leave the validation target")

    exchange = Exchange(
        name=planned.name,
        method=planned.method,
        path=path,
        auth=planned.auth,
        request_headers=_redact_headers(effective),
        request_body=body,
    )
    started = time.monotonic()
    try:
        response = session.request(
            planned.method,
            url,
            headers=effective,
            data=body.encode("utf-8") if body is not None else None,
            allow_redirects=False,
            stream=True,
            timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS),
        )
    except requests.RequestException as exc:
        exchange.error = f"{type(exc).__name__}: {str(exc)[:200]}"
        exchange.elapsed_ms = int((time.monotonic() - started) * 1000)
        return exchange
    try:
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            remaining = MAX_RESPONSE_BYTES - size
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                size += remaining
                exchange.truncated = True
                break
            chunks.append(chunk)
            size += len(chunk)
        encoding = response.encoding or "utf-8"
        exchange.body = b"".join(chunks).decode(encoding, errors="replace")
        exchange.status = response.status_code
        exchange.reason = response.reason or ""
        exchange.response_headers = {str(k): str(v) for k, v in response.headers.items()}
    except requests.RequestException as exc:
        exchange.error = f"{type(exc).__name__}: {str(exc)[:200]}"
    finally:
        response.close()
    exchange.elapsed_ms = int((time.monotonic() - started) * 1000)
    return exchange


# --------------------------------------------------------------------------
# Helpers for oracles
# --------------------------------------------------------------------------


def _sql_error_in(body: str) -> str | None:
    for pattern in SQL_ERROR_SIGNATURES:
        match = pattern.search(body)
        if match:
            return match.group(0)
    return None


def _normalized_body(exchange: Exchange) -> str:
    """Body with echoed request values removed, for page-equality comparisons."""
    body = exchange.body
    query = urlsplit(exchange.path).query
    values = [value for _key, value in parse_qsl(query, keep_blank_values=True)]
    values.append(unquote(urlsplit(exchange.path).path))
    for value in sorted({v for v in values if len(v) > 2}, key=len, reverse=True):
        body = body.replace(value, "")
    return re.sub(r"\s+", " ", body).strip()


def _same_page(left: Exchange, right: Exchange) -> bool:
    return left.status == right.status and _normalized_body(left) == _normalized_body(right)


def _excerpt(body: str, needle: str | None = None) -> str:
    text = body
    if needle:
        index = text.find(needle)
        if index >= 0:
            start = max(0, index - EVIDENCE_EXCERPT_CHARS // 2)
            text = text[start : start + EVIDENCE_EXCERPT_CHARS]
            return text.replace("...", "\u2026")
    return text[:EVIDENCE_EXCERPT_CHARS].replace("...", "\u2026")


def _sent_text(exchange: Exchange) -> str:
    return "\n".join(
        [exchange.path, exchange.request_body or "", *exchange.request_headers.values()]
    )


def _transport_failure(outcome_exchanges: list[Exchange]) -> OracleOutcome | None:
    for exchange in outcome_exchanges:
        if not exchange.ok:
            return OracleOutcome(
                VERDICT_ERROR,
                f"request {exchange.name!r} failed: {exchange.error}",
                [{"name": f"request_{exchange.name}", "passed": False, "detail": str(exchange.error)}],
            )
    return None


# --------------------------------------------------------------------------
# Oracles.  Each takes (plan, exchanges, nonces) and returns an OracleOutcome.
# --------------------------------------------------------------------------

REQUIRED_REQUESTS: dict[str, tuple[str, ...]] = {
    "sql_error": ("attack", "baseline"),
    "boolean_diff": ("baseline", "true", "false"),
    "reflected_raw": ("attack", "baseline"),
    "computed_marker": ("attack",),
    "file_signature": ("attack", "baseline"),
    "redirect_host": ("attack",),
    # access_control sends one "target" request twice, once per identity.
    "access_control": ("target",),
    "ssrf_callback": ("attack",),
}


def _oracle_sql_error(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    attack, baseline = ex["attack"], ex["baseline"]
    in_baseline = _sql_error_in(baseline.body)
    if not out.check("baseline_has_no_sql_error", in_baseline is None, in_baseline or ""):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "baseline response already contains a database error, so the attack response proves nothing"
        return out
    in_attack = _sql_error_in(attack.body)
    if out.check("attack_has_sql_error", in_attack is not None, in_attack or ""):
        out.verdict = VERDICT_CONFIRMED
        out.reason = f"database error signature appeared only in the attack response: {in_attack!r}"
        out.focus = {"attack": in_attack or ""}
    else:
        out.reason = "no database error signature in the attack response"
    return out


def _oracle_boolean_diff(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    baseline, repeat, true_req, false_req = ex["baseline"], ex["baseline_repeat"], ex["true"], ex["false"]
    if not out.check("baseline_is_stable", _same_page(baseline, repeat), "two identical baseline requests must match"):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the page changes between identical requests, so a differential cannot be trusted"
        return out
    if not out.check("true_matches_baseline", _same_page(baseline, true_req)):
        out.reason = "the always-true condition does not reproduce the baseline page"
        return out
    if out.check("false_differs_from_true", not _same_page(true_req, false_req)):
        out.verdict = VERDICT_CONFIRMED
        out.reason = "the always-true condition matches the baseline while the always-false condition changes the page"
    else:
        out.reason = "the always-false condition returned the same page as the always-true condition"
    return out


def _oracle_reflected_raw(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    reflected = nonces.substitute(str(plan.get("reflected") or ""))
    if not out.check("plan_declares_reflected_string", bool(reflected), "plan.reflected is required"):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "plan.reflected (the exact string expected back unencoded) is missing"
        return out
    if not out.check(
        "reflected_string_contains_markup",
        any(ch in reflected for ch in "<>\"'"),
        "a string without markup characters proves nothing about missing encoding",
    ):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the reflected string has no markup characters, so reflection would not show missing encoding"
        return out
    if nonces.m not in reflected:
        out.check("reflected_string_uses_nonce", False, "include __M__ so coincidental matches are impossible")
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "plan.reflected must contain __M__"
        return out
    attack, baseline = ex["attack"], ex["baseline"]
    content_type = attack.response_headers.get("Content-Type", attack.response_headers.get("content-type", ""))
    out.check("response_is_html_or_untyped", "html" in content_type.lower() or not content_type, content_type)
    if not out.check("baseline_lacks_string", reflected not in baseline.body):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the baseline response already contains the string"
        return out
    if out.check("attack_reflects_string_raw", reflected in attack.body):
        out.verdict = VERDICT_CONFIRMED
        out.reason = "the exact payload, including markup characters, was returned without encoding"
        out.focus = {"attack": reflected}
    else:
        out.reason = "the payload was not returned verbatim (it may be encoded, stripped or not reflected)"
    return out


def _oracle_computed_marker(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    expression = str(plan.get("expect") or "A*B").replace(" ", "")
    if expression == "A*B":
        expected = str(nonces.a * nonces.b)
    elif expression == "A+B":
        expected = str(nonces.a + nonces.b)
    else:
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "plan.expect must be 'A*B' or 'A+B'"
        return out
    attack = ex["attack"]
    sent = _sent_text(attack)
    # ``_template_text`` is the plan's request text *before* nonce substitution.
    template = str(plan.get("_template_text", ""))
    uses_nonces = "__A__" in template and "__B__" in template
    out.check("request_carries_server_nonces", uses_nonces, "the payload must use both __A__ and __B__")
    if not uses_nonces:
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the payload does not use __A__ and __B__, so the result cannot be attributed to evaluation"
        return out
    if not out.check("expected_value_not_in_request", expected not in sent, "the computed value must not appear in what was sent"):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the computed value already appears in the request"
        return out
    baseline = ex.get("baseline")
    if baseline is not None and not out.check("baseline_lacks_value", expected not in baseline.body):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the baseline response already contains the computed value"
        return out
    if out.check("attack_contains_computed_value", expected in attack.body):
        out.verdict = VERDICT_CONFIRMED
        out.reason = (
            f"the target returned {expected}, the result of {expression} on random numbers chosen by the "
            "server, so it evaluated attacker-controlled input"
        )
        out.focus = {"attack": expected}
    else:
        out.reason = "the computed value was not returned"
    return out


def _oracle_file_signature(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    name = str(plan.get("signature") or "passwd")
    pattern = FILE_SIGNATURES.get(name)
    if pattern is None:
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = f"unknown signature {name!r}; choose one of {', '.join(sorted(FILE_SIGNATURES))}"
        return out
    attack, baseline = ex["attack"], ex["baseline"]
    if not out.check("baseline_lacks_signature", pattern.search(baseline.body) is None):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the baseline response already contains the file signature"
        return out
    match = pattern.search(attack.body)
    if out.check("attack_contains_signature", match is not None, name):
        out.verdict = VERDICT_CONFIRMED
        out.reason = f"the response contains the {name} file signature that the baseline does not"
        out.focus = {"attack": match.group(0) if match else ""}
    else:
        out.reason = f"no {name} file signature in the attack response"
    return out


def _oracle_redirect_host(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    expected_host = nonces.substitute(str(plan.get("redirect_host") or "")).lower()
    if not out.check(
        "redirect_host_uses_reserved_suffix",
        expected_host.endswith(REDIRECT_HOST_SUFFIX) and nonces.m in expected_host,
        f"plan.redirect_host must look like __M__{REDIRECT_HOST_SUFFIX}",
    ):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = f"plan.redirect_host must be __M__{REDIRECT_HOST_SUFFIX}"
        return out
    attack = ex["attack"]
    location = attack.response_headers.get("Location", attack.response_headers.get("location", ""))
    out.check("attack_is_redirect", 300 <= attack.status < 400, str(attack.status))
    location_host = (urlsplit(location if "//" in location else "//" + location.lstrip("/")).hostname or "").lower()
    if out.check("location_points_at_attacker_host", location_host == expected_host, location):
        out.verdict = VERDICT_CONFIRMED
        out.reason = "the server redirected to a host chosen by the request"
        out.focus = {"attack": location}
    else:
        out.reason = "the response did not redirect to the attacker-chosen host"
    return out


def _oracle_access_control(plan: dict, ex: dict[str, Exchange], nonces: Nonces) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    victim_view, attacker_view = ex.get("victim_view"), ex.get("attacker_view")
    if victim_view is None or attacker_view is None:
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "access_control needs plan.victim and plan.attacker (a profile name or 'none')"
        return out
    marker = str(plan.get("marker") or "").strip()
    if not out.check("owner_can_view_resource", 200 <= victim_view.status < 300 and len(victim_view.body.strip()) >= 8,
                     f"status {victim_view.status}"):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the legitimate owner could not retrieve the resource, so the request or test data is wrong"
        return out
    if marker and not out.check("owner_response_contains_marker", marker in victim_view.body):
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the owner's response does not contain plan.marker"
        return out
    out.check("attacker_status_ok", 200 <= attacker_view.status < 300, f"status {attacker_view.status}")
    if not (200 <= attacker_view.status < 300):
        out.reason = f"the other identity was refused (HTTP {attacker_view.status})"
        return out
    if marker:
        leaked = marker in attacker_view.body
        out.check("attacker_response_contains_marker", leaked)
    else:
        leaked = _same_page(victim_view, attacker_view)
        out.check("attacker_response_matches_owner_response", leaked)
    if leaked:
        out.verdict = VERDICT_CONFIRMED
        out.reason = (
            "a different identity retrieved the owner's resource. This proves cross-identity access; "
            "confirm that the resource is not meant to be public"
        )
        out.focus = {"attack": marker} if marker else {}
    else:
        out.reason = "the other identity received a different response"
    return out


# --------------------------------------------------------------------------
# SSRF callback listener
# --------------------------------------------------------------------------


class CallbackListener:
    """One-shot HTTP listener that records which paths were requested."""

    def __init__(self, bind_host: str, port: int, advertise_host: str) -> None:
        self.hits: list[str] = []
        outer = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib naming
                outer.hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_POST = do_GET  # noqa: N815
            do_HEAD = do_GET  # noqa: N815

            def log_message(self, *args: Any) -> None:
                return

        self._server = http.server.ThreadingHTTPServer((bind_host, port), _Handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self.advertise_host = advertise_host
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def url_for(self, token: str) -> str:
        return f"http://{self.advertise_host}:{self.port}/{token}"

    def saw(self, token: str) -> bool:
        return any(token in hit for hit in self.hits)

    def wait_for(self, token: str, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.saw(token):
                return True
            time.sleep(0.1)
        return self.saw(token)

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _oracle_ssrf_callback(plan: dict, ex: dict[str, Exchange], nonces: Nonces, listener: CallbackListener | None = None) -> OracleOutcome:
    out = OracleOutcome(VERDICT_NOT_REPRODUCED, "")
    if listener is None:
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "the validation target has no callback listener configured"
        return out
    token = nonces.m
    if out.check("target_called_back", listener.wait_for(token, CALLBACK_WAIT_SECONDS), token):
        out.verdict = VERDICT_CONFIRMED
        out.reason = "the target made an outbound request to the server's one-time callback URL"
        out.focus = {"attack": token}
    else:
        # A missing callback cannot tell "not vulnerable" from "target cannot
        # reach the callback address", so it is inconclusive, not a negative.
        out.verdict = VERDICT_INCONCLUSIVE
        out.reason = "no callback was received; the target may be safe or may be unable to reach the callback address"
    return out


ORACLE_FUNCTIONS: dict[str, Callable[..., OracleOutcome]] = {
    "sql_error": _oracle_sql_error,
    "boolean_diff": _oracle_boolean_diff,
    "reflected_raw": _oracle_reflected_raw,
    "computed_marker": _oracle_computed_marker,
    "file_signature": _oracle_file_signature,
    "redirect_host": _oracle_redirect_host,
    "access_control": _oracle_access_control,
    "ssrf_callback": _oracle_ssrf_callback,
}


# --------------------------------------------------------------------------
# Plan execution
# --------------------------------------------------------------------------


def _build_request_list(plan: dict, target: ValidationTarget) -> list[PlannedRequest]:
    oracle = plan.get("oracle")
    raw = plan.get("requests")
    if not isinstance(raw, dict) or not raw:
        raise ReplayError("plan.requests must be an object of named requests")
    needed = REQUIRED_REQUESTS[oracle]
    missing = [name for name in needed if name not in raw]
    if missing:
        raise ReplayError(f"oracle {oracle} requires requests: {', '.join(missing)}")

    planned: list[PlannedRequest] = []
    if oracle == "access_control":
        base = dict(raw["target"])
        victim = plan.get("victim")
        attacker = plan.get("attacker")
        if victim in (None, "", "none"):
            raise ReplayError("access_control requires plan.victim (a configured profile name)")
        if attacker is None:
            raise ReplayError("access_control requires plan.attacker (a profile name or 'none')")
        if str(attacker) == str(victim):
            raise ReplayError("plan.attacker and plan.victim must be different identities")
        planned.append(parse_plan_request("victim_view", {**base, "auth": victim}, target))
        planned.append(parse_plan_request("attacker_view", {**base, "auth": attacker}, target))
        return planned

    for name, spec in raw.items():
        if name not in needed and name != "baseline":
            raise ReplayError(f"request {name!r} is not used by oracle {oracle}")
        planned.append(parse_plan_request(str(name), spec, target))
    if oracle == "boolean_diff":
        base = next(item for item in planned if item.name == "baseline")
        planned.append(
            PlannedRequest("baseline_repeat", base.method, base.path, dict(base.headers), base.body, base.auth)
        )
    return planned


def validate_plan(plan: Any, target: ValidationTarget) -> list[PlannedRequest]:
    if not isinstance(plan, dict) or not plan:
        raise ReplayError("finding has no verification_plan")
    oracle = plan.get("oracle")
    if oracle not in ORACLE_FUNCTIONS:
        raise ReplayError(f"unknown oracle {oracle!r}; choose one of {', '.join(ORACLE_NAMES)}")
    planned = _build_request_list(plan, target)
    if len(planned) > MAX_REQUESTS_PER_PLAN:
        raise ReplayError(f"a plan may send at most {MAX_REQUESTS_PER_PLAN} requests")
    return planned


def _evidence_for(exchange: Exchange, focus: str | None) -> dict[str, Any]:
    query_path = exchange.path
    request_lines = [f"{exchange.method} {query_path} HTTP/1.1"]
    request_lines.append(f"Host: {{host}}")
    for key, value in exchange.request_headers.items():
        request_lines.append(f"{key}: {value}")
    if exchange.request_body:
        request_lines.extend(["", exchange.request_body[:EVIDENCE_EXCERPT_CHARS]])
    shown_headers = {
        key: value
        for key, value in exchange.response_headers.items()
        if key.lower() in {"content-type", "location", "content-length", "server"}
    }
    return {
        "name": exchange.name,
        "auth": exchange.auth,
        "method": exchange.method,
        "path": exchange.path,
        "request": "\n".join(request_lines),
        "status": exchange.status,
        "reason": exchange.reason,
        "response_headers": shown_headers,
        "response_excerpt": _excerpt(exchange.body, focus),
        "truncated": exchange.truncated,
        "elapsed_ms": exchange.elapsed_ms,
        "error": exchange.error,
    }


def execute_plan(
    plan: dict,
    target: ValidationTarget,
    *,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Run ``plan`` against ``target`` and return a JSON-serialisable result."""
    started = time.time()
    result: dict[str, Any] = {
        "oracle": plan.get("oracle") if isinstance(plan, dict) else None,
        "verdict": VERDICT_ERROR,
        "reason": "",
        "checks": [],
        "exchanges": [],
        "nonces": {},
        "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
    }
    listener: CallbackListener | None = None
    owns_session = session is None
    session = session or _session()
    try:
        target.base_url = validate_target_url(target.base_url)
        planned = validate_plan(plan, target)
        nonces = new_nonces()
        result["nonces"] = nonces.public()

        if plan["oracle"] == "ssrf_callback":
            callback = target.callback or {}
            if callback.get("advertise_host"):
                listener = CallbackListener(
                    str(callback.get("bind_host") or "0.0.0.0"),
                    int(callback.get("port") or 0),
                    str(callback["advertise_host"]),
                )
                listener.start()
                nonces.callback_url = listener.url_for(nonces.m)

        # The text of the attack request *before* nonce substitution lets an
        # oracle check that the payload really used the server's nonces.
        plan_for_oracle = dict(plan)
        plan_for_oracle["_template_text"] = " ".join(
            f"{r.path} {r.body or ''} {' '.join(r.headers.values())}"
            for r in planned
            if r.name in {"attack", "target"}
        )

        exchanges: dict[str, Exchange] = {}
        for item in planned:
            exchanges[item.name] = send_request(session, target, item, nonces)
        result["exchanges"] = [
            _evidence_for(exchange, None) for exchange in exchanges.values()
        ]

        failure = _transport_failure(list(exchanges.values()))
        if failure is not None:
            result.update(verdict=failure.verdict, reason=failure.reason, checks=failure.checks)
            return result

        oracle_fn = ORACLE_FUNCTIONS[plan["oracle"]]
        if plan["oracle"] == "ssrf_callback":
            outcome = oracle_fn(plan_for_oracle, exchanges, nonces, listener)
        else:
            outcome = oracle_fn(plan_for_oracle, exchanges, nonces)

        result.update(verdict=outcome.verdict, reason=outcome.reason, checks=outcome.checks)
        if outcome.focus:
            for entry in result["exchanges"]:
                focus = outcome.focus.get(entry["name"])
                if focus:
                    exchange = exchanges[entry["name"]]
                    entry["response_excerpt"] = _excerpt(exchange.body, focus)
        return result
    except ReplayError as exc:
        result.update(verdict=VERDICT_ERROR, reason=str(exc))
        return result
    finally:
        if listener is not None:
            listener.close()
        if owns_session:
            session.close()


def packet_from_result(result: dict[str, Any], target_host: str) -> dict[str, str] | None:
    """Build a report-ready proof packet from a *confirmed* server replay."""
    if result.get("verdict") != VERDICT_CONFIRMED:
        return None
    exchanges = result.get("exchanges") or []
    attack = next(
        (e for e in exchanges if e.get("name") in {"attack", "true", "attacker_view", "target"}),
        exchanges[-1] if exchanges else None,
    )
    if not attack:
        return None
    request = str(attack.get("request") or "").replace("{host}", target_host)
    status_line = f"HTTP/1.1 {attack.get('status')} {attack.get('reason') or ''}".rstrip()
    headers = "\n".join(f"{k}: {v}" for k, v in (attack.get("response_headers") or {}).items())
    response = status_line + ("\n" + headers if headers else "") + "\n\n" + str(attack.get("response_excerpt") or "")
    return {
        "title": f"服务端重放验证（判定器：{result.get('oracle')}）",
        "payload": str(attack.get("path") or ""),
        "request": request,
        "response": response,
        "note": f"由服务端实际发送请求并由程序判定，非模型编写。{result.get('reason') or ''}",
    }
