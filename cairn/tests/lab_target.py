"""A tiny deliberately-vulnerable HTTP target used by the replay-verification tests.

It runs on 127.0.0.1 only, on an ephemeral port, inside the test process.  Every
vulnerable endpoint has a "safe_*" twin so tests can check both that real bugs
are detected and that safe code is not reported.  Nothing here executes shell
commands or evaluates arbitrary code: the template and file endpoints implement
the vulnerable *behaviour* with simple, bounded string handling.
"""

from __future__ import annotations

import html
import http.server
import re
import threading
import urllib.request
from urllib.parse import parse_qs, urlsplit

FAKE_PASSWD = "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"

# session cookie -> user.  Notes belong to the user named in OWNERS.
SESSIONS = {"sid=alice-session": "alice", "sid=bob-session": "bob"}
NOTES = {
    "1": {"owner": "alice", "body": "alice private note: invoice 7781 for acme"},
    "2": {"owner": "bob", "body": "bob private note: password reset code 4417"},
}
_TEMPLATE_RE = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "LabTarget/1"
    state_changes: list[str] = []
    contacted_hosts: list[str] = []

    def log_message(self, *args) -> None:
        return

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8", headers: dict | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _user(self) -> str | None:
        return SESSIONS.get(self.headers.get("Cookie", "").strip())

    # -- routing ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        arg = lambda name: (query.get(name) or [""])[0]  # noqa: E731
        path = parts.path

        if path == "/search":  # error-based SQL injection
            q = arg("q")
            if "'" in q:
                return self._send(500, "<pre>You have an error in your SQL syntax; check the manual near '" + q + "' at line 1</pre>")
            return self._send(200, f"<p>3 results</p>")
        if path == "/search_safe":
            return self._send(200, "<p>3 results</p>")
        if path == "/item":  # boolean-based blind SQL injection
            raw = arg("id")
            if "1=2" in raw.replace(" ", ""):
                return self._send(200, "<h1>Item</h1><p>not found</p>")
            return self._send(200, "<h1>Item</h1><p>Widget, in stock</p>")
        if path == "/item_safe":
            return self._send(200, "<h1>Item</h1><p>Widget, in stock</p>" if arg("id").startswith("1") else "<p>bad id</p>")
        if path == "/greet":  # reflected XSS
            return self._send(200, f"<html><body>Hello {arg('name')}</body></html>")
        if path == "/greet_safe":
            return self._send(200, f"<html><body>Hello {html.escape(arg('name'))}</body></html>")
        if path == "/render":  # template injection (arithmetic only)
            template = arg("tpl")
            rendered = _TEMPLATE_RE.sub(lambda m: str(int(m.group(1)) * int(m.group(2))), template)
            return self._send(200, f"<div>{rendered}</div>")
        if path == "/echo":  # reflects input but evaluates nothing
            return self._send(200, f"<div>{html.escape(arg('tpl'))}</div>")
        if path == "/file":  # path traversal into a fake passwd file
            name = arg("name")
            if ".." in name and name.endswith("passwd"):
                return self._send(200, FAKE_PASSWD, "text/plain")
            return self._send(200, "hello from readme", "text/plain")
        if path == "/file_safe":
            return self._send(200, "hello from readme", "text/plain")
        if path == "/go":  # open redirect
            return self._send(302, "", headers={"Location": arg("next")})
        if path == "/go_safe":
            return self._send(302, "", headers={"Location": "/home"})
        if path == "/note":  # IDOR: no ownership check
            note = NOTES.get(arg("id"))
            if self._user() is None:
                return self._send(401, "login required")
            return self._send(200, note["body"]) if note else self._send(404, "no such note")
        if path == "/mynote":  # ownership enforced
            note = NOTES.get(arg("id"))
            user = self._user()
            if user is None:
                return self._send(401, "login required")
            if not note or note["owner"] != user:
                return self._send(403, "forbidden")
            return self._send(200, note["body"])
        if path == "/admin/report":  # missing authentication
            return self._send(200, "internal report: quarterly revenue 4.2M")
        if path == "/fetch":  # SSRF
            url = arg("url")
            try:
                urllib.request.urlopen(url, timeout=3).read(10)  # noqa: S310 - lab target
            except Exception:  # noqa: BLE001
                pass
            return self._send(200, "fetched")
        if path == "/bounce":  # redirects somewhere else, used to prove redirects are not followed
            return self._send(302, "", headers={"Location": arg("to")})
        if path == "/big":  # larger than the response cap
            return self._send(200, "A" * (400 * 1024), "text/plain")
        if path == "/seen":
            _Handler.contacted_hosts.append(self.headers.get("Host", ""))
            return self._send(200, "seen")
        return self._send(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        _Handler.state_changes.append(self.path)
        self._send(200, "deleted")

    do_DELETE = do_POST  # noqa: N815


class LabTarget:
    """Context manager running the lab target on a free loopback port."""

    def __init__(self) -> None:
        _Handler.state_changes = []
        _Handler.contacted_hosts = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def state_changes(self) -> list[str]:
        return _Handler.state_changes

    @property
    def contacted_hosts(self) -> list[str]:
        return _Handler.contacted_hosts

    def __enter__(self) -> "LabTarget":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
