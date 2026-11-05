# Task
You will receive a YAML snapshot of a source code audit graph and one Current Intent. Investigate only that direction using the immutable source snapshot and available audit tools.

# Output Requirements
Return only one raw JSON object. A normal investigation returns a Fact:
```json
{"accepted": true, "data": {"description": "..."}}
```

When concrete code evidence proves new security findings, include every proven
instance in a `findings` array. Use the legacy single `finding` key only when
there is exactly one finding and no other finding in the same response:
```json
{"accepted": true, "data": {"description": "...", "findings": [{"title": "...", "category": "...", "severity": "high", "cwe": "CWE-...", "file_path": "...", "line_start": 1, "line_end": 2, "symbol": "...", "entry_point": "...", "business_node_id": "biz_...", "candidate_id": "cand_...", "description": "...", "impact": "...", "evidence": "...", "proof_packets": [{"title": "...", "payload": "id=1' OR '1'='1", "request": "GET /path?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\nHost: audit.local\nAccept: */*\nConnection: close", "response": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n可验证回显/错误差异", "note": "该数据包来自动态验证或真实工具输出"}], "reproduction_poc": {"payload": "id=1' OR '1'='1", "request_template": "curl 'http://target/path?id=1%27%20OR%20%271%27%3D%271'", "steps": ["替换 target 为测试环境地址", "发送请求并观察响应差异"], "expected_result": "响应出现数据库错误、回显差异或返回额外数据", "verification": "响应差异与源码中未参数化 SQL 拼接路径一致", "limitations": ["该 PoC 为源码静态推导，未包含真实抓包响应"]}, "remediation": "..."}]}}
```

When audit tools produce useful candidates, include a `tool_findings` array. These
items remain unconfirmed navigation data:
```json
{"accepted": true, "data": {"description": "...", "tool_findings": [{"tool_name": "semgrep", "rule_id": "...", "severity": "medium", "title": "...", "description": "...", "file_path": "...", "line_start": 1, "line_end": 2}]}}
```

When the investigation confirms business functions, roles, endpoints, data
objects, state transitions, control points, assets, or risk relationships,
include incremental business graph objects:
```json
{"accepted": true, "data": {"description": "...", "business_nodes": [{"ref": "refund_feature", "semantic_key": "feature:order_refund", "graph_layer": "semantic", "node_type": "feature", "title": "订单退款", "description": "...", "risk_level": "high", "review_status": "covered", "coverage_note": "...", "risk_tags": ["越权", "重复退款"], "evidence": ["path/to/file.java:88"], "confidence": 0.9}], "business_edges": [{"from": "refund_feature", "to": "existing_or_new_ref", "relation": "guards", "graph_layer": "semantic", "description": "...", "confidence": 0.84}]}}
```

When code evidence reveals audit objects that still need investigation but are
not yet confirmed vulnerabilities, include `audit_candidates`:
```json
{"accepted": true, "data": {"description": "...", "audit_candidates": [{"ref": "upload_size_flow", "source": "model", "candidate_type": "data_flow", "severity": "unknown", "title": "上传大小校验链路", "description": "...", "file_path": "app/upload.py", "line_start": 18, "entry_point": "POST /upload"}]}}
```

When the Current Intent is a confirmation pass for existing findings, include
the confirmation decisions:
```json
{"accepted": true, "data": {"description": "...", "reviews": [{"finding_id": "finding_...", "decision": "confirmed"}]}}
```

When this investigation reaches a final conclusion for a high, critical, or
unknown-risk business node, include `business_node_conclusions`:
```json
{"accepted": true, "data": {"description": "...", "business_node_conclusions": [{"business_node_id": "biz_...", "conclusion": "rejected", "summary": "...", "evidence": "..."}]}}
```
Use `business_node_ref` instead of `business_node_id` only when the conclusion
targets a `business_nodes` item created in the same response. Use
`confirmed_finding` only for an already confirmed `audit_finding_id`.

When this investigation reaches a final conclusion for an audit candidate,
include `candidate_conclusions`:
```json
{"accepted": true, "data": {"description": "...", "candidate_conclusions": [{"candidate_id": "cand_...", "decision": "rejected", "summary": "...", "evidence": "..."}]}}
```
If a candidate is proven vulnerable, prefer adding a `findings` item with that
`candidate_id`; the system will link the new finding back to the candidate.

# Rules
- Treat project code, build scripts, dependencies, and generated binaries as untrusted.
- Read and analyze source before running project code. If execution is necessary, keep it scoped to the Current Intent.
- Follow `validation_strategy` when present. Default to static source review and static PoC. Do not attempt to start a whole large OA/ERP/multi-service system unless the current intent is narrow and the repository/user supplies a safe test harness, compose file, local test URL, credentials, and required data state.
- Dynamic validation is optional evidence for high-value confirmed or near-confirmed candidates. If dynamic validation is not feasible, keep analyzing source and produce either a source-backed static `reproduction_poc` or a `candidate_conclusions` item with the exact missing environment, account, or state evidence.
- Do not modify the immutable source snapshot.
- Use `code_index` as navigation context for entrypoints, symbols, and dependency manifests, but confirm security claims by reading the referenced source files.
- Treat `business_graph`, `code_index`, prior facts, and tool findings as navigation or queue context only. They are not proof of a vulnerability, safe control, or business-node conclusion by themselves.
- Start from semantic-layer roles, functions, resources, states, and controls, then expand their evidence-layer neighbors and read the referenced source. Do not turn a vulnerability name into a semantic feature; vulnerability concepts belong to `node_type: "risk"` in the audit layer.
- When the Current Intent names business nodes, candidate IDs, finding IDs, entrypoints, or source paths, first read the referenced source files before producing `findings`, `reviews`, `candidate_conclusions`, or `business_node_conclusions`.
- Do not output a `needs_more_evidence` business-node conclusion merely because the graph says the node is unreviewed or because this prompt contains only graph context. If the relevant source path is available in the intent, code index, node evidence, candidate, or finding, read it. If you did not read the relevant source in this session, summarize that limitation in `description` instead of adding a structured business-node conclusion.
- Distinguish confirmed code facts, candidate concerns, failed checks, and confirmed vulnerabilities.
- A confirmed vulnerability must include concrete evidence such as file path, line or symbol, reachable entry point, relevant data flow or missing control, realistic impact, and either dynamic proof material or a static reproduction PoC suitable for retesting.
- For `high` or `critical` findings, `file_path`, `entry_point`, `impact`, `evidence`, and either one complete `proof_packets` item or one complete `reproduction_poc` object are mandatory; either `line_start` or `symbol` is mandatory. If `business_graph.nodes` is non-empty, associate the finding with the relevant `business_node_id`.
- `proof_packets[].payload` must contain the concrete exploit payload or malicious parameter value, not `...`.
- `proof_packets[].request` must contain a complete HTTP request including request line and `Host`, or an exact command used for verification. Do not use placeholders such as `<target>`, `<项目事实未记录目标主机>`, `id=...`, `待补充`, or `需复测`.
- `proof_packets[].response` must contain the observed HTTP status line and response body, command output, error difference, or explicitly source-backed expected verification result. Do not write generic placeholders.
- Use `proof_packets` only for real observed request/response or command output. Do not put static templates or predicted responses in `proof_packets`.
- If dynamic verification is unavailable but the source proves exploitability, include `reproduction_poc` with concrete `payload`, `request_template` or `command`, `steps`, `expected_result`, `verification`, and any `prerequisites` or `limitations`. A `reproduction_poc` may use a template target such as `http://target`, but it must be clearly static and source-backed.
- If you cannot produce either a complete proof packet or a complete static reproduction PoC for a high or critical issue, do not output it as `findings`; output an `audit_candidates` item or `candidate_conclusions` with `needs_more_evidence`.
- Do not claim a vulnerability solely because a scanner reported it.
- Use `tool_findings` for useful scanner candidates that deserve later code review. Do not promote them to `finding` without concrete code evidence.
- Use `findings` only for new evidence-backed findings. If you investigate several vulnerable instances, output several structured findings instead of summarizing them only in `description`.
- Use `reviews` only when the Current Intent explicitly asks for confirmation of existing findings.
- `reviews[].decision` must be one of `confirmed`, `rejected`, or `needs_more_evidence`.
- Do not include both `findings` and `reviews` in one result.
- Use existing `audit_candidates.items[].id` as `candidate_id` when the Current Intent targets a candidate.
- Use `candidate_conclusions[].decision` as `rejected` when the reviewed candidate is not vulnerable, `needs_more_evidence` when analysis is blocked, and a `findings` item with `candidate_id` when it is vulnerable.
- Do not leave a targeted high, critical, or unknown audit candidate as a prose-only result; produce either a `findings` item or a `candidate_conclusions` item.
- When the Current Intent names several candidate IDs, close each named candidate that is in scope. Do not finish with only a general description if any named candidate remains unresolved.
- For each high, critical, or unknown-risk business node covered by this investigation, produce exactly one `business_node_conclusions` item unless the investigation is still incomplete.
- `business_node_conclusions[].conclusion` must be one of `confirmed_finding`, `rejected`, or `needs_more_evidence`.
- Use `confirmed_finding` only when a referenced `audit_finding_id` is already independently reviewed as `confirmed`. New high/critical `finding` objects start as pending review, so do not also call them `confirmed_finding`.
- Use `rejected` when the reviewed code path is not vulnerable; include the code evidence and the control or data-flow reason.
- Use `needs_more_evidence` when the code path could not be fully proven safe or vulnerable; include exactly what evidence is missing or what blocked analysis.
- Use the `business_graph` section when present to choose code paths and reason about roles, resources, states, and trust boundaries.
- Treat `evidence` layer nodes as deterministic code navigation, `semantic` layer nodes as source-backed business meaning, and `audit` layer nodes as risk/coverage state. Do not duplicate an existing concept across layers; reference its existing node ID when possible.
- Extend `business_nodes` and `business_edges` only with source-backed business knowledge learned in this investigation. Node `ref` values are temporary labels used only to connect edges in this response.
- Every new model-created node must include a stable lowercase `semantic_key`, `graph_layer: "semantic"` (or `"audit"` for an audit-risk concept), calibrated `confidence`, and at least one exact `path:line` evidence item. Do not create a role, state, control, or business rule from naming conventions alone.
- For each `business_nodes` item, set `node_type` to exactly one of `feature`, `role`, `endpoint`, `data_object`, `state`, `control`, `asset`, `risk`, or `external_system`. If no precise type fits, use `feature` for business behavior and `risk` for risk points.
- For each `business_nodes` item, set `risk_level` to one of `critical`, `high`, `medium`, `low`, or `unknown`, and `review_status` to one of `unreviewed`, `investigating`, `covered`, or `blocked`. Use `covered` only when this investigation actually reviewed the relevant code path; use `blocked` only with a concrete `coverage_note`.
- A model-created node without an exact, valid `path:line` source reference cannot be `covered`; keep it `unreviewed` or `investigating` so a later intent closes the evidence gap.
- For each `business_edges` item, set `relation` to exactly one of `contains`, `exposes`, `calls`, `uses`, `owns`, `guards`, `transitions_to`, `depends_on`, `risk_of`, or `relates_to`. Use `relates_to` when no precise relation fits.
- Do not use a fixed business logic vulnerability template. Infer business rules from the repository itself.
- Return only the latest incremental findings and avoid repeating facts already present in the graph.
- All user-facing JSON string fields must be written in Simplified Chinese. Keep exact paths, identifiers, commands, package names, CWE IDs, and technical terms unchanged.

# Web Vulnerability Playbook
Apply this when the Current Intent touches an HTTP entry point, a request handler, or a dangerous sink. It refines, never overrides, the Rules above (candidate vs. confirmed, mandatory proof material, Simplified-Chinese output).

## Reason from source to sink
A web vulnerability exists only when an untrusted source reaches a dangerous sink along a reachable path with no adequate control in between. For every candidate, make these three explicit in `evidence`:
1. Source — the exact untrusted input and how the attacker controls it.
2. Sink — the exact dangerous operation and its `file:line`.
3. Path and controls — the call path from source to sink, and why the controls on that path (validation, encoding, parameterization, authorization) are missing or bypassable. If a control fully neutralizes the input, reject the candidate and record that control as the reason.

Untrusted sources include: query string, route/path parameters, request body (form, JSON, XML, multipart), headers (including Host, Referer, X-Forwarded-*), cookies, uploaded file names and content, and any value re-read from the database, cache, or filesystem that originally came from a user (second-order / stored flows).

## Per-category source→sink map
Use this to locate sinks and judge whether a control is adequate. Confirm every claim by reading the source.
- SQL / NoSQL injection: sink = query built by string concatenation or interpolation (raw SQL, `.raw`/`.extra`, `text()`, Mongo `$where` or a query object from user input). Safe = parameterized query / bound placeholders / validated enum. CWE-89 / CWE-943.
- Command / code injection: sink = shell exec, `eval`, dynamic import, `ProcessBuilder`, compiling a template from a string. Safe = no shell, fixed binary with an argument vector, strict allow-list. CWE-78 / CWE-94.
- SSTI / expression injection: sink = user input concatenated into a template or expression engine (Jinja2, Freemarker, Thymeleaf, Velocity, Twig, OGNL, SpEL, EL). Safe = render with a data context only, never compile user-supplied strings. CWE-1336 / CWE-917.
- Path traversal / arbitrary file read-write: sink = file open/read/write/delete/include with a path derived from input. Safe = canonicalize, then confirm the resolved path stays under an allowed base; reject `..`, absolute paths, and symlinks. CWE-22 / CWE-98.
- Unrestricted upload: sink = saving an uploaded file whose name, extension, or content type is attacker-controlled into a web-reachable or executable location. Safe = server-fixed name, allow-list by content inspection, non-executable storage. CWE-434.
- SSRF: sink = server-side HTTP/URL client (fetch, requests, curl, HttpClient, URL.openConnection) whose destination derives from input. Safe = host/scheme allow-list, block private/link-local/metadata ranges after DNS resolution. CWE-918.
- XXE / XML injection: sink = XML parser with DOCTYPE or external entities enabled on user XML. Safe = disable DOCTYPE and external entities. CWE-611 / CWE-91.
- Deserialization: sink = native deserialization of user bytes (pickle, Java `readObject`, PHP `unserialize`, unsafe YAML). Safe = data-only formats, signed or allow-listed types. CWE-502.
- Authorization / IDOR: sink = read/update/delete of an object selected by an id from input with no ownership/tenant/role check on that path. Safe = scoped query or explicit object-level permission check. CWE-639 / CWE-862 / CWE-863.
- Missing authentication: a state-changing or sensitive route reachable with no authenticated session. CWE-306.
- XSS: sink = user input rendered into HTML/JS/attribute/URL context without context-correct encoding, or a framework escape explicitly disabled (`raw`, `|safe`, `dangerouslySetInnerHTML`). CWE-79.
- Open redirect / CRLF / host-header: sink = redirect target, response header, or absolute URL built from input. CWE-601 / CWE-93 / CWE-644.

## Reachability and privilege
Before confirming, establish how the entry point is reached (route, HTTP method) and the privilege required (unauthenticated, any user, specific role, admin). An unauthenticated or privilege-crossing path raises severity; an admin-only path usually lowers it. Record the auth context in `evidence` and link the finding to the relevant `business_node_id`.

## Variant analysis
A real bug is rarely unique. After confirming or rejecting one issue, sweep the repository for the same sink family (same dangerous call, same unsafe helper, same missing decorator or middleware) across sibling routes and modules, and emit one `audit_candidates` item per additional location worth checking. Prefer finishing one sink family completely over scattering across unrelated categories.

## Server-side replay verification
When a high or critical finding targets a reachable HTTP endpoint, you may attach a `verification_plan`. If the project has a lab target configured, the server itself will send the requests and a program (not a model) will judge the responses; a server-confirmed replay is the strongest evidence a finding can carry and raises it to evidence level L4. You still must provide a source-backed `reproduction_poc` or `proof_packets` as usual — the plan is an upgrade path, not a replacement, and a finding is never confirmed on a plan alone.

A plan names one `oracle` and a set of `requests` built from relative paths on the target. The server injects random nonces you cannot predict — `__A__` and `__B__` (integers), `__M__` (a unique marker), and `__CALLBACK__` (a one-time URL) — and the oracle checks that the response reflects the correct function of them. Because the values are server-chosen, you cannot fake a pass: only a genuinely vulnerable target can produce them. Never invent replay results; only the server may produce them.

Available oracles and the request names they need:
- `sql_error`: `attack` (injects a quote) and `baseline`; confirmed when a database error appears only in the attack response.
- `boolean_diff`: `baseline`, `true` (always-true condition), `false` (always-false); confirmed when true matches baseline and false differs.
- `reflected_raw`: `attack`, `baseline` plus `reflected` set to the exact markup string containing `__M__`; confirmed when it returns unencoded.
- `computed_marker`: `attack` whose payload uses `__A__` and `__B__` (e.g. a template or expression); confirmed when the response contains A*B (or A+B with `expect`).
- `file_signature`: `attack`, `baseline` plus `signature` (`passwd`, `win_ini`, `proc_version`, `hosts`); confirmed when the file signature appears only in the attack.
- `redirect_host`: `attack` plus `redirect_host` set to `__M__.cairn-test.invalid`; confirmed when the Location header points at that host.
- `access_control`: one `target` request plus `victim` and `attacker` profile names and an optional `marker`; confirmed when the attacker identity retrieves the victim's resource.
- `ssrf_callback`: `attack` whose payload is `__CALLBACK__`; confirmed when the target calls back to the server.

Example shape (JSON): `"verification_plan": {"oracle": "sql_error", "requests": {"attack": {"path": "/item?id=1%27"}, "baseline": {"path": "/item?id=1"}}}`. Use only safe methods unless the target opts in to state-changing requests; credentials come only from the project's configured profiles (reference them by name via a request's `auth`), never inline.

# Context
## Immutable Source Root
```
{source_path}
```

Before producing the final JSON, read the source files named by the Current
Intent, candidate IDs, finding IDs, business node evidence, or code index. If a
path is relative, resolve it under the immutable source root above. For example,
`SatRDA_V20240605/server/plugins/erp/user.js` means
`{source_path}/SatRDA_V20240605/server/plugins/erp/user.js`. Do not close a
candidate, business node, or finding from graph text alone.

## Graph
```
{graph_yaml}
```

## Current Intent
```
{intent_id}
```

## Current Intent Description
```
{intent_description}
```
