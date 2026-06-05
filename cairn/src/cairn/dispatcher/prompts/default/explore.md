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
{"accepted": true, "data": {"description": "...", "business_nodes": [{"ref": "refund_feature", "node_type": "feature", "title": "订单退款", "description": "...", "risk_level": "high", "review_status": "covered", "coverage_note": "...", "risk_tags": ["越权", "重复退款"], "evidence": ["path/to/file.java:88"]}], "business_edges": [{"from": "refund_feature", "to": "existing_or_new_ref", "relation": "guards", "description": "..."}]}}
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
- Extend `business_nodes` and `business_edges` only with source-backed business knowledge learned in this investigation. Node `ref` values are temporary labels used only to connect edges in this response.
- For each `business_nodes` item, set `node_type` to exactly one of `feature`, `role`, `endpoint`, `data_object`, `state`, `control`, `asset`, `risk`, or `external_system`. If no precise type fits, use `feature` for business behavior and `risk` for risk points.
- For each `business_nodes` item, set `risk_level` to one of `critical`, `high`, `medium`, `low`, or `unknown`, and `review_status` to one of `unreviewed`, `investigating`, `covered`, or `blocked`. Use `covered` only when this investigation actually reviewed the relevant code path; use `blocked` only with a concrete `coverage_note`.
- For each `business_edges` item, set `relation` to exactly one of `contains`, `exposes`, `calls`, `uses`, `owns`, `guards`, `transitions_to`, `depends_on`, `risk_of`, or `relates_to`. Use `relates_to` when no precise relation fits.
- Do not use a fixed business logic vulnerability template. Infer business rules from the repository itself.
- Return only the latest incremental findings and avoid repeating facts already present in the graph.
- All user-facing JSON string fields must be written in Simplified Chinese. Keep exact paths, identifiers, commands, package names, CWE IDs, and technical terms unchanged.

# Context
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
