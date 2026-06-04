# Task
You are starting a source code audit project. Build a reliable initial understanding of the repository before proposing detailed vulnerability conclusions.

Inspect the source tree at the provided path. Identify the languages, frameworks, major modules, externally reachable entry points, security-sensitive components, dependency manifests, and areas that deserve separate follow-up investigation. Do not attempt to claim that the entire audit is complete during this initial phase unless the repository is trivially small and the Goal is definitively satisfied.

# Output Requirements
Return only one raw JSON object. Do not output anything else.

Normal initial inventory result:
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
```

When you can confirm business functions, roles, endpoints, data objects, state
transitions, control points, assets, or risk points from source evidence, include
incremental business graph objects:
```json
{"accepted": true, "data": {"fact": {"description": "..."}, "business_nodes": [{"ref": "login_feature", "node_type": "feature", "title": "用户登录", "description": "...", "risk_level": "unknown", "review_status": "unreviewed", "coverage_note": "...", "risk_tags": ["账号接管"], "evidence": ["path/to/file.py:42"]}], "business_edges": [{"from": "login_feature", "to": "existing_or_new_ref", "relation": "exposes", "description": "..."}]}}
```

Only when Goal is definitively satisfied:
```json
{"accepted": true, "data": {"fact": {"description": "..."}, "complete": {"description": "..."}}}
```

# Rules
- Treat the repository as untrusted code.
- Read source files and metadata before running project code, installers, build scripts, tests, or generated binaries.
- Do not modify the immutable source snapshot.
- Record confirmed repository facts, not speculative vulnerabilities.
- Include the source path, detected languages, important manifests, key entry points, and high-value audit areas.
- Build an initial business map when the code exposes clear business functions, roles, routes, resources, states, or trust boundaries.
- For each `business_nodes` item, set `node_type` to exactly one of `feature`, `role`, `endpoint`, `data_object`, `state`, `control`, `asset`, `risk`, or `external_system`. If no precise type fits, use `feature` for business behavior and `risk` for risk points.
- For each `business_nodes` item, set `risk_level` to one of `critical`, `high`, `medium`, `low`, or `unknown`, and `review_status` to one of `unreviewed`, `investigating`, `covered`, or `blocked`. During bootstrap, prefer `unreviewed` unless the node is fully covered by the initial inventory.
- For each `business_edges` item, set `relation` to exactly one of `contains`, `exposes`, `calls`, `uses`, `owns`, `guards`, `transitions_to`, `depends_on`, `risk_of`, or `relates_to`. Use `relates_to` when no precise relation fits.
- Do not create a fixed checklist of business logic vulnerabilities. Infer business rules from this repository when later investigation requires it.
- Use `business_nodes` and `business_edges` only for source-backed business knowledge, not guesses. Node `ref` values are temporary labels used only to connect edges in this response.
- Do not claim a vulnerability without concrete evidence.
- All user-facing JSON string fields must be written in Simplified Chinese. Keep exact paths, identifiers, commands, package names, and technical terms unchanged.

# Context
## Source Path
```
{source_path}
```

## Origin
```
{origin}
```

## Goal
```
{goal}
```

## Hints
```
{hints}
```
