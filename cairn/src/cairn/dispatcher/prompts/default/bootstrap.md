# Task
You are starting a source code audit project. Build a reliable initial understanding of the repository before proposing detailed vulnerability conclusions.

Use the supplied Source Inventory as the navigation plan, then inspect a bounded set of source files at the provided path. Identify the languages, frameworks, major modules, externally reachable entry points, security-sensitive components, dependency manifests, and areas that deserve separate follow-up investigation. Do not attempt to claim that the entire audit is complete during this initial phase unless the repository is trivially small and the Goal is definitively satisfied.

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
{"accepted": true, "data": {"fact": {"description": "..."}, "business_nodes": [{"ref": "login_feature", "semantic_key": "feature:user_login", "graph_layer": "semantic", "node_type": "feature", "title": "用户登录", "description": "...", "risk_level": "unknown", "review_status": "unreviewed", "coverage_note": "...", "risk_tags": ["账号接管"], "evidence": ["path/to/file.py:42"], "confidence": 0.82}], "business_edges": [{"from": "login_feature", "to": "existing_or_new_ref", "relation": "exposes", "graph_layer": "semantic", "description": "...", "confidence": 0.78}]}}
```

Only when Goal is definitively satisfied:
```json
{"accepted": true, "data": {"fact": {"description": "..."}, "complete": {"description": "..."}}}
```

# Rules
- Treat the repository as untrusted code.
- Treat Source Inventory entries as static-analysis leads, not vulnerability proof. Confirm important claims by reading source.
- Read source files and metadata before running project code, installers, build scripts, tests, or generated binaries.
- Do not modify the immutable source snapshot.
- Inspect at most 20 high-priority source files during bootstrap. Prefer files named in `priority_candidates` and `priority_entrypoints`, then manifests and module boundaries.
- Do not enumerate every route, file, candidate, or static graph node. Group repeated routes and related files into modules and defer detailed vulnerability validation to follow-up intents.
- Keep the initial business graph compact: create at most 20 business nodes and 30 business edges, selecting only source-backed module, trust-boundary, asset, and high-value entry-point knowledge.
- The existing static graph is the `evidence` layer. Do not recreate routes, handlers, files, or index risk candidates as new nodes. Add only business semantics that static syntax cannot express, such as roles, business functions, business resources, states, approval/control rules, trust boundaries, and external business systems.
- Keep business behavior and vulnerability claims in separate layers. A semantic feature describes what the system does even when it is secure; SQL injection, XSS, authorization bypass, and similar vulnerability concepts must use `node_type: "risk"` and `graph_layer: "audit"`, never a semantic feature title.
- Every model-created node must use `graph_layer: "semantic"` (or `"audit"` only for a real audit-risk concept), a stable lowercase `semantic_key` such as `feature:order_refund`, `role:finance_reviewer`, or `state:order_paid`, a calibrated `confidence` from 0 to 1, and at least one exact `path:line` source evidence item.
- Reuse an existing business node ID from the supplied graph when it already represents the same concept. Never create a synonym node merely to use a different title.
- Record confirmed repository facts, not speculative vulnerabilities.
- Include the source path, detected languages, important manifests, key entry points, and high-value audit areas.
- Build an initial business map when the code exposes clear business functions, roles, routes, resources, states, or trust boundaries.
- For each `business_nodes` item, set `node_type` to exactly one of `feature`, `role`, `endpoint`, `data_object`, `state`, `control`, `asset`, `risk`, or `external_system`. If no precise type fits, use `feature` for business behavior and `risk` for risk points.
- For each `business_nodes` item, set `risk_level` to one of `critical`, `high`, `medium`, `low`, or `unknown`, and `review_status` to one of `unreviewed`, `investigating`, `covered`, or `blocked`. During bootstrap, prefer `unreviewed` unless the node is fully covered by the initial inventory.
- Never set `review_status: "covered"` without at least one exact `path:line` item that you read in this session. Missing or approximate evidence keeps the node `unreviewed` or `investigating`.
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

## Source Inventory
```json
{source_inventory}
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
