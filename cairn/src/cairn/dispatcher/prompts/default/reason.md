# Task
You will receive a YAML snapshot of a source code audit graph. Facts are confirmed audit knowledge. Intents are independent investigation directions.

Judge whether the current confirmed facts satisfy Goal. If not, propose a small number of high-value, non-overlapping audit intents that can be executed in parallel.

# Output Requirements
Return only one raw JSON object.

If Goal has been satisfied:
```json
{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "..."}}}
```

If new investigation directions are needed:
```json
{"accepted": true, "data": {"intents": [{"from": ["f001"], "target_kind": "audit_candidate", "target_id": "cand_...", "objective": "confirm_or_reject", "evidence_gap": "source_evidence", "description": "..."}]}}
```

If existing open intents already cover the valuable directions:
```json
{"accepted": true, "data": {}}
```

# Rules
- Completion means the requested audit scope has been covered and the remaining uncertainty is explicitly understood. Finding one vulnerability is not sufficient by itself.
- Use the repository facts, source snapshot metadata, `code_index`, tool findings, coverage information, and open intents in the graph.
- Use `context_profile` and `validation_strategy` as scoping information. A scoped export may omit unrelated graph items on purpose; do not infer they are absent from the project. Do not require dynamic validation before proposing static code-review intents.
- Use `code_index.entrypoints`, `code_index.symbols_sample`, and `code_index.dependency_manifests` to choose concrete audit directions instead of broad repository-wide guesses.
- Treat `business_graph`, `code_index`, prior facts, and tool findings as navigation context only. Intents must tell the explore worker to read source files before producing `findings`, `reviews`, `candidate_conclusions`, or `business_node_conclusions`.
- When proposing business-node coverage or conclusion intents, include concrete `source_targets` in the description: exact files, entrypoints, candidate IDs, finding IDs, symbols, or routes already visible in the graph. Do not ask for a conclusion based on graph text alone.
- If a high/critical/unknown business node has no concrete source target in the current scoped graph, propose a narrow intent to locate its source target first instead of asking for a final business-node conclusion.
- Use `audit_candidates` as the audit object queue. If `audit_candidates.coverage.open_required`, `audit_candidates.coverage.invalid_conclusions`, or `audit_candidates.coverage.pending_high_findings` is non-empty, do not complete the project.
- When open audit candidates exist, propose focused intents that name candidate IDs and small batches of related entry points, files, data flows, or tool findings. The intent must ask the worker to produce either structured `findings` or `candidate_conclusions`.
- For each new intent, fill `target_kind`, `target_id`, `objective`, and `evidence_gap` when the graph exposes a concrete target. Use `target_kind: "audit_candidate"` for candidate batches, `target_kind: "business_node"` for business graph coverage, and keep `target_id` to the concrete candidate/business node id or a comma-separated small batch of related ids.
- Treat `audit_candidates.items` from `source=index` as the coverage queue created by deterministic source indexing. `entrypoint`, `web_entrypoint`, and `data_flow` candidates are not vulnerability claims, but every critical/high/unknown open candidate must be closed by evidence-backed investigation before completion.
- Prefer candidate batches that share the same file, route, source variable, sink family, business node, or framework layer. Keep each batch small enough that the explore worker can read the relevant source and close every named candidate in one run.
- If many similar candidates exist, do not create one broad "audit all remaining SQL injection" intent. Create concrete batches that name candidate IDs and exact files or entry points.
- When high or critical audit findings are pending confirmation, do not create ordinary confirmation intents. Pending finding confirmation is handled by the automatic AI review task queue. Still do not complete the project while any high or critical finding remains pending confirmation.
- Use the `business_graph` section when present. Prefer intents that follow concrete business functions, roles, resources, state transitions, entry points, trust boundaries, sensitive operations, or tool-generated candidates.
- If `business_graph.coverage.high_or_unknown_open` is non-empty, do not complete the project. Propose intents that cover or explicitly block those business nodes unless existing open intents already cover them.
- If `business_graph.coverage.high_or_unknown_without_conclusion` or `business_graph.coverage.high_or_unknown_invalid_conclusion` is non-empty, do not complete the project. Propose intents that produce structured `business_node_conclusions` for those nodes unless existing open intents already cover them.
- Complete only when high/critical/unknown-risk business nodes are `covered` or `blocked` with a concrete uncertainty note and each has a structured conclusion: `confirmed_finding` linked to a confirmed finding, `rejected` with evidence, or `needs_more_evidence` with evidence.
- Keep intents independent and avoid duplicate analysis of the same code path.
- Do not use a fixed business logic vulnerability template. Infer business rules from the repository's own models, roles, state transitions, and workflows.
- Propose at most {max_intents} intents.
- All user-facing JSON string fields must be written in Simplified Chinese.

# Context
## Graph
```
{graph_yaml}
```

## Valid facts
```
{fact_ids}
```

## Open Intents
```
{open_intents}
```
