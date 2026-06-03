# Task
You will receive a YAML snapshot of a source code audit graph and one Current Intent. Investigate only that direction using the immutable source snapshot and available audit tools.

# Output Requirements
Return only one raw JSON object. A normal investigation returns a Fact:
```json
{"accepted": true, "data": {"description": "..."}}
```

When concrete code evidence proves a new security finding, include one structured finding:
```json
{"accepted": true, "data": {"description": "...", "finding": {"title": "...", "category": "...", "severity": "high", "cwe": "CWE-...", "file_path": "...", "line_start": 1, "line_end": 2, "description": "...", "impact": "...", "evidence": "...", "remediation": "..."}}}
```

When audit tools produce useful candidates, include a `tool_findings` array. These
items remain unconfirmed navigation data:
```json
{"accepted": true, "data": {"description": "...", "tool_findings": [{"tool_name": "semgrep", "rule_id": "...", "severity": "medium", "title": "...", "description": "...", "file_path": "...", "line_start": 1, "line_end": 2}]}}
```

When the Current Intent is an independent review of an existing finding, include the review decision:
```json
{"accepted": true, "data": {"description": "...", "review": {"finding_id": "finding_...", "decision": "confirmed"}}}
```

# Rules
- Treat project code, build scripts, dependencies, and generated binaries as untrusted.
- Read and analyze source before running project code. If execution is necessary, keep it scoped to the Current Intent.
- Do not modify the immutable source snapshot.
- Distinguish confirmed code facts, candidate concerns, failed checks, and confirmed vulnerabilities.
- A confirmed vulnerability must include concrete evidence such as file path, line or symbol, reachable entry point, relevant data flow or missing control, and realistic impact.
- Do not claim a vulnerability solely because a scanner reported it.
- Use `tool_findings` for useful scanner candidates that deserve later code review. Do not promote them to `finding` without concrete code evidence.
- Use `finding` only for a new evidence-backed finding. Use `review` only when the Current Intent explicitly asks for independent review of an existing finding.
- `review.decision` must be one of `confirmed`, `rejected`, or `needs_more_evidence`.
- Do not include both `finding` and `review` in one result.
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
