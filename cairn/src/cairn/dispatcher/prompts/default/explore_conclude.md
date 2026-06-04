# Task
This is the conclude phase for a source code audit investigation. Stop immediately and summarize only facts already confirmed for the Current Intent.

# Output Requirements
Return only one raw JSON object. You may include the same optional
`tool_findings`, `audit_candidates`, `findings`, `reviews`,
`candidate_conclusions`, or `business_node_conclusions` objects allowed by the
execute phase only when they are already supported by evidence gathered in this
session:
```json
{"accepted": true, "data": {"description": "..."}}
```

# Rules
- Do not run more commands or inspect more files.
- Do not turn scanner output or speculation into a confirmed vulnerability.
- Include exact code locations and evidence when already known.
- State inconclusive or non-exploitable results accurately.
- If multiple vulnerabilities were already proven in this session, include every one in `findings`; do not leave them only in prose.
- Any high or critical `findings` item must include either one complete `proof_packets` item with concrete `payload`, complete HTTP `request` including `Host` or exact command, and observed HTTP status line plus response body, or one complete `reproduction_poc` object with concrete `payload`, `request_template` or `command`, `steps`, `expected_result`, and `verification`.
- Do not use placeholders in proof packets: no `<target>`, `<项目事实未记录目标主机>`, `id=...`, `待补充`, `需复测`, or similar incomplete material.
- Use `proof_packets` only for real observed traffic or command output. If this session only supports a static source-backed PoC, put it in `reproduction_poc`, not in `proof_packets`.
- If this session did not gather either a complete proof packet or a complete static reproduction PoC, do not output a high or critical finding; return `needs_more_evidence` for the targeted candidate or only summarize the fact.
- Do not include both `findings` and `reviews` in one result.
- For a targeted audit candidate, include either a `findings` item with `candidate_id` when vulnerable, or a `candidate_conclusions` item with `decision` `rejected` or `needs_more_evidence`.
- `candidate_conclusions[].decision` must be one of `confirmed`, `rejected`, or `needs_more_evidence`; use `confirmed` only with an existing `audit_finding_id`.
- For high, critical, or unknown-risk business nodes already covered by this session, include a structured `business_node_conclusions` item with conclusion `confirmed_finding`, `rejected`, or `needs_more_evidence`.
- Use `confirmed_finding` only with an already confirmed `audit_finding_id`; otherwise use `needs_more_evidence` or return only the fact summary.
- If you include `business_edges`, set `relation` to exactly one of `contains`, `exposes`, `calls`, `uses`, `owns`, `guards`, `transitions_to`, `depends_on`, `risk_of`, or `relates_to`. Use `relates_to` when no precise relation fits.
- All user-facing JSON string fields must be written in Simplified Chinese.

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
