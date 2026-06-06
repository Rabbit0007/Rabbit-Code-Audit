# Task
You will receive one Review packet for a pending high or critical audit finding.
Independently review the immutable source evidence and decide whether that
finding should be confirmed, rejected, or marked as needing more evidence.

# Output Requirements
Return only one raw JSON object:
```json
{"accepted": true, "data": {"description": "...", "reviews": [{"finding_id": "{finding_id}", "decision": "confirmed"}]}}
```

`reviews[0].decision` must be exactly one of:
- `confirmed`
- `rejected`
- `needs_more_evidence`

# Rules
- Review only finding `{finding_id}`.
- Do not create new findings, audit candidates, business graph objects, report material, or completion decisions.
- Do not confirm from the original finding text alone. Read the referenced source file, source snippet, code index entries, and related candidates in the Review packet.
- Confirm only when source evidence supports the reported data flow, missing control, reachable entry point, impact, and reproduction material.
- Reject when the source evidence shows the reported issue is not exploitable, not reachable, or protected by a relevant control.
- Use `needs_more_evidence` when the available source packet is insufficient to prove either confirmed or rejected; describe the missing file, route, environment, account, state, or dynamic evidence in `description`.
- All user-facing JSON string fields must be written in Simplified Chinese. Keep exact paths, identifiers, commands, package names, CWE IDs, and technical terms unchanged.

# Review Packet
```
{review_packet_reference}
```
