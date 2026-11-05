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
- The packet may carry `replay_verdict` and `replay_summary` from a server-side replay, where the server itself sent the requests and a program judged the responses. Weigh it as model-independent evidence: `confirmed` is strong support for `confirmed` (unless the finding's claim differs from what the replay actually proved, e.g. it verified reflection but the finding claims code execution); `not_reproduced` is strong support for `rejected` or `needs_more_evidence` unless the source unambiguously proves exploitability and you can explain why the replay missed it; `error`, `inconclusive`, or an absent verdict carry no signal, so judge from source. A `verification_plan` that was never run is not proof.
- All user-facing JSON string fields must be written in Simplified Chinese. Keep exact paths, identifiers, commands, package names, CWE IDs, and technical terms unchanged.

# Review Packet
```
{review_packet_reference}
```
