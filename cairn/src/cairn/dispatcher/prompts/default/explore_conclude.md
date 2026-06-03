# Task
This is the conclude phase for a source code audit investigation. Stop immediately and summarize only facts already confirmed for the Current Intent.

# Output Requirements
Return only one raw JSON object. You may include the same optional
`tool_findings`, `finding`, or `review` objects allowed by the execute phase only
when they are already supported by evidence gathered in this session:
```json
{"accepted": true, "data": {"description": "..."}}
```

# Rules
- Do not run more commands or inspect more files.
- Do not turn scanner output or speculation into a confirmed vulnerability.
- Include exact code locations and evidence when already known.
- State inconclusive or non-exploitable results accurately.
- Do not include both `finding` and `review` in one result.
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
