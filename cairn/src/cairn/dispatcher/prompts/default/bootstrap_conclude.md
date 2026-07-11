# Task
This is the conclude phase for an initial source code audit inventory. Stop immediately and summarize only repository facts already confirmed in this session.

# Output Requirements
Return only one raw JSON object:
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
```

# Rules
- Do not run more commands or inspect more files.
- Do not claim speculative vulnerabilities.
- Use the supplied Source Inventory only to organize facts already confirmed in this session; static candidates are navigation leads, not vulnerability proof.
- Summarize confirmed languages, frameworks, modules, entry points, manifests, and useful follow-up audit areas.
- All user-facing JSON string fields must be written in Simplified Chinese.

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
