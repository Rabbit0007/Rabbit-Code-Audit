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
{"accepted": true, "data": {"intents": [{"from": ["f001"], "description": "..."}]}}
```

If existing open intents already cover the valuable directions:
```json
{"accepted": true, "data": {}}
```

# Rules
- Completion means the requested audit scope has been covered and the remaining uncertainty is explicitly understood. Finding one vulnerability is not sufficient by itself.
- Use the repository facts, source snapshot metadata, tool findings, coverage information, and open intents in the graph.
- Prefer intents that follow concrete repository structure, entry points, trust boundaries, sensitive operations, or tool-generated candidates.
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
