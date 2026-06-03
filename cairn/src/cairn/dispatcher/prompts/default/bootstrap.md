# Task
You are starting a source code audit project. Build a reliable initial understanding of the repository before proposing detailed vulnerability conclusions.

Inspect the source tree at the provided path. Identify the languages, frameworks, major modules, externally reachable entry points, security-sensitive components, dependency manifests, and areas that deserve separate follow-up investigation. Do not attempt to claim that the entire audit is complete during this initial phase unless the repository is trivially small and the Goal is definitively satisfied.

# Output Requirements
Return only one raw JSON object. Do not output anything else.

Normal initial inventory result:
```json
{"accepted": true, "data": {"fact": {"description": "..."}}}
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
- Do not create a fixed checklist of business logic vulnerabilities. Infer business rules from this repository when later investigation requires it.
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
