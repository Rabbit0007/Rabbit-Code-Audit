# Rabbit Code Audit Worker Environment

## Purpose

This container is used for source code audit work. The source snapshot is mounted read-only under:

```text
/audit-data/artifacts/snapshots/<snapshot-id>/source
```

Treat every repository as untrusted code.

## Audit Workflow

1. Read repository metadata and source before executing project code.
2. Use code search, language-specific analyzers, and dependency scanners to generate candidate findings.
3. Validate candidates by reading the relevant entry points, data flow, security controls, and realistic impact.
4. Do not claim a vulnerability solely because a tool reported it.
5. Do not modify the immutable source snapshot.
6. Store large logs or generated artifacts under `/home/kali/workspace`.
7. State exact paths, symbols, commands, and evidence in conclusions.

## Available Tool Categories

- Search and indexing: `rg`, `fd`, `ctags`, `jq`, `yq`
- General SAST: `semgrep`
- Secrets and supply chain: `gitleaks`, `osv-scanner`, `trivy`
- PHP: `psalm`, `phpstan`, `composer audit`
- Python: `bandit`, `pip-audit`
- JavaScript / TypeScript: `eslint`, `npm audit`
- Go: `gosec`, `govulncheck`
- Java: `spotbugs`, `findsecbugs`

Not every repository will support every tool. Prefer tools that match the detected languages and available manifests.

## Execution Safety

- Do not run installers, build scripts, tests, or generated binaries unless necessary for the current audit intent.
- Before execution, inspect the relevant scripts and explain why execution is needed.
- Do not assume network access or external services are available.
- Do not expose API keys, tokens, credentials, or sensitive environment variables in findings.
