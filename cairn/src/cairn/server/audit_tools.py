from __future__ import annotations

from dataclasses import dataclass

from cairn.server.source_models import CodeFile, SourceSnapshot


@dataclass(frozen=True)
class AuditToolPlan:
    name: str
    category: str
    command: list[str]
    reason: str
    output_format: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "command": self.command,
            "reason": self.reason,
            "output_format": self.output_format,
        }


def build_tool_plan(snapshot: SourceSnapshot, files: list[CodeFile], source_path: str) -> list[AuditToolPlan]:
    languages = set(snapshot.detected_languages)
    paths = {item.path for item in files}
    plans: list[AuditToolPlan] = [
        AuditToolPlan(
            name="semgrep",
            category="sast",
            command=["semgrep", "scan", "--config", "auto", "--json", source_path],
            reason="通用多语言静态分析与安全规则候选发现",
            output_format="json",
        ),
        AuditToolPlan(
            name="gitleaks",
            category="secrets",
            command=["gitleaks", "detect", "--no-git", "--source", source_path, "--report-format", "json"],
            reason="源码快照中的凭据与密钥候选发现",
            output_format="json",
        ),
        AuditToolPlan(
            name="osv-scanner",
            category="dependencies",
            command=["osv-scanner", "scan", "source", "-r", source_path, "--format", "json"],
            reason="依赖清单与锁文件中的已知漏洞候选发现",
            output_format="json",
        ),
        AuditToolPlan(
            name="trivy",
            category="dependencies",
            command=["trivy", "fs", "--format", "json", source_path],
            reason="文件系统依赖、配置与密钥补充扫描",
            output_format="json",
        ),
    ]
    if "PHP" in languages:
        if "composer.json" in paths:
            plans.append(
                AuditToolPlan(
                    name="composer-audit",
                    category="dependencies",
                    command=["composer", "audit", "--working-dir", source_path, "--format", "json"],
                    reason="PHP Composer 依赖漏洞检查",
                    output_format="json",
                )
            )
        plans.extend(
            [
                AuditToolPlan(
                    name="psalm",
                    category="sast",
                    command=["psalm", "--taint-analysis", "--no-cache", "--output-format=json", source_path],
                    reason="PHP 污点分析",
                    output_format="json",
                ),
                AuditToolPlan(
                    name="phpstan",
                    category="static-analysis",
                    command=["phpstan", "analyse", "--error-format=json", source_path],
                    reason="PHP 类型与异常代码路径分析",
                    output_format="json",
                ),
            ]
        )
    if "Python" in languages:
        plans.append(
            AuditToolPlan(
                name="bandit",
                category="sast",
                command=["bandit", "-r", source_path, "-f", "json"],
                reason="Python 安全规则扫描",
                output_format="json",
            )
        )
    if "Go" in languages:
        plans.extend(
            [
                AuditToolPlan(
                    name="gosec",
                    category="sast",
                    command=["gosec", "-fmt=json", "./..."],
                    reason="Go 安全规则与数据流候选发现，应在源码目录执行",
                    output_format="json",
                ),
                AuditToolPlan(
                    name="govulncheck",
                    category="dependencies",
                    command=["govulncheck", "-json", "./..."],
                    reason="Go 依赖与可调用漏洞检查，应在源码目录执行",
                    output_format="json",
                ),
            ]
        )
    if languages.intersection({"JavaScript", "TypeScript"}):
        plans.append(
            AuditToolPlan(
                name="eslint-security",
                category="sast",
                command=["eslint", "--format", "json", source_path],
                reason="JavaScript 与 TypeScript 安全热点扫描",
                output_format="json",
            )
        )
    return plans

