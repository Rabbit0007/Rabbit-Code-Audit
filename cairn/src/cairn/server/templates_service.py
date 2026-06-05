"""Built-in project templates for the Template Engine.

This module is intentionally a standalone module (``templates_service.py``)
rather than a ``services/templates.py`` package member. The existing
``cairn.server.services`` is a single module (``services.py``) imported across
the server (``from cairn.server.services import ...``); introducing a
``services/`` package would shadow that module and break those core imports. So
this additive service lives alongside ``vulnerability_extraction.py`` and
``templates_models.py`` instead, mirroring the convention already established in
this package.

Built-in templates are defined as an in-memory Python constant rather than being
stored in the database (see design.md, "Template Engine" / "Built-in
Templates"). Only user-created custom templates are persisted (in the
``templates`` table created by the product schema). The templates router merges
this constant list with a user's stored custom templates when answering
``GET /api/templates``.

Each built-in template carries a title, an ``origin`` fact, a ``goal`` fact, and
between 1 and 10 initial ``hints`` where every hint is a ``{content, creator}``
mapping whose ``creator`` is ``"template"``.

The shapes mirror :class:`cairn.server.templates_models.TemplateResponse`:
built-in templates use ``is_builtin=True`` and leave ``user_id`` as ``None``.
"""

from __future__ import annotations

# Marker stored in every built-in hint's ``creator`` field (requirement 12.2).
TEMPLATE_CREATOR = "template"


def _hint(content: str) -> dict[str, str]:
    """Build a ``{content, creator}`` hint with the template creator marker."""
    return {"content": content, "creator": TEMPLATE_CREATOR}


# The built-in templates surfaced by the Template Engine. Each entry mirrors the
# ``TemplateResponse`` shape (``is_builtin=True``, ``user_id=None``) so the
# templates router can return built-in and custom templates through one model.
BUILTIN_TEMPLATES: list[dict] = [
    {
        "id": "builtin-web-app",
        "title": "Web 应用源码审计",
        "origin": "待审计 Web 应用源码，技术栈为 [technology stack]，重点范围为 [scope]",
        "goal": "识别并记录源码中可被证明的安全漏洞、受影响路径和修复建议",
        "hints": [
            _hint("先建立路由、认证、权限和数据访问层的代码索引"),
            _hint("结合静态扫描结果追踪外部输入到敏感操作的数据流"),
            _hint("对高危和严重发现补充确认结论和证明材料"),
        ],
        "is_builtin": True,
        "user_id": None,
    },
    {
        "id": "builtin-api-backend",
        "title": "API 与后端服务审计",
        "origin": "待审计 API 或后端服务源码，框架为 [framework]，重点业务为 [business scope]",
        "goal": "验证接口鉴权、资源授权、数据校验和敏感操作中的安全缺陷",
        "hints": [
            _hint("建立控制器、中间件、服务层和 ORM 查询之间的调用关系"),
            _hint("关注对象级授权、批量操作、状态转换和多租户隔离"),
            _hint("不要使用固定逻辑漏洞模板，依据实际业务不变量提出假设"),
        ],
        "is_builtin": True,
        "user_id": None,
    },
    {
        "id": "builtin-dependency-supply-chain",
        "title": "依赖与供应链审计",
        "origin": "待审计代码仓库及其依赖清单、构建脚本和发布配置",
        "goal": "识别高风险依赖、凭据泄露、构建链和发布流程中的安全问题",
        "hints": [
            _hint("识别所有语言生态的依赖锁文件和包管理器配置"),
            _hint("检查仓库历史之外的当前快照是否包含密钥和敏感配置"),
            _hint("验证构建脚本、代码生成和发布权限边界"),
        ],
        "is_builtin": True,
        "user_id": None,
    },
    {
        "id": "builtin-full-repository",
        "title": "完整仓库代码审计",
        "origin": "待审计多语言代码仓库，核心组件和边界尚未明确",
        "goal": "建立仓库安全视图，完成重点风险区域审计并记录剩余不确定性",
        "hints": [
            _hint("先识别语言、框架、入口、配置、生成代码和原生组件"),
            _hint("使用工具结果导航，但不要把扫描器告警直接当作漏洞"),
            _hint("按风险和可达性拆分审计意图，逐步补全事实图"),
        ],
        "is_builtin": True,
        "user_id": None,
    },
]
