# Web 漏洞审计方法论

本文件是 Rabbit Code Audit 针对 Web 应用漏洞的审计方法论基线。它被压缩后写入
`bootstrap`、`explore`、`reason` 三个审计提示词，审计提示词是运行时真正驱动模型的指令，
本文件是可供人阅读、评审和迭代的完整版本。

方法论遵循当前主流 AI 代码审计实践：先建威胁模型，再做 source→sink 数据流推理，每个结论都要
区分候选与确认，确认漏洞必须带可复测的证据，确认一个漏洞后要做同类变体扫描。

## 一、核心原则：source → sink

一个 Web 漏洞成立，当且仅当**不可信输入（source）沿着可达路径到达危险操作（sink），
且路径上没有足够的控制**。审计每个候选时，必须在 `evidence` 中写清三件事：

1. **Source**：具体的不可信输入，以及攻击者如何控制它。
2. **Sink**：具体的危险操作，以及它所在的 `file:line`。
3. **Path 与控制**：从 source 到 sink 的调用路径，以及路径上的控制（校验、编码、参数化、
   鉴权）为什么缺失或可绕过。如果某个控制能完全中和输入，就应驳回候选，并把该控制记为驳回理由。

### 不可信输入来源

- URL 查询串、路由 / 路径参数
- 请求体：表单、JSON、XML、multipart
- 请求头：包含 `Host`、`Referer`、`X-Forwarded-*` 等
- Cookie
- 上传文件的文件名与内容
- **二阶 / 存储型**：先前由用户写入、之后再从数据库 / 缓存 / 文件系统读回的值

## 二、分类 source → sink → 安全写法对照

用于定位 sink，并判断控制是否充分。每一条都必须读源码确认，不能凭命名或工具告警下结论。

| 类别 | Sink 特征 | 安全写法 | CWE |
|---|---|---|---|
| SQL 注入 | 字符串拼接 / 插值构造查询：裸 SQL、`.raw` / `.extra`、`text()` | 参数化查询 / 绑定占位符 / 校验枚举 | CWE-89 |
| NoSQL 注入 | 用户对象直接进入查询，Mongo `$where`、查询条件来自用户 | 字段白名单、类型校验、不接受运算符对象 | CWE-943 |
| 命令注入 | `system` / `exec` / `shell_exec` / `popen` / `ProcessBuilder` 带用户数据 | 不走 shell，固定二进制 + 参数数组，严格白名单 | CWE-78 |
| 代码注入 | `eval`、动态 `import`、动态编译 | 不对用户串求值 | CWE-94 |
| SSTI / 表达式注入 | 用户输入拼接进模板或表达式引擎：Jinja2、Freemarker、Thymeleaf、Velocity、Twig、OGNL、SpEL、EL | 只传数据上下文渲染，绝不编译用户串 | CWE-1336 / CWE-917 |
| 路径穿越 / 任意文件读写 | 文件 open/read/write/delete/include，路径来自输入 | 规范化后确认解析路径仍在允许目录内；拒绝 `..`、绝对路径、符号链接 | CWE-22 / CWE-98 |
| 任意文件上传 | 保存上传文件时文件名 / 扩展名 / 内容类型由攻击者控制，落到 Web 可达或可执行目录 | 服务端固定文件名、按内容识别做扩展名白名单、存储目录不可执行 | CWE-434 |
| SSRF | 服务端 HTTP / URL 客户端（fetch、requests、curl、HttpClient、`URL.openConnection`）目标来自输入 | host / scheme 白名单，DNS 解析后拦截内网 / 链路本地 / 元数据地址 | CWE-918 |
| XXE / XML 注入 | XML 解析器对用户 XML 开启 DOCTYPE 或外部实体 | 关闭 DOCTYPE 与外部实体 | CWE-611 / CWE-91 |
| 反序列化 | 对用户字节做原生反序列化：pickle、Java `readObject`、PHP `unserialize`、不安全 YAML | 用纯数据格式、签名或类型白名单 | CWE-502 |
| 越权 / IDOR | 按输入里的 id 读 / 改 / 删对象，路径上没有归属 / 租户 / 角色校验 | 带作用域的查询，或显式对象级权限校验 | CWE-639 / CWE-862 / CWE-863 |
| 未认证访问 | 改状态或敏感路由无需认证会话即可到达 | 统一认证中间件覆盖敏感路由 | CWE-306 |
| XSS | 用户输入进入 HTML / JS / 属性 / URL 上下文未做上下文编码，或框架转义被显式关闭（`raw`、`|safe`、`dangerouslySetInnerHTML`） | 按输出上下文编码，默认开启框架自动转义 | CWE-79 |
| 开放重定向 / CRLF / Host 头 | 跳转目标、响应头、绝对 URL 由输入拼接 | 跳转白名单，响应头剥离 CR/LF，固定可信 Host | CWE-601 / CWE-93 / CWE-644 |
| CSRF | 改状态接口无 CSRF token / SameSite 防护，且依赖 Cookie 鉴权 | CSRF token、SameSite、校验来源 | CWE-352 |

## 三、可达性与权限

确认前要确定入口怎么到达（路由、HTTP 方法）以及到达所需权限（未认证 / 任意用户 /
特定角色 / 管理员）。未认证或跨权限路径会抬高严重度；仅管理员可达的路径通常降低严重度。
把权限上下文写进 `evidence`，并把 finding 关联到对应的 `business_node_id`。

## 四、变体分析

真实漏洞很少只有一处。确认或驳回一个问题后，应在整个仓库里扫同一 sink 家族（相同危险调用、
相同不安全封装、相同缺失的装饰器 / 中间件），覆盖兄弟路由和其他模块，为每个值得查的额外位置
产出一个 `audit_candidates`。优先把一个 sink 家族彻底查完，而不是在互不相关的类别间跳来跳去。

> 注意：导入快照会剥离 `.git`，因此变体分析是"同类 sink 在全仓库的横向扫描"，
> 而不是基于提交历史的回溯。

## 五、威胁建模（bootstrap 阶段）

对 Web 项目，bootstrap 要在既有预算内（最多 20 个文件、最多 20 个业务节点）测绘攻击面：

- **框架与路由**：识别 Web 框架以及请求如何到达 handler（路由表、控制器、装饰器、注解、
  文件名路由）；记录模板引擎、ORM / DB 层、HTTP 客户端库——它们就是 sink 家族。
- **入口族**：把对外入口按族归类（如 auth / user / admin / file / API），标注每族是未认证、
  任意登录用户，还是仅特权角色可达。不要枚举每条路由，每族建一个 `endpoint` 或 `feature`
  语义节点并给代表性 `path:line` 证据。
- **认证授权模型**：定位身份与权限在哪里强制执行（中间件、装饰器、基类控制器、过滤器），
  用 `role` / `control` 节点和 `guards` 边表达。缺失或不一致的校验是高价值线索。
- **信任边界与 sink 清单**：记录代码里存在哪些危险 sink 家族（SQL、命令 / 代码执行、
  文件读写 / 上传、模板渲染、服务端 HTTP 客户端、XML 解析、原生反序列化），作为 audit 层
  `risk` 节点标为 `unreviewed` 待后续调查。此阶段不下漏洞结论。

## 六、规划优先级（reason 阶段）

- 先查未认证与跨权限入口，再查已认证的改状态操作，最后查只读路径。
- 优先处理尚无结论、且用户输入可达的危险 sink。
- 确认一个漏洞后，排一个变体分析 intent 扫同类 sink 家族，再转到别的类别。
- 按共享入口族、共享 sink 家族或共享缺失控制来批量组织 intent，让一个 explore 任务能读完
  相关源码并关闭整批候选。
- 只要还有未认证 / 跨权限 Web 入口，或用户可达的危险 sink，没有带证据的结论，就不结项。

## 七、验证与证据分级

沿用系统既有的候选 / 确认分离纪律：

- **候选（audit_candidates）**：静态发现的可疑 source→sink 链路，未证实可达或可利用。
- **确认（findings）**：`high` / `critical` 必须给出 `file_path`、`entry_point`、`impact`、
  `evidence`，以及二选一：一条完整 `proof_packets`（真实观测到的请求 / 响应或命令输出）
  或一条完整 `reproduction_poc`（源码推导的静态可复测 PoC，需标注 `limitations`）。
- 证据不足时降级为 `audit_candidates` 或 `candidate_conclusions: needs_more_evidence`，
  并写清缺哪个文件 / 路由 / 环境 / 账号 / 状态。
- 严重和高危 finding 必须由不同 Worker 独立复核后才进入正式报告。

## 八、分类法

Web 漏洞类别及其 CWE 映射集中在 `cairn/src/cairn/server/finding_taxonomy.py`，
用于类别归一化与去重聚类。新增类别时同时补充英文 / 中文别名和 CWE 映射即可，无需改动其它代码。
