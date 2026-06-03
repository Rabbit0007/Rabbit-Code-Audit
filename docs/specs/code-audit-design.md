# Rabbit Code Audit 设计

## 定位

Rabbit Code Audit 是从 Rabbit 派生的独立代码审计系统。它保留 Fact、Intent、
Hint、Dispatcher 和 Worker 的协作模型，但不与 Rabbit Pentest 共用部署、数据库、
容器或报告。

系统目标不是让扫描器直接宣布漏洞，而是建立以下闭环：

```text
源码导入 -> 不可变快照 -> 代码索引与工具扫描 -> 候选发现
       -> Worker 调查与验证 -> 独立复核 -> 已确认漏洞 -> 审计报告
```

## 源码输入

第一版支持：

- 公共 Git 仓库，可指定 branch、tag 或 commit。
- ZIP 压缩包上传。

两种输入最终都生成不可变源码快照。所有索引、扫描结果、Fact 和漏洞记录必须绑定
到具体快照，不能只绑定到项目。

### ZIP 限制

- 压缩文件最大 1 GiB。
- 解压后最大 5 GiB。
- 最大文件数量 200,000。
- 单文件最大 100 MiB。
- 禁止绝对路径、`..`、符号链接、特殊文件和路径冲突。
- 不自动递归解压嵌套压缩包。

## 核心数据

### Source Snapshot

记录源码来源、解析后的 commit 或哈希、文件数量、总大小、语言识别结果和导入状态。

### Code Index

第一阶段建立轻量索引：

- 文件路径、大小、扩展名和内容哈希。
- 语言分布。
- 后续扩展符号、引用、入口点、危险操作和调用关系。

### Tool Finding

扫描器结果首先进入候选发现库，不直接写入 Fact。候选可以被 Worker 调查、判定为
误报、要求补充证据或升级为漏洞。

### Audit Finding

正式漏洞记录至少包含：

- 快照、文件路径、行号、类别、CWE、严重度。
- 描述、影响、证据、修复建议。
- 发现 Worker、复核 Worker 和复核状态。

`critical` 与 `high` 必须由不同 Worker 独立复核后才能进入正式确认状态。

## 容器边界

代码审计系统区分两类执行环境：

- 分析环境：读取源码、建立索引、运行静态扫描器。
- 验证环境：安装依赖、构建、启动应用和执行定向验证。

源码按不可信代码处理。验证环境不得挂载 Docker Socket，不得使用 host 网络，不得
注入模型 API Key 或 Rabbit 内部 Token，并应限制 CPU、内存、磁盘和运行时间。

## 多语言能力

系统架构支持多语言，不承诺所有语言具有相同分析深度。第一阶段工具基线：

- 通用：Semgrep、Gitleaks、OSV-Scanner、Trivy、ripgrep、ctags。
- PHP：Psalm、PHPStan、Composer Audit。
- Python：Bandit、pip-audit。
- JavaScript / TypeScript：ESLint、npm audit。
- Go：gosec、govulncheck。
- Java：第一阶段使用通用扫描与依赖扫描覆盖。

后续增强 SpotBugs、FindSecBugs、Tree-sitter、Joern、CodeQL 和框架专项索引。

## 事实图职责

事实图只记录高价值审计认知和已确认结论，不存储大体积扫描日志或完整索引。

- Hint：人工提示或值得调查的线索。
- Intent：独立、可并行的审计方向。
- Fact：已经确认的代码事实、覆盖事实或漏洞证据。
- Audit Finding：结构化漏洞记录和复核状态。
