# 跨文件污点分析落地方案（Joern + AST 调用图）

目标：让 `外部输入 → 危险 sink` 的真实跨文件数据流成为审计候选（candidate），带上入口路由与调用链证据，喂给 Worker（AI）复核与回放验证。方案分两轨，先能用、再精确。

| 轨道 | 引擎 | 跑在哪 | 基础设施 | 状态 |
|---|---|---|---|---|
| **Track A** | 纯 Python，基于 tree-sitter 跨文件调用图 | `audit-server` 进程内（候选生成处） | 无新依赖 | **已落地** |
| **Track B** | Joern CPG 跨过程污点 | **worker 容器**（已带 JRE 21） | JDK + joern-cli（约 GB 级） | 规划中，需实测调优后默认开启 |

---

## Track A：基于 AST 调用图的跨文件可达性（已落地）

实现位置：

- `cairn/src/cairn/server/ast_index.py`
  - `build_call_graph(files)`：用 tree-sitter 真实语法把 `(path, text, language)` 解析成**文件级调用图**（按名称解析 def/call，跨文件、无深度限制）。14 种语言，带规模上限（`MAX_AST_FILES=20000`、`MAX_AST_FILE_BYTES=1.5MB`）。
  - `CallGraph.route_reach_from(seed_routes)`：以 `{入口文件: 路由标签}` 为种子做多源前向 BFS，返回每个可达文件的 `RouteReach(route, entry_path, chain)` —— 既给出可达它的 HTTP 路由，也用父指针回溯出 `入口 → … → sink 文件` 的调用链。
  - `CallGraph.reachable_from / can_reach`：正/反向可达集合。
- `cairn/src/cairn/server/source_service.py`
  - `_ast_entry_reach(...)`：对快照构图并返回 `path -> RouteReach`；tree-sitter 不可用或无入口时返回空，自动降级。
  - `_ast_call_chain_evidence(reach, sink_path, sink_line, sink_label)`：把跨文件调用链渲染成候选证据（仅当链跨 ≥2 个文件时产生，并显式标注“名称解析为近似，需源码确认”）。
  - `_insert_audit_candidates_from_index(...)`：对本身没有 HTTP 入口的 `data_flow` / `capability_chain` sink，用 `RouteReach` 把它回连到真正可达它的 Controller 路由，并把调用链写入候选的 `evidence` 列。

设计取舍：

- **近似而保守**：调用按名称解析，是近似而非精确过程间 CPG。因此 Track A 只用于**生成候选 + 附证据链 + 排序**，不直接定“漏洞”；严重度沿用 sink 类别映射。
- **只增强、不泛滥**：不额外制造候选，只给已有的跨文件 sink 补上入口路由与调用链证据，不会冲高完成门禁的误报。
- **可达性参与排序**：绑定到入口的 sink 在候选排序中优先于未绑定的（tiebreaker），但不硬丢弃未命中的，避免漏报。

单测：`cairn/tests/test_ast_index.py`（`route_reach_from` 链路重建、`_ast_call_chain_evidence` 渲染、Controller→Service→DAO 端到端、tree-sitter 缺失降级）。

> 说明：tree-sitter 依赖已写入 `cairn/pyproject.toml`（`tree-sitter` + `tree-sitter-language-pack`），镜像重建后即生效；未装该依赖的旧镜像会自动走回归索引，不报错。

---

## Track B：Joern CPG 精确污点（规划中）

### 为什么是 Joern

- Apache-2.0、可自托管；一套 CPG 覆盖多语言（`joern-parse` 自动识别 Java/JVM、JS/TS、Python、C/C++、PHP、Go、C#、Ruby 等，各前端成熟度不同，需分语言验证）。
- 对比 CodeQL：CodeQL 不支持 PHP，且闭源项目要 GHAS 授权；本系统“什么语言都审”，Joern 更合适。

### 关键架构事实（决定 Joern 装在哪）

- 跑 `audit-server` / `audit-dispatcher` 的 **app 镜像**（`Dockerfile`）只做 `uv sync`，**不装扫描器、也没有 JVM**，而且被硬化过（`cap_drop: ALL`、`no-new-privileges`、`/tmp` 为 `noexec` tmpfs）——JVM 在 `noexec` 的 /tmp 上抽取本地库会崩。**所以 Joern 不能跑在 audit-server 进程里。**
- 装了扫描器的是 **worker 镜像**（`container/Dockerfile`，Kali），它**已有 `openjdk-21-jre-headless`** 及 Go/PHP/Node/Python 与 semgrep/trivy/gosec 等。dispatcher 通过 docker.sock 拉起临时 worker 容器跑 agent，扫描器即供其使用。
- 现有 `build_tool_plan` 的进程内工具链路目前是休眠的（`dispatch.yaml` 里 `tool_scan.auto_enqueue: false` + `tools: []`）。

### 落点：复用现有工具扫描管线

- `cairn/src/cairn/server/audit_tools.py` 的 `build_tool_plan(...)` 追加一条 `joern` 的 `AuditToolPlan`。
- `cairn/src/cairn/server/audit_tool_runner.py` 的 `parse_tool_output(...)` 增加 `joern` 分支 `_parse_joern(...)`；`ParsedToolFinding` 增可选富字段（`candidate_type='data_flow'`、`entry_point`、`evidence`、`symbol`、`candidate_source='joern'`），`_persist_tool_findings` 写入这些字段。
- `audit_candidates` 表已有 `entry_point / symbol / evidence` 列、且 `candidate_type` 无 CHECK 约束，污点流写成 `candidate_type='data_flow'` 即可同时进入覆盖率门禁与完成门禁。

### 安装：装进 worker 镜像

worker 镜像已有 JRE 21。Joern 需 Java ≥ 11，若某前端报缺编译器，把 `openjdk-21-jre-headless` 换成 `openjdk-21-jdk-headless`。

```dockerfile
# container/Dockerfile 末尾（USER kali 之前）
ARG JOERN_VERSION=v4.0.0        # 以实测跑通的版本为准，固定下来
RUN cd /opt && \
    wget -q "https://github.com/joernio/joern/releases/download/${JOERN_VERSION}/joern-cli.zip" -O joern-cli.zip && \
    unzip -q joern-cli.zip && rm -f joern-cli.zip && \
    ln -s /opt/joern-cli/joern /usr/local/bin/joern && \
    ln -s /opt/joern-cli/joern-parse /usr/local/bin/joern-parse
ENV JAVA_OPTS="-Xmx4g"
COPY ./container/joern-taint.sh /usr/local/bin/joern-taint.sh
RUN chmod +x /usr/local/bin/joern-taint.sh
```

### 两步执行封装成单命令

现有 `_run_one_tool` 只跑一条 `subprocess.run(plan.command)`，而 Joern 是「parse → script」两步。所以在 worker 镜像里放 `joern-taint.sh`，内部两步、把 flows JSON 打到 stdout，`parse_tool_output("joern", stdout)` 直接解析：

```bash
#!/usr/bin/env bash
# container/joern-taint.sh  <source_dir>
set -euo pipefail
SRC="$1"
CPG="$(mktemp -t cpg.XXXXXX.bin)"
OUT="$(mktemp -t flows.XXXXXX.json)"
trap 'rm -f "$CPG" "$OUT"' EXIT
joern-parse "$SRC" --output "$CPG" >/dev/null 2>&1
joern --script /opt/taint.sc --param cpgFile="$CPG" --param outFile="$OUT" >/dev/null 2>&1
cat "$OUT"
```

### `taint.sc`：CPGQL 污点查询起步版

> Joern 各版本 API 有漂移；下面是 2.x/4.x 的典型写法，以实测环境 `joern` REPL 的补全/`help` 为准，跑通后固定版本。source/sink 用调用名正则做跨语言覆盖，在实测里逐步扩充。

```scala
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext

@main def main(cpgFile: String, outFile: String): Unit = {
  importCpg(cpgFile)
  implicit val ctx: EngineContext = EngineContext()

  val sourceRe = "(?i)(getParameter|getQueryString|getHeader|getCookies|getInputStream" +
    "|_GET|_POST|_REQUEST|_COOKIE|php://input|file_get_contents" +
    "|request\\.(args|form|values|json|data|GET|POST)" +
    "|req\\.(query|body|params|headers)" +
    "|URL\\.Query|FormValue|PostFormValue|\\.Query|\\.Param)"
  def sources = cpg.call.name(sourceRe).argument

  val sinkGroups: Map[String, String] = Map(
    "sqli"           -> "(?i)(executeQuery|executeUpdate|execute|rawQuery|nativeQuery|mysqli_query|pg_query|cursor\\.execute|db\\.(Query|Exec)|knex\\.raw)",
    "cmd_exec"       -> "(?i)(Runtime\\.exec|ProcessBuilder|getRuntime|system|shell_exec|passthru|proc_open|popen|os\\.system|subprocess\\.(run|call|Popen)|child_process\\.exec|exec\\.Command)",
    "path_traversal" -> "(?i)(new File|FileInputStream|FileOutputStream|fopen|readfile|os\\.Open|ioutil\\.ReadFile|fs\\.readFile)",
    "ssrf"           -> "(?i)(openConnection|HttpURLConnection|curl_exec|requests\\.(get|post)|http\\.(Get|Post)|axios|fetch)",
    "deserialize"    -> "(?i)(readObject|unserialize|pickle\\.loads|yaml\\.load|ObjectInputStream)",
    "open_redirect"  -> "(?i)(sendRedirect|header\\(.Location|redirect|res\\.redirect|http\\.Redirect)"
  )

  val sanitizerRe = "(?i)(prepareStatement|setString|bindParam|escapeshellarg|htmlspecialchars|intval|parameterize|validate|allowlist|whitelist)"
  def isSanitized(flow: Path): Boolean = flow.elements.exists(_.code.matches(s".*$sanitizerRe.*"))

  val results = sinkGroups.toSeq.flatMap { case (category, sinkRe) =>
    val sinks = cpg.call.name(sinkRe).argument
    sinks.reachableByFlows(sources).filterNot(isSanitized).map { flow =>
      val els = flow.elements
      ujson.Obj(
        "category"   -> category,
        "sourceFile" -> els.head.location.filename,
        "sourceLine" -> els.head.lineNumber.map(_.toInt).getOrElse(-1),
        "sinkFile"   -> els.last.location.filename,
        "sinkLine"   -> els.last.lineNumber.map(_.toInt).getOrElse(-1),
        "sinkMethod" -> els.last.method.fullName,
        "path"       -> ujson.Arr.from(els.map(e => ujson.Obj(
                          "file" -> e.location.filename,
                          "line" -> e.lineNumber.map(_.toInt).getOrElse(-1),
                          "code" -> e.code)))
      )
    }
  }

  val pw = new java.io.PrintWriter(outFile)
  try pw.write(ujson.write(ujson.Obj("flows" -> ujson.Arr.from(results)))) finally pw.close()
}
```

### Python 接线要点

- `_parse_joern(payload, raw_artifact_path)`：把每条 flow 映射为 `ParsedToolFinding(candidate_type='data_flow', candidate_source='joern', severity=按类别, file_path=sinkFile, line_start=sinkLine, symbol=sinkMethod, evidence=调用链 JSON)`；类别→严重度：`cmd_exec/deserialize=critical`，`sqli/ssrf/path_traversal=high`，`open_redirect=medium`。
- 入口路由：Joern 的 source 文件/行可复用 Track A 的 `_ast_entry_reach` 按 sourceFile 查路由，填入 `entry_point`。
- 去重：稳定 id 纳入 `source + sinkFile + sinkLine + category`。

### 配置开关（默认关，灰度开）

```yaml
# dispatch.yaml
tool_scan:
  enabled: true
  auto_enqueue: true          # 或继续手动入队
  timeout_per_tool: 1800      # Joern 比其它工具慢得多，必须调大
  tools: [joern]              # 只跑 joern；留空=跑全部
  max_running: 1
```

大仓按语言/子模块在 `joern-taint.sh` 里分多次 `joern-parse`（`--language`），降低单次内存峰值。

### 实测流程

```bash
# 1) 起一个带 joern 的壳（worker 镜像）
docker run --rm -it -v "$PWD/samples:/samples" rabbit-code-audit-worker:audit bash
# 2) 先手动确认 joern 能跑通样本（最关键一步）
joern-parse /samples/owasp-benchmark --output /tmp/cpg.bin
joern --script /opt/taint.sc --param cpgFile=/tmp/cpg.bin --param outFile=/tmp/flows.json
# 3) 跑通后，走 cairn 管线（导入样本拿 project_id/snapshot_id）
uv run cairn run-audit-tools --project-id <PID> --snapshot-id <SID> --tool joern --timeout-per-tool 1800 --format json
```

验证样本（带真值才能量 TP/FP/FN）：OWASP Benchmark（Java，有 `expectedresults.csv`）、DVWA/sqli-labs（PHP）、Juice Shop（JS），以及真实的分层内网项目。调优循环：跑样本 → 比真值算 precision/recall → 调 source/sink/sanitizer 正则 → 达标后把若干确定流固化成对 `_parse_joern` 的回归断言（纯解析、不依赖 joern 本体）。

### 风险与回滚

| 风险 | 缓解 |
|---|---|
| CPG OOM / 超时 | `-Xmx`；`timeout_per_tool` 调到 600–1800s；按语言/模块分片；失败返回 timeout/skipped，不阻断整个任务 |
| 误报爆炸 | 先在样本集调达标再默认开；2000 候选上限 + `coverage_gap` 兜底；`tools:[]` 特性开关默认关 |
| 在硬化 server 上崩 | 只在 worker 容器跑，绝不在 audit-server 进程跑 |
| 解析不可信源码 | Joern 只解析不执行被审代码；用 source 前端，避开需编译产物的字节码模式；在隔离、无外网的 worker 容器里跑 |
| 版本 API 漂移 | 固定 `JOERN_VERSION`；`taint.sc` 跑通后锁版本；解析器侧有纯 Python 回归断言 |

### 验收标准

- worker 镜像装上 joern，`joern-parse` + `joern --script taint.sc` 能在样本上跑出 flows。
- `_parse_joern` + 富字段 + `_persist_tool_findings` 写出带 `entry_point/symbol/evidence` 的 `data_flow` 候选；纯解析单测通过。
- 候选正确进入覆盖率门禁与完成门禁（未处理的 high/critical 能 409 阻断 `complete`）。
- OWASP Benchmark 上 precision/recall 达到设定阈值；≥N 条已知流固化为回归断言。
- 默认关（`tools: []`），`dispatch.yaml` 改 `tools: [joern]` 可灰度开启；失败非阻断。
