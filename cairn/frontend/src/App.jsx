import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Card, Checkbox, DatePicker, Drawer, Empty, Input, InputNumber, Message, Modal as ArcoModal, Pagination, Radio, Select, Space, Spin, Switch, Tag, Tooltip, Typography } from "@arco-design/web-react";
import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowUpRight,
  ArrowLeft,
  Bell,
  Bot,
  CheckCheck,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  Clock,
  Copy,
  Download,
  Eye,
  EyeOff,
  FileArchive,
  FileText,
  Folder,
  History,
  Home,
  Inbox,
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  Monitor,
  Moon,
  Network,
  Pause,
  Pencil,
  Play,
  Plus,
  RefreshCw,
  Server,
  SlidersHorizontal,
  Timer,
  Save,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Square,
  Sun,
  Trash2,
  User,
  X,
} from "lucide-react";
import { apiRequest, AUTH_REQUIRED_EVENT, downloadFromApi } from "./api";
import {
  SEVERITY_META,
  STATUS_META,
  TASK_TYPES,
  clampText,
  cn,
  formatBytes,
  formatTime,
  go,
  parseHash,
  parseHintLines,
  relativeHeartbeat,
} from "./utils";

try {
  cytoscape.use(dagre);
} catch {
  // Vite HMR may register the extension more than once.
}

const APP_NAME = "Rabbit Code Audit";
const HUMAN_WORKER = "Human";
const SECRET_MASK = "********";

// Map the app's semantic "tone" vocabulary (used by STATUS_META / SEVERITY_META
// and the bespoke Badge) onto Arco Design's Tag color names, so status chips are
// consistent across the Arco migration without re-labelling every call site.
const ARCO_TONE_COLOR = {
  success: "green",
  warning: "orange",
  danger: "red",
  info: "arcoblue",
  muted: "gray",
  critical: "red",
  high: "orangered",
  medium: "gold",
  low: "cyan",
};

function arcoTagColor(tone) {
  return ARCO_TONE_COLOR[tone] || "gray";
}

function formatFindingStatus(status) {
  return {
    candidate: "候选",
    investigating: "调查中",
    pending_review: "待确认",
    confirmed: "已确认",
    rejected: "已拒绝",
    needs_more_evidence: "需更多证据",
  }[status] || status;
}

function findingStatusTone(status) {
  return {
    candidate: "muted",
    investigating: "info",
    pending_review: "warning",
    confirmed: "success",
    rejected: "muted",
    needs_more_evidence: "warning",
  }[status] || "muted";
}

function formatCandidateStatus(status) {
  return {
    candidate: "候选",
    investigating: "调查中",
    confirmed: "已确认",
    rejected: "已驳回",
    needs_more_evidence: "证据不足",
  }[status] || status;
}

function candidateStatusTone(status) {
  return {
    candidate: "warning",
    investigating: "info",
    confirmed: "success",
    rejected: "muted",
    needs_more_evidence: "warning",
  }[status] || "muted";
}

function formatSourceStatus(status) {
  return {
    importing: "导入中",
    ready: "可用",
    failed: "失败",
  }[status] || status;
}

function sourceStatusTone(status) {
  return {
    importing: "info",
    ready: "success",
    failed: "danger",
  }[status] || "muted";
}

function indexQualityGradeLabel(grade) {
  return {
    strong: "强",
    usable: "可用",
    weak: "偏弱",
    poor: "不足",
  }[grade] || "未知";
}

function indexQualityTone(grade) {
  return {
    strong: "success",
    usable: "info",
    weak: "warning",
    poor: "danger",
  }[grade] || "muted";
}

function indexIssueTone(severity) {
  return {
    critical: "danger",
    warning: "warning",
    info: "info",
  }[severity] || "muted";
}

function sortedCountEntries(value, limit = 6) {
  return Object.entries(value || {})
    .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0) || a[0].localeCompare(b[0]))
    .slice(0, limit);
}

function formatToolScanStatus(status) {
  return {
    pending: "等待中",
    running: "扫描中",
    completed: "已完成",
    failed: "失败",
  }[status] || status;
}

function toolScanStatusTone(status) {
  return {
    pending: "warning",
    running: "info",
    completed: "success",
    failed: "danger",
  }[status] || "muted";
}

function formatReportEnrichmentStatus(status) {
  return {
    pending: "等待写作",
    running: "生成中",
    completed: "已完成",
    failed: "失败",
  }[status] || status;
}

function reportEnrichmentStatusTone(status) {
  return {
    pending: "warning",
    running: "info",
    completed: "success",
    failed: "danger",
  }[status] || "muted";
}

function reportTaskFindingIds(item) {
  return [item?.id, item?.fact_id].filter(Boolean);
}

function hasCompletedReportMaterial(tasks, item) {
  const ids = new Set(reportTaskFindingIds(item));
  return (tasks || []).some((task) => ids.has(task.finding_id) && task.status === "completed");
}

function latestReportTaskForItem(tasks, item) {
  const ids = new Set(reportTaskFindingIds(item));
  return (tasks || []).find((task) => ids.has(task.finding_id)) || null;
}

function reportTaskMaterialSummary(task) {
  if (!task) return "尚未生成报告材料";
  const parts = [];
  if ((task.packet_templates || []).length) parts.push(`${task.packet_templates.length} 个请求模板`);
  if (Object.keys(task.reproduction_poc || {}).length) parts.push("静态 PoC");
  if ((task.evidence_chain || []).length) parts.push(`${task.evidence_chain.length} 条证据链`);
  if (Object.keys(task.report_sections || {}).length) parts.push(`${Object.keys(task.report_sections || {}).length} 个报告段落`);
  if ((task.delivery_notes || []).length) parts.push(`${task.delivery_notes.length} 条交付备注`);
  return parts.length ? parts.join(" / ") : "暂无可导出的补充材料";
}

function workerHistoryOutcomeLabel(row) {
  const base =
    {
      success: "成功",
      failed: "历史失败",
      rejected: "已拒绝",
      cancelled: "已取消",
      unhealthy: "健康检查失败",
    }[row?.outcome] || row?.outcome || "未知";
  const markers = [];
  if (row?.rate_limited) markers.push("限速");
  if (row?.used_fallback) markers.push("fallback");
  return markers.length ? `${base} · ${markers.join(" / ")}` : base;
}

function workerHistoryOutcomeTone(row) {
  if (row?.outcome === "success") return "success";
  if (row?.rate_limited) return "warning";
  if (row?.outcome === "failed" || row?.error_type) return "danger";
  return "muted";
}

function workerHistoryErrorText(row) {
  const type = row?.error_type ? `类型：${row.error_type}` : "";
  const detail = row?.error_detail ? `详情：${clampText(row.error_detail, 180)}` : "";
  return [type, detail].filter(Boolean).join("；");
}

function dynamicValidationStatusLabel(status) {
  return {
    static_only: "静态优先",
    ready: "可计划验证",
    blocked: "建议阻塞",
  }[status] || status;
}

function dynamicValidationTone(status) {
  return {
    static_only: "muted",
    ready: "info",
    blocked: "warning",
  }[status] || "muted";
}

const BUSINESS_NODE_META = {
  feature: { label: "功能", tone: "success" },
  role: { label: "角色", tone: "info" },
  endpoint: { label: "接口", tone: "high" },
  data_object: { label: "数据", tone: "medium" },
  state: { label: "状态", tone: "muted" },
  control: { label: "控制点", tone: "critical" },
  asset: { label: "资产", tone: "info" },
  risk: { label: "风险", tone: "danger" },
  external_system: { label: "外部系统", tone: "muted" },
};

const BUSINESS_EDGE_META = {
  contains: "包含",
  exposes: "暴露",
  calls: "调用",
  uses: "使用",
  extends: "继承",
  extended_by: "被继承",
  owns: "归属",
  guards: "保护",
  transitions_to: "流转",
  depends_on: "依赖",
  risk_of: "风险关联",
  relates_to: "相关",
};

const BUSINESS_RISK_META = {
  critical: { label: "严重风险", tone: "critical" },
  high: { label: "高风险", tone: "high" },
  medium: { label: "中风险", tone: "medium" },
  low: { label: "低风险", tone: "low" },
  unknown: { label: "未知风险", tone: "warning" },
};

const BUSINESS_REVIEW_STATUS_META = {
  unreviewed: { label: "未覆盖", tone: "warning" },
  investigating: { label: "调查中", tone: "info" },
  covered: { label: "已覆盖", tone: "success" },
  blocked: { label: "已阻塞", tone: "muted" },
};

const BUSINESS_GRAPH_LAYER_META = {
  evidence: { label: "代码证据", tone: "muted" },
  semantic: { label: "业务语义", tone: "info" },
  audit: { label: "审计风险", tone: "danger" },
};

const BUSINESS_EVIDENCE_STATUS_META = {
  source_backed: { label: "源码支撑", tone: "success" },
  inferred: { label: "索引推导", tone: "medium" },
  unverified: { label: "待补证", tone: "warning" },
};

const BUSINESS_CONCLUSION_META = {
  confirmed_finding: { label: "确认漏洞", tone: "danger" },
  rejected: { label: "未发现漏洞", tone: "success" },
  needs_more_evidence: { label: "证据不足", tone: "warning" },
};

function splitLines(value) {
  return String(value || "")
    .split(/\n+/)
    .map((line) => line.trim())
    .filter(Boolean);
}

async function copyText(value, setToast, successMessage = "已复制") {
  const text = String(value || "").trim();
  if (!text) {
    setToast?.({ type: "warning", message: "没有可复制的内容" });
    return false;
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      textarea.remove();
    }
    setToast?.({ type: "success", message: successMessage });
    return true;
  } catch {
    setToast?.({ type: "danger", message: "复制失败，请手动选择文本复制" });
    return false;
  }
}

function pocText(poc, key) {
  const value = poc?.[key];
  return typeof value === "string" ? value.trim() : "";
}

function pocList(poc, key) {
  const value = poc?.[key];
  return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean) : [];
}

function useRoute() {
  const [route, setRoute] = useState(parseHash);

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    if (!window.location.hash) {
      window.location.hash = "#/dashboard";
    }
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return route;
}

function useAsyncAction(setToast) {
  return useCallback(
    async (label, action) => {
      try {
        const result = await action();
        if (label) setToast({ type: "success", message: label });
        return result;
      } catch (error) {
        if (error?.status === 401) {
          setToast({ type: "warning", message: "登录状态已失效，请重新登录" });
        } else {
          setToast({ type: "danger", message: error.message || "操作失败" });
        }
        throw error;
      }
    },
    [setToast],
  );
}

export default function App() {
  const route = useRoute();
  const [user, setUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [authNotice, setAuthNotice] = useState("");
  const [toast, setToast] = useState(null);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [confirmState, setConfirmState] = useState(null);
  const [theme, setTheme] = useState(() => {
    if (typeof window === "undefined") return "light";
    return window.localStorage.getItem("rabbit-theme") === "dark" ? "dark" : "light";
  });
  const runAction = useAsyncAction(setToast);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    // Keep Arco components in sync with the app's light/dark theme.
    if (theme === "dark") {
      document.body.setAttribute("arco-theme", "dark");
    } else {
      document.body.removeAttribute("arco-theme");
    }
    window.localStorage.setItem("rabbit-theme", theme);
  }, [theme]);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  // Promise-based confirm: pages call confirmAction(...) and await a boolean.
  const confirmAction = useCallback(
    (options) =>
      new Promise((resolve) => {
        setConfirmState({ options: options || {}, resolve });
      }),
    [],
  );

  const resolveConfirm = useCallback(
    (result) => {
      setConfirmState((current) => {
        if (current) current.resolve(result);
        return null;
      });
    },
    [],
  );

  const loadUser = useCallback(async () => {
    try {
      const me = await apiRequest("/api/auth/me");
      setUser(me);
      setAuthNotice("");
    } catch {
      setUser(null);
    } finally {
      setAuthChecked(true);
    }
  }, []);

  useEffect(() => {
    const onAuthenticationRequired = () => {
      setUser(null);
      setAuthChecked(true);
      setAuthNotice("登录状态已失效，请重新登录后继续当前操作。");
    };
    window.addEventListener(AUTH_REQUIRED_EVENT, onAuthenticationRequired);
    return () => window.removeEventListener(AUTH_REQUIRED_EVENT, onAuthenticationRequired);
  }, []);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  useEffect(() => {
    if (!toast) return undefined;
    const timer = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const logout = async () => {
    await runAction(null, () => apiRequest("/api/auth/logout", { method: "POST" }));
    setUser(null);
  };

  if (!authChecked) {
    return (
      <div className="boot-screen">
        <Loader2 className="spin" size={28} />
        <span>正在载入 Rabbit</span>
      </div>
    );
  }

  if (!user) {
    return <AuthPage onAuthed={loadUser} setToast={setToast} notice={authNotice} />;
  }

  return (
    <div className="app-shell">
      <TopNav
        route={route}
        user={user}
        theme={theme}
        onToggleTheme={toggleTheme}
        onLogout={logout}
        onPassword={() => setPasswordOpen(true)}
        onSettings={() => setSettingsOpen(true)}
        setToast={setToast}
        confirmAction={confirmAction}
      />
      <main className="app-main">
        {route.page === "project" ? (
          <ProjectWorkspace
            projectId={route.projectId}
            runAction={runAction}
            setToast={setToast}
            confirmAction={confirmAction}
          />
        ) : route.page === "vulnerabilities" ? (
          <VulnerabilitiesPage route={route} runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : route.page === "workers" ? (
          <WorkersPage runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : route.page === "templates" ? (
          <TemplatesPage runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : route.page === "audit" ? (
          <AuditPage setToast={setToast} />
        ) : route.page === "projects" ? (
          <ProjectsPage runAction={runAction} setToast={setToast} confirmAction={confirmAction} />
        ) : (
          <DashboardPage runAction={runAction} setToast={setToast} />
        )}
      </main>
      {passwordOpen && <PasswordModal onClose={() => setPasswordOpen(false)} runAction={runAction} />}
      {settingsOpen && (
        <SettingsModal
          onClose={() => setSettingsOpen(false)}
          runAction={runAction}
          confirmAction={confirmAction}
        />
      )}
      {confirmState && (
        <ConfirmModal
          {...confirmState.options}
          onConfirm={() => resolveConfirm(true)}
          onCancel={() => resolveConfirm(false)}
        />
      )}
      {toast && <Toast toast={toast} onClose={() => setToast(null)} />}
    </div>
  );
}

function TopNav({ route, user, theme, onToggleTheme, onLogout, onPassword, onSettings, setToast, confirmAction }) {
  const mainNav = [
    ["projects", "项目", Folder],
    ["vulnerabilities", "审计报告", AlertTriangle],
    ["workers", "工作节点", Monitor],
  ];
  const activeNav = mainNav.find(([key]) => route.page === key || (key === "projects" && route.page === "project"));
  const sectionLabel =
    route.page === "dashboard"
      ? "仪表盘"
      : route.page === "audit"
        ? "审计日志"
        : activeNav?.[1] || APP_NAME;
  const reportSubnav = [
    { title: null, items: [["overview", "报告总览"]] },
    {
      title: "按严重程度",
      items: [
        ["critical", "严重漏洞"],
        ["high", "高危漏洞"],
        ["medium", "中危漏洞"],
        ["low", "低危漏洞"],
      ],
    },
    {
      title: "按处理状态",
      items: [
        ["confirmed", "已确认漏洞"],
        ["ignored", "已忽略漏洞"],
      ],
    },
    { title: null, items: [["export-records", "导出记录"]] },
  ];
  const vulnRouteActive = route.page === "vulnerabilities";
  const [reportExpanded, setReportExpanded] = useState(vulnRouteActive);
  const [reportManual, setReportManual] = useState(false);
  const activeView = route.page === "vulnerabilities" ? route.view || "overview" : null;

  useEffect(() => {
    if (vulnRouteActive) {
      if (!reportManual) setReportExpanded(true);
      return;
    }
    setReportExpanded(false);
    setReportManual(false);
  }, [reportManual, vulnRouteActive]);

  const toggleVulnerabilityNav = () => {
    if (!vulnRouteActive) {
      setReportManual(false);
      setReportExpanded(true);
      go("#/vulnerabilities");
      return;
    }
    setReportManual(true);
    setReportExpanded((prev) => !prev);
  };

  return (
    <>
      <header className="top-utility">
        <button className="brand" type="button" onClick={() => go("#/dashboard")}>
          <span className="brand-mark">
            <img src="/static/rabbit-icon.png" alt="Rabbit" />
          </span>
          <span className="brand-word">Rabbit</span>
        </button>
        <div className="top-section-label">{sectionLabel}</div>
        <GlobalSearch setToast={setToast} />
        <div className="nav-actions">
          <NotificationBell setToast={setToast} confirmAction={confirmAction} />
          <button
            className="icon-button"
            type="button"
            onClick={onToggleTheme}
            aria-label={theme === "dark" ? "切换为浅色模式" : "切换为深色模式"}
            title={theme === "dark" ? "浅色模式" : "深色模式"}
          >
            {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button className="user-chip" type="button" onClick={onPassword} title="修改密码">
            <span className="user-avatar">{(user.username || "U").slice(0, 1).toUpperCase()}</span>
            <span className="user-name">{user.username}</span>
          </button>
          <button className="icon-button" type="button" onClick={onLogout} aria-label="退出登录" title="退出登录">
            <LogOut size={16} />
          </button>
        </div>
      </header>
      <aside className="top-nav">
        <nav className="nav-tabs" aria-label="主导航">
          <button
            className={cn("nav-tab", route.page === "dashboard" && "active")}
            type="button"
            onClick={() => go("#/dashboard")}
          >
            <Home size={17} />
            首页
          </button>
          {mainNav.map(([key, label, Icon]) => {
            const active = route.page === key || (key === "projects" && route.page === "project");
            return (
              <div key={key} className={cn("nav-group", active && "active", key === "vulnerabilities" && reportExpanded && "expanded")}>
                <button
                  className={cn("nav-tab", active && key !== "vulnerabilities" && "active", key === "vulnerabilities" && active && "module-open")}
                  type="button"
                  onClick={() => (key === "vulnerabilities" ? toggleVulnerabilityNav() : go(key === "projects" ? "#/projects" : `#/${key}`))}
                >
                  <Icon size={17} />
                  {label}
                  {key === "vulnerabilities" && <ChevronDown className="nav-caret" size={14} />}
                </button>
                {key === "vulnerabilities" && reportExpanded && (
                  <div className="sub-nav">
                    {reportSubnav.map((group, index) => (
                      <div key={group.title || `group-${index}`} className="sub-nav-group">
                        {group.title && <span className="sub-nav-group-label">{group.title}</span>}
                        <div className="sub-nav-list">
                          {group.items.map(([view, label]) => (
                            <button
                              key={view}
                              className={cn(activeView === view && "active")}
                              type="button"
                              onClick={() => go(view === "overview" ? "#/vulnerabilities" : `#/vulnerabilities/${view}`)}
                            >
                              <span className="sub-nav-indicator" />
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          <button
            className={cn("nav-tab", route.page === "audit" && "active")}
            type="button"
            onClick={() => go("#/audit")}
          >
            <History size={17} />
            审计日志
          </button>
          <button className="nav-tab" type="button" onClick={onSettings}>
            <Settings size={17} />
            系统设置
          </button>
        </nav>
        <div className="sidebar-foot">
          <FileText size={15} />
          <span>默认工作区</span>
        </div>
      </aside>
    </>
  );
}

function GlobalSearch({ setToast }) {
  const [term, setTerm] = useState("");
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState({ vulnerabilities: [], projects: [] });
  const wrapRef = useRef(null);
  const cacheRef = useRef(null);

  // Lazily fetch the full vulnerability + project lists once, then filter
  // client-side as the user types. Kept lightweight: one fetch per session,
  // refreshed only when the dropdown is opened after being closed a while.
  const ensureData = useCallback(async () => {
    if (cacheRef.current && Date.now() - cacheRef.current.at < 60000) return cacheRef.current.payload;
    const [vulns, projects] = await Promise.all([
      apiRequest("/api/vulnerabilities").catch(() => []),
      apiRequest("/projects").catch(() => []),
    ]);
    const payload = {
      vulnerabilities: Array.isArray(vulns) ? vulns : [],
      projects: Array.isArray(projects) ? projects : [],
    };
    cacheRef.current = { at: Date.now(), payload };
    return payload;
  }, []);

  useEffect(() => {
    const value = term.trim().toLowerCase();
    if (!value) {
      setData({ vulnerabilities: [], projects: [] });
      setOpen(false);
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    const timer = window.setTimeout(async () => {
      try {
        const payload = await ensureData();
        if (cancelled) return;
        const vulnerabilities = payload.vulnerabilities
          .filter((item) =>
            [item.title, item.fact_id, item.project_name, item.project_id, item.description]
              .filter(Boolean)
              .some((field) => String(field).toLowerCase().includes(value)),
          )
          .slice(0, 6);
        const projects = payload.projects
          .filter((item) =>
            [item.title, item.id, item.goal, item.origin]
              .filter(Boolean)
              .some((field) => String(field).toLowerCase().includes(value)),
          )
          .slice(0, 5);
        setData({ vulnerabilities, projects });
        setOpen(true);
      } catch (error) {
        if (!cancelled && setToast) setToast({ type: "danger", message: error.message || "搜索失败" });
      } finally {
        if (!cancelled) setLoading(false);
      }
    }, 220);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [term, ensureData, setToast]);

  useEffect(() => {
    const onClick = (event) => {
      if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const reset = () => {
    setTerm("");
    setOpen(false);
  };

  const goVuln = (vuln) => {
    reset();
    go(`#/vulnerabilities?q=${encodeURIComponent(vuln.title || vuln.fact_id || "")}`);
  };

  const goProject = (project) => {
    reset();
    go(`#/projects/${project.id}`);
  };

  const hasResults = data.vulnerabilities.length > 0 || data.projects.length > 0;

  return (
    <div className="global-search-wrap" ref={wrapRef}>
      <Input
        allowClear
        prefix={<Search size={15} />}
        value={term}
        placeholder="搜索漏洞标题、编号、项目、标签..."
        aria-label="全局搜索"
        onChange={(value) => setTerm(value)}
        onClear={reset}
        onFocus={() => term.trim() && setOpen(true)}
        onKeyDown={(event) => {
          if (event.key === "Escape") reset();
        }}
        style={{ width: "100%" }}
      />
      {open && term.trim() && (
        <div className="search-dropdown">
          {loading && !hasResults ? (
            <div className="search-empty">
              <Loader2 className="spin" size={16} />
              <span>搜索中...</span>
            </div>
          ) : !hasResults ? (
            <div className="search-empty">
              <Search size={16} />
              <span>未找到匹配结果</span>
            </div>
          ) : (
            <>
              {data.vulnerabilities.length > 0 && (
                <section className="search-section">
                  <header>漏洞</header>
                  {data.vulnerabilities.map((vuln) => {
                    const meta = SEVERITY_META[vuln.severity] || SEVERITY_META.low;
                    return (
                      <button key={`v-${vuln.id}`} type="button" className="search-item" onClick={() => goVuln(vuln)}>
                        <span className={cn("search-dot", vuln.severity)} />
                        <span className="search-item-main">
                          <strong>{clampText(vuln.title, 42)}</strong>
                          <small>
                            {meta.label} · {vuln.fact_id} · {vuln.project_name}
                          </small>
                        </span>
                      </button>
                    );
                  })}
                </section>
              )}
              {data.projects.length > 0 && (
                <section className="search-section">
                  <header>项目</header>
                  {data.projects.map((project) => (
                    <button key={`p-${project.id}`} type="button" className="search-item" onClick={() => goProject(project)}>
                      <span className="search-icon">
                        <Folder size={15} />
                      </span>
                      <span className="search-item-main">
                        <strong>{clampText(project.title, 42)}</strong>
                        <small>{project.id}</small>
                      </span>
                    </button>
                  ))}
                </section>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function NotificationBell({ setToast, confirmAction }) {
  const [count, setCount] = useState(0);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(false);
  const wrapRef = useRef(null);

  const loadCount = useCallback(async () => {
    try {
      const res = await apiRequest("/api/notifications/unread-count");
      setCount(Number(res?.count) || 0);
    } catch {
      // Silent: the badge simply stays at its last value.
    }
  }, []);

  useEffect(() => {
    loadCount();
    const timer = window.setInterval(loadCount, 10000);
    return () => window.clearInterval(timer);
  }, [loadCount]);

  useEffect(() => {
    const onClick = (event) => {
      if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  const loadList = useCallback(async () => {
    setLoading(true);
    try {
      const list = await apiRequest("/api/notifications?limit=50");
      const items = Array.isArray(list) ? list : [];
      setItems(items);
      // Mark the just-shown unread notifications as read, then refresh the badge.
      const unreadIds = items.filter((item) => !item.read).map((item) => item.id);
      if (unreadIds.length) {
        await apiRequest("/api/notifications/read", { method: "POST", body: { ids: unreadIds } }).catch(() => {});
        setItems((prev) => prev.map((item) => ({ ...item, read: true })));
      }
      await loadCount();
    } catch (error) {
      if (setToast) setToast({ type: "danger", message: error.message || "通知加载失败" });
    } finally {
      setLoading(false);
    }
  }, [setToast, loadCount]);

  const togglePanel = async () => {
    const next = !open;
    setOpen(next);
    if (next) await loadList();
  };

  const markAllRead = async () => {
    try {
      const res = await apiRequest("/api/notifications/read", { method: "POST" });
      setCount(Number(res?.count) || 0);
      setItems((prev) => prev.map((item) => ({ ...item, read: true })));
    } catch (error) {
      if (setToast) setToast({ type: "danger", message: error.message || "操作失败" });
    }
  };

  const clearAll = async () => {
    const confirmed = await confirmAction({
      title: "清空全部通知？",
      message: "该操作会删除当前账号的全部通知记录，删除后无法恢复。",
      tone: "danger",
      confirmLabel: "清空通知",
    });
    if (!confirmed) return;
    try {
      await apiRequest("/api/notifications", { method: "DELETE" });
      setItems([]);
      setCount(0);
    } catch (error) {
      if (setToast) setToast({ type: "danger", message: error.message || "操作失败" });
    }
  };

  const openNotification = (item) => {
    if (item.link) {
      setOpen(false);
      go(item.link);
    }
  };

  return (
    <div className="notification-wrap" ref={wrapRef}>
      <button
        className="icon-button notification-button"
        type="button"
        onClick={togglePanel}
        aria-label="通知"
        title="通知"
      >
        <Bell size={16} />
        {count > 0 && <span className="notification-dot">{count > 99 ? "99+" : count}</span>}
      </button>
      {open && (
        <div className="notification-panel">
          <header className="notification-panel-head">
            <strong>通知</strong>
            <div className="notification-actions">
              <button type="button" onClick={markAllRead} disabled={!items.length}>
                <CheckCheck size={14} />
                全部已读
              </button>
              <button type="button" className="danger" onClick={clearAll} disabled={!items.length}>
                <Trash2 size={14} />
                清空
              </button>
            </div>
          </header>
          <div className="notification-list">
            {loading ? (
              <div className="search-empty">
                <Loader2 className="spin" size={16} />
                <span>加载中...</span>
              </div>
            ) : items.length === 0 ? (
              <div className="search-empty">
                <Inbox size={18} />
                <span>暂无通知</span>
              </div>
            ) : (
              items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={cn("notification-item", !item.read && "unread", item.link && "linked")}
                  onClick={() => openNotification(item)}
                >
                  <span className={cn("notification-level", item.level || "info")} />
                  <span className="notification-item-main">
                    <strong>{item.title}</strong>
                    {item.body && <p>{clampText(item.body, 90)}</p>}
                    <small>{formatTime(item.created_at)}</small>
                  </span>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ConfirmModal({ title = "确认操作", message, tone = "default", confirmLabel = "确认", cancelLabel = "取消", onConfirm, onCancel }) {
  useModalLifecycle(onCancel);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onCancel()}>
      <section className="modal-card confirm-card" role="dialog" aria-modal="true" aria-label={title}>
        <div className="confirm-body">
          <span className={cn("confirm-icon", tone)}>
            {tone === "danger" ? <AlertTriangle size={22} /> : <AlertCircle size={22} />}
          </span>
          <div className="confirm-text">
            <h2>{title}</h2>
            {message && <p>{message}</p>}
          </div>
        </div>
        <div className="modal-footer">
          <Button onClick={onCancel} autoFocus={tone === "danger"}>
            {cancelLabel}
          </Button>
          <Button
            type="primary"
            status={tone === "danger" ? "danger" : undefined}
            onClick={onConfirm}
            autoFocus={tone !== "danger"}
          >
            {confirmLabel}
          </Button>
        </div>
      </section>
    </div>
  );
}

function AuditPage({ setToast }) {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const list = await apiRequest("/api/audit?limit=100");
      setEntries(Array.isArray(list) ? list : []);
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "审计日志加载失败" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => load({ silent: true }), 10000);
    return () => window.clearInterval(timer);
  }, [load]);

  const actionTone = (action) => {
    const value = String(action || "");
    if (/delete|remove|clear|disable/i.test(value)) return "danger";
    if (/create|add|export|complete|enable/i.test(value)) return "success";
    if (/update|status|reopen|edit|patch/i.test(value)) return "info";
    return "muted";
  };

  return (
    <>
      <PageHeader
        icon={History}
        title="审计日志"
        subtitle="记录关键操作的时间、对象与详情"
        actions={
          <Button icon={<RefreshCw size={16} />} loading={loading} onClick={() => load()}>
            刷新
          </Button>
        }
      />
      <section className="content-wrap vulnerability-report-page">
        <article className="vuln-table-card audit-card">
          <header className="vuln-table-title">
            <div>
              <h2>操作记录</h2>
              <p>最近 100 条关键操作，每 10 秒自动刷新</p>
            </div>
            <span className="status-pill">
              <span className="dot success" />
              <span>{entries.length} 条</span>
            </span>
          </header>
          <div className="audit-head">
            <span>时间</span>
            <span>操作</span>
            <span>摘要</span>
            <span>对象</span>
            <span>操作者</span>
          </div>
          <div className="audit-body">
            {loading ? (
              <EmptyState icon={Loader2} title="正在加载审计日志" />
            ) : entries.length === 0 ? (
              <EmptyState icon={History} title="暂无审计记录" subtitle="关键操作发生后会在这里留痕。" />
            ) : (
              entries.map((entry) => (
                <div className="audit-row" key={entry.id}>
                  <time>{formatTime(entry.created_at)}</time>
                  <span>
                    <Badge tone={actionTone(entry.action)}>{entry.action}</Badge>
                  </span>
                  <div className="audit-summary-cell">
                    <strong title={entry.summary}>{entry.summary}</strong>
                    {entry.detail && <span title={entry.detail}>{clampText(entry.detail, 80)}</span>}
                  </div>
                  <code title={`${entry.target_type || ""} ${entry.target_id || ""}`.trim()}>
                    {entry.target_type ? `${entry.target_type}${entry.target_id ? `:${entry.target_id}` : ""}` : "-"}
                  </code>
                  <span className="audit-actor">{entry.actor || "-"}</span>
                </div>
              ))
            )}
          </div>
        </article>
      </section>
    </>
  );
}

const AUTH_FIELD_ORDER = ["username", "password", "confirm_password", "captcha_answer"];
const AUTH_FIELD_LABELS = {
  username: "用户名",
  password: "密码",
  confirm_password: "确认密码",
  captcha_answer: "验证码",
};

function authValidationMessage(field, rawMessage) {
  const message = String(rawMessage || "").replace(/^Value error,\s*/i, "").trim();
  if (field === "username" && /must not be empty|field required/i.test(message)) return "请输入用户名";
  if (field === "password" && /must not be empty|field required/i.test(message)) return "请输入密码";
  if (/username must be between/i.test(message)) return "用户名需为 3-32 位";
  if (/username may only contain/i.test(message)) return "用户名只能包含字母、数字、下划线或短横线";
  if (/password must be between/i.test(message)) return "密码需为 8-72 位";
  if (/must not be empty|field required/i.test(message)) return `请填写${AUTH_FIELD_LABELS[field] || "该项"}`;
  return message || `${AUTH_FIELD_LABELS[field] || "该项"}填写不正确`;
}

function authFieldFromLoc(loc) {
  const field = Array.isArray(loc) ? loc[loc.length - 1] : "";
  if (field === "captcha_id") return "captcha_answer";
  return AUTH_FIELD_LABELS[field] ? field : "";
}

function authErrorFeedback(error, mode) {
  const detail = error?.payload?.detail;
  if (Array.isArray(detail)) {
    const fieldErrors = {};
    detail.forEach((item) => {
      const field = authFieldFromLoc(item?.loc);
      if (field && !fieldErrors[field]) {
        fieldErrors[field] = authValidationMessage(field, item?.msg);
      }
    });
    return {
      message: Object.keys(fieldErrors).length ? "请先处理表单中标出的项目。" : "请检查表单填写是否完整。",
      fieldErrors,
      tone: "warning",
    };
  }

  const rawMessage = String(detail || error?.message || "");
  const lowerMessage = rawMessage.toLowerCase();
  if (!error?.status && /failed to fetch|load failed|network/i.test(lowerMessage)) {
    return {
      message: "无法连接服务，请确认 8765 端口服务正在运行后重试。",
      fieldErrors: {},
      tone: "danger",
    };
  }
  if (error?.status === 409 || lowerMessage.includes("username already taken")) {
    return {
      message: "用户名已存在，请换一个用户名或直接登录。",
      fieldErrors: { username: "这个用户名已被注册" },
      tone: "warning",
    };
  }
  if (rawMessage.includes("验证码")) {
    return {
      message: rawMessage,
      fieldErrors: { captcha_answer: rawMessage },
      captchaRelated: true,
      tone: "warning",
    };
  }
  if (error?.status === 429 || lowerMessage.includes("too many attempts")) {
    return {
      message: "登录失败次数过多，请等待 15 分钟后再试。",
      fieldErrors: { password: "短时间内失败次数过多" },
      tone: "warning",
    };
  }
  if (error?.status === 401 || lowerMessage.includes("invalid credentials")) {
    return {
      message: mode === "login" ? "用户名或密码错误，请检查后重试。" : "认证失败，请检查用户名和密码。",
      fieldErrors: mode === "login" ? { password: "用户名或密码不正确" } : {},
      tone: "danger",
    };
  }
  return {
    message: rawMessage || (mode === "login" ? "登录失败，请稍后重试。" : "注册失败，请稍后重试。"),
    fieldErrors: {},
    tone: "danger",
  };
}

function validateAuthForm(form, mode, captcha) {
  const errors = {};
  const username = String(form.username || "").trim();
  const password = String(form.password || "");
  const confirmPassword = String(form.confirm_password || "");
  const captchaAnswer = String(form.captcha_answer || "").trim();

  if (!username) {
    errors.username = "请输入用户名";
  } else if (mode === "register" && (username.length < 3 || username.length > 32)) {
    errors.username = "用户名需为 3-32 位";
  } else if (mode === "register" && !/^[a-zA-Z0-9_-]+$/.test(username)) {
    errors.username = "用户名只能包含字母、数字、下划线或短横线";
  }

  if (!password) {
    errors.password = mode === "register" ? "请设置密码" : "请输入密码";
  } else if (mode === "register" && (password.length < 8 || password.length > 72)) {
    errors.password = "密码需为 8-72 位";
  }

  if (mode === "register") {
    if (!confirmPassword) {
      errors.confirm_password = "请再次输入密码";
    } else if (password !== confirmPassword) {
      errors.confirm_password = "两次输入的密码不一致";
    }
  }

  if (!captcha?.captcha_id) {
    errors.captcha_answer = "验证码未加载，请先刷新验证码";
  } else if (!captchaAnswer) {
    errors.captcha_answer = "请输入验证码计算结果";
  }

  return errors;
}

function focusFirstAuthError(inputRefs, fieldErrors) {
  const field = AUTH_FIELD_ORDER.find((item) => fieldErrors[item]);
  const node = field ? inputRefs.current?.[field] : null;
  if (node) {
    window.requestAnimationFrame(() => node.focus());
  }
}

function AuthPage({ onAuthed, setToast, notice = "" }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ username: "", password: "", confirm_password: "", captcha_answer: "" });
  const [captcha, setCaptcha] = useState(null);
  const [captchaLoading, setCaptchaLoading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState("");
  const [fieldErrors, setFieldErrors] = useState({});
  const inputRefs = useRef({});

  const loadCaptcha = useCallback(
    async ({ preserveCaptchaError = false, notify = true } = {}) => {
      setCaptchaLoading(true);
      try {
        const data = await apiRequest("/api/auth/captcha");
        setCaptcha(data);
        setForm((prev) => ({ ...prev, captcha_answer: "" }));
        setFieldErrors((prev) => {
          if (preserveCaptchaError || !prev.captcha_answer) return prev;
          const next = { ...prev };
          delete next.captcha_answer;
          return next;
        });
        return data;
      } catch {
        const message = "验证码加载失败，请刷新页面或稍后重试。";
        setFormError(message);
        if (notify) setToast({ type: "danger", message });
        throw new Error(message);
      } finally {
        setCaptchaLoading(false);
      }
    },
    [setToast]
  );

  useEffect(() => {
    loadCaptcha().catch(() => {});
  }, [loadCaptcha]);

  const setFieldValue = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
    setFieldErrors((prev) => {
      if (!prev[field] && !(field === "password" && prev.confirm_password)) return prev;
      const next = { ...prev };
      delete next[field];
      if (field === "password") delete next.confirm_password;
      return next;
    });
    if (formError) setFormError("");
  };

  const switchMode = (nextMode) => {
    if (nextMode === mode) return;
    setMode(nextMode);
    setForm((prev) => ({ username: prev.username, password: "", confirm_password: "", captcha_answer: "" }));
    setFormError("");
    setFieldErrors({});
    loadCaptcha({ notify: false }).catch(() => {});
  };

  const showPhoneLoginNotice = () => {
    const message = "手机号验证码登录暂未接入，请先使用账号登录。";
    setFormError(message);
    setToast({ type: "info", message });
  };

  const submit = async (event) => {
    event.preventDefault();
    if (loading) return;
    const preparedForm = {
      ...form,
      username: String(form.username || "").trim(),
      captcha_answer: String(form.captcha_answer || "").trim(),
    };
    const localErrors = validateAuthForm(preparedForm, mode, captcha);
    if (Object.keys(localErrors).length) {
      setForm((prev) => ({ ...prev, username: preparedForm.username, captcha_answer: preparedForm.captcha_answer }));
      setFieldErrors(localErrors);
      setFormError("请先处理表单中标出的项目。");
      focusFirstAuthError(inputRefs, localErrors);
      return;
    }
    setFormError("");
    setFieldErrors({});
    setLoading(true);
    try {
      await apiRequest(`/api/auth/${mode === "login" ? "login" : "register"}`, {
        method: "POST",
        body: {
          username: preparedForm.username,
          password: preparedForm.password,
          captcha_id: captcha?.captcha_id,
          captcha_answer: preparedForm.captcha_answer,
        },
      });
      await onAuthed();
    } catch (error) {
      const feedback = authErrorFeedback(error, mode);
      setFormError(feedback.message);
      setFieldErrors(feedback.fieldErrors);
      setToast({ type: feedback.tone || "danger", message: feedback.message });
      await loadCaptcha({ preserveCaptchaError: feedback.captchaRelated, notify: false }).catch(() => {});
      focusFirstAuthError(inputRefs, feedback.fieldErrors);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-shell">
      <section className="auth-card auth-split-card">
        <aside className="auth-showcase" aria-hidden="true">
          <div className="auth-brand">
            <span className="auth-brand-logo">
              <img src="/static/rabbit-icon.png" alt="" />
            </span>
            <strong>{APP_NAME}</strong>
          </div>
          <div className="auth-hero-visual">
            <span className="cube cube-a" />
            <span className="cube cube-b" />
            <span className="cube cube-c" />
            <span className="orbit-line orbit-a" />
            <span className="orbit-line orbit-b" />
            <img src="/static/rabbit-icon.png" alt="" />
            <span className="shield-badge">
              <CheckCircle2 size={34} />
            </span>
          </div>
          <div className="auth-copy">
            <h2>
              持续代码审计
              <br />
              让证据<span>清晰可核验</span>
            </h2>
            <p>Rabbit Code Audit 帮助安全团队导入源码、建立事实图、执行多语言审计并确认关键发现。</p>
          </div>
          <div className="auth-capabilities">
            <span>
              <ShieldAlert size={16} />
              源码索引
            </span>
            <span>
              <CheckCircle2 size={16} />
              发现确认
            </span>
            <span>
              <Network size={16} />
              业务图协作
            </span>
          </div>
        </aside>

        <main className="auth-form-panel">
          {mode === "register" && (
            <button className="auth-back" type="button" onClick={() => switchMode("login")}>
              <ArrowLeft size={16} />
              返回登录
            </button>
          )}
          <div className="auth-title align-left">
            <h1>{mode === "login" ? "欢迎回来" : "创建账户"}</h1>
            <p>{mode === "login" ? "登录以继续代码审计工作流" : "加入 Rabbit Code Audit"}</p>
          </div>
          {mode === "login" && (
            <div className="segmented auth-login-tabs">
              <button className="active" type="button">
                账号登录
              </button>
              <button type="button" onClick={showPhoneLoginNotice}>
                手机号登录
              </button>
            </div>
          )}
          <div className="auth-security-note">
            <ShieldCheck size={16} />
            <span>验证码校验、失败次数限制和安全 Session 已启用</span>
          </div>
          {notice && (
            <div className="auth-form-alert session-notice" role="status">
              <AlertCircle size={16} />
              <span>{notice}</span>
            </div>
          )}
          {formError && (
            <div className="auth-form-alert" role="alert">
              <AlertCircle size={17} />
              <span>{formError}</span>
            </div>
          )}
          <form className="stack-form auth-stack-form" onSubmit={submit}>
            <label className={cn(fieldErrors.username && "has-error")}>
              <span>用户名</span>
              <Input
                ref={(node) => {
                  inputRefs.current.username = node;
                }}
                name="username"
                autoComplete="username"
                value={form.username}
                onChange={(value) => setFieldValue("username", value)}
                placeholder="请输入用户名"
                error={Boolean(fieldErrors.username)}
                aria-invalid={Boolean(fieldErrors.username)}
                aria-describedby={fieldErrors.username ? "auth-username-error" : undefined}
              />
              {fieldErrors.username && (
                <small className="field-error" id="auth-username-error">
                  {fieldErrors.username}
                </small>
              )}
            </label>
            <label className={cn(fieldErrors.password && "has-error")}>
              <span>密码</span>
              <Input.Password
                ref={(node) => {
                  inputRefs.current.password = node;
                }}
                name="password"
                autoComplete={mode === "login" ? "current-password" : "new-password"}
                value={form.password}
                onChange={(value) => setFieldValue("password", value)}
                placeholder={mode === "login" ? "请输入密码" : "请设置密码"}
                error={Boolean(fieldErrors.password)}
                aria-invalid={Boolean(fieldErrors.password)}
                aria-describedby={fieldErrors.password ? "auth-password-error" : undefined}
              />
              {fieldErrors.password && (
                <small className="field-error" id="auth-password-error">
                  {fieldErrors.password}
                </small>
              )}
            </label>
            {mode === "register" && (
              <label className={cn(fieldErrors.confirm_password && "has-error")}>
                <span>确认密码</span>
                <Input.Password
                  ref={(node) => {
                    inputRefs.current.confirm_password = node;
                  }}
                  name="confirm_password"
                  autoComplete="new-password"
                  value={form.confirm_password}
                  onChange={(value) => setFieldValue("confirm_password", value)}
                  placeholder="请再次输入密码"
                  error={Boolean(fieldErrors.confirm_password)}
                  aria-invalid={Boolean(fieldErrors.confirm_password)}
                  aria-describedby={fieldErrors.confirm_password ? "auth-confirm-password-error" : undefined}
                />
                {fieldErrors.confirm_password && (
                  <small className="field-error" id="auth-confirm-password-error">
                    {fieldErrors.confirm_password}
                  </small>
                )}
              </label>
            )}
            <label className={cn(fieldErrors.captcha_answer && "has-error")}>
              <span>验证码</span>
              <div className="captcha-row">
                <Input
                  ref={(node) => {
                    inputRefs.current.captcha_answer = node;
                  }}
                  name="captcha_answer"
                  value={form.captcha_answer}
                  onChange={(value) => setFieldValue("captcha_answer", value)}
                  placeholder="请输入计算结果"
                  inputMode="numeric"
                  error={Boolean(fieldErrors.captcha_answer)}
                  style={{ flex: 1 }}
                  aria-invalid={Boolean(fieldErrors.captcha_answer)}
                  aria-describedby={fieldErrors.captcha_answer ? "auth-captcha-error" : undefined}
                />
                <button
                  className="captcha-chip"
                  type="button"
                  onClick={() => loadCaptcha().catch(() => {})}
                  disabled={captchaLoading}
                  title="刷新验证码"
                >
                  {captchaLoading ? "加载中" : captcha?.question || "刷新验证码"}
                  <RefreshCw className={cn(captchaLoading && "spin")} size={15} />
                </button>
              </div>
              {fieldErrors.captcha_answer && (
                <small className="field-error" id="auth-captcha-error">
                  {fieldErrors.captcha_answer}
                </small>
              )}
            </label>
            <Button className="auth-submit" type="primary" long htmlType="submit" loading={loading} icon={<Lock size={16} />}>
              {loading ? (mode === "login" ? "正在登录..." : "正在注册...") : mode === "login" ? "登录" : "注册账号"}
            </Button>
          </form>
          <p className="auth-switch">
            {mode === "login" ? "还没有账号？" : "已有账号？"}
            <button type="button" onClick={() => switchMode(mode === "login" ? "register" : "login")}>
              {mode === "login" ? "立即注册" : "返回登录"}
            </button>
          </p>
        </main>
      </section>
    </div>
  );
}

function PageHeader({ icon: Icon, title, subtitle, actions, compact = false }) {
  return (
    <section className={cn("page-header", compact && "compact-report-header")}>
      <div className="page-title">
        {Icon && (
          <span className="page-icon">
            <Icon size={28} />
          </span>
        )}
        <div>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </section>
  );
}

function Toast({ toast, onClose }) {
  const type = toast.type || "info";
  const meta = {
    success: { title: "操作成功", icon: CheckCircle2 },
    warning: { title: "请注意", icon: AlertTriangle },
    danger: { title: "操作失败", icon: AlertCircle },
    info: { title: "系统提示", icon: Bell },
  }[type];
  const ToastIcon = meta.icon;

  return (
    <div
      className={cn("toast", type)}
      role={type === "danger" ? "alert" : "status"}
      aria-live={type === "danger" ? "assertive" : "polite"}
    >
      <span className="toast-icon"><ToastIcon size={18} /></span>
      <span className="toast-copy">
        <strong>{toast.title || meta.title}</strong>
        <span>{toast.message}</span>
      </span>
      <button type="button" onClick={onClose} aria-label="关闭提示" title="关闭提示">
        <X size={16} />
      </button>
      <span className="toast-timer" aria-hidden="true" />
    </div>
  );
}

function useModalLifecycle(onClose) {
  useEffect(() => {
    const previousOverflow = document.body.style.overflow;
    const onKeyDown = (event) => {
      if (event.key === "Escape") onClose();
    };
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);
}

function Modal({ title, subtitle, children, onClose, wide = false }) {
  useModalLifecycle(onClose);

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section className={cn("modal-card", wide && "wide")} role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-header">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="关闭弹窗" title="关闭">
            <X size={18} />
          </button>
        </header>
        {children}
      </section>
    </div>
  );
}

function EmptyState({ icon: Icon = Sparkles, title, subtitle, action }) {
  return (
    <div className="empty-state">
      <Icon size={42} />
      <h3>{title}</h3>
      {subtitle && <p>{subtitle}</p>}
      {action}
    </div>
  );
}

function PageErrorState({ title = "数据暂时不可用", message, onRetry }) {
  return (
    <div className="page-error-state" role="alert">
      <span className="page-error-icon"><AlertCircle size={22} /></span>
      <div>
        <h3>{title}</h3>
        <p>{message || "服务没有返回有效数据，请稍后重试。"}</p>
      </div>
      <Button size="small" type="outline" icon={<RefreshCw size={15} />} onClick={onRetry}>重试</Button>
    </div>
  );
}

function LoadingGrid({ count = 3, className = "project-grid" }) {
  return (
    <div className={cn(className, "loading-grid")} aria-label="正在加载">
      {Array.from({ length: count }, (_, index) => (
        <div className="loading-card" key={index}>
          <span className="loading-line wide" />
          <span className="loading-line medium" />
          <div className="loading-stat-row">
            <span /><span /><span />
          </div>
          <span className="loading-line full" />
        </div>
      ))}
    </div>
  );
}

function Badge({ tone = "muted", children }) {
  // Migrated to Arco Tag so every remaining <Badge> call site across the app
  // (project workspace, templates, audit log, etc.) picks up the Arco design
  // language at once, mapping the app's tone vocabulary to Arco Tag colors.
  return <Tag color={arcoTagColor(tone)}>{children}</Tag>;
}

function MiniStat({ label, value }) {
  return (
    <div className="mini-stat">
      <span>{label}</span>
      <strong>{value ?? "-"}</strong>
    </div>
  );
}

function DashboardPage({ runAction, setToast }) {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [projects, setProjects] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [newOpen, setNewOpen] = useState(false);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const [vulnList, projectList, workerList] = await Promise.all([
        apiRequest("/api/vulnerabilities"),
        apiRequest("/projects"),
        apiRequest("/api/workers").catch(() => []),
      ]);
      setVulnerabilities(Array.isArray(vulnList) ? vulnList : []);
      setProjects(Array.isArray(projectList) ? projectList : []);
      setWorkers(Array.isArray(workerList) ? workerList : []);
      setLastUpdated(new Date());
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "仪表盘数据加载失败" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => load({ silent: true }), 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const statusDistribution = useMemo(() => buildStatusDistribution(vulnerabilities), [vulnerabilities]);
  const trendData = useMemo(() => buildVulnerabilityTrend(vulnerabilities), [vulnerabilities]);
  const recentActivity = useMemo(
    () =>
      [...vulnerabilities]
        .sort((a, b) => String(b.discovered_at || "").localeCompare(String(a.discovered_at || "")))
        .slice(0, 6),
    [vulnerabilities],
  );

  const projectCounts = useMemo(() => {
    const total = projects.length;
    const active = projects.filter((project) => project.status === "active").length;
    const completed = projects.filter((project) => project.status === "completed").length;
    return { total, active, completed };
  }, [projects]);

  const workerCounts = useMemo(() => {
    return workers.reduce(
      (acc, worker) => {
        const status = worker.status || (worker.enabled === false ? "disabled" : "offline");
        acc.total += 1;
        if (status === "busy" || status === "running") acc.running += 1;
        if (["idle", "busy", "running", "online", "ready"].includes(status)) acc.online += 1;
        else acc.offline += 1;
        return acc;
      },
      { total: 0, online: 0, running: 0, offline: 0 },
    );
  }, [workers]);

  const quickActions = [
    { key: "new", label: "新建项目", desc: "导入源码并定义审计目标", icon: Plus, onClick: () => setNewOpen(true) },
    { key: "vulns", label: "审计报告", desc: "查看已确认的安全发现", icon: AlertTriangle, onClick: () => go("#/vulnerabilities") },
    { key: "workers", label: "工作节点", desc: "状态与模型配置", icon: Monitor, onClick: () => go("#/workers") },
    { key: "audit", label: "审计日志", desc: "查看系统审计操作", icon: History, onClick: () => go("#/audit") },
  ];

  return (
    <>
      <PageHeader
        icon={Home}
        title="仪表盘"
        subtitle="代码审计全局概览：项目、发现、Worker 与最近活动"
        actions={
          <>
            <div className="status-pill">
              <span className="dot success" />
              <span>{lastUpdated ? `更新于 ${lastUpdated.toLocaleTimeString("zh-CN")}` : "待更新"}</span>
            </div>
            <Button icon={<RefreshCw size={16} />} loading={loading} onClick={() => load()}>
              刷新
            </Button>
          </>
        }
      />
      <section className="content-wrap vulnerability-report-page">
        {loading ? (
          <EmptyState icon={Loader2} title="正在加载仪表盘" />
        ) : (
          <>
            <div className="metric-grid dashboard-summary-grid">
              <MetricCard label="全部项目" value={projectCounts.total} tone="info" icon={Folder} description="所有审计项目" />
              <MetricCard label="运行中项目" value={projectCounts.active} tone="success" icon={Play} description="当前正在执行" />
              <MetricCard label="审计发现" value={statusDistribution.total || 0} tone="high" icon={ShieldAlert} description="候选与确认发现" />
              <MetricCard
                label="在线 Worker"
                value={workerCounts.online}
                tone="success"
                icon={Monitor}
                description={`${workerCounts.running} 个运行中`}
              />
            </div>
            <div className="dashboard-grid">
              <VulnerabilityTrend data={trendData} />
              <VulnerabilityStatusDistribution data={statusDistribution} />
            </div>
            <section className="vuln-analysis-card dashboard-activity-card">
              <header>
                <h3>最近活动</h3>
                <span>最新发现</span>
              </header>
              {recentActivity.length === 0 ? (
                <p className="analysis-empty">暂无漏洞活动</p>
              ) : (
                <div className="recent-vuln-list">
                  {recentActivity.map((item) => {
                    const meta = SEVERITY_META[item.severity] || SEVERITY_META.low;
                    return (
                      <article key={`activity-${item.id}`}>
                        <span className={cn("activity-dot", item.severity)} />
                        <div>
                          <strong title={item.title}>{clampText(item.title, 48)}</strong>
                          <p>
                            {meta.label} · {item.project_name} · {formatTime(item.discovered_at)}
                          </p>
                        </div>
                      </article>
                    );
                  })}
                </div>
              )}
            </section>
            <section className="vuln-analysis-card dashboard-quick-card">
              <header>
                <h3>快捷操作</h3>
                <span>常用入口</span>
              </header>
              <div className="quick-action-grid">
                {quickActions.map((action) => (
                  <button
                    key={action.key}
                    className={cn("quick-action", action.key)}
                    type="button"
                    onClick={action.onClick}
                  >
                    <span className="quick-action-chip">
                      <action.icon size={20} />
                    </span>
                    <span className="quick-action-text">
                      <strong>{action.label}</strong>
                      <small>{action.desc}</small>
                    </span>
                    <ChevronRight size={18} />
                  </button>
                ))}
              </div>
            </section>
          </>
        )}
      </section>
      {newOpen && (
        <NewProjectModal
          onClose={() => setNewOpen(false)}
          onCreated={(projectId) => {
            setNewOpen(false);
            go(`#/projects/${projectId}`);
          }}
          runAction={runAction}
        />
      )}
    </>
  );
}

function ProjectsPage({ runAction, setToast, confirmAction }) {
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [newOpen, setNewOpen] = useState(false);
  const [reopenTarget, setReopenTarget] = useState(null);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    setLoadError("");
    try {
      setProjects(await apiRequest("/projects"));
    } catch (error) {
      setLoadError(error?.status === 401 ? "登录状态已失效，请重新登录。" : (error.message || "项目加载失败"));
      if (error?.status !== 401) setToast({ type: "danger", message: error.message || "项目加载失败" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  const counts = useMemo(() => {
    const total = projects.length;
    const active = projects.filter((project) => project.status === "active").length;
    const completed = projects.filter((project) => project.status === "completed").length;
    const stopped = projects.filter((project) => project.status === "stopped").length;
    return { total, active, completed, stopped };
  }, [projects]);

  const filteredProjects = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return projects.filter((project) => {
      const matchesStatus = statusFilter === "all" || project.status === statusFilter;
      const matchesQuery = !normalized || `${project.title} ${project.id}`.toLowerCase().includes(normalized);
      return matchesStatus && matchesQuery;
    });
  }, [projects, query, statusFilter]);

  const deleteProject = async (project) => {
    const ok = await confirmAction({
      title: "删除项目",
      message: `确认删除项目「${project.title}」？此操作不可恢复。`,
      tone: "danger",
      confirmLabel: "删除",
    });
    if (!ok) return;
    await runAction("项目已删除", () => apiRequest(`/projects/${project.id}`, { method: "DELETE" }));
    await load();
  };

  const updateStatus = async (project, status) => {
    await runAction("项目状态已更新", () =>
      apiRequest(`/projects/${project.id}/status`, { method: "PUT", body: { status } }),
    );
    await load();
  };

  const reopenProject = (project) => {
    setReopenTarget(project);
  };

  const submitReopen = async (description) => {
    const project = reopenTarget;
    if (!project) return;
    await runAction("项目已重新打开", () =>
      apiRequest(`/projects/${project.id}/reopen`, {
        method: "POST",
        body: { description, creator: HUMAN_WORKER },
      }),
    );
    setReopenTarget(null);
    await load();
  };

  return (
    <>
      <PageHeader
        icon={Network}
        title="代码审计项目"
        subtitle="源码快照、审计事实、调查方向与确认过程"
        actions={
          <>
            <div className="status-pill">
              <span className="dot success" />
              <span>{counts.active} 个运行中</span>
            </div>
            <Button type="primary" icon={<Plus size={16} />} onClick={() => setNewOpen(true)}>
              新建项目
            </Button>
            <Button icon={<RefreshCw size={16} />} loading={loading} onClick={() => load()}>
              刷新
            </Button>
          </>
        }
      />
      <section className="content-wrap">
            <div className="metric-grid">
          <MetricCard label="全部项目" value={counts.total} tone="info" onClick={() => setStatusFilter("all")} />
          <MetricCard label="运行中" value={counts.active} tone="success" onClick={() => setStatusFilter("active")} />
          <MetricCard label="已完成" value={counts.completed} tone="muted" onClick={() => setStatusFilter("completed")} />
          <MetricCard label="已停止" value={counts.stopped} tone="warning" onClick={() => setStatusFilter("stopped")} />
        </div>
        {loadError && projects.length > 0 && <PageErrorState message={loadError} onRetry={() => load()} />}
        <div className="collection-toolbar">
          <Input allowClear prefix={<Search size={15} />} value={query} onChange={(value) => setQuery(value)} placeholder="搜索项目名称或编号" aria-label="搜索项目名称或编号" style={{ maxWidth: 320 }} />
          <Radio.Group type="button" name="project-filter" value={statusFilter} onChange={setStatusFilter}>
            {[['all', '全部'], ['active', '运行中'], ['stopped', '已停止'], ['completed', '已完成']].map(([value, label]) => (
              <Radio key={value} value={value}>{label}</Radio>
            ))}
          </Radio.Group>
          <span className="collection-count"><SlidersHorizontal size={14} /> {filteredProjects.length} 个项目</span>
        </div>
        {loading ? (
          <LoadingGrid count={3} />
        ) : loadError && projects.length === 0 ? (
          <PageErrorState title="项目列表加载失败" message={loadError} onRetry={() => load()} />
        ) : projects.length === 0 ? (
          <EmptyState
            icon={Folder}
            title="还没有代码审计项目"
            subtitle="导入公共 Git 仓库或 ZIP 源码后，Rabbit Code Audit 会建立不可变源码快照。"
            action={
              <Button type="primary" icon={<Plus size={16} />} onClick={() => setNewOpen(true)}>
                新建项目
              </Button>
            }
          />
        ) : filteredProjects.length === 0 ? (
          <EmptyState icon={Search} title="没有匹配的项目" subtitle="换一个关键词或清除当前筛选条件。" action={<Button type="outline" size="small" icon={<X size={15} />} onClick={() => { setQuery(""); setStatusFilter("all"); }}>清除筛选</Button>} />
        ) : (
          <div className="project-grid">
            {filteredProjects.map((project) => (
              <ProjectCard
                key={project.id}
                project={project}
                onDelete={() => deleteProject(project)}
                onStop={() => updateStatus(project, "stopped")}
                onStart={() => updateStatus(project, "active")}
                onReopen={() => reopenProject(project)}
              />
            ))}
          </div>
        )}
      </section>
      {newOpen && (
        <NewProjectModal
          onClose={() => setNewOpen(false)}
          onCreated={(projectId) => {
            setNewOpen(false);
            go(`#/projects/${projectId}`);
          }}
          runAction={runAction}
        />
      )}
      {reopenTarget && (
        <TextActionModal
          title={`重新打开「${reopenTarget.title}」`}
          label="重新打开原因"
          placeholder="补充验证或重新探索"
          defaultValue="补充验证或重新探索"
          submitLabel="重新打开"
          onClose={() => setReopenTarget(null)}
          onSubmit={submitReopen}
        />
      )}
    </>
  );
}

function MetricCard({ label, value, tone, icon: Icon, description, onClick }) {
  const Component = onClick ? "button" : "div";
  return (
    <Component className={cn("metric-card", tone, onClick && "interactive")} type={onClick ? "button" : undefined} onClick={onClick}>
      {Icon ? (
        <span className="metric-icon">
          <Icon size={22} />
        </span>
      ) : (
        <span className="metric-dot" />
      )}
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
        {description && <small>{description}</small>}
      </div>
    </Component>
  );
}

function ProjectCard({ project, onDelete, onStop, onStart, onReopen }) {
  const status = STATUS_META[project.status] || STATUS_META.active;
  return (
    <article className="project-card">
      <button className="project-open" type="button" onClick={() => go(`#/projects/${project.id}`)}>
        <span className="project-folder">
          <Folder size={24} />
        </span>
        <span className="project-main">
          <span className="project-title-row">
            <strong>{project.title}</strong>
            <Badge tone={status.tone}>{status.label}</Badge>
          </span>
          <span className="project-sub">
            {project.id} · 创建于 {formatTime(project.created_at)}
          </span>
        </span>
      </button>
      <div className="project-stats">
        <MiniStat label="事实" value={project.fact_count} />
        <MiniStat label="意图" value={project.intent_count} />
        <MiniStat label="工作中" value={project.working_intent_count} />
      </div>
      {project.reason && (
        <div className="reason-strip">
          <Activity size={16} />
          <span>{project.reason.worker}</span>
          <span>{project.reason.trigger}</span>
        </div>
      )}
      <div className="card-actions">
        <Button size="small" type="outline" icon={<Eye size={16} />} onClick={() => go(`#/projects/${project.id}`)}>
          打开
        </Button>
        {project.status === "active" && (
          <Button size="small" type="outline" status="warning" icon={<Square size={16} />} onClick={onStop}>
            停止
          </Button>
        )}
        {project.status === "stopped" && (
          <Button size="small" type="outline" icon={<Play size={16} />} onClick={onStart}>
            继续
          </Button>
        )}
        {project.status === "completed" && (
          <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={onReopen}>
            重新打开
          </Button>
        )}
        <Button size="small" type="outline" status="danger" icon={<Trash2 size={16} />} onClick={onDelete}>
          删除
        </Button>
      </div>
    </article>
  );
}

function NewProjectModal({ onClose, onCreated, runAction, initial = null }) {
  const [form, setForm] = useState({
    title: initial?.title || "",
    origin: initial?.origin || "待审计源码将在导入后生成不可变快照。",
    goal: initial?.goal || "完成指定源码范围的安全审计，记录已确认漏洞、审计覆盖和剩余不确定性。",
    hints: initial?.hints?.map((hint) => hint.content).join("\n") || "",
    sourceType: "git",
    repositoryUrl: "",
    ref: "",
    archive: null,
  });
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    let createdProjectId = null;
    try {
      const detail = await runAction("项目已创建", () =>
        apiRequest("/projects", {
          method: "POST",
          body: {
            title: form.title,
            origin: form.origin,
            goal: form.goal,
            hints: parseHintLines(form.hints, HUMAN_WORKER),
          },
        }),
      );
      createdProjectId = detail.project.id;
      if (form.sourceType === "git") {
        await runAction("Git 源码已导入", () =>
          apiRequest(`/api/projects/${detail.project.id}/sources/git`, {
            method: "POST",
            body: {
              repository_url: form.repositoryUrl,
              ref: form.ref || null,
            },
          }),
        );
      } else {
        const upload = new FormData();
        upload.append("archive", form.archive);
        await runAction("ZIP 源码已导入", () =>
          apiRequest(`/api/projects/${detail.project.id}/sources/zip`, {
            method: "POST",
            body: upload,
          }),
        );
      }
      onCreated(detail.project.id);
    } catch (error) {
      if (createdProjectId) {
        try {
          await apiRequest(`/projects/${createdProjectId}`, { method: "DELETE" });
        } catch (cleanupError) {
          setToast({
            type: "danger",
            message: `${error.message || "源码导入失败"}；自动清理失败：${cleanupError.message || "请手动删除项目"}`,
          });
        }
      }
      throw error;
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="新建代码审计项目" subtitle="导入源码快照后，Worker 会围绕事实图、代码索引和工具线索推进审计。" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>项目名称</span>
          <Input value={form.title} onChange={(value) => setForm({ ...form, title: value })} required />
        </label>
        <fieldset className="source-import-panel">
          <legend>源码来源</legend>
          <Radio.Group
            type="button"
            name="source-type"
            value={form.sourceType}
            onChange={(value) => setForm({ ...form, sourceType: value })}
            style={{ marginBottom: 12 }}
          >
            <Radio value="git">Git 仓库</Radio>
            <Radio value="zip">ZIP 上传</Radio>
          </Radio.Group>
          {form.sourceType === "git" ? (
            <div className="two-col tight">
              <label>
                <span>公共仓库 URL</span>
                <Input
                  type="url"
                  value={form.repositoryUrl}
                  onChange={(value) => setForm({ ...form, repositoryUrl: value })}
                  placeholder="https://github.com/example/project.git"
                  required
                />
              </label>
              <label>
                <span>Branch、Tag 或 Commit（可选）</span>
                <Input
                  value={form.ref}
                  onChange={(value) => setForm({ ...form, ref: value })}
                  placeholder="main"
                />
              </label>
            </div>
          ) : (
            <label className="source-file-input">
              <span>ZIP 压缩包</span>
              <input
                type="file"
                accept=".zip,application/zip"
                onChange={(event) => setForm({ ...form, archive: event.target.files?.[0] || null })}
                required
              />
              <small>压缩文件最大 1 GB，解压后最大 5 GB。源码会生成不可变快照。</small>
            </label>
          )}
        </fieldset>
        <div className="two-col">
          <label>
            <span>起点</span>
            <Input.TextArea
              value={form.origin}
              onChange={(value) => setForm({ ...form, origin: value })}
              autoSize={{ minRows: 6, maxRows: 12 }}
              required
            />
          </label>
          <label>
            <span>目标</span>
            <Input.TextArea
              value={form.goal}
              onChange={(value) => setForm({ ...form, goal: value })}
              autoSize={{ minRows: 6, maxRows: 12 }}
              required
            />
          </label>
        </div>
        <label>
          <span>初始提示</span>
          <Input.TextArea
            value={form.hints}
            onChange={(value) => setForm({ ...form, hints: value })}
            autoSize={{ minRows: 4, maxRows: 8 }}
            placeholder="每行一条提示"
          />
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>
            取消
          </Button>
          <Button type="primary" htmlType="submit" loading={saving} icon={<Plus size={16} />}>
            创建并导入源码
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ValidationTargetPanel({ projectId, runAction, setToast }) {
  const [loading, setLoading] = useState(true);
  const [configured, setConfigured] = useState(false);
  const [baseUrl, setBaseUrl] = useState("");
  const [allowStateChanging, setAllowStateChanging] = useState(false);
  const [profilesText, setProfilesText] = useState("");
  const [callbackHost, setCallbackHost] = useState("");
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiRequest(`/api/projects/${projectId}/audit-validation-target`);
      setConfigured(Boolean(data && data.configured));
      const target = (data && data.target) || {};
      setBaseUrl(target.base_url || "");
      setAllowStateChanging(Boolean(target.allow_state_changing));
      setProfilesText(
        target.profiles && Object.keys(target.profiles).length
          ? JSON.stringify(target.profiles, null, 2)
          : ""
      );
      setCallbackHost((target.callback && target.callback.advertise_host) || "");
    } catch (error) {
      /* leave fields blank when unreadable */
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    load();
  }, [load]);

  const save = async () => {
    let profiles = {};
    if (profilesText.trim()) {
      try {
        profiles = JSON.parse(profilesText);
      } catch (error) {
        Message.error("凭据档案必须是合法 JSON");
        return;
      }
    }
    const body = { base_url: baseUrl.trim(), allow_state_changing: allowStateChanging, profiles };
    if (callbackHost.trim()) {
      body.callback = { advertise_host: callbackHost.trim(), bind_host: "127.0.0.1", port: 0 };
    }
    setSaving(true);
    try {
      await runAction("验证靶机已保存", () =>
        apiRequest(`/api/projects/${projectId}/audit-validation-target`, { method: "PUT", body })
      );
    } finally {
      setSaving(false);
    }
    load();
  };

  const remove = async () => {
    if (typeof window !== "undefined" && !window.confirm("删除验证靶机？高危发现将不再自动重放验证。")) {
      return;
    }
    await runAction("验证靶机已删除", () =>
      apiRequest(`/api/projects/${projectId}/audit-validation-target`, { method: "DELETE" })
    );
    load();
  };

  return (
    <Card
      title={
        <Space>
          <ShieldAlert size={16} />
          <span>验证靶机</span>
        </Space>
      }
      style={{ marginTop: 16 }}
    >
      <Typography.Paragraph type="secondary" style={{ marginTop: 0 }}>
        配置后，带验证计划的高危发现会由服务端实际重放，并由程序判定（证据等级 L4）。凭据仅用于重放，读取时已脱敏为 ***。
      </Typography.Paragraph>
      {loading ? (
        <Spin style={{ display: "block", textAlign: "center", padding: "24px 0" }} />
      ) : (
        <Space direction="vertical" size="medium" style={{ width: "100%" }}>
          <div>
            <Typography.Text>靶机地址（仅限你有授权的测试环境）</Typography.Text>
            <Input value={baseUrl} onChange={setBaseUrl} placeholder="http://127.0.0.1:8080" allowClear />
          </div>
          <Space align="center">
            <Switch checked={allowStateChanging} onChange={setAllowStateChanging} />
            <Typography.Text>允许改状态请求（POST/PUT/PATCH/DELETE）</Typography.Text>
          </Space>
          <div>
            <Typography.Text>凭据档案 JSON（可选，用于越权/IDOR 重放）</Typography.Text>
            <Input.TextArea
              value={profilesText}
              onChange={setProfilesText}
              autoSize={{ minRows: 4, maxRows: 10 }}
              placeholder={'{"alice": {"headers": {"Cookie": "sid=alice"}}, "bob": {"headers": {"Cookie": "sid=bob"}}}'}
            />
          </div>
          <div>
            <Typography.Text>SSRF 回连地址（可选，服务端可达的本机地址）</Typography.Text>
            <Input value={callbackHost} onChange={setCallbackHost} placeholder="127.0.0.1" allowClear />
          </div>
          <Space>
            <Button type="primary" loading={saving} onClick={save}>
              保存
            </Button>
            {configured && (
              <Button status="danger" onClick={remove}>
                删除
              </Button>
            )}
          </Space>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            仅对你有授权测试权限的靶机使用；重放会从服务端真实发起 HTTP 请求。
          </Typography.Text>
        </Space>
      )}
    </Card>
  );
}

function ProjectWorkspace({ projectId, runAction, setToast, confirmAction }) {
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [toolPlan, setToolPlan] = useState([]);
  const [toolScanTasks, setToolScanTasks] = useState([]);
  const [reportEnrichmentTasks, setReportEnrichmentTasks] = useState([]);
  const [toolFindings, setToolFindings] = useState([]);
  const [auditCandidates, setAuditCandidates] = useState([]);
  const [auditFindings, setAuditFindings] = useState([]);
  const [businessGraph, setBusinessGraph] = useState({ nodes: [], edges: [], conclusions: [] });
  const [sourceIndexSummary, setSourceIndexSummary] = useState(null);
  const [sourceIndexQuality, setSourceIndexQuality] = useState(null);
  const [dynamicValidationPlan, setDynamicValidationPlan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [selectedSourceId, setSelectedSourceId] = useState("");
  const [tab, setTab] = useState("details");
  const [modal, setModal] = useState(null);
  const [editingBusinessNode, setEditingBusinessNode] = useState(null);
  const [concludingBusinessNode, setConcludingBusinessNode] = useState(null);
  const [layout, setLayout] = useState("dagre");

  const load = useCallback(async () => {
    try {
      const [
        project,
        events,
        projectToolFindings,
        projectAuditCandidates,
        projectAuditFindings,
        graph,
        conclusions,
        projectReportEnrichments,
      ] = await Promise.all([
        apiRequest(`/projects/${projectId}`),
        apiRequest(`/api/projects/${projectId}/timeline`).catch(() => []),
        apiRequest(`/api/projects/${projectId}/tool-findings`).catch(() => []),
        apiRequest(`/api/projects/${projectId}/audit-candidates`).catch(() => []),
        apiRequest(`/api/projects/${projectId}/audit-findings`).catch(() => []),
        apiRequest(`/api/projects/${projectId}/business-graph`).catch(() => ({ nodes: [], edges: [] })),
        apiRequest(`/api/projects/${projectId}/business-graph/conclusions`).catch(() => []),
        apiRequest(`/api/projects/${projectId}/report-enrichments`).catch(() => []),
      ]);
      const projectSources = project.sources || [];
      const selectedSource =
        projectSources.find((source) => source.id === selectedSourceId) ||
        projectSources.find((source) => source.status === "ready") ||
        projectSources[0] ||
        null;
      const [plan, indexSummary, indexQuality, scanTasks, validationPlan] = selectedSource?.status === "ready"
        ? await Promise.all([
            apiRequest(`/api/projects/${projectId}/sources/${selectedSource.id}/tool-plan`).catch(() => []),
            apiRequest(`/api/projects/${projectId}/sources/${selectedSource.id}/index-summary`).catch(() => null),
            apiRequest(`/api/projects/${projectId}/sources/${selectedSource.id}/index-quality`).catch(() => null),
            apiRequest(`/api/projects/${projectId}/tool-scan-tasks?snapshot_id=${encodeURIComponent(selectedSource.id)}`).catch(() => []),
            apiRequest(`/api/projects/${projectId}/sources/${selectedSource.id}/dynamic-validation-plan`).catch(() => null),
          ])
        : [[], null, null, [], null];
      setDetail(project);
      setTimeline(events);
      setToolPlan(plan);
      setToolScanTasks(Array.isArray(scanTasks) ? scanTasks : []);
      setReportEnrichmentTasks(Array.isArray(projectReportEnrichments) ? projectReportEnrichments : []);
      setToolFindings(projectToolFindings);
      setAuditCandidates(projectAuditCandidates);
      setAuditFindings(projectAuditFindings);
      setSourceIndexSummary(indexSummary);
      setSourceIndexQuality(indexQuality);
      setDynamicValidationPlan(validationPlan);
      setBusinessGraph({
        nodes: Array.isArray(graph?.nodes) ? graph.nodes : [],
        edges: Array.isArray(graph?.edges) ? graph.edges : [],
        conclusions: Array.isArray(conclusions) ? conclusions : [],
      });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "项目加载失败" });
    } finally {
      setLoading(false);
    }
  }, [projectId, selectedSourceId, setToast]);

  useEffect(() => {
    setLoading(true);
    setSelected(null);
    load();
  }, [load]);

  useEffect(() => {
    if (detail?.project?.status !== "active") return undefined;
    const timer = window.setInterval(load, 5000);
    return () => window.clearInterval(timer);
  }, [detail?.project?.status, load]);

  const project = detail?.project;
  const facts = detail?.facts || [];
  const semanticBusinessNodeCount = businessGraph.nodes.filter(
    (node) => (node.graph_layer || "semantic") === "semantic",
  ).length;
  const intents = detail?.intents || [];
  const sources = detail?.sources || [];
  const currentSource =
    sources.find((source) => source.id === selectedSourceId) ||
    sources.find((source) => source.status === "ready") ||
    sources[0] ||
    null;
  const selectedFactIds = selected?.type === "fact" ? [selected.id] : facts.length ? ["origin"] : [];
  const selectedIntent = selected?.type === "intent" ? intents.find((intent) => intent.id === selected.id) : null;

  const updateTitle = () => {
    setModal("title");
  };

  const submitTitle = async (title) => {
    if (!title || title === project.title) {
      setModal(null);
      return;
    }
    await runAction("项目名称已更新", () =>
      apiRequest(`/projects/${project.id}/title`, { method: "PUT", body: { title } }),
    );
    setModal(null);
    await load();
  };

  const updateStatus = async (status) => {
    await runAction("项目状态已更新", () =>
      apiRequest(`/projects/${project.id}/status`, { method: "PUT", body: { status } }),
    );
    await load();
  };

  const submitBusinessNode = async (payload) => {
    await runAction("业务节点已保存", () =>
      apiRequest(`/api/projects/${project.id}/business-graph/nodes`, { method: "POST", body: payload }),
    );
    setModal(null);
    await load();
  };

  const updateBusinessNode = async (node, payload) => {
    await runAction("业务节点已更新", () =>
      apiRequest(`/api/projects/${project.id}/business-graph/nodes/${node.id}`, { method: "PUT", body: payload }),
    );
    setEditingBusinessNode(null);
    await load();
  };

  const submitBusinessEdge = async (payload) => {
    await runAction("业务关系已保存", () =>
      apiRequest(`/api/projects/${project.id}/business-graph/edges`, { method: "POST", body: payload }),
    );
    setModal(null);
    await load();
  };

  const submitBusinessConclusion = async (payload) => {
    await runAction("业务结论已保存", () =>
      apiRequest(`/api/projects/${project.id}/business-graph/conclusions`, { method: "POST", body: payload }),
    );
    setConcludingBusinessNode(null);
    await load();
  };

  const deleteBusinessNode = async (node) => {
    const ok = await confirmAction({
      title: "删除业务节点",
      message: `确认删除业务节点「${node.title}」？关联关系也会被删除。`,
      tone: "danger",
      confirmLabel: "删除",
    });
    if (!ok) return;
    await runAction("业务节点已删除", () =>
      apiRequest(`/api/projects/${project.id}/business-graph/nodes/${node.id}`, { method: "DELETE" }),
    );
    await load();
  };

  const deleteBusinessEdge = async (edge) => {
    await runAction("业务关系已删除", () =>
      apiRequest(`/api/projects/${project.id}/business-graph/edges/${edge.id}`, { method: "DELETE" }),
    );
    await load();
  };

  const deleteProject = async () => {
    const ok = await confirmAction({
      title: "删除项目",
      message: `确认删除项目「${project.title}」？此操作不可恢复。`,
      tone: "danger",
      confirmLabel: "删除",
    });
    if (!ok) return;
    await runAction("项目已删除", () => apiRequest(`/projects/${project.id}`, { method: "DELETE" }));
    go("#/projects");
  };

  const exportProject = async (format) => {
    await runAction(null, () => downloadFromApi(`/projects/${project.id}/export?format=${format}`, `${project.id}.${format}`));
  };

  const importSource = async (payload) => {
    if (payload.sourceType === "git") {
      await runAction("Git 源码已导入", () =>
        apiRequest(`/api/projects/${project.id}/sources/git`, {
          method: "POST",
          body: {
            repository_url: payload.repositoryUrl,
            ref: payload.ref || null,
          },
        }),
      );
    } else {
      const upload = new FormData();
      upload.append("archive", payload.archive);
      await runAction("ZIP 源码已导入", () =>
        apiRequest(`/api/projects/${project.id}/sources/zip`, {
          method: "POST",
          body: upload,
        }),
      );
    }
    setModal(null);
    await load();
  };

  const retrySourceImport = async (source) => {
    if (source.source_type !== "git" || !source.repository_url) {
      setToast({ type: "warning", message: "ZIP 快照需要重新上传文件，不能直接重试" });
      setModal("source-import");
      return;
    }
    await importSource({
      sourceType: "git",
      repositoryUrl: source.repository_url,
      ref: source.requested_ref || "",
    });
  };

  const reindexCurrentSource = async () => {
    if (!currentSource || currentSource.status !== "ready") {
      setToast({ type: "warning", message: "源码快照尚未准备完成，暂不能重建索引" });
      return;
    }
    await runAction("源码索引已重建", () =>
      apiRequest(`/api/projects/${project.id}/sources/${currentSource.id}/reindex`, { method: "POST" }),
    );
    await load();
  };

  const createToolScanTask = async ({ tools = [], timeout_per_tool = 180 } = {}) => {
    if (!currentSource || currentSource.status !== "ready") {
      setToast({ type: "warning", message: "源码快照尚未准备完成，暂不能创建工具扫描任务" });
      return;
    }
    await runAction("工具扫描任务已创建", () =>
      apiRequest(`/api/projects/${project.id}/sources/${currentSource.id}/tool-scan-tasks`, {
        method: "POST",
        body: { created_by: HUMAN_WORKER, tools, timeout_per_tool },
      }),
    );
    setTab("tools");
    await load();
  };

  const cancelToolScanTask = async (task) => {
    await runAction("工具扫描任务已取消", () =>
      apiRequest(`/api/tool-scans/${task.id}/cancel`, { method: "POST", body: { worker: HUMAN_WORKER } }),
    );
    await load();
  };

  const retryToolScanTask = async (task) => {
    await runAction("工具扫描任务已重试", () =>
      apiRequest(`/api/tool-scans/${task.id}/retry`, { method: "POST", body: { worker: HUMAN_WORKER } }),
    );
    setTab("tools");
    await load();
  };

  const createReportEnrichmentTask = async (finding) => {
    if (finding.status !== "confirmed") {
      setToast({ type: "warning", message: "只有已确认发现可以生成报告材料" });
      return;
    }
    await runAction("报告材料任务已创建", () =>
      apiRequest(`/api/projects/${project.id}/report-enrichments`, {
        method: "POST",
        body: { finding_id: finding.id, created_by: HUMAN_WORKER },
      }),
    );
    setTab("findings");
    await load();
  };

  const cancelReportEnrichmentTask = async (task) => {
    await runAction("报告材料任务已取消", () =>
      apiRequest(`/api/report-enrichments/${task.id}/cancel`, { method: "POST", body: { worker: HUMAN_WORKER } }),
    );
    await load();
  };

  const retryReportEnrichmentTask = async (task) => {
    await runAction("报告材料任务已重试", () =>
      apiRequest(`/api/report-enrichments/${task.id}/retry`, { method: "POST", body: { worker: HUMAN_WORKER } }),
    );
    setTab("findings");
    await load();
  };

  const persistDynamicValidationPlan = async () => {
    if (!currentSource || currentSource.status !== "ready") {
      setToast({ type: "warning", message: "源码快照尚未准备完成，暂不能保存动态验证计划" });
      return;
    }
    await runAction("动态验证计划已保存", () =>
      apiRequest(`/api/projects/${project.id}/sources/${currentSource.id}/dynamic-validation-plan`, {
        method: "POST",
        body: { created_by: HUMAN_WORKER },
      }),
    );
    setTab("tools");
    await load();
  };

  const submitAuditFinding = async (payload) => {
    if (!currentSource || currentSource.status !== "ready") {
      setToast({ type: "warning", message: "源码快照尚未准备完成，暂不能录入发现" });
      return;
    }
    await runAction("审计发现已保存", () =>
      apiRequest(`/api/projects/${project.id}/audit-findings`, {
        method: "POST",
        body: {
          ...payload,
          snapshot_id: currentSource.id,
          discovered_by: HUMAN_WORKER,
        },
      }),
    );
    setModal(null);
    await load();
  };

  const concludeAuditCandidate = async (candidate, payload) => {
    await runAction("候选结论已保存", () =>
      apiRequest(`/api/projects/${project.id}/audit-candidates/${candidate.id}/conclude`, {
        method: "POST",
        body: payload,
      }),
    );
    setModal(null);
    await load();
  };

  if (loading) {
    return <EmptyState icon={Loader2} title="正在载入图谱" />;
  }

  if (!detail) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="项目不可用"
        action={
          <Button type="primary" onClick={() => go("#/projects")}>
            返回项目
          </Button>
        }
      />
    );
  }

  const status = STATUS_META[project.status] || STATUS_META.active;

  return (
    <>
      <section className="workspace-header">
        <Button type="text" icon={<ArrowLeft size={20} />} onClick={() => go("#/projects")} aria-label="返回项目" />
        <div className="workspace-title">
          <span>{project.id}</span>
          <button type="button" onClick={updateTitle}>
            {project.title}
          </button>
          <Badge tone={status.tone}>{status.label}</Badge>
        </div>
        <div className="workspace-actions">
          <div className="status-pill">
            <span>{facts.length} 个事实</span>
            <span>{intents.length} 个意图</span>
            <span>{semanticBusinessNodeCount} 个业务语义</span>
          </div>
          <Button size="small" type="outline" icon={<Download size={16} />} onClick={() => exportProject("yaml")}>YAML</Button>
          <Button size="small" type="outline" icon={<Clock size={16} />} onClick={() => exportProject("timeline")}>时间线</Button>
          {project.status === "active" ? (
            <Button size="small" type="outline" status="warning" icon={<Square size={16} />} onClick={() => updateStatus("stopped")}>停止</Button>
          ) : project.status === "stopped" ? (
            <Button size="small" type="outline" icon={<Play size={16} />} onClick={() => updateStatus("active")}>继续</Button>
          ) : (
            <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={() => setModal("reopen")}>重新打开</Button>
          )}
          <Button size="small" type="outline" status="danger" icon={<Trash2 size={16} />} onClick={deleteProject}>删除</Button>
          <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={load}>刷新</Button>
        </div>
      </section>
      <section className="workspace-layout">
        <div className="graph-panel">
          {currentSource && (
            <div className="source-snapshot-bar">
              <div>
                <span>源码快照</span>
                <strong>{currentSource.resolved_commit || currentSource.snapshot_sha256 || currentSource.id}</strong>
              </div>
              <div>
                <span>语言</span>
                <strong>{Object.keys(currentSource.detected_languages || {}).join(" / ") || "未识别"}</strong>
              </div>
              <div>
                <span>文件</span>
                <strong>{currentSource.file_count}</strong>
              </div>
              <div>
                <span>大小</span>
                <strong>{formatBytes(currentSource.total_bytes)}</strong>
              </div>
              <div>
                <span>结构索引</span>
                <strong>
                  {sourceIndexSummary
                    ? `${sourceIndexSummary.symbol_count} 符号 / ${sourceIndexSummary.entrypoint_count} 入口 / ${sourceIndexSummary.relationship_count || 0} 关系`
                    : "未生成"}
                </strong>
              </div>
            </div>
          )}
          <div className="graph-toolbar floating">
            <Select value={layout} onChange={(value) => setLayout(value)} size="small" style={{ width: 120 }}>
              <Select.Option value="dagre">Dagre</Select.Option>
              <Select.Option value="breadthfirst">层级</Select.Option>
              <Select.Option value="circle">环形</Select.Option>
              <Select.Option value="grid">网格</Select.Option>
            </Select>
          </div>
          <div className="graph-actions floating right">
            <Button size="small" type="outline" icon={<Plus size={16} />} onClick={() => setModal("intent")}>意图</Button>
            <Button size="small" type="outline" status="success" icon={<CheckCircle2 size={16} />} onClick={() => setModal("conclude")} disabled={!selectedIntent || selectedIntent.to}>完成</Button>
            <Button size="small" type="outline" status="warning" icon={<Sparkles size={16} />} onClick={() => setModal("hint")}>提示</Button>
            <Button size="small" type="outline" icon={<ShieldAlert size={16} />} onClick={() => setModal("complete")}>总结</Button>
          </div>
          <GraphCanvas detail={detail} selected={selected} onSelect={setSelected} layout={layout} />
        </div>
        <Inspector
          detail={detail}
          selected={selected}
          setSelected={setSelected}
          tab={tab}
          setTab={setTab}
          timeline={timeline}
          toolPlan={toolPlan}
          toolScanTasks={toolScanTasks}
          reportEnrichmentTasks={reportEnrichmentTasks}
          toolFindings={toolFindings}
          auditCandidates={auditCandidates}
          auditFindings={auditFindings}
          businessGraph={businessGraph}
          sources={sources}
          currentSource={currentSource}
          selectedSourceId={currentSource?.id || ""}
          sourceIndexQuality={sourceIndexQuality}
          dynamicValidationPlan={dynamicValidationPlan}
          onRefresh={load}
          runAction={runAction}
          onCreateToolScan={createToolScanTask}
          onCancelToolScan={cancelToolScanTask}
          onRetryToolScan={retryToolScanTask}
          onCreateReportEnrichment={createReportEnrichmentTask}
          onCancelReportEnrichment={cancelReportEnrichmentTask}
          onRetryReportEnrichment={retryReportEnrichmentTask}
          onPersistDynamicValidationPlan={persistDynamicValidationPlan}
          onSelectSource={(sourceId) => setSelectedSourceId(sourceId)}
          onImportSource={() => setModal("source-import")}
          onRetrySource={retrySourceImport}
          onReindexSource={reindexCurrentSource}
          onCreateAuditFinding={() => setModal("audit-finding")}
          onConcludeAuditCandidate={(candidate) => setModal({ type: "candidate-conclusion", candidate })}
          onAddBusinessNode={() => setModal("business-node")}
          onAddBusinessEdge={() => setModal("business-edge")}
          onEditBusinessNode={setEditingBusinessNode}
          onAddBusinessConclusion={setConcludingBusinessNode}
          onDeleteBusinessNode={deleteBusinessNode}
          onDeleteBusinessEdge={deleteBusinessEdge}
        />
      </section>
      {modal === "intent" && (
        <IntentModal
          title="新增探索意图"
          fromIds={selectedFactIds}
          facts={facts}
          onClose={() => setModal(null)}
          onSubmit={async (payload) => {
            await runAction("意图已创建", () =>
              apiRequest(`/projects/${project.id}/intents`, { method: "POST", body: payload }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "conclude" && selectedIntent && (
        <TextActionModal
          title={`完成意图 ${selectedIntent.id}`}
          label="产出事实"
          onClose={() => setModal(null)}
          onSubmit={async (description) => {
            await runAction("意图已完成", () =>
              apiRequest(`/projects/${project.id}/intents/${selectedIntent.id}/conclude`, {
                method: "POST",
                body: { worker: selectedIntent.worker || HUMAN_WORKER, description },
              }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "hint" && (
        <TextActionModal
          title="添加项目提示"
          label="提示内容"
          onClose={() => setModal(null)}
          onSubmit={async (content) => {
            await runAction("提示已添加", () =>
              apiRequest(`/projects/${project.id}/hints`, { method: "POST", body: { content, creator: HUMAN_WORKER } }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "complete" && (
        <TextActionModal
          title="总结项目"
          label="总结结论"
          onClose={() => setModal(null)}
          onSubmit={async (description) => {
            await runAction("项目已完成", () =>
              apiRequest(`/projects/${project.id}/complete`, {
                method: "POST",
                body: { from: selectedFactIds, worker: HUMAN_WORKER, description },
              }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "reopen" && (
        <TextActionModal
          title="重新打开项目"
          label="重新打开原因"
          onClose={() => setModal(null)}
          onSubmit={async (description) => {
            await runAction("项目已重新打开", () =>
              apiRequest(`/projects/${project.id}/reopen`, {
                method: "POST",
                body: { creator: HUMAN_WORKER, description },
              }),
            );
            setModal(null);
            await load();
          }}
        />
      )}
      {modal === "title" && (
        <TextActionModal
          title="重命名项目"
          label="项目名称"
          multiline={false}
          defaultValue={project.title}
          submitLabel="保存名称"
          onClose={() => setModal(null)}
          onSubmit={submitTitle}
        />
      )}
      {modal === "business-node" && (
        <BusinessNodeModal onClose={() => setModal(null)} onSubmit={submitBusinessNode} />
      )}
      {editingBusinessNode && (
        <BusinessNodeModal
          initial={editingBusinessNode}
          title="编辑业务节点"
          submitLabel="保存节点"
          onClose={() => setEditingBusinessNode(null)}
          onSubmit={(payload) => updateBusinessNode(editingBusinessNode, payload)}
        />
      )}
      {modal === "business-edge" && (
        <BusinessEdgeModal
          nodes={businessGraph.nodes}
          onClose={() => setModal(null)}
          onSubmit={submitBusinessEdge}
        />
      )}
      {concludingBusinessNode && (
        <BusinessConclusionModal
          node={concludingBusinessNode}
          findings={auditFindings}
          onClose={() => setConcludingBusinessNode(null)}
          onSubmit={submitBusinessConclusion}
        />
      )}
      {modal === "source-import" && (
        <SourceImportModal onClose={() => setModal(null)} onSubmit={importSource} />
      )}
      {modal === "audit-finding" && (
        <AuditFindingModal
          businessNodes={businessGraph.nodes}
          toolFindings={toolFindings}
          onClose={() => setModal(null)}
          onSubmit={submitAuditFinding}
        />
      )}
      {modal?.type === "candidate-conclusion" && (
        <AuditCandidateConclusionModal
          candidate={modal.candidate}
          auditFindings={auditFindings}
          onClose={() => setModal(null)}
          onSubmit={(payload) => concludeAuditCandidate(modal.candidate, payload)}
        />
      )}
    </>
  );
}

function GraphCanvas({ detail, selected, onSelect, layout }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  const elements = useMemo(() => {
    const compactLabel = (value, length = 40) => clampText(String(value || ""), length);
    const nodes = detail.facts.map((fact) => ({
      data: {
        id: fact.id,
        label: fact.id === "origin" ? "起点" : fact.id === "goal" ? "目标" : `${fact.id}: ${compactLabel(fact.description)}`,
      },
      classes: cn("fact-node", fact.id),
    }));
    const intentNodes = detail.intents.map((intent) => ({
      data: {
        id: intent.id,
        label: `${intent.id}: ${compactLabel(intent.description)}`,
      },
      classes: cn("intent-node", intent.to ? "done" : intent.worker ? "claimed" : "open"),
    }));
    const edges = [];
    detail.intents.forEach((intent) => {
      (intent.from || []).forEach((source) => {
        edges.push({
          data: { id: `${source}-${intent.id}`, source, target: intent.id, label: "触发" },
          classes: "source-edge",
        });
      });
      if (intent.to) {
        edges.push({
          data: { id: `${intent.id}-${intent.to}`, source: intent.id, target: intent.to, label: "产出" },
          classes: "result-edge",
        });
      }
    });
    return [...nodes, ...intentNodes, ...edges];
  }, [detail]);

  useEffect(() => {
    if (!containerRef.current) return undefined;
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: 0.35,
      maxZoom: 2.2,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-family": "sans-serif",
            "font-size": 15,
            "font-weight": 600,
            color: "#fff",
            "text-wrap": "wrap",
            "text-max-width": 190,
            "text-valign": "center",
            "text-halign": "center",
            width: 196,
            height: 72,
            shape: "round-rectangle",
            "background-color": "#007aff",
            "background-opacity": 0.96,
            "border-width": 0,
          },
        },
        {
          selector: ".fact-node",
          style: {
            "background-color": "#0a84ff",
          },
        },
        {
          selector: ".origin",
          style: {
            width: 220,
            height: 104,
            "background-color": "#34c759",
            "font-size": 26,
          },
        },
        {
          selector: ".goal",
          style: {
            width: 220,
            height: 104,
            "background-color": "#ff6b6b",
            opacity: 0.88,
            "font-size": 26,
          },
        },
        {
          selector: ".intent-node.open",
          style: {
            "background-color": "#ff9f0a",
          },
        },
        {
          selector: ".intent-node.claimed",
          style: {
            "background-color": "#5856d6",
          },
        },
        {
          selector: ".intent-node.done",
          style: {
            "background-color": "#007aff",
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "curve-style": "bezier",
            "target-arrow-shape": "triangle",
            "line-color": "#7ee0c5",
            "target-arrow-color": "#7ee0c5",
            label: "data(label)",
            "font-size": 12,
            color: "#334155",
            "text-background-color": "#fff",
            "text-background-opacity": 0.9,
            "text-background-padding": 4,
          },
        },
        {
          selector: ".source-edge",
          style: {
            "line-style": "dashed",
          },
        },
        {
          selector: ":selected",
          style: {
            "border-width": 5,
            "border-color": "#ffffff",
          },
        },
      ],
    });
    cyRef.current = cy;
    cy.on("tap", "node", (event) => {
      const node = event.target;
      const id = node.id();
      const type = detail.facts.some((fact) => fact.id === id) ? "fact" : "intent";
      onSelect({ type, id });
    });
    cy.on("tap", (event) => {
      if (event.target === cy) onSelect(null);
    });
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [elements, detail.facts, onSelect]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const options =
      layout === "dagre"
        ? { name: "dagre", rankDir: "TB", nodeSep: 75, rankSep: 125, fit: true, padding: 44 }
        : { name: layout, fit: true, padding: 54 };
    cy.layout(options).run();
    window.setTimeout(() => {
      if (!cyRef.current) return;
      const currentZoom = cyRef.current.zoom();
      if (currentZoom < 0.72) {
        cyRef.current.zoom({ level: 0.72, renderedPosition: { x: cyRef.current.width() / 2, y: cyRef.current.height() / 2 } });
        cyRef.current.center();
      }
    }, 80);
  }, [layout, elements]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes().unselect();
    if (selected?.id) {
      cy.getElementById(selected.id).select();
    }
  }, [selected]);

  return <div className="graph-canvas" ref={containerRef} />;
}

function Inspector({
  detail,
  selected,
  setSelected,
  tab,
  setTab,
  timeline,
  toolPlan,
  toolScanTasks,
  reportEnrichmentTasks,
  toolFindings,
  auditCandidates,
  auditFindings,
  businessGraph,
  sources,
  currentSource,
  selectedSourceId,
  sourceIndexQuality,
  dynamicValidationPlan,
  onRefresh,
  runAction,
  onCreateToolScan,
  onCancelToolScan,
  onRetryToolScan,
  onCreateReportEnrichment,
  onCancelReportEnrichment,
  onRetryReportEnrichment,
  onPersistDynamicValidationPlan,
  onSelectSource,
  onImportSource,
  onRetrySource,
  onReindexSource,
  onCreateAuditFinding,
  onConcludeAuditCandidate,
  onAddBusinessNode,
  onAddBusinessEdge,
  onEditBusinessNode,
  onAddBusinessConclusion,
  onDeleteBusinessNode,
  onDeleteBusinessEdge,
}) {
  const facts = detail.facts;
  const intents = detail.intents;
  const semanticBusinessNodeCount = businessGraph.nodes.filter(
    (node) => (node.graph_layer || "semantic") === "semantic",
  ).length;
  const fact = selected?.type === "fact" ? facts.find((item) => item.id === selected.id) : null;
  const intent = selected?.type === "intent" ? intents.find((item) => item.id === selected.id) : null;
  const tabs = [
    ["details", "详情", null],
    ["sources", "源码", sources.length],
    ["business", "业务", semanticBusinessNodeCount],
    ["hints", "提示", detail.hints.length],
    ["tools", "工具", toolPlan.length + toolScanTasks.length],
    ["findings", "发现", auditFindings.length + auditCandidates.length],
    ["logs", "日志", intents.length],
    ["timeline", "时间线", timeline.length],
  ];

  const claimIntent = async () => {
    if (!intent) return;
    await runAction("意图已认领", () =>
      apiRequest(`/projects/${detail.project.id}/intents/${intent.id}/heartbeat`, {
        method: "POST",
        body: { worker: HUMAN_WORKER },
      }),
    );
    onRefresh();
  };

  const releaseIntent = async () => {
    if (!intent) return;
    await runAction("意图已释放", () =>
      apiRequest(`/projects/${detail.project.id}/intents/${intent.id}/release`, {
        method: "POST",
        body: { worker: intent.worker || HUMAN_WORKER },
      }),
    );
    onRefresh();
  };

  return (
    <aside className="inspector">
      <div className="inspector-tabs">
        {tabs.map(([key, label, count]) => (
          <button key={key} className={cn(tab === key && "active")} type="button" onClick={() => setTab(key)}>
            <span className="inspector-tab-label">{label}</span>
            {count !== null && <span className="inspector-tab-badge">{count}</span>}
          </button>
        ))}
      </div>
      <div className="inspector-body">
        {tab === "details" && (
          <>
            {!selected && (
              <div className="detail-card">
                <span>项目</span>
                <h3>{detail.project.title}</h3>
                <p>{detail.project.id}</p>
                <div className="detail-grid">
                  <MiniStat label="事实" value={facts.length} />
                  <MiniStat label="意图" value={intents.length} />
                </div>
              </div>
            )}
            {fact && (
              <div className="detail-card">
                <span>事实</span>
                <h3>{fact.id}</h3>
                <p>{fact.description}</p>
              </div>
            )}
            {intent && (
              <div className="detail-card">
                <span>意图</span>
                <h3>{intent.id}</h3>
                <p>{intent.description}</p>
                <div className="detail-meta">
                  <span>来源：{(intent.from || []).join(", ")}</span>
                  <span>产出：{intent.to || "未完成"}</span>
                  <span>创建者：{intent.creator}</span>
                  <span>Worker：{intent.worker || "未认领"}</span>
                </div>
                {!intent.to && (
                  <div className="button-row">
                    {!intent.worker ? (
                      <Button size="small" type="outline" icon={<Activity size={16} />} onClick={claimIntent}>认领</Button>
                    ) : (
                      <Button size="small" type="outline" icon={<Pause size={16} />} onClick={releaseIntent}>释放</Button>
                    )}
                  </div>
                )}
              </div>
            )}
            <MaturityChecklist
              sources={sources}
              currentSource={currentSource}
              toolScanTasks={toolScanTasks}
              reportEnrichmentTasks={reportEnrichmentTasks}
              auditCandidates={auditCandidates}
              auditFindings={auditFindings}
              businessGraph={businessGraph}
            />
          </>
        )}
        {tab === "sources" && (
          <SourceSnapshotPanel
            sources={sources}
            currentSource={currentSource}
            selectedSourceId={selectedSourceId}
            sourceIndexQuality={sourceIndexQuality}
            onSelectSource={onSelectSource}
            onImportSource={onImportSource}
            onRetrySource={onRetrySource}
            onReindexSource={onReindexSource}
          />
        )}
        {tab === "hints" && (
          <div className="timeline-list">
            {detail.hints.length === 0 ? (
              <EmptyState title="暂无提示" />
            ) : (
              detail.hints.map((hint) => (
                <article className="timeline-item" key={hint.id}>
                  <span>{hint.id}</span>
                  <p>{hint.content}</p>
                  <small>
                    {hint.creator} · {formatTime(hint.created_at)}
                  </small>
                </article>
              ))
            )}
          </div>
        )}
        {tab === "business" && (
          <BusinessGraphPanel
            graph={businessGraph}
            auditFindings={auditFindings}
            onAddNode={onAddBusinessNode}
            onAddEdge={onAddBusinessEdge}
            onEditNode={onEditBusinessNode}
            onAddConclusion={onAddBusinessConclusion}
            onDeleteNode={onDeleteBusinessNode}
            onDeleteEdge={onDeleteBusinessEdge}
          />
        )}
        {tab === "tools" && (
          <ToolExperiencePanel
            currentSource={currentSource}
            toolPlan={toolPlan}
            toolScanTasks={toolScanTasks}
            toolFindings={toolFindings}
            dynamicValidationPlan={dynamicValidationPlan}
            onCreateToolScan={onCreateToolScan}
            onCancelToolScan={onCancelToolScan}
            onRetryToolScan={onRetryToolScan}
            onPersistDynamicValidationPlan={onPersistDynamicValidationPlan}
            onRefresh={onRefresh}
          />
        )}
        {tab === "findings" && (
          <>
            <FindingGovernancePanel
              currentSource={currentSource}
              auditFindings={auditFindings}
              auditCandidates={auditCandidates}
              reportEnrichmentTasks={reportEnrichmentTasks}
              toolFindings={toolFindings}
              businessGraph={businessGraph}
              onCreateAuditFinding={onCreateAuditFinding}
              onConcludeAuditCandidate={onConcludeAuditCandidate}
              onCreateReportEnrichment={onCreateReportEnrichment}
              onCancelReportEnrichment={onCancelReportEnrichment}
              onRetryReportEnrichment={onRetryReportEnrichment}
            />
            <ValidationTargetPanel projectId={projectId} runAction={runAction} setToast={setToast} />
          </>
        )}
        {tab === "logs" && (
          <div className="timeline-list">
            {intents.map((item) => (
              <button
                className="timeline-item clickable"
                key={item.id}
                type="button"
                onClick={() => {
                  setSelected({ type: "intent", id: item.id });
                  setTab("details");
                }}
              >
                <span>{item.id}</span>
                <p>{item.description}</p>
                <small>{item.worker || item.creator}</small>
              </button>
            ))}
          </div>
        )}
        {tab === "timeline" && (
          <div className="timeline-list">
            {timeline.length === 0 ? (
              <EmptyState title="暂无时间线" />
            ) : (
              timeline.map((event) => (
                <button
                  className="timeline-item clickable"
                  key={event.id}
                  type="button"
                  onClick={() => event.node_id && setSelected({ type: event.node_id.startsWith("i") ? "intent" : "fact", id: event.node_id })}
                >
                  <span>{event.event_type}</span>
                  <p>{event.description}</p>
                  <small>
                    {formatTime(event.timestamp)} {event.actor ? `· ${event.actor}` : ""}
                  </small>
                </button>
              ))
            )}
          </div>
        )}
      </div>
    </aside>
  );
}

function MaturityChecklist({ sources, currentSource, toolScanTasks, reportEnrichmentTasks, auditCandidates, auditFindings, businessGraph }) {
  const sourceReady = currentSource?.status === "ready";
  const completedScan = toolScanTasks.some((task) => task.status === "completed");
  const activeScan = toolScanTasks.some((task) => task.status === "pending" || task.status === "running");
  const openCandidates = auditCandidates.filter((item) => ["candidate", "investigating"].includes(item.status || "candidate"));
  const nodes = businessGraph.nodes || [];
  const highRiskNodes = nodes.filter(isHighRiskBusinessNode);
  const openHighRisk = highRiskNodes.filter((node) => !hasBusinessCoverage(node));
  const reportableFindings = auditFindings.filter((finding) => finding.status === "confirmed" && finding.severity !== "info");
  const missingReportMaterials = reportableFindings.filter((finding) => !hasCompletedReportMaterial(reportEnrichmentTasks, finding));
  const activeReportTasks = (reportEnrichmentTasks || []).filter((task) => task.status === "pending" || task.status === "running");
  const items = [
    {
      key: "source",
      label: "源码快照",
      value: sourceReady ? currentSource.id : sources.length ? "等待 ready" : "未导入",
      ok: sourceReady,
      tone: sourceReady ? "success" : sources.length ? "warning" : "muted",
    },
    {
      key: "scan",
      label: "工具扫描",
      value: completedScan ? "已完成" : activeScan ? "运行中" : "未扫描",
      ok: completedScan,
      tone: completedScan ? "success" : activeScan ? "info" : "muted",
    },
    {
      key: "candidates",
      label: "候选闭环",
      value: openCandidates.length ? `${openCandidates.length} 条待处理` : "无待处理候选",
      ok: openCandidates.length === 0,
      tone: openCandidates.length ? "warning" : "success",
    },
    {
      key: "business",
      label: "业务覆盖",
      value: !highRiskNodes.length ? "未记录高风险节点" : openHighRisk.length ? `${openHighRisk.length} 个高风险节点待覆盖` : "高风险节点已覆盖",
      ok: highRiskNodes.length > 0 && openHighRisk.length === 0,
      tone: !highRiskNodes.length ? "muted" : openHighRisk.length ? "warning" : "success",
    },
    {
      key: "report",
      label: "MD 报告",
      value: !reportableFindings.length
        ? "暂无可导出发现"
        : missingReportMaterials.length
          ? `${reportableFindings.length - missingReportMaterials.length}/${reportableFindings.length} 条材料完成${activeReportTasks.length ? `，${activeReportTasks.length} 个任务处理中` : ""}`
          : `${reportableFindings.length} 条材料完成`,
      ok: reportableFindings.length > 0 && missingReportMaterials.length === 0,
      tone: !reportableFindings.length ? "muted" : missingReportMaterials.length ? "warning" : "success",
    },
  ];
  return (
    <div className="maturity-panel">
      <header>
        <span>项目成熟度</span>
        <strong>{items.filter((item) => item.ok).length}/{items.length}</strong>
      </header>
      <div className="maturity-list">
        {items.map((item) => (
          <div className="maturity-item" key={item.key}>
            <Badge tone={item.tone}>{item.ok ? "完成" : "待处理"}</Badge>
            <div>
              <strong>{item.label}</strong>
              <small>{item.value}</small>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SourceSnapshotPanel({
  sources,
  currentSource,
  selectedSourceId,
  sourceIndexQuality,
  onSelectSource,
  onImportSource,
  onRetrySource,
  onReindexSource,
}) {
  return (
    <div className="source-panel">
      <div className="panel-toolbar">
        <Button size="small" type="outline" icon={<Plus size={16} />} onClick={onImportSource}>导入新快照</Button>
      </div>
      {currentSource && (
        <IndexQualityPanel
          currentSource={currentSource}
          quality={sourceIndexQuality}
          onReindexSource={onReindexSource}
        />
      )}
      {sources.length === 0 ? (
        <EmptyState icon={Folder} title="暂无源码快照" subtitle="导入 Git 仓库或 ZIP 源码后会在这里生成不可变快照。" />
      ) : (
        <div className="source-snapshot-list">
          {sources.map((source) => {
            const active = source.id === selectedSourceId || source.id === currentSource?.id;
            const label = source.resolved_commit || source.snapshot_sha256 || source.original_name || source.id;
            return (
              <article className={cn("source-snapshot-card", active && "active")} key={source.id}>
                <header>
                  <div>
                    <span>{source.source_type.toUpperCase()}</span>
                    <strong>{clampText(label, 42)}</strong>
                  </div>
                  <Badge tone={sourceStatusTone(source.status)}>{formatSourceStatus(source.status)}</Badge>
                </header>
                <div className="source-meta-grid">
                  <MiniStat label="文件" value={source.file_count || 0} />
                  <MiniStat label="大小" value={formatBytes(source.total_bytes)} />
                </div>
                <div className="source-kv">
                  {source.repository_url && <span>{source.repository_url}</span>}
                  {source.requested_ref && <span>ref: {source.requested_ref}</span>}
                  <span>snapshot: {source.id}</span>
                </div>
                {source.error_message && <p className="source-error">{source.error_message}</p>}
                <div className="button-row">
                  <Button size="small" type="outline" icon={<Eye size={16} />} onClick={() => onSelectSource(source.id)}>使用此快照</Button>
                  {source.status === "failed" && (
                    <Button size="small" type="outline" status="warning" icon={<RefreshCw size={16} />} onClick={() => onRetrySource(source)}>重试</Button>
                  )}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </div>
  );
}

function IndexQualityPanel({ currentSource, quality, onReindexSource }) {
  if (currentSource.status !== "ready") {
    return (
      <section className="index-quality-panel">
        <header>
          <div>
            <span>索引质量</span>
            <strong>{formatSourceStatus(currentSource.status)}</strong>
          </div>
          <Badge tone={sourceStatusTone(currentSource.status)}>{currentSource.id}</Badge>
        </header>
      </section>
    );
  }

  if (!quality) {
    return (
      <section className="index-quality-panel">
        <header>
          <div>
            <span>索引质量</span>
            <strong>未生成</strong>
          </div>
          <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={onReindexSource}>重建索引</Button>
        </header>
      </section>
    );
  }

  const summary = quality.summary || {};
  const score = Number(quality.score || 0);
  const entrypointTotal = Number(summary.entrypoint_count || 0);
  const dataPathRatio = entrypointTotal ? `${quality.entrypoints_with_data_paths || 0}/${entrypointTotal}` : "-";
  const confidence = quality.confidence || {};
  const lowConfidence = quality.low_confidence || {};
  const issues = quality.issues || [];
  const recommendations = quality.recommendations || [];
  const orphanEntryPoints = quality.orphan_entrypoints || [];
  const readiness = quality.audit_readiness || {};
  const graphCompression = quality.graph_compression || {};
  const languageCoverage = quality.language_coverage || {};
  const languageEntries = Object.entries(languageCoverage).sort((a, b) => Number(b[1]?.files || 0) - Number(a[1]?.files || 0));
  return (
    <section className="index-quality-panel">
      <header>
        <div>
          <span>索引质量</span>
          <strong>{currentSource.id}</strong>
        </div>
        <div className="index-quality-actions">
          <Badge tone={indexQualityTone(quality.grade)}>{indexQualityGradeLabel(quality.grade)}</Badge>
          <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={onReindexSource}>重建索引</Button>
        </div>
      </header>
      <div className="quality-score-row">
        <div className={cn("quality-score", indexQualityTone(quality.grade))}>
          <strong>{score}</strong>
          <span>/100</span>
        </div>
        <div className="quality-score-detail">
          <div>
            <span>结构覆盖</span>
            <strong>
              {summary.symbol_count || 0} 符号 / {summary.entrypoint_count || 0} 入口 / {summary.relationship_count || 0} 关系
            </strong>
          </div>
          <div className="quality-meter" aria-hidden="true">
            <span style={{ width: `${Math.max(0, Math.min(100, score))}%` }} />
          </div>
        </div>
      </div>
      <div className="quality-stat-grid">
        <MiniStat label="代码文件" value={quality.code_file_count || 0} />
        <MiniStat label="数据对象" value={quality.data_object_count || 0} />
        <MiniStat label="入口数据链" value={dataPathRatio} />
        <MiniStat label="审计就绪" value={readiness.score !== undefined ? `${readiness.score}/100` : "-"} />
        <MiniStat label="图压缩" value={graphCompression.compression_ratio !== undefined ? `${Math.round(Number(graphCompression.compression_ratio || 0) * 100)}%` : "-"} />
        <MiniStat label="低置信关系" value={lowConfidence.relationships || 0} />
      </div>
      {readiness.checkpoints?.length > 0 && (
        <div className="quality-section">
          <span>审计就绪度</span>
          <div className="quality-pill-row">
            {readiness.checkpoints.map((item) => (
              <Badge key={item.key} tone={item.status === "ok" ? "success" : item.status === "missing" ? "danger" : "warning"}>
                {item.label} {item.current}/{item.target}
              </Badge>
            ))}
          </div>
        </div>
      )}
      {languageEntries.length > 0 && (
        <div className="quality-section">
          <span>语言覆盖</span>
          <div className="quality-pill-row">
            {languageEntries.slice(0, 8).map(([language, item]) => (
              <Badge key={language} tone={item.status === "strong" ? "success" : item.status === "weak" ? "warning" : "info"}>
                {language} {item.files || 0} 文件 / {item.entrypoints || 0} 入口
              </Badge>
            ))}
          </div>
        </div>
      )}
      {graphCompression.top_modules?.length > 0 && (
        <div className="quality-section">
          <span>业务图压缩</span>
          <div className="orphan-entrypoint-list">
            {graphCompression.top_modules.slice(0, 5).map((item) => (
              <p key={item.id}>
                {item.title} · {item.child_count || 0} 节点 · {item.risk_count || 0} 风险链
              </p>
            ))}
          </div>
        </div>
      )}
      <div className="quality-section">
        <span>框架</span>
        <div className="quality-pill-row">
          {sortedCountEntries(quality.framework_counts).length ? (
            sortedCountEntries(quality.framework_counts).map(([key, count]) => (
              <Badge key={key} tone="info">
                {key} {count}
              </Badge>
            ))
          ) : (
            <Badge>未识别</Badge>
          )}
        </div>
      </div>
      <div className="quality-section">
        <span>关系</span>
        <div className="quality-pill-row">
          {sortedCountEntries(quality.relationship_counts).length ? (
            sortedCountEntries(quality.relationship_counts).map(([key, count]) => (
              <Badge key={key} tone="muted">
                {key} {count}
              </Badge>
            ))
          ) : (
            <Badge>无关系</Badge>
          )}
        </div>
      </div>
      <div className="quality-confidence-row">
        <span>平均置信度</span>
        <strong>
          symbols {confidence.symbols ?? 0} / entrypoints {confidence.entrypoints ?? 0} / relationships {confidence.relationships ?? 0}
        </strong>
      </div>
      {issues.length > 0 && (
        <div className="quality-section">
          <span>问题</span>
          <div className="quality-issue-list">
            {issues.map((issue) => (
              <article key={issue.code}>
                <Badge tone={indexIssueTone(issue.severity)}>{issue.severity}</Badge>
                <div>
                  <strong>{issue.title}</strong>
                  <p>{issue.description}</p>
                </div>
              </article>
            ))}
          </div>
        </div>
      )}
      {orphanEntryPoints.length > 0 && (
        <div className="quality-section">
          <span>孤立入口</span>
          <div className="orphan-entrypoint-list">
            {orphanEntryPoints.slice(0, 5).map((entrypoint) => (
              <p key={entrypoint.id}>
                {entrypoint.method ? `${entrypoint.method} ` : ""}
                {entrypoint.route} · {entrypoint.path}
              </p>
            ))}
          </div>
        </div>
      )}
      {recommendations.length > 0 && (
        <div className="quality-section">
          <span>修复建议</span>
          <ul className="quality-recommendations">
            {recommendations.slice(0, 4).map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function FindingGovernancePanel({
  currentSource,
  auditFindings,
  auditCandidates,
  reportEnrichmentTasks = [],
  toolFindings,
  businessGraph,
  onCreateAuditFinding,
  onConcludeAuditCandidate,
  onCreateReportEnrichment,
  onCancelReportEnrichment,
  onRetryReportEnrichment,
}) {
  const openCandidates = auditCandidates.filter((item) => ["candidate", "investigating"].includes(item.status || "candidate"));
  const confirmedFindings = auditFindings.filter((item) => item.status === "confirmed");
  const completedReportMaterials = confirmedFindings.filter((finding) => hasCompletedReportMaterial(reportEnrichmentTasks, finding));
  const activeReportTasks = reportEnrichmentTasks.filter((task) => task.status === "pending" || task.status === "running");
  return (
    <div className="finding-governance-panel">
      <div className="finding-toolbar">
        <Button size="small" type="outline" disabled={currentSource?.status !== "ready"} icon={<Plus size={16} />} onClick={onCreateAuditFinding}>录入发现</Button>
        <Badge tone={currentSource?.status === "ready" ? "success" : "warning"}>
          {currentSource?.status === "ready" ? currentSource.id : "等待源码 ready"}
        </Badge>
      </div>
      <div className="metric-grid mini">
        <MetricCard label="正式发现" value={auditFindings.length} tone="info" />
        <MetricCard label="已确认" value={confirmedFindings.length} tone="success" />
        <MetricCard label="候选待处理" value={openCandidates.length} tone={openCandidates.length ? "warning" : "success"} />
        <MetricCard
          label="报告材料"
          value={confirmedFindings.length ? `${completedReportMaterials.length}/${confirmedFindings.length}` : 0}
          tone={!confirmedFindings.length ? "muted" : completedReportMaterials.length < confirmedFindings.length ? "warning" : "success"}
        />
        <MetricCard label="工具候选" value={toolFindings.length} tone="muted" />
      </div>
      <div className="business-section">
        <span>审计候选</span>
        {auditCandidates.length === 0 ? (
          <div className="soft-box compact">暂无候选发现。工具扫描或 Worker 推理出的候选会出现在这里。</div>
        ) : (
          <div className="finding-list">
            {auditCandidates.map((candidate) => {
              const severity = SEVERITY_META[candidate.severity] || { label: "未知", tone: "warning" };
              const node = (businessGraph.nodes || []).find((item) => item.id === candidate.business_node_id);
              const canConclude = !["confirmed", "rejected"].includes(candidate.status);
              return (
                <article className="finding-card" key={candidate.id}>
                  <header>
                    <div>
                      <span>{candidate.id}</span>
                      <strong>{candidate.title}</strong>
                    </div>
                    <div className="business-badge-row">
                      <Badge tone={severity.tone}>{severity.label}</Badge>
                      <Badge tone={candidateStatusTone(candidate.status)}>{formatCandidateStatus(candidate.status)}</Badge>
                    </div>
                  </header>
                  <p>{candidate.description}</p>
                  <small>
                    {candidate.file_path || candidate.entry_point || candidate.candidate_type} · {candidate.created_by}
                    {node ? ` · ${node.title}` : ""}
                  </small>
                  {candidate.conclusion_summary && <p className="finding-note">{candidate.conclusion_summary}</p>}
                  <div className="button-row">
                    <Button size="small" type="outline" disabled={!canConclude} icon={<CheckCircle2 size={16} />} onClick={() => onConcludeAuditCandidate(candidate)}>记录结论</Button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>
      <div className="business-section">
        <span>正式发现</span>
        {auditFindings.length === 0 ? (
          <EmptyState title="暂无审计发现" subtitle="Worker 验证代码证据后会在这里记录正式发现。" />
        ) : (
          <div className="finding-list">
            {auditFindings.map((finding) => {
              const severity = SEVERITY_META[finding.severity] || SEVERITY_META.info;
              const node = (businessGraph.nodes || []).find((item) => item.id === finding.business_node_id);
              const reportTask = latestReportTaskForItem(reportEnrichmentTasks, finding);
              const reportComplete = hasCompletedReportMaterial(reportEnrichmentTasks, finding);
              const reportActive = reportTask && (reportTask.status === "pending" || reportTask.status === "running");
              const reportFailed = reportTask?.status === "failed";
              const canRequestReport = finding.status === "confirmed" && !reportActive && !reportFailed;
              return (
                <article className="finding-card" key={finding.id}>
                  <header>
                    <div>
                      <span>{finding.id}</span>
                      <strong>{finding.title}</strong>
                    </div>
                    <div className="business-badge-row">
                      <Badge tone={severity.tone}>{severity.label}</Badge>
                      <Badge tone={findingStatusTone(finding.status)}>{formatFindingStatus(finding.status)}</Badge>
                    </div>
                  </header>
                  <p>{finding.description}</p>
                  <small>
                    {finding.file_path || finding.category} · {finding.discovered_by}
                    {node ? ` · ${node.title}` : ""}
                  </small>
                  {finding.remediation && <p className="finding-note">{finding.remediation}</p>}
                  <div className="report-material-box">
                    <div className="report-material-head">
                      <span>报告材料</span>
                      <Badge tone={reportTask ? reportEnrichmentStatusTone(reportTask.status) : "muted"}>
                        {reportTask ? formatReportEnrichmentStatus(reportTask.status) : "未生成"}
                      </Badge>
                    </div>
                    <p>{reportTask ? reportTaskMaterialSummary(reportTask) : "尚未提交写报告 Worker 生成补充材料。"}</p>
                    {reportTask && (
                      <small>
                        {reportTask.id} · {reportTask.worker || reportTask.created_by} · {formatTime(reportTask.created_at)}
                      </small>
                    )}
                    {reportTask?.error_message && <p className="finding-note">{reportTask.error_message}</p>}
                    <div className="button-row">
                      {canRequestReport && (
                        <Button size="small" type="outline" icon={<FileText size={16} />} onClick={() => onCreateReportEnrichment(finding)}>
                          {reportComplete ? "重新生成材料" : "生成材料"}
                        </Button>
                      )}
                      {reportActive && (
                        <Button size="small" type="outline" status="warning" icon={<Square size={16} />} onClick={() => onCancelReportEnrichment(reportTask)}>取消任务</Button>
                      )}
                      {reportFailed && (
                        <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={() => onRetryReportEnrichment(reportTask)}>重试任务</Button>
                      )}
                      {activeReportTasks.length > 0 && reportTask?.status === "completed" && (
                        <Badge tone="info">{activeReportTasks.length} 个材料任务处理中</Badge>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function ToolExperiencePanel({
  currentSource,
  toolPlan = [],
  toolScanTasks = [],
  toolFindings = [],
  dynamicValidationPlan,
  onCreateToolScan,
  onCancelToolScan,
  onRetryToolScan,
  onPersistDynamicValidationPlan,
  onRefresh,
}) {
  const [selectedTools, setSelectedTools] = useState([]);
  const [timeoutPerTool, setTimeoutPerTool] = useState(180);
  const latestScan = toolScanTasks[0] || null;
  const runningScan = toolScanTasks.find((task) => task.status === "running" || task.status === "pending");
  const sourceReady = currentSource?.status === "ready";
  const canCreateScan = sourceReady && !runningScan;
  const scanSummary = latestScan?.summaries || [];
  const validationIndicators = dynamicValidationPlan?.launch_indicators || [];
  const validationWarnings = dynamicValidationPlan?.warnings || [];
  const scanDisabledReason = !currentSource
    ? "等待源码导入完成后才能创建扫描任务"
    : !sourceReady
      ? "源码快照还没有 ready，暂不能创建扫描任务"
      : runningScan
        ? "已有扫描任务在等待或运行，完成后才能创建新任务"
        : "";
  const scanBadgeTone = runningScan || latestScan ? toolScanStatusTone(runningScan?.status || latestScan?.status) : "muted";
  const validationDisabledReason = !currentSource
    ? "等待源码导入完成后才能保存动态验证计划"
    : !sourceReady
      ? "源码快照还没有 ready，计划只会在 ready 后生成"
      : "";
  const plannedToolNames = useMemo(() => toolPlan.map((tool) => tool.name).filter(Boolean), [toolPlan]);
  const toggleTool = (toolName) => {
    setSelectedTools((prev) => (prev.includes(toolName) ? prev.filter((item) => item !== toolName) : [...prev, toolName]));
  };

  return (
    <div className="tool-experience-panel">
      <section className="tool-control-card">
        <header>
          <div>
            <span>后台工具扫描</span>
            <h3>{runningScan ? formatToolScanStatus(runningScan.status) : latestScan ? formatToolScanStatus(latestScan.status) : "未创建任务"}</h3>
          </div>
          <Badge tone={scanBadgeTone}>{toolScanTasks.length} 个任务</Badge>
        </header>
        <p>
          工具扫描只生成工具候选和审计候选；模型仍需回到源码证据中验证，不能直接确认漏洞。
        </p>
        {plannedToolNames.length > 0 && (
          <div className="tool-picker">
            <span>扫描工具</span>
            <div>
              <Button size="small" type="outline" onClick={() => setSelectedTools([])}>
                全部
              </Button>
              {plannedToolNames.map((toolName) => (
                <Tag
                  key={toolName}
                  checkable
                  checked={selectedTools.includes(toolName)}
                  onCheck={() => toggleTool(toolName)}
                  color="arcoblue"
                >
                  {toolName}
                </Tag>
              ))}
            </div>
          </div>
        )}
        <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--muted)", fontSize: 12, fontWeight: 620 }}>
          <span>单工具超时</span>
          <InputNumber
            min={10}
            max={1800}
            precision={0}
            value={timeoutPerTool}
            onChange={(value) => setTimeoutPerTool(Number(value) || 180)}
            suffix="秒"
            style={{ width: 140 }}
          />
        </div>
        <div className="tool-action-row">
          <Button
            size="small"
            type="outline"
            loading={runningScan}
            disabled={!canCreateScan}
            icon={<Play size={16} />}
            onClick={() => onCreateToolScan({ tools: selectedTools, timeout_per_tool: timeoutPerTool })}
          >
            {runningScan ? "已有任务" : "创建扫描任务"}
          </Button>
          {runningScan && (
            <Button size="small" type="outline" status="warning" icon={<Square size={16} />} onClick={() => onCancelToolScan(runningScan)}>取消任务</Button>
          )}
          <Button size="small" type="outline" icon={<RefreshCw size={16} />} onClick={onRefresh}>刷新状态</Button>
        </div>
        {scanDisabledReason && <small className="control-note">{scanDisabledReason}</small>}
        {!currentSource && (
          <div className="soft-box compact warning-box">
            尚未发现 ready 源码快照。源码导入完成后才能创建工具扫描任务。
          </div>
        )}
        {runningScan && (
          <div className="soft-box compact warning-box">
            当前已有 {formatToolScanStatus(runningScan.status)} 任务：{runningScan.id}。后台每轮只跑一个工具扫描任务，避免影响模型 worker。
          </div>
        )}
        {toolScanTasks.length > 0 && (
          <div className="tool-task-list">
            {toolScanTasks.slice(0, 5).map((task) => (
              <article className="tool-task-item" key={task.id}>
                <div>
                  <strong>{task.id}</strong>
                  <small>
                    {task.worker || task.created_by} · {formatTime(task.created_at)}
                  </small>
                </div>
                <Badge tone={toolScanStatusTone(task.status)}>{formatToolScanStatus(task.status)}</Badge>
                {task.error_message && <p>{task.error_message}</p>}
                <div className="tool-task-actions">
                  {task.status === "failed" && (
                    <Button size="small" type="outline" icon={<RefreshCw size={15} />} onClick={() => onRetryToolScan(task)}>重试</Button>
                  )}
                  {(task.status === "pending" || task.status === "running") && (
                    <Button size="small" type="outline" status="warning" icon={<Square size={15} />} onClick={() => onCancelToolScan(task)}>取消</Button>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
        {scanSummary.length > 0 && (
          <div className="tool-summary-grid">
            {scanSummary.slice(0, 6).map((item, index) => (
              <div className="tool-summary-item" key={`${item.tool_name || "tool"}-${index}`}>
                <strong>{item.tool_name || "tool"}</strong>
                <span>{item.status || "-"}</span>
                <small>{Number(item.finding_count || 0)} 条候选</small>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="tool-control-card validation-card">
        <header>
          <div>
            <span>动态验证计划</span>
            <h3>{dynamicValidationPlan ? dynamicValidationStatusLabel(dynamicValidationPlan.status) : "未生成"}</h3>
          </div>
          <Badge tone={dynamicValidationTone(dynamicValidationPlan?.status)}>
            {dynamicValidationPlan?.execution_default === "disabled" ? "默认关闭" : "未知"}
          </Badge>
        </header>
        <p>
          这里仅识别后续沙箱验证的可行性，不会执行 install、build、start 或 compose up。
        </p>
        <div className="tool-action-row">
          <Button size="small" type="outline" disabled={!currentSource} icon={<Save size={16} />} onClick={onPersistDynamicValidationPlan}>保存计划</Button>
        </div>
        {validationDisabledReason && <small className="control-note">{validationDisabledReason}</small>}
        {dynamicValidationPlan?.summary && (
          <div className="soft-box compact">{dynamicValidationPlan.summary}</div>
        )}
        {validationIndicators.length > 0 && (
          <div className="validation-indicator-list">
            {validationIndicators.slice(0, 5).map((item, index) => (
              <article key={`${item.type}-${item.path || index}`}>
                <span>{item.type}</span>
                <strong>{item.path || item.script || item.command || "-"}</strong>
                {(item.command || item.preflight_command || item.execution_command) && (
                  <code>{item.command || item.preflight_command || item.execution_command}</code>
                )}
              </article>
            ))}
          </div>
        )}
        {validationWarnings.length > 0 && (
          <div className="validation-warning-list">
            {validationWarnings.slice(0, 4).map((warning) => (
              <p key={warning}>
                <AlertTriangle size={14} />
                {warning}
              </p>
            ))}
          </div>
        )}
      </section>

      <section className="tool-control-card">
        <header>
          <div>
            <span>工具计划</span>
            <h3>{toolPlan.length} 个可用计划</h3>
          </div>
          <Badge tone="info">{toolFindings.length} 条工具候选</Badge>
        </header>
        {toolPlan.length === 0 ? (
          <EmptyState title="暂无工具计划" subtitle="源码快照准备完成后会生成多语言工具计划。" />
        ) : (
          <div className="timeline-list compact-list">
            {toolPlan.map((tool) => (
              <article className="timeline-item" key={`${tool.category}-${tool.name}`}>
                <span>{tool.category}</span>
                <p>{tool.name}</p>
                <small>{tool.reason}</small>
                <code>{Array.isArray(tool.command) ? tool.command.join(" ") : String(tool.command || "")}</code>
              </article>
            ))}
          </div>
        )}
        {toolFindings.length > 0 && (
          <div className="tool-finding-list">
            <span>工具候选</span>
            {toolFindings.slice(0, 8).map((finding) => {
              const severity = SEVERITY_META[finding.severity] || SEVERITY_META.info;
              return (
                <article key={finding.id}>
                  <div>
                    <strong>{finding.title}</strong>
                    <small>{finding.tool_name} · {finding.file_path || finding.rule_id || finding.id}</small>
                  </div>
                  <Badge tone={severity.tone}>{severity.label}</Badge>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

function isHighRiskBusinessNode(node) {
  return ["critical", "high", "unknown"].includes(node.risk_level || "unknown");
}

function hasBusinessCoverage(node) {
  if (
    ["model", "mixed"].includes(node.source_kind || "model")
    && (node.evidence_status || "unverified") !== "source_backed"
  ) {
    return false;
  }
  if (node.review_status === "covered") return true;
  return node.review_status === "blocked" && String(node.coverage_note || "").trim();
}

function getBusinessConclusionIssue(node, conclusion, auditFindingById) {
  if (!isHighRiskBusinessNode(node)) return null;
  if (
    ["model", "mixed"].includes(node.source_kind || "model")
    && (node.evidence_status || "unverified") !== "source_backed"
  ) return "源码证据未验证";
  if (!hasBusinessCoverage(node)) return "缺少覆盖";
  if (!conclusion) return "缺少结论";
  if (conclusion.conclusion === "confirmed_finding") {
    const finding = auditFindingById.get(conclusion.audit_finding_id);
    if (!finding) return "漏洞记录缺失";
    if (finding.status !== "confirmed") return "漏洞未确认";
  }
  return null;
}

function BusinessGraphPanel({
  graph,
  auditFindings,
  onAddNode,
  onAddEdge,
  onEditNode,
  onAddConclusion,
  onDeleteNode,
  onDeleteEdge,
}) {
  const nodes = graph.nodes || [];
  const edges = graph.edges || [];
  const conclusions = graph.conclusions || [];
  const [layerFilter, setLayerFilter] = useState("semantic");
  const layerCounts = useMemo(
    () =>
      nodes.reduce(
        (counts, node) => ({ ...counts, [node.graph_layer || "semantic"]: (counts[node.graph_layer || "semantic"] || 0) + 1 }),
        { evidence: 0, semantic: 0, audit: 0 },
      ),
    [nodes],
  );
  const visibleNodes = useMemo(
    () => (layerFilter === "all" ? nodes : nodes.filter((node) => (node.graph_layer || "semantic") === layerFilter)),
    [layerFilter, nodes],
  );
  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(
    () => edges.filter((edge) => visibleNodeIds.has(edge.from_node_id) && visibleNodeIds.has(edge.to_node_id)),
    [edges, visibleNodeIds],
  );
  const nodeById = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const auditFindingById = useMemo(
    () => new Map((auditFindings || []).map((finding) => [finding.id, finding])),
    [auditFindings],
  );
  const latestConclusionByNode = useMemo(() => {
    const map = new Map();
    for (const conclusion of conclusions) {
      if (!map.has(conclusion.business_node_id)) map.set(conclusion.business_node_id, conclusion);
    }
    return map;
  }, [conclusions]);
  const highRiskNodes = useMemo(() => nodes.filter(isHighRiskBusinessNode), [nodes]);
  const unresolvedNodes = useMemo(
    () =>
      highRiskNodes.filter((node) =>
        Boolean(getBusinessConclusionIssue(node, latestConclusionByNode.get(node.id), auditFindingById)),
      ),
    [auditFindingById, highRiskNodes, latestConclusionByNode],
  );

  return (
    <div className="business-graph-panel">
      <div className="business-toolbar">
        <Button size="small" type="outline" icon={<Plus size={16} />} onClick={onAddNode}>节点</Button>
        <Button size="small" type="outline" disabled={nodes.length < 2} icon={<Network size={16} />} onClick={onAddEdge}>关系</Button>
        <div className="business-layer-tabs" role="tablist" aria-label="业务图图层">
          {[
            ["all", "全部", nodes.length],
            ["evidence", "代码证据", layerCounts.evidence],
            ["semantic", "业务语义", layerCounts.semantic],
            ["audit", "审计风险", layerCounts.audit],
          ].map(([key, label, count]) => (
            <button
              className={cn(layerFilter === key && "active")}
              type="button"
              role="tab"
              aria-selected={layerFilter === key}
              key={key}
              onClick={() => setLayerFilter(key)}
            >
              {label}
              <span>{count}</span>
            </button>
          ))}
        </div>
      </div>
      {highRiskNodes.length > 0 && (
        <div className={cn("business-closure-strip", unresolvedNodes.length ? "warning" : "success")}>
          <div>
            <span>高风险闭环</span>
            <strong>
              {highRiskNodes.length - unresolvedNodes.length}/{highRiskNodes.length}
            </strong>
          </div>
          <p>
            {unresolvedNodes.length
              ? `${unresolvedNodes.length} 个严重/高/未知风险节点还缺覆盖或结构化结论`
              : "所有严重/高/未知风险节点已有覆盖和结构化结论"}
          </p>
        </div>
      )}
      {nodes.length === 0 ? (
        <EmptyState
          icon={Network}
          title="暂无业务图"
          subtitle="先记录业务功能、角色、接口、数据对象和状态流转，Worker 后续会把它作为审计上下文。"
        />
      ) : (
        <>
          <div className="business-section">
            <span>业务节点</span>
            <div className="business-node-list">
              {visibleNodes.map((node) => {
                const meta = BUSINESS_NODE_META[node.node_type] || { label: node.node_type, tone: "muted" };
                const risk = BUSINESS_RISK_META[node.risk_level || "unknown"] || BUSINESS_RISK_META.unknown;
                const layer = BUSINESS_GRAPH_LAYER_META[node.graph_layer || "semantic"] || BUSINESS_GRAPH_LAYER_META.semantic;
                const evidenceStatus =
                  BUSINESS_EVIDENCE_STATUS_META[node.evidence_status || "unverified"] || BUSINESS_EVIDENCE_STATUS_META.unverified;
                const review =
                  BUSINESS_REVIEW_STATUS_META[node.review_status || "unreviewed"] ||
                  BUSINESS_REVIEW_STATUS_META.unreviewed;
                const conclusion = latestConclusionByNode.get(node.id);
                const conclusionMeta = conclusion
                  ? BUSINESS_CONCLUSION_META[conclusion.conclusion] || { label: conclusion.conclusion, tone: "muted" }
                  : null;
                const issue = getBusinessConclusionIssue(node, conclusion, auditFindingById);
                return (
                  <article className={cn("business-node-card", issue && "needs-closure")} key={node.id}>
                    <div className="business-node-head">
                      <div className="business-badge-row">
                        <Badge tone={meta.tone}>{meta.label}</Badge>
                        <Badge tone={layer.tone}>{layer.label}</Badge>
                        <Badge tone={evidenceStatus.tone}>{evidenceStatus.label}</Badge>
                        <Badge tone={risk.tone}>{risk.label}</Badge>
                        <Badge tone={review.tone}>{review.label}</Badge>
                        {conclusionMeta && <Badge tone={conclusionMeta.tone}>{conclusionMeta.label}</Badge>}
                        {issue && <Badge tone="warning">{issue}</Badge>}
                      </div>
                      <div className="button-row">
                        <button className="icon-button tiny" type="button" title="记录结论" onClick={() => onAddConclusion(node)}>
                          <CheckCheck size={14} />
                        </button>
                        <button className="icon-button tiny" type="button" title="编辑节点" onClick={() => onEditNode(node)}>
                          <Pencil size={14} />
                        </button>
                        <button className="icon-button tiny danger" type="button" title="删除节点" onClick={() => onDeleteNode(node)}>
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </div>
                    <h3>{node.title}</h3>
                    <div className="business-node-provenance">
                      <code>{node.semantic_key || node.id}</code>
                      <span>修订 {node.revision || 1}</span>
                      <span>{(node.contributors || [node.created_by]).join("、")}</span>
                    </div>
                    {node.description && <p>{node.description}</p>}
                    {node.coverage_note && <p className="business-coverage-note">{node.coverage_note}</p>}
                    {conclusion && (
                      <div className="business-conclusion-box">
                        <strong>{conclusion.summary}</strong>
                        {conclusion.evidence && <p>{conclusion.evidence}</p>}
                        <small>
                          {conclusion.audit_finding_id || "无关联漏洞"} · {conclusion.created_by}
                        </small>
                      </div>
                    )}
                    {node.risk_tags?.length > 0 && (
                      <div className="business-chip-row">
                        {node.risk_tags.map((tag) => (
                          <span key={tag}>{tag}</span>
                        ))}
                      </div>
                    )}
                    {node.evidence?.length > 0 && (
                      <div className="business-evidence">
                        {node.evidence.map((item) => (
                          <code key={item}>{item}</code>
                        ))}
                      </div>
                    )}
                  </article>
                );
              })}
            </div>
          </div>
          <div className="business-section">
            <span>业务关系</span>
            {visibleEdges.length === 0 ? (
              <div className="soft-box compact">暂无关系</div>
            ) : (
              <div className="business-edge-list">
                {visibleEdges.map((edge) => {
                  const from = nodeById.get(edge.from_node_id);
                  const to = nodeById.get(edge.to_node_id);
                  return (
                    <article className="business-edge-card" key={edge.id}>
                      <div>
                        <strong>{from?.title || edge.from_node_id}</strong>
                        <span>{BUSINESS_EDGE_META[edge.relation] || edge.relation}</span>
                        <strong>{to?.title || edge.to_node_id}</strong>
                      </div>
                      <small>{BUSINESS_GRAPH_LAYER_META[edge.graph_layer || "semantic"]?.label || "业务语义"} · 修订 {edge.revision || 1}</small>
                      {edge.description && <p>{edge.description}</p>}
                      <button className="icon-button tiny danger" type="button" title="删除关系" onClick={() => onDeleteEdge(edge)}>
                        <Trash2 size={14} />
                      </button>
                    </article>
                  );
                })}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

function IntentModal({ fromIds, facts, onClose, onSubmit }) {
  const [form, setForm] = useState({
    from: fromIds,
    description: "",
    worker: "",
  });
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({
        from: form.from,
        description: form.description,
        creator: HUMAN_WORKER,
        worker: form.worker || null,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="新增探索意图" onClose={onClose}>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>来源事实</span>
          <Select
            mode="multiple"
            allowClear
            showSearch
            placeholder="选择一个或多个事实"
            value={form.from}
            onChange={(values) => setForm({ ...form, from: values || [] })}
            renderFormat={(option, value) => value}
            style={{ width: "100%" }}
          >
            {facts.map((fact) => (
              <Select.Option key={fact.id} value={fact.id}>
                {fact.id} · {clampText(fact.description, 60)}
              </Select.Option>
            ))}
          </Select>
        </label>
        <label>
          <span>意图描述</span>
          <Input.TextArea
            value={form.description}
            onChange={(value) => setForm({ ...form, description: value })}
            autoSize={{ minRows: 5, maxRows: 10 }}
            required
          />
        </label>
        <label>
          <span>直接认领给 Worker（可选）</span>
          <Input value={form.worker} onChange={(value) => setForm({ ...form, worker: value })} />
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={saving || !form.from.length} icon={<Plus size={16} />}>
            保存
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function TextActionModal({
  title,
  label,
  onClose,
  onSubmit,
  defaultValue = "",
  multiline = true,
  placeholder,
  submitLabel = "保存",
}) {
  const [text, setText] = useState(defaultValue);
  const [saving, setSaving] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit(text);
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal title={title} onClose={onClose}>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>{label}</span>
          {multiline ? (
            <Input.TextArea
              value={text}
              placeholder={placeholder}
              onChange={(value) => setText(value)}
              autoSize={{ minRows: 6, maxRows: 12 }}
              autoFocus
              required
            />
          ) : (
            <Input
              value={text}
              placeholder={placeholder}
              onChange={(value) => setText(value)}
              autoFocus
              required
            />
          )}
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>
            取消
          </Button>
          <Button type="primary" htmlType="submit" loading={saving} icon={<Save size={16} />}>
            {submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function BusinessNodeModal({ onClose, onSubmit, initial = null, title = "新增业务节点", submitLabel = "保存节点" }) {
  const [form, setForm] = useState({
    node_type: initial?.node_type || "feature",
    title: initial?.title || "",
    description: initial?.description || "",
    risk_level: initial?.risk_level || "unknown",
    review_status: initial?.review_status || "unreviewed",
    coverage_note: initial?.coverage_note || "",
    risk_tags: (initial?.risk_tags || []).join("\n"),
    evidence: (initial?.evidence || []).join("\n"),
  });
  const [saving, setSaving] = useState(false);
  const isEditing = Boolean(initial);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      const payload = {
        node_type: form.node_type,
        title: form.title,
        description: form.description || null,
        risk_level: form.risk_level,
        review_status: form.review_status,
        coverage_note: form.coverage_note || null,
        last_intent_id: initial?.last_intent_id || null,
        risk_tags: splitLines(form.risk_tags),
        evidence: splitLines(form.evidence),
      };
      if (!isEditing) payload.created_by = HUMAN_WORKER;
      await onSubmit(payload);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title={title} subtitle="记录功能、角色、接口、数据对象、状态或风险点。" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="two-col">
          <label>
            <span>类型</span>
            <Select value={form.node_type} onChange={(value) => setForm({ ...form, node_type: value })} style={{ width: "100%" }}>
              {Object.entries(BUSINESS_NODE_META).map(([key, meta]) => (
                <Select.Option key={key} value={key}>
                  {meta.label}
                </Select.Option>
              ))}
            </Select>
          </label>
          <label>
            <span>标题</span>
            <Input value={form.title} onChange={(value) => setForm({ ...form, title: value })} required />
          </label>
        </div>
        <div className="two-col">
          <label>
            <span>风险等级</span>
            <Select value={form.risk_level} onChange={(value) => setForm({ ...form, risk_level: value })} style={{ width: "100%" }}>
              {Object.entries(BUSINESS_RISK_META).map(([key, meta]) => (
                <Select.Option key={key} value={key}>
                  {meta.label}
                </Select.Option>
              ))}
            </Select>
          </label>
          <label>
            <span>覆盖状态</span>
            <Select value={form.review_status} onChange={(value) => setForm({ ...form, review_status: value })} style={{ width: "100%" }}>
              {Object.entries(BUSINESS_REVIEW_STATUS_META).map(([key, meta]) => (
                <Select.Option key={key} value={key}>
                  {meta.label}
                </Select.Option>
              ))}
            </Select>
          </label>
        </div>
        <label>
          <span>说明</span>
          <Input.TextArea
            value={form.description}
            onChange={(value) => setForm({ ...form, description: value })}
            autoSize={{ minRows: 4, maxRows: 10 }}
          />
        </label>
        <label>
          <span>覆盖说明</span>
          <Input.TextArea
            value={form.coverage_note}
            placeholder="已覆盖/阻塞时写明依据或剩余不确定性"
            onChange={(value) => setForm({ ...form, coverage_note: value })}
            autoSize={{ minRows: 3, maxRows: 8 }}
          />
        </label>
        <div className="two-col">
          <label>
            <span>风险标签</span>
            <Input.TextArea
              value={form.risk_tags}
              placeholder="每行一个，例如：越权"
              onChange={(value) => setForm({ ...form, risk_tags: value })}
              autoSize={{ minRows: 4, maxRows: 10 }}
            />
          </label>
          <label>
            <span>代码证据</span>
            <Input.TextArea
              value={form.evidence}
              placeholder="每行一个路径或符号"
              onChange={(value) => setForm({ ...form, evidence: value })}
              autoSize={{ minRows: 4, maxRows: 10 }}
            />
          </label>
        </div>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} icon={<Save size={16} />}>
            {submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function BusinessEdgeModal({ nodes, onClose, onSubmit }) {
  const [form, setForm] = useState({
    from_node_id: nodes[0]?.id || "",
    to_node_id: nodes[1]?.id || nodes[0]?.id || "",
    relation: "relates_to",
    description: "",
  });
  const [saving, setSaving] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({
        from_node_id: form.from_node_id,
        to_node_id: form.to_node_id,
        relation: form.relation,
        description: form.description || null,
        created_by: HUMAN_WORKER,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="新增业务关系" subtitle="把业务功能、接口、角色、数据对象和状态流转连接起来。" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="two-col">
          <label>
            <span>起点</span>
            <Select showSearch value={form.from_node_id} onChange={(value) => setForm({ ...form, from_node_id: value })} style={{ width: "100%" }}>
              {nodes.map((node) => (
                <Select.Option key={node.id} value={node.id}>
                  {node.title}
                </Select.Option>
              ))}
            </Select>
          </label>
          <label>
            <span>终点</span>
            <Select showSearch value={form.to_node_id} onChange={(value) => setForm({ ...form, to_node_id: value })} style={{ width: "100%" }}>
              {nodes.map((node) => (
                <Select.Option key={node.id} value={node.id}>
                  {node.title}
                </Select.Option>
              ))}
            </Select>
          </label>
        </div>
        <label>
          <span>关系</span>
          <Select value={form.relation} onChange={(value) => setForm({ ...form, relation: value })} style={{ width: "100%" }}>
            {Object.entries(BUSINESS_EDGE_META).map(([key, label]) => (
              <Select.Option key={key} value={key}>
                {label}
              </Select.Option>
            ))}
          </Select>
        </label>
        <label>
          <span>说明</span>
          <Input.TextArea
            value={form.description}
            onChange={(value) => setForm({ ...form, description: value })}
            autoSize={{ minRows: 4, maxRows: 10 }}
          />
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={saving || !form.from_node_id || !form.to_node_id} icon={<Save size={16} />}>
            保存关系
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function BusinessConclusionModal({ node, findings, onClose, onSubmit }) {
  const confirmedFindings = useMemo(
    () => (findings || []).filter((finding) => finding.business_node_id === node.id && finding.status === "confirmed"),
    [findings, node.id],
  );
  const [form, setForm] = useState({
    conclusion: "rejected",
    summary: "",
    evidence: "",
    audit_finding_id: "",
  });
  const [saving, setSaving] = useState(false);
  const requiresFinding = form.conclusion === "confirmed_finding";

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({
        business_node_id: node.id,
        conclusion: form.conclusion,
        summary: form.summary,
        evidence: requiresFinding ? form.evidence || null : form.evidence,
        audit_finding_id: requiresFinding ? form.audit_finding_id : null,
        created_by: HUMAN_WORKER,
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="记录业务结论" subtitle={node.title} onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="two-col">
          <label>
            <span>结论类型</span>
            <Select
              value={form.conclusion}
              onChange={(value) => setForm({ ...form, conclusion: value, audit_finding_id: "" })}
              style={{ width: "100%" }}
            >
              {Object.entries(BUSINESS_CONCLUSION_META).map(([key, meta]) => (
                <Select.Option key={key} value={key}>
                  {meta.label}
                </Select.Option>
              ))}
            </Select>
          </label>
          <label>
            <span>关联漏洞</span>
            <Select
              value={form.audit_finding_id}
              onChange={(value) => setForm({ ...form, audit_finding_id: value })}
              disabled={!requiresFinding}
              style={{ width: "100%" }}
            >
              <Select.Option value="">{requiresFinding ? "选择已确认漏洞" : "无需关联"}</Select.Option>
              {confirmedFindings.map((finding) => (
                <Select.Option key={finding.id} value={finding.id}>
                  {finding.id} · {finding.title}
                </Select.Option>
              ))}
            </Select>
          </label>
        </div>
        {requiresFinding && confirmedFindings.length === 0 && (
          <div className="soft-box compact">当前业务节点没有已确认漏洞；先让 finding 进入已确认状态，再记录确认漏洞结论。</div>
        )}
        <label>
          <span>结论摘要</span>
          <Input.TextArea
            value={form.summary}
            placeholder="写清这条业务路径最终判断是什么"
            onChange={(value) => setForm({ ...form, summary: value })}
            autoSize={{ minRows: 4, maxRows: 10 }}
            required
          />
        </label>
        <label>
          <span>证据</span>
          <Input.TextArea
            value={form.evidence}
            placeholder="未发现漏洞或证据不足时必须写代码证据、阻塞原因或缺失证据"
            onChange={(value) => setForm({ ...form, evidence: value })}
            autoSize={{ minRows: 4, maxRows: 10 }}
            required={!requiresFinding}
          />
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={saving || (requiresFinding && !form.audit_finding_id)} icon={<Save size={16} />}>
            保存结论
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SourceImportModal({ onClose, onSubmit }) {
  const [form, setForm] = useState({
    sourceType: "git",
    repositoryUrl: "",
    ref: "",
    archive: null,
  });
  const [saving, setSaving] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit(form);
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal title="导入源码快照" subtitle="新增快照不会修改已有快照和审计事实。" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <fieldset className="source-import-panel">
          <legend>源码来源</legend>
          <Radio.Group
            type="button"
            name="snapshot-source-type"
            value={form.sourceType}
            onChange={(value) => setForm({ ...form, sourceType: value })}
            style={{ marginBottom: 12 }}
          >
            <Radio value="git">Git 仓库</Radio>
            <Radio value="zip">ZIP 上传</Radio>
          </Radio.Group>
          {form.sourceType === "git" ? (
            <div className="two-col tight">
              <label>
                <span>公共仓库 URL</span>
                <Input
                  type="url"
                  value={form.repositoryUrl}
                  onChange={(value) => setForm({ ...form, repositoryUrl: value })}
                  placeholder="https://github.com/example/project.git"
                  required
                />
              </label>
              <label>
                <span>Branch、Tag 或 Commit</span>
                <Input value={form.ref} onChange={(value) => setForm({ ...form, ref: value })} placeholder="main" />
              </label>
            </div>
          ) : (
            <label className="source-file-input">
              <span>ZIP 压缩包</span>
              <input
                type="file"
                accept=".zip,application/zip"
                onChange={(event) => setForm({ ...form, archive: event.target.files?.[0] || null })}
                required
              />
              <small>ZIP 重新导入必须重新选择文件；旧快照保持不可变。</small>
            </label>
          )}
        </fieldset>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={saving || (form.sourceType === "zip" && !form.archive)} icon={<Plus size={16} />}>
            导入快照
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function AuditFindingModal({ businessNodes, toolFindings, onClose, onSubmit }) {
  const [form, setForm] = useState({
    toolFindingId: "",
    title: "",
    category: "业务逻辑",
    severity: "medium",
    cwe: "",
    file_path: "",
    line_start: "",
    line_end: "",
    symbol: "",
    entry_point: "",
    business_node_id: "",
    description: "",
    impact: "",
    evidence: "",
    remediation: "",
    proof_title: "",
    proof_payload: "",
    proof_request: "",
    proof_response: "",
    poc_payload: "",
    poc_request_template: "",
    poc_expected_result: "",
    poc_steps: "",
    poc_verification: "",
  });
  const [saving, setSaving] = useState(false);
  const applyToolFinding = (id) => {
    const finding = toolFindings.find((item) => item.id === id);
    if (!finding) {
      setForm({ ...form, toolFindingId: id });
      return;
    }
    setForm({
      ...form,
      toolFindingId: id,
      title: form.title || finding.title || "",
      severity: finding.severity === "info" ? form.severity : finding.severity || form.severity,
      category: form.category || finding.tool_name || "工具候选",
      file_path: form.file_path || finding.file_path || "",
      line_start: form.line_start || finding.line_start || "",
      line_end: form.line_end || finding.line_end || "",
      description: form.description || finding.description || "",
      evidence: form.evidence || `${finding.tool_name}${finding.rule_id ? ` / ${finding.rule_id}` : ""}`,
    });
  };
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      const proofPacket =
        form.proof_title || form.proof_payload || form.proof_request || form.proof_response
          ? {
              title: form.proof_title || "漏洞证明",
              payload: form.proof_payload,
              request: form.proof_request,
              response: form.proof_response,
            }
          : null;
      const reproduction_poc = {};
      if (form.poc_payload) reproduction_poc.payload = form.poc_payload;
      if (form.poc_request_template) reproduction_poc.request_template = form.poc_request_template;
      if (form.poc_expected_result) reproduction_poc.expected_result = form.poc_expected_result;
      if (form.poc_steps) reproduction_poc.steps = splitLines(form.poc_steps);
      if (form.poc_verification) reproduction_poc.verification = form.poc_verification;
      await onSubmit({
        title: form.title,
        category: form.category,
        severity: form.severity,
        cwe: form.cwe || null,
        file_path: form.file_path || null,
        line_start: form.line_start ? Number(form.line_start) : null,
        line_end: form.line_end ? Number(form.line_end) : null,
        symbol: form.symbol || null,
        entry_point: form.entry_point || null,
        business_node_id: form.business_node_id || null,
        description: form.description,
        impact: form.impact || null,
        evidence: form.evidence || null,
        proof_packets: proofPacket ? [proofPacket] : [],
        reproduction_poc,
        remediation: form.remediation || null,
      });
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal title="录入审计发现" subtitle="用于把已验证的源码证据记录成正式发现；不会自动改动候选或报告状态。" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        {toolFindings.length > 0 && (
          <label>
            <span>从工具候选填充</span>
            <Select showSearch value={form.toolFindingId} onChange={(value) => applyToolFinding(value)} style={{ width: "100%" }}>
              <Select.Option value="">不使用工具候选</Select.Option>
              {toolFindings.map((finding) => (
                <Select.Option key={finding.id} value={finding.id}>
                  {finding.tool_name} · {finding.title}
                </Select.Option>
              ))}
            </Select>
          </label>
        )}
        <div className="two-col">
          <label>
            <span>标题</span>
            <Input value={form.title} onChange={(value) => setForm({ ...form, title: value })} required />
          </label>
          <label>
            <span>类别</span>
            <Input value={form.category} onChange={(value) => setForm({ ...form, category: value })} required />
          </label>
        </div>
        <div className="three-col">
          <label>
            <span>严重程度</span>
            <Select value={form.severity} onChange={(value) => setForm({ ...form, severity: value })} style={{ width: "100%" }}>
              {Object.entries(SEVERITY_META).map(([key, meta]) => (
                <Select.Option key={key} value={key}>{meta.label}</Select.Option>
              ))}
            </Select>
          </label>
          <label>
            <span>CWE</span>
            <Input value={form.cwe} onChange={(value) => setForm({ ...form, cwe: value })} placeholder="CWE-639" />
          </label>
          <label>
            <span>业务节点</span>
            <Select showSearch value={form.business_node_id} onChange={(value) => setForm({ ...form, business_node_id: value })} style={{ width: "100%" }}>
              <Select.Option value="">不关联</Select.Option>
              {businessNodes.map((node) => (
                <Select.Option key={node.id} value={node.id}>{node.title}</Select.Option>
              ))}
            </Select>
          </label>
        </div>
        <div className="three-col">
          <label>
            <span>文件路径</span>
            <Input value={form.file_path} onChange={(value) => setForm({ ...form, file_path: value })} />
          </label>
          <label>
            <span>起始行</span>
            <InputNumber
              min={1}
              precision={0}
              value={form.line_start === "" ? undefined : Number(form.line_start)}
              onChange={(value) => setForm({ ...form, line_start: value ?? "" })}
              style={{ width: "100%" }}
            />
          </label>
          <label>
            <span>结束行</span>
            <InputNumber
              min={1}
              precision={0}
              value={form.line_end === "" ? undefined : Number(form.line_end)}
              onChange={(value) => setForm({ ...form, line_end: value ?? "" })}
              style={{ width: "100%" }}
            />
          </label>
        </div>
        <div className="two-col">
          <label>
            <span>符号</span>
            <Input value={form.symbol} onChange={(value) => setForm({ ...form, symbol: value })} />
          </label>
          <label>
            <span>入口点</span>
            <Input value={form.entry_point} onChange={(value) => setForm({ ...form, entry_point: value })} />
          </label>
        </div>
        <label>
          <span>描述</span>
          <Input.TextArea value={form.description} onChange={(value) => setForm({ ...form, description: value })} autoSize={{ minRows: 5, maxRows: 12 }} required />
        </label>
        <div className="two-col">
          <label>
            <span>影响</span>
            <Input.TextArea value={form.impact} onChange={(value) => setForm({ ...form, impact: value })} autoSize={{ minRows: 4, maxRows: 10 }} />
          </label>
          <label>
            <span>代码证据</span>
            <Input.TextArea value={form.evidence} onChange={(value) => setForm({ ...form, evidence: value })} autoSize={{ minRows: 4, maxRows: 10 }} />
          </label>
        </div>
        <label>
          <span>修复建议</span>
          <Input.TextArea value={form.remediation} onChange={(value) => setForm({ ...form, remediation: value })} autoSize={{ minRows: 4, maxRows: 10 }} />
        </label>
        <details className="form-details">
          <summary>证明数据包 / 静态 PoC</summary>
          <div className="two-col">
            <label>
              <span>证明标题</span>
              <Input value={form.proof_title} onChange={(value) => setForm({ ...form, proof_title: value })} />
            </label>
            <label>
              <span>Payload</span>
              <Input value={form.proof_payload} onChange={(value) => setForm({ ...form, proof_payload: value })} />
            </label>
          </div>
          <div className="two-col">
            <label>
              <span>请求数据包</span>
              <Input.TextArea value={form.proof_request} onChange={(value) => setForm({ ...form, proof_request: value })} autoSize={{ minRows: 6, maxRows: 14 }} />
            </label>
            <label>
              <span>响应/回显</span>
              <Input.TextArea value={form.proof_response} onChange={(value) => setForm({ ...form, proof_response: value })} autoSize={{ minRows: 6, maxRows: 14 }} />
            </label>
          </div>
          <div className="two-col">
            <label>
              <span>PoC 请求/命令模板</span>
              <Input.TextArea value={form.poc_request_template} onChange={(value) => setForm({ ...form, poc_request_template: value })} autoSize={{ minRows: 4, maxRows: 10 }} />
            </label>
            <label>
              <span>PoC 预期结果</span>
              <Input.TextArea value={form.poc_expected_result} onChange={(value) => setForm({ ...form, poc_expected_result: value })} autoSize={{ minRows: 4, maxRows: 10 }} />
            </label>
          </div>
          <div className="two-col">
            <label>
              <span>PoC Payload</span>
              <Input.TextArea value={form.poc_payload} onChange={(value) => setForm({ ...form, poc_payload: value })} autoSize={{ minRows: 3, maxRows: 8 }} />
            </label>
            <label>
              <span>PoC 步骤</span>
              <Input.TextArea value={form.poc_steps} onChange={(value) => setForm({ ...form, poc_steps: value })} autoSize={{ minRows: 3, maxRows: 8 }} />
            </label>
          </div>
          <label>
            <span>PoC 判断标准</span>
            <Input.TextArea value={form.poc_verification} onChange={(value) => setForm({ ...form, poc_verification: value })} autoSize={{ minRows: 3, maxRows: 8 }} />
          </label>
        </details>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} icon={<Save size={16} />}>
            保存发现
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function AuditCandidateConclusionModal({ candidate, auditFindings, onClose, onSubmit }) {
  const [form, setForm] = useState({
    decision: "rejected",
    summary: "",
    evidence: "",
    audit_finding_id: "",
  });
  const [saving, setSaving] = useState(false);
  const requiresFinding = form.decision === "confirmed";
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({
        reviewer: HUMAN_WORKER,
        decision: form.decision,
        summary: form.summary,
        evidence: form.evidence || null,
        audit_finding_id: requiresFinding ? form.audit_finding_id : null,
      });
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal title="记录候选结论" subtitle={candidate.title} onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="two-col">
          <label>
            <span>结论</span>
            <Select value={form.decision} onChange={(value) => setForm({ ...form, decision: value, audit_finding_id: "" })} style={{ width: "100%" }}>
              <Select.Option value="rejected">驳回候选</Select.Option>
              <Select.Option value="needs_more_evidence">证据不足</Select.Option>
              <Select.Option value="confirmed">确认并关联正式发现</Select.Option>
            </Select>
          </label>
          <label>
            <span>关联正式发现</span>
            <Select
              showSearch
              value={form.audit_finding_id}
              onChange={(value) => setForm({ ...form, audit_finding_id: value })}
              disabled={!requiresFinding}
              style={{ width: "100%" }}
            >
              <Select.Option value="">{requiresFinding ? "选择正式发现" : "无需关联"}</Select.Option>
              {auditFindings.map((finding) => (
                <Select.Option key={finding.id} value={finding.id}>{finding.id} · {finding.title}</Select.Option>
              ))}
            </Select>
          </label>
        </div>
        <label>
          <span>结论摘要</span>
          <Input.TextArea value={form.summary} onChange={(value) => setForm({ ...form, summary: value })} autoSize={{ minRows: 4, maxRows: 10 }} required />
        </label>
        <label>
          <span>证据 / 阻塞原因</span>
          <Input.TextArea value={form.evidence} onChange={(value) => setForm({ ...form, evidence: value })} autoSize={{ minRows: 5, maxRows: 12 }} required={!requiresFinding} />
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={saving || (requiresFinding && !form.audit_finding_id)} icon={<Save size={16} />}>
            保存结论
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function VulnerabilitiesPage({ route, runAction, setToast, confirmAction }) {
  const view = route?.view || "overview";
  const severityViews = { critical: "严重漏洞", high: "高危漏洞", medium: "中危漏洞", low: "低危漏洞" };
  const statusViews = { confirmed: "已确认漏洞", ignored: "已忽略漏洞" };
  const viewTitle =
    view === "export-records"
      ? "导出记录"
      : severityViews[view] || statusViews[view] || "报告总览";

  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [reportEnrichmentTasks, setReportEnrichmentTasks] = useState([]);
  const [projects, setProjects] = useState([]);
  const [filters, setFilters] = useState({ severity: "", project_id: "", status: "", search: route?.search || "", date_from: "", date_to: "" });
  const [expandedVulns, setExpandedVulns] = useState({});
  const [selectedIds, setSelectedIds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [exportOpen, setExportOpen] = useState(false);

  // The left sub-nav drives a severity or status filter via the URL view. The
  // in-page filter selects (project/search) still compose on top of it.
  const viewSeverity = severityViews[view] ? view : "";
  const viewStatus = statusViews[view] ? view : "";

  const query = useMemo(() => {
    const params = new URLSearchParams();
    const severity = viewSeverity || filters.severity;
    const status = viewStatus || filters.status;
    if (severity) params.set("severity", severity);
    if (filters.project_id) params.set("project_id", filters.project_id);
    if (status) params.set("status", status);
    const suffix = params.toString();
    return suffix ? `?${suffix}` : "";
  }, [filters.project_id, filters.severity, filters.status, viewSeverity, viewStatus]);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const [list, projectList, reportTasks] = await Promise.all([
        apiRequest(`/api/vulnerabilities${query}`),
        apiRequest("/projects"),
        apiRequest("/api/report-enrichment-tasks?limit=500").catch(() => []),
      ]);
      setVulnerabilities(list);
      setReportEnrichmentTasks(Array.isArray(reportTasks) ? reportTasks : []);
      setProjects(projectList);
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "审计报告加载失败" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [query, setToast]);

  useEffect(() => {
    load();
  }, [load]);

  // When the global search navigates here with a ?q= term, reflect it in the
  // in-page search filter even if this page is already mounted.
  useEffect(() => {
    if (route?.search !== undefined) {
      setFilters((prev) => (prev.search === route.search ? prev : { ...prev, search: route.search || "" }));
    }
  }, [route?.search]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      load({ silent: true });
    }, 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const refresh = async () => {
    await runAction("审计报告已刷新", () => apiRequest("/api/vulnerabilities/refresh", { method: "POST" }));
    await load();
  };

  const exportReport = async ({ selected = [], title = "vulnerabilities", scopeFilters = {}, format = "bundle" }) => {
    const formatMeta = {
      bundle: { extension: "zip", label: "审计交付包" },
      docx: { extension: "docx", label: "Word 报告" },
      pdf: { extension: "pdf", label: "PDF 报告" },
      md: { extension: "md", label: "Markdown 报告" },
    }[format] || { extension: format, label: "审计报告" };
    const params = new URLSearchParams({ format });
    if (selected.length) params.set("vulnerability_ids", selected.join(","));
    if (!selected.length && scopeFilters.project_id) params.set("project_id", scopeFilters.project_id);
    if (!selected.length && scopeFilters.severity) params.set("severity", scopeFilters.severity);
    if (!selected.length && scopeFilters.status) params.set("status", scopeFilters.status);
    await runAction(`${formatMeta.label}已生成`, () =>
      downloadFromApi(`/api/vulnerabilities/export?${params}`, `${title}.${formatMeta.extension}`),
    );
  };

  const enqueueReportMaterials = async (items) => {
    const targets = [];
    const seen = new Set();
    for (const item of items) {
      const findingId = item.fact_id || item.id;
      const key = `${item.project_id}:${findingId}`;
      if (!item.project_id || !findingId || item.status !== "confirmed" || seen.has(key)) continue;
      seen.add(key);
      targets.push({ project_id: item.project_id, finding_id: findingId });
    }
    if (!targets.length) {
      setToast({ type: "warning", message: "当前范围没有可提交的已确认漏洞" });
      return;
    }
    await runAction(`已提交 ${targets.length} 个报告材料任务`, () =>
      Promise.all(
        targets.map((target) =>
          apiRequest(`/api/projects/${target.project_id}/report-enrichments`, {
            method: "POST",
            body: { finding_id: target.finding_id, created_by: HUMAN_WORKER },
          }),
        ),
      ),
    );
    await load({ silent: true });
  };

  const updateVulnerabilityStatus = async (vuln, status) => {
    const label = status === "ignored" ? "漏洞已标记为忽略" : "漏洞已恢复为已确认";
    await runAction(label, () =>
      apiRequest(`/api/vulnerabilities/${encodeURIComponent(vuln.id)}/status`, {
        method: "PATCH",
        body: { status },
      }),
    );
    await load();
  };

  const visibleVulnerabilities = useMemo(() => {
    const term = filters.search.trim().toLowerCase();
    const from = filters.date_from;
    const to = filters.date_to;
    return vulnerabilities.filter((item) => {
      if (term) {
        const matched = [item.title, item.description, item.project_name, item.project_id, item.fact_id, item.source_worker]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(term));
        if (!matched) return false;
      }
      const day = String(item.discovered_at || "").slice(0, 10);
      if (from && day && day < from) return false;
      if (to && day && day > to) return false;
      return true;
    });
  }, [filters.search, filters.date_from, filters.date_to, vulnerabilities]);

  const filteredProjectCount = useMemo(
    () => new Set(visibleVulnerabilities.map((item) => item.project_id)).size,
    [visibleVulnerabilities],
  );
  const filteredVulnCount = visibleVulnerabilities.length;
  const totalPages = Math.max(1, Math.ceil(filteredVulnCount / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pagedVulnerabilities = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return visibleVulnerabilities.slice(start, start + pageSize);
  }, [visibleVulnerabilities, currentPage, pageSize]);
  const pageStart = filteredVulnCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const pageEnd = Math.min(currentPage * pageSize, filteredVulnCount);
  const pageNumbers = useMemo(() => buildPageNumbers(currentPage, totalPages), [currentPage, totalPages]);
  const visibleSummary = useMemo(() => summarizeSeverity(visibleVulnerabilities), [visibleVulnerabilities]);
  const statusDistribution = useMemo(() => buildStatusDistribution(visibleVulnerabilities), [visibleVulnerabilities]);
  const visibleIds = useMemo(() => visibleVulnerabilities.map((item) => item.id), [visibleVulnerabilities]);
  const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => selectedIds.includes(id));
  const severityTop = useMemo(() => buildSeverityTop(visibleVulnerabilities), [visibleVulnerabilities]);
  const trendData = useMemo(() => buildVulnerabilityTrend(visibleVulnerabilities), [visibleVulnerabilities]);

  useEffect(() => {
    setSelectedIds((prev) => prev.filter((id) => visibleIds.includes(id)));
  }, [visibleIds]);

  // Reset to the first page whenever the result set or page size changes.
  useEffect(() => {
    setPage(1);
  }, [query, filters.search, filters.date_from, filters.date_to, pageSize]);

  // Keep the current page within bounds if the total shrinks.
  useEffect(() => {
    setPage((prev) => Math.min(prev, totalPages));
  }, [totalPages]);

  const toggleSelected = (id) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]));
  };

  const toggleVisibleSelected = () => {
    setSelectedIds(allVisibleSelected ? [] : visibleIds);
  };

  if (view === "export-records") {
    return <ExportRecordsView setToast={setToast} confirmAction={confirmAction} />;
  }

  return (
    <>
      <PageHeader
        compact
        title={`审计报告 / ${viewTitle}`}
        subtitle="仅展示已确认的代码审计发现"
        actions={
          <Button type="primary" icon={<Download size={16} />} onClick={() => setExportOpen(true)}>
            报告交付
          </Button>
        }
      />
      <section className="content-wrap vulnerability-report-page">
        <div className="metric-grid severity">
          {["critical", "high", "medium", "low"].map((level) => (
            <MetricCard key={level} label={`${SEVERITY_META[level].label}漏洞`} value={visibleSummary[level] || 0} tone={level} />
          ))}
          <MetricCard label="已确认" value={statusDistribution.confirmed || 0} tone="success" />
        </div>
        <div className="report-filter-bar">
          <Input
            allowClear
            prefix={<Search size={15} />}
            value={filters.search}
            onChange={(value) => setFilters({ ...filters, search: value })}
            placeholder="搜索漏洞标题、编号、组件、标签..."
            style={{ flex: "1 1 240px", minWidth: 220, alignSelf: "flex-end" }}
          />
          <label className="filter-field">
            <span>项目</span>
            <Select value={filters.project_id || ""} onChange={(value) => setFilters({ ...filters, project_id: value })} style={{ width: 180 }}>
              <Select.Option value="">全部项目</Select.Option>
              {projects.map((project) => (
                <Select.Option key={project.id} value={project.id}>{project.title}</Select.Option>
              ))}
            </Select>
          </label>
          <label className="filter-field">
            <span>严重程度</span>
            <Select
              value={viewSeverity || filters.severity || ""}
              disabled={!!viewSeverity}
              onChange={(value) => setFilters({ ...filters, severity: value })}
              style={{ width: 120 }}
            >
              <Select.Option value="">全部</Select.Option>
              {Object.entries(SEVERITY_META).map(([key, meta]) => (
                <Select.Option key={key} value={key}>{meta.label}</Select.Option>
              ))}
            </Select>
          </label>
          <label className="filter-field">
            <span>状态</span>
            <Select
              value={viewStatus || filters.status || ""}
              disabled={!!viewStatus}
              onChange={(value) => setFilters({ ...filters, status: value })}
              style={{ width: 130 }}
            >
              <Select.Option value="">全部状态</Select.Option>
              <Select.Option value="confirmed">已确认</Select.Option>
              <Select.Option value="ignored">已忽略</Select.Option>
            </Select>
          </label>
          <label className="filter-field date-field">
            <span>发现时间</span>
            <DatePicker.RangePicker
              allowClear
              value={filters.date_from || filters.date_to ? [filters.date_from, filters.date_to] : undefined}
              onChange={(dateStrings) => setFilters({ ...filters, date_from: dateStrings?.[0] || "", date_to: dateStrings?.[1] || "" })}
              style={{ width: 260 }}
            />
          </label>
          <Button
            type="outline"
            icon={<X size={15} />}
            style={{ alignSelf: "flex-end" }}
            onClick={() => setFilters({ severity: "", project_id: "", status: "", search: "", date_from: "", date_to: "" })}
          >
            重置
          </Button>
        </div>
        {loading ? (
          <EmptyState icon={Loader2} title="正在加载审计报告" />
        ) : visibleVulnerabilities.length === 0 ? (
          <EmptyState icon={CheckCircle2} title="没有匹配的漏洞" subtitle="当前筛选范围内尚未发现漏洞。" />
        ) : (
          <div className="vuln-report-grid">
            <article className="vuln-table-card">
              <header className="vuln-table-title">
                <div>
                  <h2>漏洞列表</h2>
                  <p>点击单条漏洞查看证据、过程和证明数据包</p>
                </div>
                <Button size="small" type="outline" disabled={!visibleIds.length} onClick={toggleVisibleSelected}>
                  {allVisibleSelected ? "取消全选" : "全选当前"}
                </Button>
              </header>
              <div className="vuln-table-head">
                <span />
                <span>漏洞名称</span>
                <span>所属项目</span>
                <span>严重度</span>
                <span>状态</span>
                <span>发现时间</span>
                <span>操作</span>
              </div>
              <div className="vuln-table-body">
                {pagedVulnerabilities.map((vuln) => (
                  <VulnerabilityItem
                    key={vuln.id}
                    vuln={vuln}
                    selected={selectedIds.includes(vuln.id)}
                    setToast={setToast}
                    onSelect={() => toggleSelected(vuln.id)}
                    expanded={!!expandedVulns[vuln.id]}
                    onToggle={() => setExpandedVulns({ ...expandedVulns, [vuln.id]: !expandedVulns[vuln.id] })}
                    onExport={() => exportReport({ selected: [vuln.id], title: `${vuln.project_id}-${vuln.fact_id}` })}
                    onStatusChange={(status) => updateVulnerabilityStatus(vuln, status)}
                  />
                ))}
              </div>
              <footer className="vuln-table-footer">
                <Pagination
                  total={filteredVulnCount}
                  current={currentPage}
                  pageSize={pageSize}
                  sizeCanChange
                  showTotal
                  sizeOptions={[10, 20, 50, 100]}
                  onChange={(pageNum, size) => {
                    setPage(pageNum);
                    if (size && size !== pageSize) setPageSize(size);
                  }}
                  onPageSizeChange={(size) => {
                    setPageSize(size);
                    setPage(1);
                  }}
                />
              </footer>
            </article>
            <aside className="vuln-side-panels">
              <VulnerabilityTrend data={trendData} />
              <SeverityTopList items={severityTop} />
              <VulnerabilityStatusDistribution data={statusDistribution} />
            </aside>
          </div>
        )}
      </section>
      {exportOpen && (
        <ReportExportModal
          projects={projects}
          filters={{ ...filters, severity: viewSeverity || filters.severity, status: viewStatus || filters.status }}
          vulnerabilities={visibleVulnerabilities}
          selectedIds={selectedIds}
          reportEnrichmentTasks={reportEnrichmentTasks}
          selectedCount={selectedIds.length}
          visibleCount={filteredVulnCount}
          onClose={() => setExportOpen(false)}
          onEnqueueReportMaterials={enqueueReportMaterials}
          onSubmit={async ({ mode, scopeFilters, format }) => {
            await exportReport({
              selected: mode === "selected" ? selectedIds : [],
              title: mode === "selected" ? "rabbit-selected-vulnerabilities" : "rabbit-vulnerabilities",
              scopeFilters,
              format,
            });
            setExportOpen(false);
          }}
        />
      )}
    </>
  );
}

function ReportExportModal({
  projects,
  filters,
  vulnerabilities = [],
  selectedIds = [],
  reportEnrichmentTasks = [],
  selectedCount,
  visibleCount,
  onClose,
  onSubmit,
  onEnqueueReportMaterials,
}) {
  const [form, setForm] = useState({
    mode: selectedCount ? "selected" : "filtered",
    format: "bundle",
    project_id: filters.project_id || "",
    severity: filters.severity || "",
    status: filters.status || "",
  });
  const [saving, setSaving] = useState(false);
  const [materialBusy, setMaterialBusy] = useState(false);
  const scopedVulnerabilities = useMemo(() => {
    const selected = new Set(selectedIds);
    if (form.mode === "selected") {
      return vulnerabilities.filter((item) => selected.has(item.id));
    }
    return vulnerabilities.filter((item) => {
      if (form.project_id && item.project_id !== form.project_id) return false;
      if (form.severity && item.severity !== form.severity) return false;
      if (form.status && item.status !== form.status) return false;
      return true;
    });
  }, [form.mode, form.project_id, form.severity, form.status, selectedIds, vulnerabilities]);
  const missingReportMaterials = useMemo(
    () =>
      scopedVulnerabilities.filter(
        (item) => item.status === "confirmed" && !hasCompletedReportMaterial(reportEnrichmentTasks, item),
      ),
    [reportEnrichmentTasks, scopedVulnerabilities],
  );
  const activeReportMaterials = useMemo(
    () =>
      reportEnrichmentTasks.filter(
        (task) =>
          (task.status === "pending" || task.status === "running") &&
          scopedVulnerabilities.some((item) => reportTaskFindingIds(item).includes(task.finding_id)),
      ),
    [reportEnrichmentTasks, scopedVulnerabilities],
  );
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSubmit({
        mode: form.mode,
        format: form.format,
        scopeFilters: {
          project_id: form.project_id,
          severity: form.severity,
          status: form.status,
        },
      });
    } finally {
      setSaving(false);
    }
  };
  const enqueueMaterials = async () => {
    setMaterialBusy(true);
    try {
      await onEnqueueReportMaterials(missingReportMaterials);
    } finally {
      setMaterialBusy(false);
    }
  };
  return (
    <Modal title="审计报告交付" subtitle="生成可归档交付包，或单独导出 Word、PDF 与 Markdown。" onClose={onClose}>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="report-format-picker" role="group" aria-label="报告格式">
          {[
            ["bundle", "交付包", "Word、PDF、MD、JSON 与校验清单"],
            ["docx", "Word", "正式可编辑报告"],
            ["pdf", "PDF", "正式只读报告"],
            ["md", "Markdown", "完整技术原文"],
          ].map(([key, label, description]) => (
            <button
              className={cn(form.format === key && "active")}
              type="button"
              aria-pressed={form.format === key}
              key={key}
              onClick={() => setForm({ ...form, format: key })}
            >
              {key === "bundle" ? <FileArchive size={17} /> : <FileText size={17} />}
              <span>
                <strong>{label}</strong>
                <small>{description}</small>
              </span>
            </button>
          ))}
        </div>
        <label>
          <span>导出范围</span>
          <Select value={form.mode} onChange={(value) => setForm({ ...form, mode: value })} style={{ width: "100%" }}>
            <Select.Option value="filtered">当前筛选范围（{visibleCount} 条）</Select.Option>
            <Select.Option value="selected" disabled={!selectedCount}>已选漏洞（{selectedCount} 条）</Select.Option>
          </Select>
        </label>
        {form.mode === "filtered" && (
          <>
            <label>
              <span>项目</span>
              <Select value={form.project_id || ""} onChange={(value) => setForm({ ...form, project_id: value })} style={{ width: "100%" }}>
                <Select.Option value="">全部项目</Select.Option>
                {projects.map((project) => (
                  <Select.Option key={project.id} value={project.id}>{project.title}</Select.Option>
                ))}
              </Select>
            </label>
            <div className="two-col">
              <label>
                <span>严重程度</span>
                <Select value={form.severity || ""} onChange={(value) => setForm({ ...form, severity: value })} style={{ width: "100%" }}>
                  <Select.Option value="">全部</Select.Option>
                  {["critical", "high", "medium", "low"].map((level) => (
                    <Select.Option key={level} value={level}>{SEVERITY_META[level].label}</Select.Option>
                  ))}
                </Select>
              </label>
              <label>
                <span>状态</span>
                <Select value={form.status || ""} onChange={(value) => setForm({ ...form, status: value })} style={{ width: "100%" }}>
                  <Select.Option value="">全部状态</Select.Option>
                  <Select.Option value="confirmed">已确认</Select.Option>
                  <Select.Option value="ignored">已忽略</Select.Option>
                </Select>
              </label>
            </div>
          </>
        )}
        <div className={cn("soft-box compact report-readiness", missingReportMaterials.length ? "warning-box" : "ready")}>
          当前导出范围预估 {scopedVulnerabilities.length} 条；其中 {missingReportMaterials.length} 条已确认漏洞缺少已完成的报告材料。
          {activeReportMaterials.length ? ` ${activeReportMaterials.length} 个报告材料任务正在等待或生成。` : " "}
          导出不会自动触发扫描或动态验证。
          {missingReportMaterials.length > 0 && (
            <div className="button-row">
              <Button size="small" type="outline" loading={materialBusy} icon={<FileText size={15} />} onClick={enqueueMaterials}>
                提交写报告 Worker
              </Button>
            </div>
          )}
        </div>
        <div className="modal-footer">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={form.mode === "selected" && !selectedCount} icon={<Download size={16} />}>
            {form.format === "bundle" ? "生成交付包" : `导出 ${form.format === "docx" ? "Word" : form.format.toUpperCase()}`}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ExportRecordsView({ setToast, confirmAction }) {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState(null);

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      const list = await apiRequest("/api/vulnerabilities/export-records");
      setRecords(Array.isArray(list) ? list : []);
    } catch (error) {
      if (!silent) setToast({ type: "danger", message: error.message || "导出记录加载失败" });
    } finally {
      if (!silent) setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = window.setInterval(() => load({ silent: true }), 8000);
    return () => window.clearInterval(timer);
  }, [load]);

  const formatLabels = { bundle: "交付包", zip: "交付包", md: "Markdown", markdown: "Markdown", json: "JSON", csv: "CSV", pdf: "PDF", docx: "Word", word: "Word" };

  const redownload = async (record) => {
    setBusyId(record.id);
    try {
      const params = new URLSearchParams();
      params.set("format", record.format || "md");
      if (record.project_id) params.set("project_id", record.project_id);
      if (record.severity) params.set("severity", record.severity);
      if (record.status) params.set("status", record.status);
      await downloadFromApi(`/api/vulnerabilities/export?${params}`, record.filename);
      setToast({ type: "success", message: "已重新导出报告" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "重新导出失败" });
    } finally {
      setBusyId(null);
    }
  };

  const removeRecord = async (record) => {
    const ok = await confirmAction({
      title: "删除导出记录",
      message: `确认删除「${record.filename}」这条导出记录？`,
      tone: "danger",
      confirmLabel: "删除",
    });
    if (!ok) return;
    try {
      await apiRequest(`/api/vulnerabilities/export-records/${record.id}`, { method: "DELETE" });
      setToast({ type: "success", message: "记录已删除" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "删除失败" });
    }
  };

  const clearAll = async () => {
    const ok = await confirmAction({
      title: "清空导出记录",
      message: "确认清空全部导出记录？此操作不可撤销。",
      tone: "danger",
      confirmLabel: "清空",
    });
    if (!ok) return;
    try {
      await apiRequest("/api/vulnerabilities/export-records", { method: "DELETE" });
      setToast({ type: "success", message: "导出记录已清空" });
      await load({ silent: true });
    } catch (error) {
      setToast({ type: "danger", message: error.message || "清空失败" });
    }
  };

  return (
    <>
      <PageHeader
        compact
        title="审计报告 / 导出记录"
        subtitle="查看历史导出操作，包括导出范围、格式和时间"
      />
      <section className="content-wrap vulnerability-report-page">
        <article className="vuln-table-card export-records-card">
          <header className="vuln-table-title">
            <div>
              <h2>导出记录</h2>
              <p>每次导出审计报告都会在此留痕</p>
            </div>
            <div className="button-row">
              <Button size="small" type="outline" status="danger" disabled={!records.length} icon={<Trash2 size={15} />} onClick={clearAll}>
                清空记录
              </Button>
              <Button size="small" icon={<RefreshCw size={15} />} onClick={() => load()}>
                刷新
              </Button>
            </div>
          </header>
          <div className="export-records-head">
            <span>导出时间</span>
            <span>范围</span>
            <span>格式</span>
            <span>漏洞数</span>
            <span>文件名</span>
            <span>操作</span>
          </div>
          <div className="export-records-body">
            {loading ? (
              <EmptyState icon={Loader2} title="正在加载导出记录" />
            ) : records.length === 0 ? (
              <EmptyState icon={Download} title="暂无导出记录" subtitle="在漏洞列表中导出报告后，记录会显示在这里。" />
            ) : (
              records.map((record) => (
                <div className="export-records-row" key={record.id}>
                  <time>{formatTime(record.created_at)}</time>
                  <div className="export-scope-cell">
                    <strong>{record.scope}</strong>
                    {record.project_name && <span>{record.project_name}</span>}
                  </div>
                  <span><Tag color="arcoblue">{formatLabels[record.format] || record.format.toUpperCase()}</Tag></span>
                  <span className="export-count">{record.vulnerability_count}</span>
                  <code title={record.filename}>{record.filename}</code>
                  <div className="button-row export-record-actions">
                    <Tooltip content="重新导出">
                      <Button type="text" size="small" loading={busyId === record.id} icon={<Download size={15} />} aria-label="重新导出" onClick={() => redownload(record)} />
                    </Tooltip>
                    <Tooltip content="删除记录">
                      <Button type="text" size="small" status="danger" icon={<Trash2 size={15} />} aria-label="删除记录" onClick={() => removeRecord(record)} />
                    </Tooltip>
                  </div>
                </div>
              ))
            )}
          </div>
        </article>
      </section>
    </>
  );
}

function summarizeSeverity(items) {
  return items.reduce(
    (acc, item) => {
      acc[item.severity] = (acc[item.severity] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
}

function buildVulnerabilityTrend(items) {
  // Build a fixed 7-day calendar window ending today (local time), so the
  // chart always shows 近 7 天 even on days with no findings.
  const dayKeys = [];
  const byKey = new Map();
  const now = new Date();
  for (let offset = 6; offset >= 0; offset -= 1) {
    const day = new Date(now.getFullYear(), now.getMonth(), now.getDate() - offset);
    const key = `${day.getFullYear()}-${String(day.getMonth() + 1).padStart(2, "0")}-${String(day.getDate()).padStart(2, "0")}`;
    dayKeys.push(key);
    byKey.set(key, {
      date: key,
      label: `${String(day.getMonth() + 1).padStart(2, "0")}-${String(day.getDate()).padStart(2, "0")}`,
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  }
  items.forEach((item) => {
    const key = String(item.discovered_at || "").slice(0, 10);
    const entry = byKey.get(key);
    if (!entry) return;
    entry.total += 1;
    if (entry[item.severity] !== undefined) entry[item.severity] += 1;
  });
  return dayKeys.map((key) => byKey.get(key));
}

function buildSeverityTop(items, limit = 5) {
  const rank = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...items]
    .sort((a, b) => {
      const byRank = (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
      if (byRank !== 0) return byRank;
      return String(b.discovered_at || "").localeCompare(String(a.discovered_at || ""));
    })
    .slice(0, limit);
}

function buildPageNumbers(current, total) {
  // Compact pager: always show first/last, current ±1, with ellipsis gaps.
  if (total <= 7) {
    return Array.from({ length: total }, (_, index) => index + 1);
  }
  const pages = new Set([1, total, current, current - 1, current + 1]);
  const sorted = [...pages].filter((page) => page >= 1 && page <= total).sort((a, b) => a - b);
  const result = [];
  let prev = 0;
  for (const page of sorted) {
    if (page - prev > 1) result.push("...");
    result.push(page);
    prev = page;
  }
  return result;
}

function buildStatusDistribution(items) {
  return items.reduce(
    (acc, item) => {
      if (item.status === "ignored") acc.ignored += 1;
      else acc.confirmed += 1;
      acc.total += 1;
      return acc;
    },
    { total: 0, confirmed: 0, ignored: 0 },
  );
}

function VulnerabilityTrend({ data }) {
  const series = [
    ["critical", "严重", "#ff375f"],
    ["high", "高危", "#ff7a1a"],
    ["medium", "中危", "#f5b700"],
    ["low", "低危", "#0a84ff"],
  ];
  const hasData = data.some((item) => item.total > 0);
  const max = Math.max(1, ...data.flatMap((item) => series.map(([key]) => item[key] || 0)));
  const width = 280;
  const height = 120;
  const padX = 6;
  const innerW = width - padX * 2;
  const pointX = (index) => (data.length <= 1 ? width / 2 : padX + (index / (data.length - 1)) * innerW);
  const pointY = (value) => height - ((value || 0) / max) * (height - 18) - 9;
  const toPoints = (key) => data.map((item, index) => `${pointX(index)},${pointY(item[key])}`).join(" ");
  return (
    <section className="vuln-analysis-card">
      <header>
        <h3>漏洞趋势</h3>
        <span>近 7 天</span>
      </header>
      {!hasData ? (
        <p className="analysis-empty">近 7 天暂无新发现</p>
      ) : (
        <>
          <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="漏洞趋势">
            {series.map(([key, label, color]) => (
              <polyline
                key={key}
                points={toPoints(key)}
                fill="none"
                stroke={color}
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-label={label}
              />
            ))}
            {data.map((item, index) =>
              series.map(([key, label, color]) => (
                <circle
                  key={`${item.date}-${key}`}
                  cx={pointX(index)}
                  cy={pointY(item[key])}
                  r="2.8"
                  fill={color}
                  aria-label={`${item.date} ${label} ${item[key] || 0}`}
                />
              )),
            )}
          </svg>
          <div className="trend-axis">
            {data.map((item) => (
              <span key={`axis-${item.date}`}>{item.label}</span>
            ))}
          </div>
          <div className="trend-legend">
            {series.map(([key, label, color]) => (
              <span key={key}>
                <i style={{ background: color }} />
                <strong>{data.reduce((sum, item) => sum + (item[key] || 0), 0)}</strong>
                {label}
              </span>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

function SeverityTopList({ items }) {
  return (
    <section className="vuln-analysis-card severity-top-card">
      <header>
        <h3>严重漏洞 TOP 5</h3>
        <span>{items.length} 条</span>
      </header>
      <div className="severity-top-list">
        {items.length === 0 ? (
          <p className="analysis-empty">暂无漏洞</p>
        ) : (
          items.map((item, index) => {
            const meta = SEVERITY_META[item.severity] || SEVERITY_META.low;
            return (
              <article key={`top-${item.id}`}>
                <span className="severity-top-rank">{index + 1}</span>
                <span className={cn("status-badge", meta.tone)}>{meta.label}</span>
                <strong title={item.title}>{clampText(item.title, 30)}</strong>
                <code>{item.fact_id}</code>
              </article>
            );
          })
        )}
      </div>
    </section>
  );
}

function VulnerabilityStatusDistribution({ data }) {
  const total = Math.max(0, data.total || 0);
  const confirmed = data.confirmed || 0;
  const ignored = data.ignored || 0;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const confirmedLength = total ? (confirmed / total) * circumference : 0;
  const ignoredLength = total ? (ignored / total) * circumference : 0;
  return (
    <section className="vuln-analysis-card status-distribution-card">
      <header>
        <h3>状态分布</h3>
        <span>实时数据</span>
      </header>
      {total === 0 ? (
        <p className="analysis-empty">暂无状态数据</p>
      ) : (
        <div className="status-distribution">
          <svg viewBox="0 0 96 96" role="img" aria-label="漏洞状态分布">
            <circle className="donut-track" cx="48" cy="48" r={radius} />
            <circle
              className="donut-segment confirmed"
              cx="48"
              cy="48"
              r={radius}
              strokeDasharray={`${confirmedLength} ${circumference - confirmedLength}`}
            />
            <circle
              className="donut-segment ignored"
              cx="48"
              cy="48"
              r={radius}
              strokeDasharray={`${ignoredLength} ${circumference - ignoredLength}`}
              strokeDashoffset={-confirmedLength}
            />
            <text x="48" y="45" textAnchor="middle">
              {total}
            </text>
            <text x="48" y="59" textAnchor="middle" className="donut-caption">
              总计
            </text>
          </svg>
          <div className="status-distribution-list">
            <span>
              <i className="status-dot confirmed" />
              已确认
              <strong>{confirmed}</strong>
            </span>
            <span>
              <i className="status-dot ignored" />
              已忽略
              <strong>{ignored}</strong>
            </span>
          </div>
        </div>
      )}
    </section>
  );
}

function formatVulnerabilityCopyText(vuln) {
  const meta = SEVERITY_META[vuln.severity] || SEVERITY_META.low;
  const evidence = (vuln.evidence || []).filter(Boolean);
  const poc = vuln.reproduction_poc || {};
  const pocRequest =
    pocText(poc, "request_template") ||
    pocText(poc, "curl") ||
    pocText(poc, "command");
  return [
    `漏洞名称：${vuln.title || "未记录"}`,
    `严重程度：${meta.label || vuln.severity || "未记录"}`,
    `状态：${vuln.status === "ignored" ? "已忽略" : "已确认"}`,
    `项目：${vuln.project_name || "未记录"} (${vuln.project_id || "未记录"})`,
    `确认事实：${vuln.fact_id || "未记录"}`,
    `发现时间：${formatTime(vuln.discovered_at)}`,
    "",
    "漏洞描述：",
    vuln.description || "未记录",
    "",
    "关键证据：",
    ...(evidence.length ? evidence.map((item) => `- ${item}`) : ["- 未记录"]),
    "",
    `证明数据包：${(vuln.proof_packets || []).length ? `${vuln.proof_packets.length} 个` : "未记录"}`,
    `静态 PoC：${pocRequest ? pocRequest : "未记录"}`,
  ].join("\n");
}

function CopyButton({ value, setToast, message = "已复制", className, children, title = "复制" }) {
  return (
    <button
      className={cn("copy-button", className)}
      type="button"
      title={title}
      aria-label={title}
      onClick={() => copyText(value, setToast, message)}
    >
      <Copy size={14} />
      {children}
    </button>
  );
}

function CopyableBlock({ label, value, setToast, codeClassName }) {
  const text = String(value || "未记录");
  return (
    <div className="copyable-block">
      <div className="copyable-head">
        <span>{label}</span>
        <CopyButton value={text} setToast={setToast} message={`${label}已复制`} />
      </div>
      <pre className={codeClassName}>{text}</pre>
    </div>
  );
}

function VulnerabilityItem({ vuln, selected, setToast, onSelect, expanded, onToggle, onExport, onStatusChange }) {
  const meta = SEVERITY_META[vuln.severity] || SEVERITY_META.low;
  const ignored = vuln.status === "ignored";
  const hasProofPackets = (vuln.proof_packets || []).length > 0;
  const hasStaticPoc = !!(vuln.reproduction_poc && Object.keys(vuln.reproduction_poc).length);
  const summaryText = formatVulnerabilityCopyText(vuln);
  return (
    <article className={cn("vuln-table-item", ignored && "ignored")}>
      <div className="vuln-table-row">
        <label className="vuln-select">
          <Checkbox checked={selected} onChange={onSelect} />
        </label>
        <div className="vuln-name-cell">
          <div className="vuln-meta">
            <span>{vuln.fact_id}</span>
            <CopyButton
              className="inline-copy"
              value={vuln.fact_id}
              setToast={setToast}
              message="确认事实 ID 已复制"
              title="复制确认事实 ID"
            />
          </div>
          <h3>{vuln.title}</h3>
        </div>
        <div className="vuln-project-cell">
          <strong>{vuln.project_name}</strong>
          <span>{vuln.project_id}</span>
        </div>
        <div>
          <Tag color={arcoTagColor(meta.tone)}>{meta.label}</Tag>
        </div>
        <div>
          <Tag color={ignored ? "gray" : "green"}>{ignored ? "已忽略" : "已确认"}</Tag>
        </div>
        <time>{formatTime(vuln.discovered_at)}</time>
        <div className="button-row">
          <Tooltip content="复制漏洞摘要">
            <Button type="text" size="small" icon={<Copy size={16} />} aria-label="复制漏洞摘要" onClick={() => copyText(summaryText, setToast, "漏洞摘要已复制")} />
          </Tooltip>
          <Tooltip content={ignored ? "恢复确认" : "设为忽略"}>
            <Button type="text" size="small" status={ignored ? "success" : "warning"} icon={ignored ? <CheckCircle2 size={16} /> : <X size={16} />} aria-label={ignored ? "恢复确认" : "设为忽略"} onClick={() => onStatusChange(ignored ? "confirmed" : "ignored")} />
          </Tooltip>
          <Tooltip content="导出当前漏洞">
            <Button type="text" size="small" icon={<Download size={16} />} aria-label="导出当前漏洞" onClick={onExport} />
          </Tooltip>
          <Tooltip content="查看详情">
            <Button type="text" size="small" icon={expanded ? <ChevronDown size={16} /> : <Eye size={16} />} aria-label="查看详情" onClick={onToggle} />
          </Tooltip>
        </div>
      </div>
      {expanded && (
        <div className="vuln-detail">
          <div className="detail-toolbar">
            <div className="evidence-state">
              <Tag color={hasProofPackets ? "green" : "orange"}>
                {hasProofPackets ? "已有证明数据包" : "缺少证明数据包"}
              </Tag>
              <Tag color={hasStaticPoc ? "arcoblue" : "gray"}>
                {hasStaticPoc ? "已有静态 PoC" : "未记录静态 PoC"}
              </Tag>
            </div>
            <Button size="small" type="outline" icon={<Copy size={15} />} onClick={() => copyText(summaryText, setToast, "漏洞摘要已复制")}>
              复制摘要
            </Button>
          </div>
          <div className="detail-grid cards">
            <InfoBox label="项目来源" value={`${vuln.project_name} (${vuln.project_id})`} />
            <InfoBox label="确认事实" value={vuln.fact_id} />
            <InfoBox label="来源意图" value={vuln.source_intent_id || "未记录"} />
            <InfoBox label="工作节点" value={vuln.source_worker || "未记录"} />
          </div>
          <section>
            <h4>完整描述</h4>
            <p className="soft-box">{vuln.description}</p>
          </section>
          <section>
            <h4>关键证据</h4>
            <div className="evidence-list">
              {(vuln.evidence?.length ? vuln.evidence : ["未记录"]).map((item, index) => (
                <div className="evidence-row" key={`${item}-${index}`}>
                  <p>{item}</p>
                  <CopyButton
                    className="inline-copy evidence-copy"
                    value={item}
                    setToast={setToast}
                    message="证据已复制"
                    title="复制证据"
                  />
                </div>
              ))}
            </div>
          </section>
          <section>
            <h4>漏洞证明数据包</h4>
            <div className="packet-list">
              {(vuln.proof_packets || []).length === 0 ? (
                <p className="soft-box">未记录证明数据包。</p>
              ) : (
                vuln.proof_packets.map((packet, index) => (
                  <article className="packet-card" key={`${packet.title}-${index}`}>
                    <strong>{packet.title || `证明 ${index + 1}`}</strong>
                    {packet.payload && <CopyableBlock label="Payload" value={packet.payload} setToast={setToast} />}
                    <CopyableBlock label="请求数据包" value={packet.request || "未记录"} setToast={setToast} />
                    <CopyableBlock label="响应/回显" value={packet.response || "未记录"} setToast={setToast} />
                    {packet.note && <p>{packet.note}</p>}
                  </article>
                ))
              )}
            </div>
          </section>
          <StaticPocSection poc={vuln.reproduction_poc} setToast={setToast} />
          <section>
            <h4>漏洞浮现过程</h4>
            <div className="process-list">
              {(vuln.process || []).map((step, index) => (
                <article className="process-step" key={`${step.id}-${index}`}>
                  <span>{index + 1}</span>
                  <div>
                    <strong>
                      {step.label || step.type || "过程"} {step.id || ""}
                    </strong>
                    <p>{step.description || "无描述"}</p>
                    {(step.worker || step.time) && (
                      <small>
                        {step.worker || ""} {step.time ? `· ${formatTime(step.time)}` : ""}
                      </small>
                    )}
                  </div>
                </article>
              ))}
            </div>
          </section>
        </div>
      )}
    </article>
  );
}

function StaticPocSection({ poc, setToast }) {
  if (!poc || typeof poc !== "object" || Object.keys(poc).length === 0) {
    return (
      <section>
        <h4>静态复现 PoC</h4>
        <p className="soft-box">未记录静态复现 PoC。导出的 Markdown 会保留当前证明材料状态。</p>
      </section>
    );
  }
  const payload = pocText(poc, "payload");
  const requestTemplate = pocText(poc, "request_template") || pocText(poc, "curl") || pocText(poc, "command");
  const expectedResult = pocText(poc, "expected_result") || pocText(poc, "expected_response");
  const verification = pocText(poc, "verification");
  const steps = pocList(poc, "steps");
  const prerequisites = pocList(poc, "prerequisites");
  const limitations = pocList(poc, "limitations");
  const fullText = [
    payload ? `Payload:\n${payload}` : "",
    steps.length ? `复现步骤:\n${steps.map((step, index) => `${index + 1}. ${step}`).join("\n")}` : "",
    requestTemplate ? `请求/命令模板:\n${requestTemplate}` : "",
    expectedResult ? `预期结果:\n${expectedResult}` : "",
    verification ? `判断标准:\n${verification}` : "",
    prerequisites.length ? `利用前提:\n${prerequisites.map((item) => `- ${item}`).join("\n")}` : "",
    limitations.length ? `限制与说明:\n${limitations.map((item) => `- ${item}`).join("\n")}` : "",
  ].filter(Boolean).join("\n\n");

  return (
    <section>
      <div className="section-heading-row">
        <h4>静态复现 PoC</h4>
        <Button size="small" type="outline" icon={<Copy size={15} />} onClick={() => copyText(fullText, setToast, "静态 PoC 已复制")}>复制 PoC</Button>
      </div>
      <div className="static-poc-panel">
        {payload && <CopyableBlock label="Payload" value={payload} setToast={setToast} />}
        {steps.length > 0 && (
          <div className="poc-steps">
            <div className="copyable-head">
              <span>复现步骤</span>
              <CopyButton value={steps.map((step, index) => `${index + 1}. ${step}`).join("\n")} setToast={setToast} message="复现步骤已复制" />
            </div>
            <ol>
              {steps.map((step, index) => (
                <li key={`${step}-${index}`}>{step}</li>
              ))}
            </ol>
          </div>
        )}
        {requestTemplate && <CopyableBlock label="请求/命令模板" value={requestTemplate} setToast={setToast} codeClassName="bash-block" />}
        {expectedResult && (
          <div className="poc-note-block">
            <strong>预期结果</strong>
            <p>{expectedResult}</p>
          </div>
        )}
        {verification && (
          <div className="poc-note-block">
            <strong>判断标准</strong>
            <p>{verification}</p>
          </div>
        )}
        {(prerequisites.length > 0 || limitations.length > 0) && (
          <div className="poc-note-grid">
            {prerequisites.length > 0 && (
              <div className="poc-note-block">
                <strong>利用前提</strong>
                <ul>
                  {prerequisites.map((item, index) => (
                    <li key={`${item}-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
            {limitations.length > 0 && (
              <div className="poc-note-block">
                <strong>限制与说明</strong>
                <ul>
                  {limitations.map((item, index) => (
                    <li key={`${item}-${index}`}>{item}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function InfoBox({ label, value }) {
  return (
    <div className="info-box">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function WorkersPage({ runAction, setToast, confirmAction }) {
  const [workers, setWorkers] = useState([]);
  const [config, setConfig] = useState(null);
  const [history, setHistory] = useState({});
  const [editor, setEditor] = useState(null);
  const [historyWorker, setHistoryWorker] = useState(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadErrors, setLoadErrors] = useState({ status: "", config: "" });
  const [workerQuery, setWorkerQuery] = useState("");
  const [workerFilter, setWorkerFilter] = useState("all");
  const [workerView, setWorkerView] = useState("nodes");
  const [toolTaskQueue, setToolTaskQueue] = useState([]);
  const [reportTaskQueue, setReportTaskQueue] = useState([]);
  const [taskBusyId, setTaskBusyId] = useState(null);

  const fetchWorkerHistory = useCallback((workerName) => {
    return apiRequest(`/api/workers/${encodeURIComponent(workerName)}/history`);
  }, []);

  const load = useCallback(async () => {
    setRefreshing(true);
    setLoadErrors({ status: "", config: "" });
    const [statusResult, configResult, toolQueueResult, reportQueueResult] = await Promise.allSettled([
      apiRequest("/api/workers"),
      apiRequest("/api/workers/config"),
      apiRequest("/api/tool-scan-tasks?limit=80"),
      apiRequest("/api/report-enrichment-tasks?limit=80"),
    ]);
    if (statusResult.status === "fulfilled" && Array.isArray(statusResult.value)) {
      setWorkers(statusResult.value);
      setLastUpdated(new Date());
    } else if (statusResult.status === "rejected" && statusResult.reason?.status !== 401) {
      setLoadErrors((prev) => ({ ...prev, status: statusResult.reason?.message || "实时状态暂不可用" }));
    }
    if (configResult.status === "fulfilled" && configResult.value) {
      setConfig(configResult.value);
      setLastUpdated(new Date());
    } else if (configResult.status === "rejected" && configResult.reason?.status !== 401) {
      setLoadErrors((prev) => ({ ...prev, config: configResult.reason?.message || "Worker 配置暂不可用" }));
    }
    if (toolQueueResult.status === "fulfilled") setToolTaskQueue(Array.isArray(toolQueueResult.value) ? toolQueueResult.value : []);
    if (reportQueueResult.status === "fulfilled") setReportTaskQueue(Array.isArray(reportQueueResult.value) ? reportQueueResult.value : []);
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const statusByName = useMemo(() => new Map(workers.map((worker) => [worker.name, worker])), [workers]);
  const visibleWorkers = useMemo(() => {
    const configured = config?.workers || [];
    const names = new Set(configured.map((worker) => worker.name));
    const statusOnly = workers.filter((worker) => !names.has(worker.name)).map((worker) => ({ ...worker, env: {} }));
    return [...configured, ...statusOnly];
  }, [config, workers]);

  // Summary counts derived from the real worker status array (idle/busy/offline/
  // disabled). "在线" = enabled and reachable (idle or busy); we never fabricate
  // metrics that the API does not expose.
  const workerCounts = useMemo(() => {
    const counts = { total: visibleWorkers.length, online: 0, running: 0, offline: 0, tasks: 0 };
    for (const worker of visibleWorkers) {
      const status = statusByName.get(worker.name) || worker;
      const effective = status.status || (worker.enabled === false ? "disabled" : "offline");
      if (effective === "busy") counts.running += 1;
      if (effective === "idle" || effective === "busy") counts.online += 1;
      else counts.offline += 1;
      counts.tasks += status.tasks_completed || 0;
    }
    return counts;
  }, [visibleWorkers, statusByName]);

  const saveWorkers = async (nextWorkers, label = "Worker 配置已保存") => {
    const updated = await runAction(label, () =>
      apiRequest("/api/workers/config", { method: "PUT", body: { workers: nextWorkers } }),
    );
    setConfig(updated);
    await load();
  };

  const setEnabled = async (worker, enabled) => {
    if (!config) return;
    const next = config.workers.map((item) => (item.name === worker.name ? { ...item, enabled } : item));
    await saveWorkers(next, enabled ? "Worker 已启用" : "Worker 已关闭");
  };

  const testWorker = async (worker) => {
    const source = config?.workers?.find((item) => item.name === worker.name) || worker;
    const result = await runAction(null, () =>
      apiRequest("/api/workers/config/test", { method: "POST", body: { worker: normalizeWorkerForSave(source) } }),
    );
    setToast({
      type: result.ok ? "success" : "danger",
      message: result.ok ? `${result.worker_name} 连通性正常` : `${result.worker_name} 测试失败：${result.preview || result.stderr_preview}`,
    });
  };

  const loadHistory = async (workerName, options = {}) => {
    if (!options.force && history[workerName]) return history[workerName];
    setHistoryLoading(true);
    setHistoryError("");
    try {
      const rows = await fetchWorkerHistory(workerName);
      setHistory((prev) => ({ ...prev, [workerName]: Array.isArray(rows) ? rows : [] }));
      return rows;
    } catch (error) {
      if (error?.status !== 401) setHistoryError(error.message || "任务历史加载失败");
      return [];
    } finally {
      setHistoryLoading(false);
    }
  };

  const openHistory = async (workerName) => {
    setHistoryWorker(workerName);
    await loadHistory(workerName, { force: true });
  };

  const visibleFilteredWorkers = useMemo(() => {
    const normalized = workerQuery.trim().toLowerCase();
    return visibleWorkers.filter((worker) => {
      const status = statusByName.get(worker.name) || worker;
      const effective = status.status || (worker.enabled === false ? "disabled" : "offline");
      const matchesFilter = workerFilter === "all"
        || (workerFilter === "online" && (effective === "idle" || effective === "busy"))
        || (workerFilter === "busy" && effective === "busy")
        || (workerFilter === "offline" && effective === "offline")
        || (workerFilter === "disabled" && effective === "disabled");
      const matchesQuery = !normalized || `${worker.name} ${worker.type} ${workerModelLabel(worker)}`.toLowerCase().includes(normalized);
      return matchesFilter && matchesQuery;
    });
  }, [statusByName, visibleWorkers, workerFilter, workerQuery]);

  const saveEditor = async (worker) => {
    if (!config) return;
    const normalized = normalizeWorkerForSave(worker);
    const exists = config.workers.some((item) => item.name === normalized.name);
    const next = exists
      ? config.workers.map((item) => (item.name === normalized.name ? normalized : item))
      : [...config.workers, normalized];
    await saveWorkers(next, exists ? "Worker 已更新" : "Worker 已新增");
    setEditor(null);
  };

  const deleteWorker = async (worker) => {
    if (!config) return;
    const ok = await confirmAction({
      title: "删除工作节点",
      message: `确认删除 Worker「${worker.name}」？`,
      tone: "danger",
      confirmLabel: "删除",
    });
    if (!ok) return;
    await saveWorkers(config.workers.filter((item) => item.name !== worker.name), "Worker 已删除");
    setEditor(null);
  };

  const cancelQueueTask = async (task) => {
    setTaskBusyId(task.id);
    try {
      await runAction("任务已取消", () =>
        apiRequest(`/api/tool-scans/${task.id}/cancel`, { method: "POST", body: { worker: HUMAN_WORKER } }),
      );
      await load();
    } finally {
      setTaskBusyId(null);
    }
  };

  const retryQueueTask = async (task) => {
    setTaskBusyId(task.id);
    try {
      await runAction("任务已重试", () =>
        apiRequest(`/api/tool-scans/${task.id}/retry`, { method: "POST", body: { worker: HUMAN_WORKER } }),
      );
      await load();
    } finally {
      setTaskBusyId(null);
    }
  };

  const cancelReportQueueTask = async (task) => {
    setTaskBusyId(task.id);
    try {
      await runAction("报告材料任务已取消", () =>
        apiRequest(`/api/report-enrichments/${task.id}/cancel`, { method: "POST", body: { worker: HUMAN_WORKER } }),
      );
      await load();
    } finally {
      setTaskBusyId(null);
    }
  };

  const retryReportQueueTask = async (task) => {
    setTaskBusyId(task.id);
    try {
      await runAction("报告材料任务已重试", () =>
        apiRequest(`/api/report-enrichments/${task.id}/retry`, { method: "POST", body: { worker: HUMAN_WORKER } }),
      );
      await load();
    } finally {
      setTaskBusyId(null);
    }
  };

  const selectedHistoryRows = historyWorker ? history[historyWorker] || [] : [];
  const selectedHistoryWorker = historyWorker ? visibleWorkers.find((worker) => worker.name === historyWorker) : null;
  const queueCount = toolTaskQueue.length + reportTaskQueue.length;
  const hasWorkerData = visibleWorkers.length > 0;
  const workerDataUnavailable = !loading && !hasWorkerData && (loadErrors.status || loadErrors.config);

  return (
    <>
      <PageHeader
        icon={Monitor}
        title="工作节点"
        subtitle="实时状态、模型配置、任务历史与健康检查"
        actions={
          <>
            <Button type="primary" icon={<Plus size={16} />} disabled={!config} onClick={() => setEditor(defaultWorkerDraft(config?.workers || []))}>
              新增 Worker
            </Button>
            <div className="status-pill">
              <span className={cn("dot", lastUpdated ? "success" : "warning")} />
              <span>{lastUpdated ? `更新于 ${lastUpdated.toLocaleTimeString("zh-CN")}` : "待更新"}</span>
            </div>
            <Button icon={<RefreshCw size={16} />} loading={refreshing} onClick={load}>
              刷新
            </Button>
          </>
        }
      />
      <section className="content-wrap">
        {loading ? (
          <LoadingGrid count={6} className="worker-grid" />
        ) : workerDataUnavailable ? (
          <PageErrorState title="工作节点暂时不可用" message={loadErrors.status || loadErrors.config} onRetry={load} />
        ) : !hasWorkerData ? (
          <EmptyState
            icon={Bot}
            title="还没有配置工作节点"
            subtitle="新增 Worker 后，调度器会按优先级和并发配置分配任务。"
            action={
              <Button type="primary" disabled={!config} icon={<Plus size={16} />} onClick={() => setEditor(defaultWorkerDraft([]))}>
                新增 Worker
              </Button>
            }
          />
        ) : (
          <>
            <div className="metric-grid">
              <MetricCard label="在线" value={workerCounts.online} tone="success" onClick={() => setWorkerFilter("online")} />
              <MetricCard label="离线" value={workerCounts.offline} tone="muted" onClick={() => setWorkerFilter("offline")} />
              <MetricCard label="运行中" value={workerCounts.running} tone="info" onClick={() => setWorkerFilter("busy")} />
              <MetricCard label="累计任务" value={workerCounts.tasks} tone="info" onClick={() => setWorkerView("queues")} />
            </div>
            {(loadErrors.status || loadErrors.config) && (
              <div className="data-warning-banner" role="status">
                <AlertTriangle size={16} />
                <span>{loadErrors.status || loadErrors.config}</span>
                <button type="button" onClick={load}>重新读取</button>
              </div>
            )}
            <Radio.Group type="button" name="worker-view" value={workerView} onChange={setWorkerView} style={{ marginBottom: 16 }}>
              <Radio value="nodes"><span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><Server size={15} />节点概览 ({visibleWorkers.length})</span></Radio>
              <Radio value="queues"><span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}><Timer size={15} />任务队列 ({queueCount})</span></Radio>
            </Radio.Group>
            {workerView === "nodes" ? (
              <>
                <div className="collection-toolbar worker-toolbar">
                  <Input
                    allowClear
                    prefix={<Search size={15} />}
                    value={workerQuery}
                    onChange={setWorkerQuery}
                    placeholder="搜索节点、类型或模型"
                    aria-label="搜索工作节点"
                    style={{ maxWidth: 320 }}
                  />
                  <Radio.Group type="button" name="worker-filter" value={workerFilter} onChange={setWorkerFilter}>
                    {[['all', '全部'], ['online', '在线'], ['busy', '运行中'], ['offline', '离线'], ['disabled', '已关闭']].map(([value, label]) => (
                      <Radio key={value} value={value}>{label}</Radio>
                    ))}
                  </Radio.Group>
                  <span className="collection-count"><SlidersHorizontal size={14} /> {visibleFilteredWorkers.length} 个节点</span>
                </div>
                {visibleFilteredWorkers.length === 0 ? (
                  <EmptyState icon={Search} title="没有匹配的工作节点" subtitle="尝试清除搜索或切换状态筛选。" action={<Button type="outline" size="small" icon={<X size={15} />} onClick={() => { setWorkerQuery(""); setWorkerFilter("all"); }}>清除筛选</Button>} />
                ) : (
                  <div className="worker-grid">
                    {visibleFilteredWorkers.map((worker) => {
                      const status = statusByName.get(worker.name) || worker;
                      const statusMeta = STATUS_META[status.status || (worker.enabled === false ? "disabled" : "offline")] || STATUS_META.offline;
                      const taskTypes = worker.task_types || [];
                      return (
                        <article className="worker-card" key={worker.name}>
                          <header className="worker-card-header">
                            <span className={cn("worker-status-orb", statusMeta.tone)}><span /></span>
                            <div className="worker-heading">
                              <div className="worker-name-line"><h3>{worker.name}</h3><Tag color={arcoTagColor(statusMeta.tone)} size="small">{statusMeta.label}</Tag></div>
                              <p>{worker.type} <span>·</span> {workerModelLabel(worker)}</p>
                            </div>
                          </header>
                          {taskTypes.length > 0 && <div className="worker-task-chips">{taskTypes.slice(0, 4).map((type) => <Tag key={type} size="small" bordered>{type}</Tag>)}{taskTypes.length > 4 && <Tag size="small" bordered>+{taskTypes.length - 4}</Tag>}</div>}
                          {status.current_task ? <div className="worker-current-task"><Activity size={15} /><span>{status.current_task}</span></div> : <div className="worker-current-task quiet"><Circle size={12} /><span>当前没有运行中的任务</span></div>}
                          <div className="project-stats worker-stats">
                            <MiniStat label="任务数" value={status.tasks_completed ?? 0} />
                            <MiniStat label="平均耗时" value={status.avg_duration_seconds ? `${status.avg_duration_seconds}s` : "-"} />
                            <MiniStat label="最近心跳" value={relativeHeartbeat(status.last_heartbeat_seconds_ago)} />
                          </div>
                          <div className="card-actions worker-actions">
                            <Button size="small" type="outline" status={worker.enabled === false ? "success" : "warning"} disabled={!config} style={{ flex: 1 }} icon={worker.enabled === false ? <Play size={15} /> : <Pause size={15} />} onClick={() => setEnabled(worker, worker.enabled === false)}>{worker.enabled === false ? "启用" : "关闭"}</Button>
                            <Button size="small" type="outline" disabled={!config} style={{ flex: 1 }} icon={<Activity size={15} />} onClick={() => testWorker(worker)}>测试</Button>
                            <Button size="small" type="outline" disabled={!config} style={{ flex: 1 }} icon={<Settings size={15} />} onClick={() => setEditor(worker)}>编辑</Button>
                          </div>
                          <Button type="text" long style={{ marginTop: 4 }} icon={<History size={15} />} onClick={() => openHistory(worker.name)}>查看任务历史</Button>
                        </article>
                      );
                    })}
                  </div>
                )}
              </>
            ) : (
              <div className="queue-stack">
                <TaskOperationsPanel title="工具扫描队列" emptyText="暂无工具扫描任务。" tasks={toolTaskQueue} busyId={taskBusyId} onCancel={cancelQueueTask} onRetry={retryQueueTask} onRefresh={load} />
                <TaskOperationsPanel title="报告材料队列" emptyText="暂无报告材料任务。" kind="report" tasks={reportTaskQueue} busyId={taskBusyId} onCancel={cancelReportQueueTask} onRetry={retryReportQueueTask} onRefresh={load} />
              </div>
            )}
          </>
        )}
      </section>
      {editor && (
        <WorkerEditor
          worker={editor}
          onClose={() => setEditor(null)}
          onSave={saveEditor}
          onDelete={config?.workers?.some((item) => item.name === editor.name) ? () => deleteWorker(editor) : null}
        />
      )}
      {historyWorker && (
        <WorkerHistoryDrawer
          worker={selectedHistoryWorker}
          rows={selectedHistoryRows}
          loading={historyLoading}
          error={historyError}
          onClose={() => setHistoryWorker(null)}
          onRefresh={() => loadHistory(historyWorker, { force: true })}
        />
      )}
    </>
  );
}

function WorkerHistoryDrawer({ worker, rows, loading, error, onClose, onRefresh }) {
  const [filter, setFilter] = useState("all");
  const visibleRows = rows.filter((row) => filter === "all" || (filter === "success" ? row.outcome === "success" : row.outcome !== "success"));
  const failedCount = rows.filter((row) => row.outcome !== "success").length;
  const successCount = rows.length - failedCount;
  return (
    <Drawer
      visible
      width={540}
      onCancel={onClose}
      onOk={onClose}
      footer={null}
      maskClosable
      title={
        <div className="drawer-title">
          <strong style={{ display: "block", fontSize: 16, lineHeight: 1.3 }}>{worker?.name || "工作节点"}</strong>
          <span style={{ color: "var(--muted)", fontSize: 12, fontWeight: 400 }}>{worker?.type || "-"} · {worker ? workerModelLabel(worker) : ""}</span>
        </div>
      }
    >
      <div className="drawer-summary"><div><strong>{rows.length}</strong><span>最近记录</span></div><div><strong>{successCount}</strong><span>成功</span></div><div><strong className={failedCount ? "danger-text" : ""}>{failedCount}</strong><span>需关注</span></div></div>
      <div className="drawer-toolbar">
        <Radio.Group type="button" name="history-filter" value={filter} onChange={setFilter}>
          <Radio value="all">全部</Radio>
          <Radio value="success">成功</Radio>
          <Radio value="failed">失败/中断</Radio>
        </Radio.Group>
        <Button size="small" icon={<RefreshCw size={15} />} loading={loading} onClick={onRefresh}>刷新</Button>
      </div>
      <div className="drawer-body">
        {error ? <PageErrorState title="历史记录加载失败" message={error} onRetry={onRefresh} /> : loading && rows.length === 0 ? <div className="drawer-loading"><Spin /> 正在读取记录</div> : visibleRows.length === 0 ? <EmptyState icon={History} title="暂无任务历史" subtitle="节点执行任务后，最近记录会显示在这里。" /> : visibleRows.map((row, index) => (
          <article className={cn("history-timeline-row", row.outcome !== "success" && "attention")} key={`${row.started_at}-${row.task_type}-${index}`}>
            <span className="history-timeline-dot" />
            <div className="history-timeline-content"><div className="history-row-header"><strong>{row.task_type}</strong><Tag color={arcoTagColor(workerHistoryOutcomeTone(row))} size="small">{workerHistoryOutcomeLabel(row)}</Tag></div><p>{row.description}</p><div className="history-meta"><span>{row.project_name}</span><span>{formatTime(row.started_at)}</span>{row.duration_seconds != null && <span><Timer size={13} /> {row.duration_seconds}s</span>}</div>{workerHistoryErrorText(row) && <details><summary>查看错误详情</summary><pre>{workerHistoryErrorText(row)}</pre></details>}</div>
          </article>
        ))}
      </div>
    </Drawer>
  );
}

function TaskOperationsPanel({ title, emptyText, kind = "tool", tasks, busyId, onCancel, onRetry, onRefresh }) {
  const counts = useMemo(
    () =>
      tasks.reduce(
        (acc, task) => {
          acc[task.status] = (acc[task.status] || 0) + 1;
          acc.total += 1;
          return acc;
        },
        { total: 0, pending: 0, running: 0, completed: 0, failed: 0 },
      ),
    [tasks],
  );
  const formatStatus = kind === "report" ? formatReportEnrichmentStatus : formatToolScanStatus;
  const statusTone = kind === "report" ? reportEnrichmentStatusTone : toolScanStatusTone;
  return (
    <section className="task-ops-panel">
      <header>
        <div>
          <span>任务运维</span>
          <h2>{title}</h2>
        </div>
        <div className="button-row">
          <Tag color="arcoblue">{counts.running} 运行中</Tag>
          <Tag color="orange">{counts.pending} 等待中</Tag>
          <Tag color="red">{counts.failed} 失败</Tag>
          <Button size="small" icon={<RefreshCw size={15} />} onClick={onRefresh}>刷新</Button>
        </div>
      </header>
      {tasks.length === 0 ? (
        <div className="soft-box compact">{emptyText}</div>
      ) : (
        <div className="task-ops-list">
          {tasks.map((task) => (
            <article className="task-ops-row" key={task.id}>
              <div>
                <strong>{task.id}</strong>
                <span>{task.project_title || task.project_id}</span>
                <small>
                  {kind === "report"
                    ? `${task.finding_title || task.finding_id} · ${task.finding_id} · ${task.worker || task.created_by} · ${formatTime(task.created_at)}`
                    : `${task.source_label || task.snapshot_id} · ${task.worker || task.created_by} · ${formatTime(task.created_at)}`}
                </small>
                {kind === "report" && task.status === "completed" && <small>{reportTaskMaterialSummary(task)}</small>}
                {task.error_message && <p>{task.error_message}</p>}
              </div>
              <Tag color={arcoTagColor(statusTone(task.status))}>{formatStatus(task.status)}</Tag>
              <div className="button-row">
                {(task.status === "pending" || task.status === "running") && (
                  <Button size="small" type="outline" status="warning" loading={busyId === task.id} icon={<Square size={15} />} onClick={() => onCancel(task)}>取消</Button>
                )}
                {task.status === "failed" && (
                  <Button size="small" type="outline" loading={busyId === task.id} icon={<RefreshCw size={15} />} onClick={() => onRetry(task)}>重试</Button>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function workerModelLabel(worker) {
  const env = worker.env || {};
  return env.ANTHROPIC_MODEL || env.CODEX_MODEL || env.PI_MODEL || "未配置模型";
}

function defaultWorkerDraft(existingWorkers) {
  let index = 1;
  const names = new Set(existingWorkers.map((worker) => worker.name));
  while (names.has(`worker_local_${index}`)) index += 1;
  return {
    name: `worker_local_${index}`,
    type: "pi",
    enabled: true,
    task_types: [...TASK_TYPES],
    max_running: 1,
    priority: 0,
    env: {
      PI_MODEL: "",
      PI_BASE_URL: "",
      PI_API_KEY: "",
      PI_PROVIDER_API: "openai-completions",
    },
    secret_env_keys: ["PI_API_KEY"],
  };
}

function normalizeWorkerForSave(worker) {
  return {
    name: worker.name.trim(),
    type: worker.type,
    enabled: worker.enabled !== false,
    task_types: worker.task_types?.length ? worker.task_types : [...TASK_TYPES],
    max_running: Number(worker.max_running) || 1,
    priority: Number(worker.priority) || 0,
    env: Object.fromEntries(Object.entries(worker.env || {}).map(([key, value]) => [key, String(value ?? "")])),
    secret_env_keys: worker.secret_env_keys || [],
  };
}

const WORKER_PRESETS = [
  {
    id: "pi-deepseek-pro",
    label: "Pi · DeepSeek V4 Pro",
    type: "pi",
    env: {
      PI_MODEL: "deepseek-v4-pro",
      PI_BASE_URL: "https://api.deepseek.com",
      PI_API_KEY: "",
      PI_PROVIDER_API: "openai-completions",
    },
  },
  {
    id: "pi-glm-5",
    label: "Pi · GLM-5",
    type: "pi",
    env: {
      PI_MODEL: "glm-5",
      PI_BASE_URL: "http://10.2.8.77:3000/v1",
      PI_API_KEY: "",
      PI_PROVIDER_API: "openai-completions",
    },
  },
  {
    id: "claude-code",
    label: "Claude Code · Anthropic",
    type: "claudecode",
    env: {
      ANTHROPIC_MODEL: "claude-3-5-sonnet-latest",
      ANTHROPIC_BASE_URL: "https://api.anthropic.com",
      ANTHROPIC_AUTH_TOKEN: "",
    },
  },
  {
    id: "codex",
    label: "Codex · Responses API",
    type: "codex",
    env: {
      CODEX_MODEL: "gpt-5",
      CODEX_BASE_URL: "https://api.openai.com/v1",
      OPENAI_API_KEY: "",
    },
  },
  {
    id: "mock",
    label: "Mock",
    type: "mock",
    env: {},
  },
];

function WorkerEditor({ worker, onClose, onSave, onDelete }) {
  const [draft, setDraft] = useState(() => JSON.parse(JSON.stringify(worker)));
  const [saving, setSaving] = useState(false);
  const envKeys = useMemo(() => workerEnvKeys(draft.type), [draft.type]);

  const applyPreset = (presetId) => {
    const preset = WORKER_PRESETS.find((item) => item.id === presetId);
    if (!preset) return;
    setDraft((prev) => ({
      ...prev,
      type: preset.type,
      env: { ...preset.env },
      secret_env_keys: Object.keys(preset.env).filter((key) => /KEY|TOKEN|SECRET/i.test(key)),
    }));
  };

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSave(draft);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="Worker 配置" subtitle="保存后由调度器验证并热更新，失败时原配置保持不变。" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <div className="two-col tight">
          <label>
            <span>快速模板</span>
            <Select placeholder="选择模型模板" style={{ width: "100%" }} onChange={(value) => applyPreset(value)}>
              {WORKER_PRESETS.map((preset) => (
                <Select.Option key={preset.id} value={preset.id}>
                  {preset.label}
                </Select.Option>
              ))}
            </Select>
          </label>
          <label className="switch-line">
            <span>启用状态</span>
            <Switch checked={draft.enabled !== false} onChange={(checked) => setDraft({ ...draft, enabled: checked })} />
          </label>
        </div>
        <div className="two-col tight">
          <label>
            <span>名称</span>
            <Input value={draft.name} onChange={(value) => setDraft({ ...draft, name: value })} required />
          </label>
          <label>
            <span>类型</span>
            <Select
              value={draft.type}
              style={{ width: "100%" }}
              onChange={(type) => {
                setDraft({ ...draft, type, env: defaultEnvForType(type), secret_env_keys: workerEnvKeys(type).filter((key) => /KEY|TOKEN|SECRET/i.test(key)) });
              }}
            >
              <Select.Option value="pi">pi</Select.Option>
              <Select.Option value="claudecode">claudecode</Select.Option>
              <Select.Option value="codex">codex</Select.Option>
              <Select.Option value="mock">mock</Select.Option>
            </Select>
          </label>
        </div>
        <div className="three-col">
          <label style={{ alignSelf: "start" }}>
            <span>最大并发</span>
            <InputNumber min={1} value={Number(draft.max_running) || 1} onChange={(value) => setDraft({ ...draft, max_running: value })} style={{ width: "100%" }} />
          </label>
          <label style={{ alignSelf: "start" }}>
            <span>优先级</span>
            <InputNumber min={0} value={Number(draft.priority) || 0} onChange={(value) => setDraft({ ...draft, priority: value })} style={{ width: "100%" }} />
          </label>
          <label>
            <span>任务类型</span>
            <Checkbox.Group
              value={draft.task_types || []}
              onChange={(values) => setDraft({ ...draft, task_types: values })}
              style={{ display: "flex", flexWrap: "wrap", gap: "4px 12px" }}
            >
              {TASK_TYPES.map((type) => (
                <Checkbox key={type} value={type}>{type}</Checkbox>
              ))}
            </Checkbox.Group>
          </label>
        </div>
        <div className="env-grid">
          {envKeys.map((key) => {
            const secret = /KEY|TOKEN|SECRET/i.test(key);
            const InputComp = secret ? Input.Password : Input;
            return (
              <label key={key}>
                <span>{key}</span>
                <InputComp
                  value={draft.env?.[key] ?? ""}
                  placeholder={secret ? SECRET_MASK : ""}
                  required={draft.type !== "mock"}
                  onChange={(value) =>
                    setDraft({
                      ...draft,
                      env: { ...(draft.env || {}), [key]: value },
                      secret_env_keys: secret
                        ? Array.from(new Set([...(draft.secret_env_keys || []), key]))
                        : draft.secret_env_keys || [],
                    })
                  }
                />
              </label>
            );
          })}
        </div>
        <div className="modal-footer split">
          <div>
            {onDelete && (
              <Button type="outline" status="danger" icon={<Trash2 size={16} />} onClick={onDelete}>
                删除 Worker
              </Button>
            )}
          </div>
          <div className="button-row">
            <Button onClick={onClose}>取消</Button>
            <Button type="primary" htmlType="submit" loading={saving} icon={<Save size={16} />}>
              保存配置
            </Button>
          </div>
        </div>
      </form>
    </Modal>
  );
}

function workerEnvKeys(type) {
  if (type === "claudecode") return ["ANTHROPIC_MODEL", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"];
  if (type === "codex") return ["CODEX_MODEL", "CODEX_BASE_URL", "OPENAI_API_KEY"];
  if (type === "pi") return ["PI_MODEL", "PI_BASE_URL", "PI_API_KEY", "PI_PROVIDER_API", "PI_MODEL_CONTEXT_WINDOW"];
  return [];
}

function defaultEnvForType(type) {
  const preset = WORKER_PRESETS.find((item) => item.type === type);
  return { ...(preset?.env || {}) };
}

function TemplatesPage({ runAction, setToast, confirmAction }) {
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [newTemplate, setNewTemplate] = useState(false);
  const [projectTemplate, setProjectTemplate] = useState(null);
  const [category, setCategory] = useState("all");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setTemplates(await apiRequest("/api/templates"));
    } catch (error) {
      setToast({ type: "danger", message: error.message || "模板加载失败" });
    } finally {
      setLoading(false);
    }
  }, [setToast]);

  useEffect(() => {
    load();
  }, [load]);

  const deleteTemplate = async (template) => {
    const ok = await confirmAction({
      title: "删除模板",
      message: `确认删除模板「${template.title}」？`,
      tone: "danger",
      confirmLabel: "删除",
    });
    if (!ok) return;
    await runAction("模板已删除", () => apiRequest(`/api/templates/${template.id}`, { method: "DELETE" }));
    await load();
  };

  const categoryCounts = useMemo(() => {
    const counts = {};
    for (const template of templates) {
      const key = templateCategory(template);
      counts[key] = (counts[key] || 0) + 1;
    }
    return counts;
  }, [templates]);

  const visibleTemplates = useMemo(
    () => (category === "all" ? templates : templates.filter((template) => templateCategory(template) === category)),
    [templates, category],
  );

  return (
    <>
      <PageHeader
        icon={FileText}
        title="模板"
        subtitle="把常用目标、起点和提示保存成可复用项目模板"
        actions={
          <>
            <Button type="primary" icon={<Plus size={16} />} onClick={() => setNewTemplate(true)}>
              新建模板
            </Button>
            <Button icon={<RefreshCw size={16} />} loading={loading} onClick={load}>
              刷新
            </Button>
          </>
        }
      />
      <section className="content-wrap">
        <Radio.Group type="button" name="template-category" value={category} onChange={setCategory} style={{ marginBottom: 16 }}>
          {TEMPLATE_CATEGORIES.map((tab) => {
            const count = tab.key === "all" ? templates.length : categoryCounts[tab.key] || 0;
            return (
              <Radio key={tab.key} value={tab.key}>
                {tab.label} ({count})
              </Radio>
            );
          })}
        </Radio.Group>
        {loading ? (
          <EmptyState icon={Loader2} title="正在加载模板" />
        ) : visibleTemplates.length === 0 ? (
          <EmptyState
            icon={FileText}
            title="该分类下暂无模板"
            subtitle="切换分类查看其他模板，或新建一个自定义模板。"
            action={
              <Button type="primary" icon={<Plus size={16} />} onClick={() => setNewTemplate(true)}>
                新建模板
              </Button>
            }
          />
        ) : (
          <div className="template-grid">
            {visibleTemplates.map((template) => {
              const catKey = templateCategory(template);
              const catMeta = TEMPLATE_CATEGORY_META[catKey] || TEMPLATE_CATEGORY_META.custom;
              const hintCount = template.hints?.length || 0;
              return (
                <article className="template-card" key={template.id}>
                  <header>
                    <span className="template-icon">
                      <FileText size={20} />
                    </span>
                    <div className="template-heading">
                      <h3>{template.title}</h3>
                      <div className="template-badges">
                        <Badge tone={catMeta.tone}>{catMeta.label}</Badge>
                        <Badge tone={template.is_builtin ? "info" : "success"}>
                          {template.is_builtin ? "内置" : "自定义"}
                        </Badge>
                      </div>
                    </div>
                  </header>
                  <p className="template-description">{template.goal}</p>
                  <div className="template-section">
                    <span>起点</span>
                    <p>{template.origin}</p>
                  </div>
                  <div className="template-foot">
                    <span className="template-meta">
                      <Sparkles size={14} />
                      {hintCount ? `${hintCount} 条提示` : "无初始提示"}
                    </span>
                    <div className="card-actions">
                      <Button size="small" type="outline" icon={<Plus size={16} />} onClick={() => setProjectTemplate(template)}>
                        使用模板
                      </Button>
                      {!template.is_builtin && (
                        <Button size="small" type="outline" status="danger" icon={<Trash2 size={16} />} onClick={() => deleteTemplate(template)}>
                          删除
                        </Button>
                      )}
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
      {newTemplate && (
        <TemplateEditor
          onClose={() => setNewTemplate(false)}
          onSave={async (payload) => {
            await runAction("模板已创建", () => apiRequest("/api/templates", { method: "POST", body: payload }));
            setNewTemplate(false);
            await load();
          }}
        />
      )}
      {projectTemplate && (
        <NewProjectModal
          initial={projectTemplate}
          runAction={runAction}
          onClose={() => setProjectTemplate(null)}
          onCreated={(projectId) => {
            setProjectTemplate(null);
            go(`#/projects/${projectId}`);
          }}
        />
      )}
    </>
  );
}

const TEMPLATE_CATEGORIES = [
  { key: "all", label: "全部模板" },
  { key: "web", label: "Web 源码" },
  { key: "backend", label: "API 后端" },
  { key: "supply", label: "依赖供应链" },
  { key: "repository", label: "完整仓库" },
  { key: "custom", label: "自定义" },
];

const TEMPLATE_CATEGORY_META = {
  web: { label: "Web 源码", tone: "info" },
  backend: { label: "API 后端", tone: "high" },
  supply: { label: "依赖供应链", tone: "medium" },
  repository: { label: "完整仓库", tone: "critical" },
  custom: { label: "自定义", tone: "success" },
};

// Presentational-only category grouping derived from the template's own text.
// Templates have no category field from the API, so this never fabricates data;
// it only buckets a template for the filter tabs and badge.
function templateCategory(template) {
  if (!template.is_builtin) return "custom";
  const text = `${template.title || ""} ${template.origin || ""} ${template.goal || ""}`;
  if (text.includes("供应链") || text.includes("依赖")) return "supply";
  if (text.includes("API") || text.includes("后端")) return "backend";
  if (text.includes("完整仓库") || text.includes("多语言")) return "repository";
  return "web";
}

function TemplateEditor({ onClose, onSave }) {
  const [form, setForm] = useState({ title: "", origin: "", goal: "", hints: "" });
  const [saving, setSaving] = useState(false);
  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await onSave({
        title: form.title,
        origin: form.origin,
        goal: form.goal,
        hints: parseHintLines(form.hints, HUMAN_WORKER),
      });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="新建模板" onClose={onClose} wide>
      <form className="stack-form modal-body" onSubmit={submit}>
        <label>
          <span>模板名称</span>
          <Input value={form.title} onChange={(value) => setForm({ ...form, title: value })} required />
        </label>
        <div className="two-col">
          <label>
            <span>起点</span>
            <Input.TextArea value={form.origin} onChange={(value) => setForm({ ...form, origin: value })} autoSize={{ minRows: 6, maxRows: 12 }} required />
          </label>
          <label>
            <span>目标</span>
            <Input.TextArea value={form.goal} onChange={(value) => setForm({ ...form, goal: value })} autoSize={{ minRows: 6, maxRows: 12 }} required />
          </label>
        </div>
        <label>
          <span>提示</span>
          <Input.TextArea value={form.hints} onChange={(value) => setForm({ ...form, hints: value })} autoSize={{ minRows: 4, maxRows: 8 }} />
        </label>
        <div className="modal-footer">
          <Button onClick={onClose}>
            取消
          </Button>
          <Button type="primary" htmlType="submit" loading={saving} icon={<Save size={16} />}>
            保存模板
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function PasswordModal({ onClose, runAction }) {
  const [form, setForm] = useState({ current_password: "", new_password: "", confirm_password: "" });
  const [show, setShow] = useState({ current: false, next: false });
  const [saving, setSaving] = useState(false);

  const rules = [
    { key: "len", label: "至少 8 个字符", ok: form.new_password.length >= 8 },
    { key: "case", label: "包含大小写字母", ok: /[a-z]/.test(form.new_password) && /[A-Z]/.test(form.new_password) },
    { key: "num", label: "包含数字", ok: /\d/.test(form.new_password) },
    { key: "sym", label: "包含特殊字符", ok: /[^A-Za-z0-9]/.test(form.new_password) },
  ];
  const allOk = rules.every((rule) => rule.ok);
  const matched = form.confirm_password.length > 0 && form.new_password === form.confirm_password;
  const canSubmit = !!form.current_password && allOk && matched && !saving;

  const submit = async (event) => {
    event.preventDefault();
    if (!canSubmit) return;
    setSaving(true);
    try {
      await runAction("密码已修改", () =>
        apiRequest("/api/auth/password", {
          method: "PUT",
          body: {
            current_password: form.current_password,
            new_password: form.new_password,
          },
        }),
      );
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal title="修改密码" subtitle="为账号设置一个更安全的新密码" onClose={onClose}>
      <form className="stack-form modal-body password-form" onSubmit={submit}>
        <label>
          <span>当前密码</span>
          <Input.Password
            prefix={<KeyRound size={16} />}
            value={form.current_password}
            onChange={(value) => setForm({ ...form, current_password: value })}
            placeholder="请输入当前密码"
            autoComplete="current-password"
          />
        </label>
        <label>
          <span>新密码</span>
          <Input.Password
            prefix={<Lock size={16} />}
            value={form.new_password}
            onChange={(value) => setForm({ ...form, new_password: value })}
            placeholder="请输入新密码"
            autoComplete="new-password"
          />
        </label>
        <label>
          <span>确认新密码</span>
          <Input.Password
            prefix={<Lock size={16} />}
            value={form.confirm_password}
            onChange={(value) => setForm({ ...form, confirm_password: value })}
            placeholder="请再次输入新密码"
            autoComplete="new-password"
          />
          {form.confirm_password.length > 0 && !matched && <small className="field-hint danger">两次输入的密码不一致</small>}
        </label>
        <ul className="password-rules">
          {rules.map((rule) => (
            <li key={rule.key} className={cn(rule.ok && "ok")}>
              {rule.ok ? <CheckCircle2 size={14} /> : <Circle size={14} />}
              {rule.label}
            </li>
          ))}
        </ul>
        <div className="modal-footer">
          <Button onClick={onClose}>
            取消
          </Button>
          <Button type="primary" htmlType="submit" loading={saving} disabled={!canSubmit} icon={<Save size={16} />}>
            保存
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SettingsModal({ onClose, runAction, confirmAction }) {
  const [settings, setSettings] = useState(null);
  const [health, setHealth] = useState(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [backups, setBackups] = useState([]);
  const [backupBusy, setBackupBusy] = useState(null);

  const settingsFallback = useMemo(
    () => ({
      intent_timeout: 15,
      reason_timeout: 15,
      worker_unhealthy_retry_after_seconds: 5,
      worker_rejected_retry_after_seconds: 5,
      max_failed_login_attempts: 5,
      rate_limit_window_minutes: 15,
      session_duration_hours: 24,
      log_retention_days: 30,
      export_retention_days: 30,
      notification_retention_days: 14,
      project_idle_alert_hours: 12,
    }),
    [],
  );

  useEffect(() => {
    apiRequest("/settings").then(setSettings).catch(() => setSettings(settingsFallback));
  }, [settingsFallback]);

  const loadHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      setHealth(await apiRequest("/settings/health"));
    } catch {
      setHealth(null);
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    loadHealth();
  }, [loadHealth]);

  const loadBackups = useCallback(async () => {
    try {
      const rows = await apiRequest("/api/maintenance/backups?limit=20");
      setBackups(Array.isArray(rows) ? rows : []);
    } catch {
      setBackups([]);
    }
  }, []);

  useEffect(() => {
    loadBackups();
  }, [loadBackups]);

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    try {
      await runAction("设置已保存", () => apiRequest("/settings", { method: "PUT", body: settings }));
      await loadHealth();
    } finally {
      setSaving(false);
    }
  };

  const runCleanup = async () => {
    setCleaning(true);
    try {
      await runAction("系统清理已完成", () => apiRequest("/settings/cleanup", { method: "POST" }));
      await loadHealth();
    } finally {
      setCleaning(false);
    }
  };

  const createBackup = async () => {
    setBackupBusy("create");
    try {
      await runAction("数据库备份已创建并通过完整性校验", () =>
        apiRequest("/api/maintenance/backups", {
          method: "POST",
          body: { label: "手动备份" },
        }),
      );
      await Promise.all([loadBackups(), loadHealth()]);
    } finally {
      setBackupBusy(null);
    }
  };

  const verifyBackup = async (backup) => {
    setBackupBusy(backup.id);
    try {
      await runAction("备份完整性校验通过", () =>
        apiRequest(`/api/maintenance/backups/${backup.id}/verify`, { method: "POST" }),
      );
      await loadBackups();
    } finally {
      setBackupBusy(null);
    }
  };

  const restoreBackup = async (backup) => {
    const confirmed = await confirmAction({
      title: "恢复数据库备份？",
      message: `将数据库恢复到 ${formatTime(backup.created_at)} 的状态。系统会先创建恢复前安全备份，所有项目必须处于停止状态。`,
      tone: "danger",
      confirmLabel: "确认恢复",
    });
    if (!confirmed) return;
    setBackupBusy(`restore:${backup.id}`);
    try {
      await runAction("数据库已恢复，恢复前安全备份已保留", () =>
        apiRequest(`/api/maintenance/backups/${backup.id}/restore`, { method: "POST" }),
      );
      await Promise.all([loadBackups(), loadHealth()]);
    } finally {
      setBackupBusy(null);
    }
  };

  const setNumber = (key, value) => {
    // Arco InputNumber reports a cleared field as undefined/null; keep the old
    // native behaviour where an empty field meant 0 instead of storing NaN.
    setSettings((current) => ({ ...current, [key]: Number(value ?? 0) }));
  };

  const healthTone = (status) => (status === "error" ? "danger" : status === "warning" ? "high" : "success");
  const healthLabel = (status) => (status === "error" ? "异常" : status === "warning" ? "告警" : "正常");

  return (
    <Modal
      title="系统设置"
      subtitle="统一管理调度、安全策略、历史保留周期和系统健康检查。"
      onClose={onClose}
      wide
    >
      {!settings ? (
        <EmptyState icon={Loader2} title="正在读取设置" />
      ) : (
        <form className="stack-form modal-body settings-shell" onSubmit={submit}>
          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>运行控制</h3>
                <p>只影响调度节奏与冷却策略，不改项目和 Worker 配置结构。</p>
              </div>
              <Badge tone="info">调度</Badge>
            </div>
            <div className="two-col">
              <label>
                <span>意图超时（秒）</span>
                <InputNumber
                  min={5}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.intent_timeout}
                  onChange={(value) => setNumber("intent_timeout", value)}
                />
                <small className="field-hint">意图在被回收前允许等待的最长时间。</small>
              </label>
              <label>
                <span>Reason 超时（秒）</span>
                <InputNumber
                  min={5}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.reason_timeout}
                  onChange={(value) => setNumber("reason_timeout", value)}
                />
                <small className="field-hint">Reason 阶段在判定超时前的最长执行时间。</small>
              </label>
            </div>
            <div className="two-col">
              <label>
                <span>Worker 不健康冷却（秒）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.worker_unhealthy_retry_after_seconds}
                  onChange={(value) => setNumber("worker_unhealthy_retry_after_seconds", value)}
                />
                <small className="field-hint">Worker 健康检查失败后，重新参与调度前的冷却时间。</small>
              </label>
              <label>
                <span>拒绝任务重试间隔（秒）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.worker_rejected_retry_after_seconds}
                  onChange={(value) => setNumber("worker_rejected_retry_after_seconds", value)}
                />
                <small className="field-hint">同一 Worker 暂时拒绝任务后，再次尝试分配的等待时间。</small>
              </label>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>备份与恢复</h3>
                <p>创建 SQLite 一致性备份并校验 SHA-256；恢复前会自动保留当前数据库。</p>
              </div>
              <Button type="outline" size="small" loading={backupBusy === "create"} disabled={Boolean(backupBusy)} icon={<Save size={16} />} onClick={createBackup}>
                创建备份
              </Button>
            </div>
            {backups.length === 0 ? (
              <div className="soft-box">尚无数据库备份。建议在导入大型项目和系统升级前创建备份。</div>
            ) : (
              <div className="backup-list">
                {backups.map((backup) => (
                  <article className="backup-row" key={backup.id}>
                    <div className="backup-main">
                      <strong>{backup.label || backup.filename}</strong>
                      <span>{formatTime(backup.created_at)} · {formatBytes(backup.size_bytes)}</span>
                      <code title={backup.sha256}>SHA-256 {backup.sha256.slice(0, 20)}...</code>
                    </div>
                    <Badge tone={backup.integrity_status === "ok" ? "success" : "danger"}>
                      {backup.integrity_status === "ok" ? "校验通过" : "校验失败"}
                    </Badge>
                    <div className="button-row">
                      <Button size="small" type="outline" loading={backupBusy === backup.id} disabled={Boolean(backupBusy)} icon={<ShieldCheck size={15} />} onClick={() => verifyBackup(backup)}>
                        校验
                      </Button>
                      <Button
                        size="small"
                        type="outline"
                        status="danger"
                        loading={backupBusy === `restore:${backup.id}`}
                        disabled={Boolean(backupBusy) || Number(health?.summary?.active_projects || 0) > 0 || backup.integrity_status !== "ok"}
                        title={Number(health?.summary?.active_projects || 0) > 0 ? "请先停止所有活动项目" : "恢复此备份"}
                        icon={<History size={15} />}
                        onClick={() => restoreBackup(backup)}
                      >
                        恢复
                      </Button>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>认证与会话</h3>
                <p>控制登录失败锁定、会话寿命和浏览器认证窗口。</p>
              </div>
              <Badge tone="success">安全</Badge>
            </div>
            <div className="three-col">
              <label>
                <span>失败锁定阈值</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.max_failed_login_attempts}
                  onChange={(value) => setNumber("max_failed_login_attempts", value)}
                />
                <small className="field-hint">同一账号在窗口期内允许的最大失败次数。</small>
              </label>
              <label>
                <span>限流窗口（分钟）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.rate_limit_window_minutes}
                  onChange={(value) => setNumber("rate_limit_window_minutes", value)}
                />
                <small className="field-hint">超过失败阈值后，窗口期内继续登录会被直接拦截。</small>
              </label>
              <label>
                <span>Session 时长（小时）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.session_duration_hours}
                  onChange={(value) => setNumber("session_duration_hours", value)}
                />
                <small className="field-hint">有效会话的滑动过期时间。</small>
              </label>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>保留与清理</h3>
                <p>只清理历史记录、导出记录和已读通知，不触碰项目事实、意图和漏洞数据。</p>
              </div>
              <Badge tone="medium">维护</Badge>
            </div>
            <div className="three-col">
              <label>
                <span>日志保留（天）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.log_retention_days}
                  onChange={(value) => setNumber("log_retention_days", value)}
                />
                <small className="field-hint">用于审计日志、Worker 历史和登录尝试记录。</small>
              </label>
              <label>
                <span>导出记录保留（天）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.export_retention_days}
                  onChange={(value) => setNumber("export_retention_days", value)}
                />
                <small className="field-hint">只清理导出历史记录，不影响实时导出功能。</small>
              </label>
              <label>
                <span>通知保留（天）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.notification_retention_days}
                  onChange={(value) => setNumber("notification_retention_days", value)}
                />
                <small className="field-hint">仅清理已读通知，未读通知会保留。</small>
              </label>
            </div>
            <div className="two-col">
              <label>
                <span>项目无进展告警（小时）</span>
                <InputNumber
                  min={1}
                  precision={0}
                  style={{ width: "100%" }}
                  value={settings.project_idle_alert_hours}
                  onChange={(value) => setNumber("project_idle_alert_hours", value)}
                />
                <small className="field-hint">活动项目最近无新增提示、意图或 Reason 心跳时触发告警。</small>
              </label>
              <div className="settings-action-card">
                <div>
                  <strong>立即清理历史数据</strong>
                  <p>按当前保留策略删除过期日志、已读通知、导出记录和失效会话。</p>
                </div>
                <Button size="small" type="outline" loading={cleaning} icon={<Trash2 size={16} />} onClick={runCleanup}>
                  立即清理
                </Button>
              </div>
            </div>
          </section>

          <section className="settings-section">
            <div className="settings-section-head">
              <div>
                <h3>系统健康</h3>
                <p>查看当前 API、数据库、调度器和 Worker 的整体状态。</p>
              </div>
              <Button size="small" type="outline" loading={healthLoading} icon={<RefreshCw size={16} />} onClick={loadHealth}>
                刷新状态
              </Button>
            </div>

            {health ? (
              <>
                <div className="settings-health-grid">
                  <article className={cn("settings-health-card", health.summary.status)}>
                    <span>系统状态</span>
                    <strong>{healthLabel(health.summary.status)}</strong>
                    <small>更新时间 {formatTime(health.generated_at)}</small>
                  </article>
                  <article className="settings-health-card">
                    <span>活动项目</span>
                    <strong>{health.summary.active_projects}</strong>
                    <small>项目总数 {health.stats.projects}</small>
                  </article>
                  <article className="settings-health-card">
                    <span>在线 Worker</span>
                    <strong>{health.summary.online_workers}</strong>
                    <small>离线 {health.summary.offline_workers}</small>
                  </article>
                  <article className="settings-health-card">
                    <span>未读通知</span>
                    <strong>{health.stats.notifications_unread}</strong>
                    <small>审计日志 {health.stats.audit_entries}</small>
                  </article>
                </div>

                <div className="settings-check-list">
                  {health.checks.map((check) => (
                    <article key={check.key} className={cn("settings-check-item", check.status)}>
                      <div className="settings-check-head">
                        <strong>{check.label}</strong>
                        <Badge tone={healthTone(check.status)}>{healthLabel(check.status)}</Badge>
                      </div>
                      <p>{check.summary}</p>
                      {check.detail && <small>{check.detail}</small>}
                    </article>
                  ))}
                </div>

                <div className="settings-alert-block">
                  <div className="settings-alert-head">
                    <strong>告警与提醒</strong>
                    <span>{health.alerts.length} 条</span>
                  </div>
                  {health.alerts.length === 0 ? (
                    <div className="soft-box">当前没有需要处理的系统级告警。</div>
                  ) : (
                    <div className="settings-alert-list">
                      {health.alerts.map((alert, index) => (
                        <article key={`${alert.title}-${index}`} className={cn("settings-alert-item", alert.level)}>
                          <div className="settings-alert-title">
                            <AlertTriangle size={16} />
                            <strong>{alert.title}</strong>
                          </div>
                          {alert.detail && <p>{alert.detail}</p>}
                        </article>
                      ))}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="soft-box">系统健康状态暂不可用，可稍后刷新重试。</div>
            )}
          </section>

          <div className="modal-footer">
            <Button onClick={onClose}>
              关闭
            </Button>
            <Button type="primary" htmlType="submit" loading={saving} icon={<Save size={16} />}>
              保存
            </Button>
          </div>
        </form>
      )}
    </Modal>
  );
}
