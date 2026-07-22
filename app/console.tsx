"use client";

import {
  FormEvent,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";

type View =
  | "overview"
  | "health"
  | "observability"
  | "reliability"
  | "reports"
  | "security"
  | "hosts"
  | "assets"
  | "patches"
  | "baseline"
  | "automation"
  | "diagnostics"
  | "tasks"
  | "versions"
  | "alerts"
  | "backups"
  | "logs"
  | "audit"
  | "users"
  | "groups";
type AuthUser = {
  id: string;
  username: string;
  displayName: string;
  permissions: string[];
};
type UiEvent = {
  id: string;
  occurredAt: string;
  sessionId: string;
  actorId: string;
  actorName: string;
  eventType: string;
  page: string;
  action: string;
  target?: string;
  result: string;
};
type AuditStats = {
  totalEvents: number;
  todayEvents: number;
  activeSessions24h: number;
  chainVerified: boolean;
};
type HostRow = {
  id: string;
  name: string;
  ip: string;
  group: string;
  os: string;
  cpu: number;
  ram: number;
  disk: number;
  state: "healthy" | "warning" | "offline";
  seen: string;
  lastSeenAt?: string | null;
  uptimeSeconds?: number;
  load?: number[];
  failedServices?: string[];
  error?: string;
};

const views: Array<{ id: View; label: string }> = [
  { id: "overview", label: "營運總覽" },
  { id: "health", label: "平台健檢" },
  { id: "observability", label: "容量與服務" },
  { id: "reliability", label: "可靠性報表" },
  { id: "reports", label: "營運報表" },
  { id: "security", label: "安全中心" },
  { id: "hosts", label: "主機監控" },
  { id: "assets", label: "資產盤點" },
  { id: "patches", label: "更新盤點" },
  { id: "baseline", label: "主機基準" },
  { id: "automation", label: "巡檢排程" },
  { id: "diagnostics", label: "AI 診斷" },
  { id: "tasks", label: "維運任務" },
  { id: "versions", label: "設定版控" },
  { id: "alerts", label: "告警中心" },
  { id: "backups", label: "備份管理" },
  { id: "logs", label: "日誌查詢" },
  { id: "audit", label: "行為稽核" },
  { id: "users", label: "用戶管理" },
  { id: "groups", label: "群組管理" },
];

const fallbackHosts: HostRow[] = [
  {
    id: "server-1",
    name: "server-1",
    ip: "192.168.0.152",
    group: "LAB / MANAGED",
    os: "等待中央 API 回報",
    cpu: 0,
    ram: 0,
    disk: 0,
    state: "offline",
    seen: "尚未同步",
  },
  {
    id: "server-2",
    name: "server-2",
    ip: "192.168.0.153",
    group: "LAB / MANAGED",
    os: "等待中央 API 回報",
    cpu: 0,
    ram: 0,
    disk: 0,
    state: "offline",
    seen: "尚未同步",
  },
];

const emptyStats: AuditStats = {
  totalEvents: 0,
  todayEvents: 0,
  activeSessions24h: 0,
  chainVerified: true,
};

function createEventId() {
  if (typeof globalThis.crypto?.randomUUID === "function")
    return globalThis.crypto.randomUUID();
  return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`;
}

function MetricBar({ value }: { value: number }) {
  return (
    <span className="metric">
      <i
        style={{ width: `${Math.min(value, 100)}%` }}
        className={value >= 80 ? "hot" : ""}
      />
    </span>
  );
}

function State({ value }: { value: HostRow["state"] }) {
  const text =
    value === "healthy" ? "正常" : value === "warning" ? "注意" : "離線";
  return (
    <span className={`state ${value}`}>
      <i />
      {text}
    </span>
  );
}

function formatUptime(seconds?: number) {
  if (seconds == null) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days ? `${days} 天 ${hours} 小時` : `${hours} 小時`;
}

export default function Console() {
  const [user, setUser] = useState<AuthUser | null | undefined>(undefined);

  useEffect(() => {
    fetch("/api/auth/me", { cache: "no-store" })
      .then(async (response) =>
        response.ok
          ? ((await response.json()) as { user: AuthUser }).user
          : null,
      )
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  if (user === undefined)
    return (
      <div className="auth-loading">
        <span>L·</span>
        <p>正在確認管理平台 Session…</p>
      </div>
    );
  if (!user) return <LoginScreen onLogin={setUser} />;
  return <AuthenticatedConsole user={user} onLogout={() => setUser(null)} />;
}

function LoginScreen({ onLogin }: { onLogin: (user: AuthUser) => void }) {
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
          otp: form.get("otp"),
        }),
      });
      const body = (await response.json()) as {
        user?: AuthUser;
        detail?: string;
      };
      if (!response.ok || !body.user)
        throw new Error(body.detail || "登入失敗");
      onLogin(body.user);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "登入失敗");
    } finally {
      setLoading(false);
    }
  };
  return (
    <main className="login-screen">
      <section>
        <div className="login-brand">
          <span>L·</span>
          <div>
            <strong>LINUX/AI</strong>
            <small>CONTROL PLANE</small>
          </div>
        </div>
        <small>LOCAL ADMIN SESSION</small>
        <h1>登入管理平台</h1>
        <p>登入後才能查看主機、系統日誌、稽核紀錄及開啟 Web SSH。</p>
        {error && <div className="modal-error">{error}</div>}
        <form onSubmit={submit}>
          <label>
            登入帳號
            <input name="username" autoComplete="username" required autoFocus />
          </label>
          <label>
            密碼
            <input
              data-private
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <label>
            MFA 動態碼／復原碼（未啟用可留空）
            <input data-private name="otp" inputMode="numeric" autoComplete="one-time-code" placeholder="123456" />
          </label>
          <button className="create" disabled={loading}>
            {loading ? "驗證中…" : "登入"}
          </button>
        </form>
        <footer>Session 由 PostgreSQL 保存，Cookie 為 HttpOnly。</footer>
      </section>
    </main>
  );
}

function AuthenticatedConsole({
  user,
  onLogout,
}: {
  user: AuthUser;
  onLogout: () => void;
}) {
  const [view, setView] = useState<View>("overview");
  const [search, setSearch] = useState("");
  const [events, setEvents] = useState<UiEvent[]>([]);
  const [stats, setStats] = useState<AuditStats>(emptyStats);
  const [hosts, setHosts] = useState<HostRow[]>(fallbackHosts);
  const [toast, setToast] = useState("");
  const [addHostOpen, setAddHostOpen] = useState(false);
  const [terminalHost, setTerminalHost] = useState<HostRow | null>(null);
  const [preferredLogHost, setPreferredLogHost] = useState("server-1");
  const queue = useRef<UiEvent[]>([]);
  const activeView = useRef<View>(view);
  const sessionId = useRef(
    `ses-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
  );
  const scrollMarks = useRef(new Set<number>());
  const can = useCallback(
    (permission: string) =>
      user.permissions.includes("*") || user.permissions.includes(permission),
    [user.permissions],
  );

  useEffect(() => {
    activeView.current = view;
  }, [view]);

  const loadHosts = useCallback(async (force = false) => {
    try {
      const response = await fetch(
        `/api/hosts${force ? "?refresh=true" : ""}`,
        { cache: "no-store" },
      );
      if (!response.ok) return false;
      const payload = (await response.json()) as { hosts?: HostRow[] };
      if (Array.isArray(payload.hosts)) setHosts(payload.hosts);
      return true;
    } catch {
      return false;
    }
  }, []);

  const loadAudit = useCallback(async () => {
    try {
      const response = await fetch("/api/audit-events?limit=200", {
        cache: "no-store",
      });
      if (!response.ok) return;
      const payload = (await response.json()) as {
        events?: UiEvent[];
        stats?: AuditStats;
      };
      if (Array.isArray(payload.events)) setEvents(payload.events);
      if (payload.stats) setStats(payload.stats);
    } catch {
      // The last successfully loaded audit state remains visible.
    }
  }, []);

  useEffect(() => {
    void loadHosts();
    void loadAudit();
    const hostTimer = window.setInterval(() => void loadHosts(), 10_000);
    const auditTimer = window.setInterval(() => void loadAudit(), 15_000);
    return () => {
      window.clearInterval(hostTimer);
      window.clearInterval(auditTimer);
    };
  }, [loadAudit, loadHosts]);

  const record = useCallback(
    (
      eventType: string,
      action: string,
      target?: string,
      result = "recorded",
    ) => {
      const event: UiEvent = {
        id: createEventId(),
        occurredAt: new Date().toISOString(),
        sessionId: sessionId.current,
        actorId: user.id,
        actorName: user.displayName,
        eventType,
        page:
          views.find((item) => item.id === activeView.current)?.label ??
          activeView.current,
        action,
        target,
        result,
      };
      queue.current.push(event);
      setEvents((current) => [event, ...current].slice(0, 200));
    },
    [user.displayName, user.id],
  );

  const logout = async () => {
    record("session.logout", "登出管理平台", user.username, "success");
    const outgoing = queue.current.splice(0, queue.current.length);
    if (outgoing.length)
      await fetch("/api/audit-events", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ events: outgoing }),
        keepalive: true,
      }).catch(() => undefined);
    await fetch("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    onLogout();
  };

  const flush = useCallback(() => {
    if (!queue.current.length) return;
    const outgoing = queue.current.splice(0, queue.current.length);
    fetch("/api/audit-events", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ events: outgoing }),
      keepalive: true,
    })
      .then((response) => {
        if (!response.ok) throw new Error("audit write failed");
        window.setTimeout(() => void loadAudit(), 300);
      })
      .catch(() => queue.current.unshift(...outgoing));
  }, [loadAudit]);

  useEffect(() => {
    record(
      "session.start",
      "進入管理平台",
      window.location.pathname,
      "success",
    );
    const capture = (event: Event) => {
      const control =
        event.target instanceof Element
          ? event.target.closest("button,a,input,select,textarea")
          : null;
      if (!control || control.closest("[data-private]")) return;
      const name =
        control.getAttribute("data-audit") ||
        control.getAttribute("aria-label") ||
        control.getAttribute("name") ||
        control.textContent?.trim().replace(/\s+/g, " ").slice(0, 48) ||
        control.tagName.toLowerCase();
      const type =
        event.type === "click"
          ? "ui.click"
          : event.type === "change"
            ? "ui.field.change"
            : event.type === "focusin"
              ? "ui.field.focus"
              : "ui.submit";
      const target = control.getAttribute("data-target") ?? undefined;
      // Let React controlled inputs update before audit state causes a rerender.
      queueMicrotask(() =>
        record(
          type,
          `${event.type === "click" ? "點擊" : "操作"}「${name}」`,
          target,
        ),
      );
    };
    const onScroll = () => {
      const total = document.documentElement.scrollHeight - window.innerHeight;
      if (total <= 0) return;
      const percent = Math.round((window.scrollY / total) * 100);
      const mark = [25, 50, 75, 100].find(
        (value) => percent >= value && !scrollMarks.current.has(value),
      );
      if (mark) {
        scrollMarks.current.add(mark);
        record("ui.scroll.depth", `頁面捲動至 ${mark}%`);
      }
    };
    document.addEventListener("click", capture, true);
    document.addEventListener("change", capture, true);
    document.addEventListener("focusin", capture, true);
    document.addEventListener("submit", capture, true);
    window.addEventListener("scroll", onScroll, { passive: true });
    const timer = window.setInterval(flush, 2000);
    return () => {
      document.removeEventListener("click", capture, true);
      document.removeEventListener("change", capture, true);
      document.removeEventListener("focusin", capture, true);
      document.removeEventListener("submit", capture, true);
      window.removeEventListener("scroll", onScroll);
      window.clearInterval(timer);
      flush();
    };
  }, [flush, record]);

  const notify = (message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 2800);
  };

  const go = (next: View) => {
    record(
      "navigation.view",
      `切換至「${views.find((item) => item.id === next)?.label}」`,
      next,
      "success",
    );
    scrollMarks.current.clear();
    setView(next);
  };

  const openLogs = (hostId: string) => {
    setPreferredLogHost(hostId);
    go("logs");
  };

  const removeHost = async (host: HostRow) => {
    if (
      !window.confirm(
        `確定要將 ${host.name}（${host.ip}）移出監控嗎？\n\n這不會刪除遠端 Linux 上的任何資料。`,
      )
    )
      return;
    record("hosts.delete.request", "確認移除受管主機", host.name, "requested");
    try {
      const response = await fetch(
        `/api/hosts/${encodeURIComponent(host.id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail || "刪除主機失敗");
      }
      record("hosts.delete.complete", "受管主機已移除", host.name, "success");
      await loadHosts(true);
      notify(`${host.name} 已移出監控`);
    } catch (reason) {
      record("hosts.delete.complete", "移除受管主機失敗", host.name, "failure");
      notify(reason instanceof Error ? reason.message : "刪除主機失敗");
    }
  };

  const refresh = async () => {
    record("hosts.refresh", "手動重新探測所有主機", undefined, "requested");
    notify(
      (await loadHosts(true))
        ? "主機資料已重新同步"
        : "同步失敗，保留最後一次資料",
    );
  };

  const filteredHosts = useMemo(
    () =>
      hosts.filter((host) =>
        `${host.name} ${host.ip} ${host.group} ${host.os}`
          .toLowerCase()
          .includes(search.toLowerCase()),
      ),
    [hosts, search],
  );

  return (
    <div className="console-shell">
      <aside className="rail">
        <div className="identity">
          <span className="identity-mark">
            L<span>·</span>
          </span>
          <div>
            <strong>
              LINUX<span>/AI</span>
            </strong>
            <small>CONTROL PLANE</small>
          </div>
        </div>
        <div className="workspace">
          <small>目前工作區</small>
          <button data-audit="檢視工作區">
            <span>LB</span>
            <div>
              <strong>Local Lab</strong>
              <small>{hosts.length} hosts</small>
            </div>
          </button>
        </div>
        <nav aria-label="平台功能">
          {views
            .filter(
              (item) =>
                (!["users", "groups"].includes(item.id) ||
                  can("access.manage")) &&
                (item.id !== "alerts" || can("alerts.read")) &&
                (item.id !== "backups" || can("backup.read")) &&
                (item.id !== "diagnostics" || can("ai.read")) &&
                (item.id !== "tasks" || can("tasks.read")) &&
                (item.id !== "health" || can("audit.read")) &&
                (item.id !== "observability" || can("audit.read")) &&
                (item.id !== "security" || can("access.manage")) &&
                (item.id !== "patches" || can("hosts.read")) &&
                (item.id !== "baseline" || can("hosts.read")) &&
                (item.id !== "automation" || can("hosts.read")) &&
                (item.id !== "versions" || can("audit.read")),
            )
            .map((item) => (
              <button
                key={item.id}
                className={view === item.id ? "active" : ""}
                onClick={() => go(item.id)}
                data-audit={`導覽：${item.label}`}
              >
                <span>{item.label}</span>
              </button>
            ))}
        </nav>
        <div className="rail-status">
          <p>
            <i />每 10 秒自動探測
          </p>
          <small>
            {hosts.filter((host) => host.state !== "offline").length}/
            {hosts.length} 台可連線
          </small>
        </div>
        <div className="account">
          <span>{user.displayName.slice(0, 1)}</span>
          <div>
            <strong>{user.displayName}</strong>
            <small>@{user.username}</small>
          </div>
          <button aria-label="登出" onClick={logout}>
            ↪
          </button>
        </div>
      </aside>

      <main>
        <header className="command-bar">
          <div>
            <small>LOCAL LAB / CONTROL PLANE</small>
            <h1>{views.find((item) => item.id === view)?.label}</h1>
          </div>
          <div className="command-actions">
            <label>
              <span>⌕</span>
              <input
                name="主機搜尋"
                aria-label="搜尋主機"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="搜尋主機、IP、作業系統…"
              />
            </label>
            <button
              className="create"
              onClick={refresh}
              data-audit="立即同步主機"
            >
              同步資料 ↻
            </button>
          </div>
        </header>

        <div className="screen">
          {view === "overview" && (
            <Overview
              hosts={hosts}
              events={events}
              stats={stats}
              go={go}
              onRefresh={refresh}
            />
          )}
          {view === "health" && can("audit.read") && <PlatformHealth canRelease={can("backup.manage")} record={record} />}
          {view === "observability" && can("audit.read") && <ObservabilityCenter />}
          {view === "reliability" && can("audit.read") && <ReliabilityCenter canManage={can("backup.manage")} />}
          {view === "reports" && can("audit.read") && <ReportCenter canManage={can("backup.manage")} />}
          {view === "security" && can("access.manage") && <SecurityCenter />}
          {view === "hosts" && (
            <Hosts
              rows={filteredHosts}
              openLogs={openLogs}
              openTerminal={setTerminalHost}
              removeHost={removeHost}
              onAdd={() => setAddHostOpen(true)}
              canManage={can("hosts.manage")}
              canTerminal={can("terminal.open")}
            />
          )}
          {view === "patches" && can("hosts.read") && (
            <PatchInventory canManage={can("hosts.manage")} record={record} />
          )}
          {view === "assets" && can("hosts.read") && (
            <AssetInventory canManage={can("hosts.manage")} record={record} />
          )}
          {view === "baseline" && can("hosts.read") && (
            <SecurityBaselines canManage={can("hosts.manage")} record={record} />
          )}
          {view === "automation" && can("hosts.read") && (
            <AutomationCenter canManage={can("hosts.manage")} record={record} />
          )}
          {view === "logs" && (
            <Logs
              hosts={hosts}
              initialHost={preferredLogHost}
              record={record}
            />
          )}
          {view === "diagnostics" && can("ai.read") && (
            <Diagnostics
              hosts={hosts}
              canManage={can("ai.manage")}
              record={record}
            />
          )}
          {view === "tasks" && can("tasks.read") && (
            <MaintenanceTasks
              hosts={hosts}
              canRequest={can("tasks.request")}
              canApprove={can("tasks.approve")}
              canExecute={can("tasks.execute")}
              record={record}
            />
          )}
          {view === "versions" && can("audit.read") && (
            <ConfigVersions canManage={can("access.manage")} currentUserId={user.id} record={record} />
          )}
          {view === "alerts" && can("alerts.read") && (
            <Alerts
              hosts={hosts}
              canManage={can("alerts.manage")}
              canRequest={can("tasks.request")}
              canTaskRead={can("tasks.read")}
              record={record}
            />
          )}
          {view === "backups" && can("backup.read") && (
            <Backups hosts={hosts} canManage={can("backup.manage")} record={record} />
          )}
          {view === "audit" && <Audit events={events} stats={stats} />}
          {view === "users" && can("access.manage") && <Access section="users" record={record} currentUserId={user.id} />}
          {view === "groups" && can("access.manage") && <Access section="groups" record={record} currentUserId={user.id} />}
        </div>
      </main>

      {toast && (
        <div className="toast" role="status">
          <span>✓</span>
          {toast}
        </div>
      )}
      {addHostOpen && (
        <AddHostModal
          close={() => setAddHostOpen(false)}
          onCreated={async () => {
            await loadHosts(true);
            notify("新主機已驗證並加入監控");
            setAddHostOpen(false);
          }}
          record={record}
        />
      )}
      {terminalHost && (
        <TerminalModal
          host={terminalHost}
          close={() => setTerminalHost(null)}
          record={record}
        />
      )}
    </div>
  );
}

function Overview({
  hosts,
  events,
  stats,
  go,
  onRefresh,
}: {
  hosts: HostRow[];
  events: UiEvent[];
  stats: AuditStats;
  go: (view: View) => void;
  onRefresh: () => void;
}) {
  const online = hosts.filter((host) => host.state !== "offline");
  const issues = hosts.filter((host) => host.state !== "healthy");
  const average = (key: "cpu" | "ram" | "disk") =>
    online.length
      ? Math.round(
          online.reduce((sum, host) => sum + host[key], 0) / online.length,
        )
      : 0;
  return (
    <>
      <section className="signal">
        <div>
          <span className="live-dot" />
          {issues.length
            ? `${issues.length} 台主機需要注意`
            : "所有受管主機目前正常"}
        </div>
        <p>資料來自中央 API 的即時 SSH 唯讀探測</p>
        <button onClick={onRefresh}>立即探測 ↻</button>
      </section>
      <section className="numbers">
        <article>
          <small>ONLINE HOSTS</small>
          <strong>
            {online.length}
            <span>/{hosts.length}</span>
          </strong>
          <p className={online.length === hosts.length ? "up" : "danger"}>
            {online.length === hosts.length
              ? "全部可連線"
              : `${hosts.length - online.length} 台離線`}
          </p>
        </article>
        <article>
          <small>AVERAGE LOAD</small>
          <strong>
            {average("cpu")}
            <span>% CPU</span>
          </strong>
          <p>
            RAM {average("ram")}% · DISK {average("disk")}%
          </p>
        </article>
        <article>
          <small>TODAY AUDIT EVENTS</small>
          <strong>{stats.todayEvents}</strong>
          <p>總計 {stats.totalEvents} 筆</p>
        </article>
        <article>
          <small>AUDIT CHAIN</small>
          <strong>{stats.chainVerified ? "OK" : "!"}</strong>
          <p className={stats.chainVerified ? "up" : "danger"}>
            {stats.chainVerified ? "雜湊鏈驗證通過" : "完整性驗證失敗"}
          </p>
        </article>
      </section>
      <section className="overview-grid">
        <article className="card fleet-card">
          <CardHead
            eyebrow="LIVE HOST DATA"
            title="主機即時狀態"
            action="查看全部"
            onAction={() => go("hosts")}
          />
          <div className="fleet-head">
            <span>主機</span>
            <span>CPU</span>
            <span>RAM</span>
            <span>DISK</span>
            <span>狀態</span>
          </div>
          {hosts.map((host) => (
            <div className="fleet-row" key={host.id}>
              <span>
                <i className={`node ${host.state}`}>▤</i>
                <span>
                  <strong>{host.name}</strong>
                  <small>{host.ip}</small>
                </span>
              </span>
              <span>
                <MetricBar value={host.cpu} />
                <small>{host.cpu}%</small>
              </span>
              <span>
                <MetricBar value={host.ram} />
                <small>{host.ram}%</small>
              </span>
              <span>
                <MetricBar value={host.disk} />
                <small>{host.disk}%</small>
              </span>
              <State value={host.state} />
            </div>
          ))}
        </article>
        <div className="overview-stack">
          <article className="card">
            <CardHead
              eyebrow="DERIVED ALERTS"
              title="目前異常"
              action="查看日誌"
              onAction={() => go("logs")}
            />
            <div className="truth-list">
              {issues.length === 0 ? (
                <div className="empty-state">
                  <strong>沒有偵測到異常</strong>
                  <small>沒有離線主機、失敗服務或超過 80% 的資源。</small>
                </div>
              ) : (
                issues.map((host) => (
                  <div className="truth-row" key={host.id}>
                    <State value={host.state} />
                    <span>
                      <strong>{host.name}</strong>
                      <small>
                        {host.state === "offline"
                          ? host.error || "SSH 無法連線"
                          : host.failedServices?.length
                            ? `${host.failedServices.length} 個失敗服務`
                            : "資源使用率超過 80%"}
                      </small>
                    </span>
                  </div>
                ))
              )}
            </div>
          </article>
          <article className="card">
            <CardHead
              eyebrow="POSTGRESQL AUDIT"
              title="最近 UI 行為"
              action="完整紀錄"
              onAction={() => go("audit")}
            />
            <div className="truth-list">
              {events.slice(0, 4).map((event) => (
                <div className="truth-row" key={event.id}>
                  <code>{event.eventType}</code>
                  <span>
                    <strong>{event.action}</strong>
                    <small>
                      {new Date(event.occurredAt).toLocaleString("zh-TW", {
                        hour12: false,
                      })}
                    </small>
                  </span>
                </div>
              ))}
              {events.length === 0 && (
                <div className="empty-state">
                  <strong>目前沒有稽核事件</strong>
                  <small>操作介面後，事件會寫入 PostgreSQL。</small>
                </div>
              )}
            </div>
          </article>
        </div>
      </section>
    </>
  );
}

type PlatformHealthCheck = {
  id: string;
  category: string;
  label: string;
  status: "healthy" | "warning" | "critical";
  detail: string;
  remediation: string;
  required: boolean;
};

function PlatformHealth({canRelease,record}:{canRelease:boolean;record:(type:string,action:string,target?:string,result?:string)=>void}) {
  const [checks, setChecks] = useState<PlatformHealthCheck[]>([]);
  const [status, setStatus] = useState<"healthy" | "warning" | "critical">("warning");
  const [summary, setSummary] = useState({ healthy: 0, warning: 0, critical: 0 });
  const [checkedAt, setCheckedAt] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [release, setRelease] = useState<{version:string;schema?:{currentVersion?:string;latestVersion?:string;pending?:string[]};compatible?:boolean}|null>(null);
  const [releaseOperations, setReleaseOperations] = useState<Array<{id:string;version:string;status:string;backupStatus?:string;requestedAt:string}>>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [response,versionResponse,releasesResponse] = await Promise.all([fetch("/api/platform-health", { cache: "no-store" }),fetch("/api/system/version",{cache:"no-store"}),fetch("/api/releases",{cache:"no-store"})]);
      const body = (await response.json()) as {
        status?: "healthy" | "warning" | "critical";
        summary?: { healthy: number; warning: number; critical: number };
        checkedAt?: string;
        checks?: PlatformHealthCheck[];
        detail?: string;
      };
      if (!response.ok) throw new Error(body.detail || "無法讀取平台健檢結果");
      setChecks(body.checks ?? []);
      if (body.status) setStatus(body.status);
      if (body.summary) setSummary(body.summary);
      setCheckedAt(body.checkedAt ?? "");
      setError("");
      if(versionResponse.ok) setRelease(await versionResponse.json());
      if(releasesResponse.ok) { const releaseBody=await releasesResponse.json() as {operations?:typeof releaseOperations}; setReleaseOperations(releaseBody.operations??[]); }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "平台健檢失敗");
    } finally {
      setLoading(false);
    }
  }, []);

  const prepareRelease=async()=>{const target=window.prompt("輸入準備更新的版本，例如 1.0.1",release?.version||"1.0.0");if(!target)return;setLoading(true);setError("");try{const response=await fetch("/api/releases/preflight",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({version:target})});const body=await response.json() as {detail?:string};if(!response.ok)throw new Error(body.detail||"更新前檢查失敗");record("release.preflight","更新前相容性檢查與備份",target,"requested");await load();}catch(reason){setError(reason instanceof Error?reason.message:"更新前檢查失敗");}finally{setLoading(false)}};

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const categories = useMemo(() => {
    const grouped = new Map<string, PlatformHealthCheck[]>();
    checks.forEach((check) => grouped.set(check.category, [...(grouped.get(check.category) ?? []), check]));
    return [...grouped.entries()];
  }, [checks]);
  const statusText = { healthy: "健康", warning: "需要設定", critical: "需要處理" };

  return (
    <section className="platform-health-page">
      <div className="card health-heading">
        <div className="page-heading">
          <div><small>CONTROL PLANE SELF OBSERVABILITY</small><h2>中央平台健康檢查</h2><p>只讀檢查中央服務、備份、SSH、版控、Watchdog、通知與 AI 模式；不會修改任何設定。</p></div>
          <button className="create" onClick={() => void load()} disabled={loading}>{loading ? "檢查中…" : "立即重新檢查"}</button>
        </div>
        {error && <div className="log-error">{error}</div>}
        <div className="health-summary">
          <article><small>整體狀態</small><strong className={status}>{statusText[status]}</strong></article>
          <article><small>正常</small><strong>{summary.healthy}</strong></article>
          <article><small>提醒</small><strong>{summary.warning}</strong></article>
          <article><small>異常</small><strong>{summary.critical}</strong></article>
          <article><small>檢查時間</small><strong>{checkedAt ? new Date(checkedAt).toLocaleTimeString("zh-TW", { hour12: false }) : "—"}</strong></article>
        </div>
      </div>

      <div className="card release-center"><header className="alert-section-head"><div><small>VERSIONED RELEASE & ROLLBACK</small><h2>系統版本與更新準備</h2></div>{canRelease&&<button className="secondary-action" onClick={()=>void prepareRelease()} disabled={loading}>更新前檢查＋備份</button>}</header><div className="release-summary"><span><small>目前版本</small><strong>v{release?.version||"—"}</strong></span><span><small>資料庫 Schema</small><strong>{release?.schema?.currentVersion||"—"} / {release?.schema?.latestVersion||"—"}</strong></span><span><small>相容性</small><strong className={release?.compatible?"ok":"warn"}>{release?.compatible?"通過":"待確認"}</strong></span></div><div className="data-table"><table><thead><tr><th>目標版本</th><th>狀態</th><th>更新前備份</th><th>時間</th></tr></thead><tbody>{releaseOperations.slice(0,5).map(item=><tr key={item.id}><td><strong>v{item.version}</strong></td><td>{item.status}</td><td>{item.backupStatus||"等待建立"}</td><td>{new Date(item.requestedAt).toLocaleString("zh-TW",{hour12:false})}</td></tr>)}</tbody></table></div>{!releaseOperations.length&&<div className="empty-state"><strong>尚無版本更新操作</strong><small>執行前會先驗證 migration 並建立可還原備份。</small></div>}</div>

      {categories.map(([category, categoryChecks]) => (
        <div className="card health-category" key={category}>
          <header className="alert-section-head"><div><small>READ-ONLY CHECKS</small><h2>{category}</h2></div><span>{categoryChecks.filter((item) => item.status === "healthy").length}/{categoryChecks.length} 正常</span></header>
          <div className="health-check-list">
            {categoryChecks.map((check) => (
              <article key={check.id} className={check.status}>
                <span className="health-icon">{check.status === "healthy" ? "✓" : check.status === "warning" ? "!" : "×"}</span>
                <div><strong>{check.label}</strong><small>{check.detail}</small>{check.remediation && <p>{check.remediation}</p>}</div>
                <div className="health-check-state"><span>{statusText[check.status]}</span><small>{check.required ? "必要項目" : "選用項目"}</small></div>
              </article>
            ))}
          </div>
        </div>
      ))}
      {!checks.length && !error && <div className="card empty-state page-empty"><strong>正在取得中央平台狀態…</strong></div>}
    </section>
  );
}

type ServiceObservation={service:string;status:"healthy"|"warning"|"critical";metrics:Record<string,number>;detail:string;collectedAt:string};
type CapacityForecast={hostId:string;hostName:string;resource:"cpu"|"ram"|"disk";currentPercent:number;slopePerDay:number;thresholdPercent:number;predictedDays:number|null;sampleCount:number;confidence:"low"|"medium"|"high";calculatedAt:string};
type WorkerObservation={id:string;version:string;concurrency:number;activeTasks:number;online:boolean;lastHeartbeatAt:string};

function ObservabilityCenter(){
  const [services,setServices]=useState<ServiceObservation[]>([]);const [forecasts,setForecasts]=useState<CapacityForecast[]>([]);const [workers,setWorkers]=useState<WorkerObservation[]>([]);const [loading,setLoading]=useState(false);const [error,setError]=useState("");
  const load=useCallback(async(refresh=false)=>{setLoading(true);try{const response=await fetch(`/api/observability${refresh?"?refresh=true":""}`,{cache:"no-store"});const body=await response.json() as {services?:ServiceObservation[];forecasts?:CapacityForecast[];workers?:WorkerObservation[];detail?:string};if(!response.ok)throw new Error(body.detail||"無法讀取可觀測性資料");setServices(body.services??[]);setForecasts(body.forecasts??[]);setWorkers(body.workers??[]);setError("");}catch(reason){setError(reason instanceof Error?reason.message:"載入失敗");}finally{setLoading(false)}},[]);
  useEffect(()=>{void load();const timer=window.setInterval(()=>void load(),30000);return()=>window.clearInterval(timer)},[load]);
  const labels={postgres:"PostgreSQL", "maintenance-worker":"維運 Worker", "backup-worker":"備份 Worker"};const resources={cpu:"CPU",ram:"記憶體",disk:"磁碟"};
  return <section className="observability-page"><div className="card observability-heading"><div className="page-heading"><div><small>SERVICE OBSERVABILITY & CAPACITY</small><h2>中央服務與容量預測</h2><p>整合 Worker 心跳、任務佇列、資料庫容量及最近 7 天主機資源趨勢。</p></div><button className="create" disabled={loading} onClick={()=>void load(true)}>{loading?"計算中…":"立即重新計算"}</button></div>{error&&<div className="log-error">{error}</div>}</div><div className="service-observations">{services.map(item=><article className={`card ${item.status}`} key={item.service}><header><span>{item.status==="healthy"?"✓":"!"}</span><div><small>SERVICE</small><strong>{labels[item.service as keyof typeof labels]||item.service}</strong></div></header><p>{item.detail}</p><dl>{Object.entries(item.metrics).map(([key,value])=><div key={key}><dt>{key}</dt><dd>{Number(value).toLocaleString()}</dd></div>)}</dl><footer>{new Date(item.collectedAt).toLocaleString("zh-TW",{hour12:false})}</footer></article>)}</div><div className="card capacity-center"><header className="alert-section-head"><div><small>7-DAY LINEAR FORECAST</small><h2>受管主機容量趨勢</h2></div><span>門檻 85% · 14 天內告警</span></header><div className="data-table"><table><thead><tr><th>主機</th><th>資源</th><th>目前</th><th>每日變化</th><th>預計達門檻</th><th>可信度</th><th>樣本</th></tr></thead><tbody>{forecasts.map(item=><tr key={`${item.hostId}-${item.resource}`}><td><strong>{item.hostName}</strong></td><td>{resources[item.resource]}</td><td>{item.currentPercent.toFixed(1)}%</td><td className={item.slopePerDay>0.05?"warn":"ok"}>{item.slopePerDay>=0?"+":""}{item.slopePerDay.toFixed(2)}%／天</td><td><span className={`forecast-risk ${item.predictedDays!==null&&item.predictedDays<=14?"urgent":"stable"}`}>{item.predictedDays===null?"趨勢穩定":item.predictedDays<=0?"已達門檻":`${item.predictedDays.toFixed(1)} 天`}</span></td><td>{({low:"低",medium:"中",high:"高"} as const)[item.confidence]}</td><td>{item.sampleCount}</td></tr>)}</tbody></table></div>{!forecasts.length&&<div className="empty-state"><strong>尚無足夠的效能樣本</strong><small>平台持續採集後會自動建立最近 7 天容量趨勢。</small></div>}</div><div className="card worker-registry"><header className="alert-section-head"><div><small>PERSISTENT WORKER REGISTRY</small><h2>Worker 登錄狀態</h2></div><span>超過 10 分鐘未回報會自動清理</span></header>{workers.map(worker=><article key={worker.id}><div><strong>{worker.id}</strong><small>v{worker.version}</small></div><span className={`watchdog-status ${worker.online?"online":"stale"}`}>{worker.online?"在線":"離線"}</span><div><strong>{worker.activeTasks} / {worker.concurrency}</strong><small>執行中／並行上限</small></div><time>{new Date(worker.lastHeartbeatAt).toLocaleString("zh-TW",{hour12:false})}</time></article>)}</div></section>;
}

type ReliabilityPolicy={windowDays:number;availabilityTarget:number;mttaTargetMinutes:number;mttrTargetMinutes:number;updatedAt:string};
type ReliabilityEntity={name:string;kind:"service"|"host";samples:number;availability:number|null;target:number;met:boolean};
type ReliabilityReport={policy:ReliabilityPolicy;entities:ReliabilityEntity[];incidents:{total:number;critical:number;acknowledged:number;resolved:number;mttaMinutes:number|null;mttrMinutes:number|null;mttaMet:boolean;mttrMet:boolean};trend:Array<{day:string;incidents:number;critical:number}>;generatedAt:string};

function ReliabilityCenter({canManage}:{canManage:boolean}){
  const [report,setReport]=useState<ReliabilityReport|null>(null);const [loading,setLoading]=useState(false);const [error,setError]=useState("");const [editing,setEditing]=useState(false);
  const load=useCallback(async()=>{setLoading(true);try{const response=await fetch("/api/reliability",{cache:"no-store"});const body=await response.json() as ReliabilityReport&{detail?:string};if(!response.ok)throw new Error(body.detail||"無法讀取可靠性報表");setReport(body);setError("");}catch(reason){setError(reason instanceof Error?reason.message:"載入失敗");}finally{setLoading(false)}},[]);
  useEffect(()=>{void load()},[load]);
  const save=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();const data=new FormData(event.currentTarget);const response=await fetch("/api/reliability/policy",{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify({windowDays:Number(data.get("windowDays")),availabilityTarget:Number(data.get("availabilityTarget")),mttaTargetMinutes:Number(data.get("mttaTargetMinutes")),mttrTargetMinutes:Number(data.get("mttrTargetMinutes"))})});const body=await response.json() as ReliabilityReport&{detail?:string};if(!response.ok){setError(body.detail||"儲存失敗");return}setReport(body);setEditing(false)};
  const incident=report?.incidents;const policy=report?.policy;
  return <section className="reliability-page"><div className="card reliability-heading"><div className="page-heading"><div><small>SLO & INCIDENT PERFORMANCE</small><h2>可靠性目標與營運報表</h2><p>依中央服務、主機探測與告警事件計算可用率、平均確認時間與平均修復時間。</p></div><div className="reliability-actions"><a href="/api/reliability/export.csv">匯出 CSV</a>{canManage&&<button className="secondary-action" onClick={()=>setEditing(true)}>調整目標</button>}<button className="create" onClick={()=>void load()} disabled={loading}>{loading?"更新中…":"重新計算"}</button></div></div>{error&&<div className="log-error">{error}</div>}<div className="reliability-kpis"><article><small>統計範圍</small><strong>{policy?`${policy.windowDays} 天`:"—"}</strong></article><article><small>可用率目標</small><strong>{policy?`${policy.availabilityTarget}%`:"—"}</strong></article><article><small>平均確認 MTTA</small><strong className={incident?.mttaMet?"ok":"warn"}>{incident?.mttaMinutes==null?"尚無資料":`${incident.mttaMinutes} 分`}</strong></article><article><small>平均修復 MTTR</small><strong className={incident?.mttrMet?"ok":"warn"}>{incident?.mttrMinutes==null?"尚無資料":`${incident.mttrMinutes} 分`}</strong></article><article><small>事件／重大</small><strong>{incident?`${incident.total} / ${incident.critical}`:"—"}</strong></article></div></div><div className="card reliability-table"><header className="alert-section-head"><div><small>SERVICE LEVEL OBJECTIVES</small><h2>可用率達標狀態</h2></div><span>{report?.entities.filter(item=>item.met).length||0}/{report?.entities.length||0} 達標</span></header><div className="data-table"><table><thead><tr><th>類型</th><th>服務／主機</th><th>樣本數</th><th>實際可用率</th><th>目標</th><th>狀態</th></tr></thead><tbody>{report?.entities.map(item=><tr key={`${item.kind}-${item.name}`}><td>{item.kind==="service"?"中央服務":"受管主機"}</td><td><strong>{item.name}</strong></td><td>{item.samples}</td><td>{item.availability==null?"—":`${item.availability.toFixed(3)}%`}</td><td>{item.target.toFixed(2)}%</td><td><span className={`slo-state ${item.met?"met":"missed"}`}>{item.met?"達標":"未達標"}</span></td></tr>)}</tbody></table></div>{!report?.entities.length&&<div className="empty-state"><strong>尚無足夠樣本</strong><small>中央持續採集後會自動產生可靠性統計。</small></div>}</div>{editing&&policy&&<div className="modal-shell" role="dialog" aria-modal="true"><form className="modal reliability-policy" onSubmit={save}><header><div><small>RELIABILITY POLICY</small><h2>調整可靠性目標</h2></div><button type="button" onClick={()=>setEditing(false)}>×</button></header><label>統計天數<input name="windowDays" type="number" min="7" max="90" defaultValue={policy.windowDays}/></label><label>可用率目標（%）<input name="availabilityTarget" type="number" min="90" max="100" step="0.01" defaultValue={policy.availabilityTarget}/></label><label>MTTA 目標（分鐘）<input name="mttaTargetMinutes" type="number" min="1" max="1440" defaultValue={policy.mttaTargetMinutes}/></label><label>MTTR 目標（分鐘）<input name="mttrTargetMinutes" type="number" min="1" max="10080" defaultValue={policy.mttrTargetMinutes}/></label><footer><button type="button" onClick={()=>setEditing(false)}>取消</button><button className="create" type="submit">儲存目標</button></footer></form></div>}</section>;
}

type ReportPolicy={enabled:boolean;weeklyDay:number;monthlyDay:number;generateHourUtc:number;notifyEnabled:boolean;updatedAt:string};
type OperationalReport={id:string;reportType:"manual"|"weekly"|"monthly";periodStart:string;periodEnd:string;status:string;snapshot:{alertsByHost:Array<{name:string;count:number;critical:number}>;alertsByRule:Array<{name:string;count:number;critical:number}>;reliability:{incidents:{total:number;critical:number;mttaMinutes:number|null;mttrMinutes:number|null}};tasks:{total:number;succeeded:number;failed:number}};deliveryStatus:string;deliveredChannels:string[];createdAt:string};
function ReportCenter({canManage}:{canManage:boolean}){
 const [policy,setPolicy]=useState<ReportPolicy|null>(null);const [reports,setReports]=useState<OperationalReport[]>([]);const [channels,setChannels]=useState<Array<{id:string;name:string;enabled:boolean}>>([]);const [error,setError]=useState("");const [busy,setBusy]=useState(false);const [editing,setEditing]=useState(false);const [selected,setSelected]=useState<OperationalReport|null>(null);
 const load=useCallback(async()=>{const response=await fetch("/api/reports",{cache:"no-store"});const body=await response.json();if(!response.ok){setError(body.detail||"無法讀取營運報表");return}setPolicy(body.policy);setReports(body.reports||[]);setChannels(body.channels||[]);setError("")},[]);useEffect(()=>{void load()},[load]);
 const generate=async(notify=false)=>{setBusy(true);try{const response=await fetch(`/api/reports?notify=${notify}`,{method:"POST"});const body=await response.json();if(!response.ok)throw new Error(body.detail||"產生報表失敗");await load();setSelected(body)}catch(reason){setError(reason instanceof Error?reason.message:"產生失敗")}finally{setBusy(false)}};
 const save=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();const data=new FormData(event.currentTarget);const response=await fetch("/api/reports/policy",{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify({enabled:data.get("enabled")==="on",weeklyDay:Number(data.get("weeklyDay")),monthlyDay:Number(data.get("monthlyDay")),generateHourUtc:Number(data.get("generateHourUtc")),notifyEnabled:data.get("notifyEnabled")==="on"})});const body=await response.json();if(!response.ok){setError(body.detail||"儲存失敗");return}setPolicy(body.policy);setReports(body.reports||[]);setEditing(false)};
 const kind={manual:"手動",weekly:"週報",monthly:"月報"};
 return <section className="reports-page"><div className="card report-heading"><div className="page-heading"><div><small>SCHEDULED OPERATIONS REPORTS</small><h2>週／月營運報表</h2><p>彙整 SLO、告警趨勢、高頻主機與維運任務結果，並沿用已啟用的通知管道。</p></div><div className="reliability-actions">{canManage&&<button className="secondary-action" onClick={()=>setEditing(true)}>排程設定</button>}{canManage&&<button className="create" disabled={busy} onClick={()=>void generate(false)}>{busy?"產生中…":"立即產生"}</button>}</div></div>{error&&<div className="log-error">{error}</div>}<div className="report-kpis"><article><small>自動排程</small><strong>{policy?.enabled?"啟用":"停用"}</strong></article><article><small>每週</small><strong>週 {policy?.weeklyDay||"—"}</strong></article><article><small>每月</small><strong>{policy?.monthlyDay||"—"} 日</strong></article><article><small>產生時間</small><strong>{policy?`${policy.generateHourUtc}:00 UTC`:"—"}</strong></article><article><small>通知管道</small><strong>{channels.filter(item=>item.enabled).length}</strong></article></div></div><div className="card report-history"><header className="alert-section-head"><div><small>REPORT ARCHIVE</small><h2>報表歷史</h2></div><span>{reports.length} 筆</span></header><div className="data-table"><table><thead><tr><th>類型</th><th>期間</th><th>事件／重大</th><th>MTTA／MTTR</th><th>發送</th><th>建立時間</th><th>操作</th></tr></thead><tbody>{reports.map(item=><tr key={item.id}><td><strong>{kind[item.reportType]}</strong></td><td>{item.periodStart}～{item.periodEnd}</td><td>{item.snapshot.reliability.incidents.total} / {item.snapshot.reliability.incidents.critical}</td><td>{item.snapshot.reliability.incidents.mttaMinutes??"—"} / {item.snapshot.reliability.incidents.mttrMinutes??"—"} 分</td><td>{item.deliveryStatus}</td><td>{new Date(item.createdAt).toLocaleString("zh-TW",{hour12:false})}</td><td><div className="row-actions"><button onClick={()=>setSelected(item)}>查看</button><a href={`/api/reports/${item.id}/export.csv`}>CSV</a></div></td></tr>)}</tbody></table></div>{!reports.length&&<div className="empty-state"><strong>尚無營運報表</strong></div>}</div>{editing&&policy&&<div className="modal-shell"><form className="modal report-policy" onSubmit={save}><header><div><small>REPORT POLICY</small><h2>營運報表排程</h2></div><button type="button" onClick={()=>setEditing(false)}>×</button></header><label className="inline-check"><input name="enabled" type="checkbox" defaultChecked={policy.enabled}/><span>啟用自動週報與月報</span></label><label>每週產生日（1=週一）<input name="weeklyDay" type="number" min="1" max="7" defaultValue={policy.weeklyDay}/></label><label>每月產生日<input name="monthlyDay" type="number" min="1" max="28" defaultValue={policy.monthlyDay}/></label><label>UTC 小時<input name="generateHourUtc" type="number" min="0" max="23" defaultValue={policy.generateHourUtc}/></label><label className="inline-check"><input name="notifyEnabled" type="checkbox" defaultChecked={policy.notifyEnabled}/><span>產生後發送至已啟用通知管道</span></label><footer><button type="button" onClick={()=>setEditing(false)}>取消</button><button className="create">儲存</button></footer></form></div>}{selected&&<div className="modal-shell"><div className="modal report-detail"><header><div><small>{selected.id}</small><h2>營運報表內容</h2></div><button onClick={()=>setSelected(null)}>×</button></header><section><h3>高頻告警主機</h3>{selected.snapshot.alertsByHost.map(item=><p key={item.name}><strong>{item.name}</strong><span>{item.count} 次／重大 {item.critical}</span></p>)}<h3>高頻告警規則</h3>{selected.snapshot.alertsByRule.map(item=><p key={item.name}><strong>{item.name}</strong><span>{item.count} 次／重大 {item.critical}</span></p>)}</section><footer><a href={`/api/reports/${selected.id}/export.csv`}>下載 CSV</a><button onClick={()=>setSelected(null)}>關閉</button></footer></div></div>}</section>;
}

type SecuritySession = {
  id: string; userId: string; username: string; displayName: string;
  sourceAddress: string; userAgent: string; createdAt: string;
  lastSeenAt: string; expiresAt: string; isCurrent: boolean;
};
type LoginEvent = {
  id: string; username: string; displayName?: string | null; success: boolean;
  reason: string; sourceAddress: string; userAgent: string; occurredAt: string;
};
type AuthSecurityPolicy = {
  maxFailedAttempts: number; lockoutMinutes: number; eventRetentionDays: number; requireMfaAdmins: boolean; updatedAt?: string;
};
type VaultSecret = { id:string; name:string; purpose:string; version:number; createdAt:string; updatedAt:string };
type KeyRetirement = { id:string; rotationId:string; status:string; requestedBy?:string; approvedBy?:string; requestedAt:string; completedAt?:string|null; error?:string|null };

function SecurityCenter() {
  const [sessions, setSessions] = useState<SecuritySession[]>([]);
  const [loginEvents, setLoginEvents] = useState<LoginEvent[]>([]);
  const [eventFilter, setEventFilter] = useState<"all" | "success" | "failed">("all");
  const [policy, setPolicy] = useState<AuthSecurityPolicy>({ maxFailedAttempts: 5, lockoutMinutes: 5, eventRetentionDays: 90, requireMfaAdmins: false });
  const [policyOpen, setPolicyOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [posture, setPosture] = useState<{mfa:{enabled:boolean};providers:Array<{providerType:string;displayName:string;enabled:boolean}>;vaultCount:number;masterKeySource:string;sshRotation?:{id:string;status:string;fingerprint:string}|null}>({mfa:{enabled:false},providers:[],vaultCount:0,masterKeySource:"unknown",sshRotation:null});
  const [mfaSetup, setMfaSetup] = useState<{secret:string;otpauthUri:string;recoveryCodes:string[]}|null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaManage, setMfaManage] = useState<"recovery"|"disable"|null>(null);
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[]>([]);
  const [vaultSecrets, setVaultSecrets] = useState<VaultSecret[]>([]);
  const [secretOpen, setSecretOpen] = useState(false);
  const [editingSecret, setEditingSecret] = useState<VaultSecret|null>(null);
  const [retirements, setRetirements] = useState<KeyRetirement[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [response, postureResponse, secretResponse, retirementResponse] = await Promise.all([fetch("/api/security/sessions", { cache: "no-store" }), fetch("/api/security/posture", { cache: "no-store" }), fetch("/api/security/secrets", {cache:"no-store"}), fetch("/api/security/ssh-keys/retirements", {cache:"no-store"})]);
      const body = (await response.json()) as { sessions?: SecuritySession[]; loginEvents?: LoginEvent[]; policy?: AuthSecurityPolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "無法讀取 Session 安全狀態");
      setSessions(body.sessions ?? []);
      setLoginEvents(body.loginEvents ?? []);
      if (body.policy) setPolicy(body.policy);
      if (postureResponse.ok) setPosture(await postureResponse.json());
      if (secretResponse.ok) setVaultSecrets(((await secretResponse.json()) as {secrets:VaultSecret[]}).secrets || []);
      if (retirementResponse.ok) setRetirements(((await retirementResponse.json()) as {requests:KeyRetirement[]}).requests || []);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "安全狀態載入失敗");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const revoke = async (session: SecuritySession) => {
    if (!window.confirm(`確定撤銷 ${session.displayName} 從 ${session.sourceAddress} 建立的 Session？`)) return;
    const response = await fetch(`/api/security/sessions/${encodeURIComponent(session.id)}`, { method: "DELETE" });
    const body = response.status === 204 ? {} : (await response.json()) as { detail?: string };
    if (!response.ok) { setError(body.detail || "撤銷 Session 失敗"); return; }
    await load();
  };

  const revokeOthers = async () => {
    if (!window.confirm("確定登出目前帳號在其他瀏覽器或裝置上的所有 Session？")) return;
    const response = await fetch("/api/security/sessions/revoke-others", { method: "POST" });
    const body = (await response.json()) as { revoked?: number; detail?: string };
    if (!response.ok) { setError(body.detail || "登出其他裝置失敗"); return; }
    await load();
  };

  const savePolicy = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const response = await fetch("/api/security/policy", {
      method: "PUT", headers: { "content-type": "application/json" },
      body: JSON.stringify({
        maxFailedAttempts: Number(form.get("maxFailedAttempts")),
        lockoutMinutes: Number(form.get("lockoutMinutes")),
        eventRetentionDays: Number(form.get("eventRetentionDays")),
        requireMfaAdmins: form.get("requireMfaAdmins") === "on",
      }),
    });
    const body = (await response.json()) as { policy?: AuthSecurityPolicy; detail?: string };
    if (!response.ok) { setError(body.detail || "安全政策儲存失敗"); return; }
    if (body.policy) setPolicy(body.policy);
    setPolicyOpen(false);
  };

  const filteredEvents = loginEvents.filter((event) => eventFilter === "all" || (eventFilter === "success" ? event.success : !event.success));
  const failures24h = loginEvents.filter((event) => !event.success && Date.now() - new Date(event.occurredAt).getTime() <= 86_400_000).length;
  const reasonLabel: Record<string, string> = { authenticated: "驗證成功", invalid_credentials: "帳號或密碼錯誤", rate_limited: "嘗試過多，已限制" };
  const beginMfa = async () => {
    const response = await fetch("/api/security/mfa/setup", { method: "POST" });
    const body = await response.json();
    if (!response.ok) { setError(body.detail || "無法建立 MFA"); return; }
    setMfaSetup(body);
  };
  const enableMfa = async () => {
    const response = await fetch("/api/security/mfa/enable", { method: "POST", headers: {"content-type":"application/json"}, body: JSON.stringify({code:mfaCode}) });
    const body = await response.json();
    if (!response.ok) { setError(body.detail || "MFA 驗證失敗"); return; }
    setMfaSetup(null); setMfaCode(""); await load();
  };
  const storeSecret = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const form=new FormData(event.currentTarget); const name=String(form.get("name")||"");
    const response = await fetch(`/api/security/secrets/${encodeURIComponent(name)}`, {method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify({name,value:form.get("value"),purpose:form.get("purpose")})});
    const body = await response.json(); if (!response.ok) { setError(body.detail || "祕密儲存失敗"); return; }
    setSecretOpen(false); setEditingSecret(null); await load();
  };
  const deleteSecret = async (secret:VaultSecret) => {
    if (!window.confirm(`確定刪除 ${secret.name}？使用它的外部整合可能立即失效。`)) return;
    const response=await fetch(`/api/security/secrets/${encodeURIComponent(secret.name)}`,{method:"DELETE"});
    if (!response.ok) { setError(((await response.json()).detail)||"刪除失敗"); return; } await load();
  };
  const manageMfa = async () => {
    const endpoint=mfaManage==="recovery"?"/api/security/mfa/recovery-codes":"/api/security/mfa";
    const response=await fetch(endpoint,{method:mfaManage==="recovery"?"POST":"DELETE",headers:{"content-type":"application/json"},body:JSON.stringify({code:mfaCode})});
    const body=response.status===204?{}:await response.json(); if(!response.ok){setError(body.detail||"MFA 操作失敗");return;}
    if(body.recoveryCodes){setNewRecoveryCodes(body.recoveryCodes);setMfaCode("");}else{setMfaManage(null);setMfaCode("");await load();}
  };
  const stageSshKey = async () => {
    if (!window.confirm("建立新金鑰只會進入 staged，不會立即移除舊金鑰。是否繼續？")) return;
    const response = await fetch("/api/security/ssh-keys/rotations", {method:"POST"}); const body = await response.json();
    if (!response.ok) { setError(body.detail || "建立輪替失敗"); return; } await load();
  };
  const deploySshKey = async () => {
    const id = posture.sshRotation?.id; if (!id) return;
    const response = await fetch(`/api/security/ssh-keys/rotations/${encodeURIComponent(id)}/deploy`, {method:"POST"}); const body = await response.json();
    if (!response.ok) { setError(body.detail || "金鑰部署驗證失敗"); return; }
    if (body.ready && window.confirm("所有主機均已用新金鑰驗證。要將新金鑰設為中央作用中金鑰嗎？舊金鑰仍會保留以便回復。")) {
      const promoted = await fetch(`/api/security/ssh-keys/rotations/${encodeURIComponent(id)}/promote`, {method:"POST"});
      if (!promoted.ok) setError(((await promoted.json()).detail) || "金鑰切換失敗");
    } await load();
  };
  const requestRetirement=async()=>{const response=await fetch("/api/security/ssh-keys/retirements",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({note:"新金鑰已逐台驗證，申請退役舊金鑰"})});const body=await response.json();if(!response.ok){setError(body.detail||"建立退役申請失敗");return;}await load();};
  const actRetirement=async(item:KeyRetirement,action:"approve"|"reject"|"execute")=>{const response=await fetch(`/api/security/ssh-keys/retirements/${encodeURIComponent(item.id)}/${action}`,{method:"POST",headers:{"content-type":"application/json"},body:action!=="execute"?JSON.stringify({note:action==="approve"?"確認新金鑰可正常登入":"拒絕本次退役"}):undefined});const body=await response.json();if(!response.ok){setError(body.detail||"舊金鑰退役操作失敗");return;}await load();};

  return (
    <section className="security-page">
      <div className="card security-heading">
        <div className="page-heading">
          <div><small>IDENTITY AND SESSION SECURITY</small><h2>帳號與 Session 安全中心</h2><p>登入事件不保存密碼；Session 只保存不可逆 Token 雜湊、來源與到期時間。</p></div>
          <div className="heading-actions"><button className="secondary-action" onClick={() => setPolicyOpen(true)}>登入安全政策</button><button className="secondary-action" onClick={() => void revokeOthers()}>登出我的其他裝置</button><button className="create" onClick={() => void load()} disabled={loading}>{loading ? "更新中…" : "重新整理"}</button></div>
        </div>
        {error && <div className="log-error">{error}</div>}
        <div className="security-summary"><span><strong>{sessions.length}</strong>有效 Session</span><span><strong>{new Set(sessions.map((item) => item.userId)).size}</strong>登入使用者</span><span><strong className={failures24h ? "warn" : "ok"}>{failures24h}</strong>24 小時失敗</span><span><strong>{policy.maxFailedAttempts} 次／{policy.lockoutMinutes} 分</strong>登入限制</span></div>
      </div>

      <div className="card security-sessions">
        <header className="alert-section-head"><div><small>ACTIVE SESSIONS</small><h2>有效登入 Session</h2></div><span>到期後由 PostgreSQL 自動清理</span></header>
        <div className="data-table"><table><thead><tr><th>使用者</th><th>來源 IP</th><th>瀏覽器／裝置</th><th>建立時間</th><th>最後活動</th><th>到期時間</th><th>操作</th></tr></thead><tbody>{sessions.map((session) => <tr key={session.id}><td><strong>{session.displayName}</strong><small>@{session.username}{session.isCurrent ? " · 目前 Session" : ""}</small></td><td><code>{session.sourceAddress}</code></td><td className="session-agent">{session.userAgent}</td><td>{new Date(session.createdAt).toLocaleString("zh-TW", { hour12: false })}</td><td>{new Date(session.lastSeenAt).toLocaleString("zh-TW", { hour12: false })}</td><td>{new Date(session.expiresAt).toLocaleString("zh-TW", { hour12: false })}</td><td>{session.isCurrent ? <span className="session-current">使用中</span> : <button className="table-action danger-action" onClick={() => void revoke(session)}>撤銷</button>}</td></tr>)}</tbody></table></div>
        {!sessions.length && <div className="empty-state"><strong>沒有有效 Session</strong></div>}
      </div>

      <div className="card security-sessions">
        <header className="alert-section-head"><div><small>IDENTITY HARDENING</small><h2>身分、祕密與 SSH 金鑰治理</h2></div><div className="heading-actions">{!posture.mfa.enabled ? <button className="create" onClick={() => void beginMfa()}>啟用 MFA</button> : <><button className="secondary-action" onClick={() => {setNewRecoveryCodes([]);setMfaCode("");setMfaManage("recovery")}}>重建復原碼</button><button className="secondary-action" onClick={() => {setMfaCode("");setMfaManage("disable")}}>停用 MFA</button></>}<button className="secondary-action" onClick={() => {setEditingSecret(null);setSecretOpen(true)}}>新增祕密</button>{!posture.sshRotation || posture.sshRotation.status === "active" ? <button className="secondary-action" onClick={() => void stageSshKey()}>建立 SSH 新金鑰</button> : <button className="secondary-action" onClick={() => void deploySshKey()}>部署並驗證 SSH 金鑰</button>}</div></header>
        <div className="security-summary"><span><strong className={posture.mfa.enabled ? "ok" : "warn"}>{posture.mfa.enabled ? "已啟用" : "未啟用"}</strong>我的 TOTP MFA</span><span><strong>{posture.providers.filter(item => item.enabled).length}</strong>外部身分提供者</span><span><strong>{posture.vaultCount}</strong>加密祕密</span><span><strong>{posture.sshRotation?.status || "尚未輪替"}</strong>SSH 金鑰</span></div>
        <p className="notification-help">OIDC／LDAP 採選用整合；client secret 與 bind password 必須放入祕密庫。{posture.masterKeySource === "derived-lab-fallback" ? "目前使用實驗室衍生主金鑰，正式使用前請設定 PLATFORM_MASTER_KEY。" : "主金鑰由環境變數提供。"}</p>
      </div>

      <div className="card security-sessions"><header className="alert-section-head"><div><small>ENCRYPTED SECRET VAULT</small><h2>加密祕密庫</h2></div><span>API 永不回傳祕密值</span></header><div className="data-table"><table><thead><tr><th>名稱</th><th>用途</th><th>版本</th><th>最後輪替</th><th>操作</th></tr></thead><tbody>{vaultSecrets.map(secret=><tr key={secret.id}><td><strong>{secret.name}</strong></td><td>{secret.purpose}</td><td>v{secret.version}</td><td>{new Date(secret.updatedAt).toLocaleString("zh-TW",{hour12:false})}</td><td><span className="row-actions"><button className="table-action" onClick={()=>{setEditingSecret(secret);setSecretOpen(true)}}>輪替</button><button className="table-action danger-action" onClick={()=>void deleteSecret(secret)}>刪除</button></span></td></tr>)}</tbody></table></div>{!vaultSecrets.length&&<div className="empty-state"><strong>尚未保存任何祕密</strong></div>}</div>

      <div className="card security-sessions"><header className="alert-section-head"><div><small>SSH KEY RETIREMENT</small><h2>SSH 舊金鑰退役</h2></div>{posture.sshRotation?.status==="active"&&<button className="secondary-action" onClick={()=>void requestRetirement()}>申請退役舊金鑰</button>}</header><div className="data-table"><table><thead><tr><th>申請</th><th>申請者</th><th>核准者</th><th>狀態</th><th>時間</th><th>操作</th></tr></thead><tbody>{retirements.map(item=><tr key={item.id}><td><code>{item.id}</code></td><td>{item.requestedBy||"—"}</td><td>{item.approvedBy||"—"}</td><td>{item.status}</td><td>{new Date(item.requestedAt).toLocaleString("zh-TW",{hour12:false})}</td><td>{item.status==="pending"?<span className="row-actions"><button className="table-action" onClick={()=>void actRetirement(item,"approve")}>核准</button><button className="table-action danger-action" onClick={()=>void actRetirement(item,"reject")}>拒絕</button></span>:item.status==="approved"?<button className="table-action danger-action" onClick={()=>void actRetirement(item,"execute")}>執行退役</button>:"—"}</td></tr>)}</tbody></table></div>{!retirements.length&&<div className="empty-state"><strong>尚無舊金鑰退役申請</strong></div>}</div>

      <div className="card login-events">
        <header className="alert-section-head"><div><small>AUTHENTICATION EVENTS</small><h2>最近登入紀錄</h2></div><select value={eventFilter} onChange={(event) => setEventFilter(event.target.value as typeof eventFilter)}><option value="all">全部結果</option><option value="success">僅成功</option><option value="failed">僅失敗</option></select></header>
        <div className="data-table"><table><thead><tr><th>時間</th><th>帳號</th><th>來源 IP</th><th>結果</th><th>原因</th><th>瀏覽器／裝置</th></tr></thead><tbody>{filteredEvents.map((event) => <tr key={event.id}><td>{new Date(event.occurredAt).toLocaleString("zh-TW", { hour12: false })}</td><td><strong>{event.displayName || event.username}</strong><small>@{event.username}</small></td><td><code>{event.sourceAddress}</code></td><td><span className={`login-result ${event.success ? "success" : "failed"}`}>{event.success ? "成功" : "失敗"}</span></td><td>{reasonLabel[event.reason] || event.reason}</td><td className="session-agent">{event.userAgent}</td></tr>)}</tbody></table></div>
        {!filteredEvents.length && <div className="empty-state"><strong>沒有符合條件的登入紀錄</strong></div>}
      </div>
      {policyOpen && <div className="modal-layer"><form className="modal security-policy-modal" onSubmit={savePolicy}><button type="button" className="close" onClick={() => setPolicyOpen(false)}>×</button><small>DATABASE-BACKED LOGIN PROTECTION</small><h2>登入安全政策</h2><p>限制資料保存在 PostgreSQL，API 重新啟動後仍然有效。成功登入會重設相同帳號與來源 IP 的失敗計數。</p><label>允許失敗次數<input name="maxFailedAttempts" type="number" min="3" max="10" defaultValue={policy.maxFailedAttempts} required /><small>達到次數後暫時拒絕登入</small></label><label>鎖定時間（分鐘）<input name="lockoutMinutes" type="number" min="1" max="1440" defaultValue={policy.lockoutMinutes} required /></label><label>登入紀錄保留天數<input name="eventRetentionDays" type="number" min="30" max="365" defaultValue={policy.eventRetentionDays} required /></label><label className="inline-check"><input name="requireMfaAdmins" type="checkbox" defaultChecked={policy.requireMfaAdmins} /><span>強制所有啟用中的系統管理員使用 MFA</span></label><div className="modal-actions"><button type="button" onClick={() => setPolicyOpen(false)}>取消</button><button className="create">儲存政策</button></div></form></div>}
      {mfaSetup && <div className="modal-layer"><section className="modal"><button className="close" onClick={() => setMfaSetup(null)}>×</button><small>TOTP MULTI-FACTOR AUTHENTICATION</small><h2>啟用 MFA</h2><p>在手機驗證器新增下列金鑰，再輸入 6 位數動態碼。請先離線保存復原碼；關閉後不會再次顯示。</p><label>設定金鑰<code>{mfaSetup.secret}</code></label><label>驗證器 URI<textarea readOnly value={mfaSetup.otpauthUri} /></label><div className="fingerprint"><small>一次性復原碼</small><code>{mfaSetup.recoveryCodes.join("  ")}</code></div><label>目前動態碼<input value={mfaCode} onChange={event => setMfaCode(event.target.value)} inputMode="numeric" autoComplete="one-time-code" /></label><div className="modal-actions"><button onClick={() => setMfaSetup(null)}>取消</button><button className="create" onClick={() => void enableMfa()}>驗證並啟用</button></div></section></div>}
      {mfaManage && <div className="modal-layer"><section className="modal"><button className="close" onClick={()=>setMfaManage(null)}>×</button><small>MFA SECURITY ACTION</small><h2>{mfaManage==="recovery"?"重新產生復原碼":"停用 MFA"}</h2>{newRecoveryCodes.length?<><p>舊復原碼已全部失效。新復原碼只顯示這一次，請離線保存。</p><div className="fingerprint"><code>{newRecoveryCodes.join("  ")}</code></div></>:<><p>此操作必須用目前動態碼或尚未使用的復原碼確認。</p><label>動態碼／復原碼<input data-private value={mfaCode} onChange={event=>setMfaCode(event.target.value)} autoComplete="one-time-code" /></label></>}<div className="modal-actions"><button onClick={()=>setMfaManage(null)}>關閉</button>{!newRecoveryCodes.length&&<button className={mfaManage==="disable"?"danger-action":"create"} onClick={()=>void manageMfa()}>確認</button>}</div></section></div>}
      {secretOpen&&<div className="modal-layer"><form className="modal" onSubmit={storeSecret}><button type="button" className="close" onClick={()=>{setSecretOpen(false);setEditingSecret(null)}}>×</button><small>AES-256-GCM SECRET VAULT</small><h2>{editingSecret?"輪替祕密":"新增祕密"}</h2><p>儲存後不會再顯示明文；輪替會增加版本，使用端需另行重新載入。</p><label>名稱<input name="name" pattern="[A-Za-z0-9._-]+" defaultValue={editingSecret?.name||""} readOnly={Boolean(editingSecret)} required /></label><label>用途<input name="purpose" defaultValue={editingSecret?.purpose||"identity-provider"} required /></label><label>新的祕密值<input data-private name="value" type="password" autoComplete="new-password" required /></label><div className="modal-actions"><button type="button" onClick={()=>{setSecretOpen(false);setEditingSecret(null)}}>取消</button><button className="create">確認儲存</button></div></form></div>}
    </section>
  );
}

function CardHead({
  eyebrow,
  title,
  action,
  onAction,
}: {
  eyebrow: string;
  title: string;
  action?: string;
  onAction?: () => void;
}) {
  return (
    <header className="card-head">
      <div>
        <small>{eyebrow}</small>
        <h2>{title}</h2>
      </div>
      {action && <button onClick={onAction}>{action} →</button>}
    </header>
  );
}

type AutomationJob = {
  jobType: "asset_inventory" | "patch_inventory" | "security_baseline";
  name: string; enabled: boolean; intervalHours: number; dueNow: boolean;
  lastStartedAt?: string | null; lastCompletedAt?: string | null; nextRunAt?: string | null;
};
type AutomationRun = {
  id: string; jobType: AutomationJob["jobType"]; triggerType: "scheduled" | "manual";
  status: "running" | "success" | "partial" | "failed"; requestedBy: string;
  totalHosts: number; succeededHosts: number; failedHosts: number;
  error?: string | null; startedAt: string; completedAt?: string | null; durationMs?: number | null;
};
type AutomationRunResult = {
  hostId: string; hostName: string; address: string; status: "success" | "failed";
  error?: string | null; checkedAt: string;
  snapshot?: AssetSnapshot; changes?: AssetChanges; snapshotSha256?: string | null;
  pendingCount?: number; securityCount?: number; cveCount?: number;
  riskSummary?: { high?: number; medium?: number; normal?: number }; rebootRequired?: boolean;
  securityPackages?: Array<{ name?: string; candidateVersion?: string; cves?: string[] }>;
  score?: number; checks?: BaselineCheck[];
};
type AutomationRunDetail = { run: AutomationRun; results: AutomationRunResult[] };

function AutomationCenter({ canManage, record }: {
  canManage: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [jobs, setJobs] = useState<AutomationJob[]>([]);
  const [runs, setRuns] = useState<AutomationRun[]>([]);
  const [running, setRunning] = useState("");
  const [detail, setDetail] = useState<AutomationRunDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    const response = await fetch("/api/automation", { cache: "no-store" });
    const body = (await response.json()) as { jobs?: AutomationJob[]; runs?: AutomationRun[]; detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取巡檢排程");
    setJobs(body.jobs ?? []); setRuns(body.runs ?? []);
  }, []);
  useEffect(() => {
    void load().catch(reason => setError(reason instanceof Error ? reason.message : "載入失敗"));
    const timer = window.setInterval(() => void load().catch(() => undefined), 10000);
    return () => window.clearInterval(timer);
  }, [load]);
  const runNow = async (job: AutomationJob) => {
    setRunning(job.jobType); setError("");
    record("automation.run", "立即執行巡檢工作", job.jobType, "requested");
    try {
      const response = await fetch(`/api/automation/${job.jobType}/run`, { method: "POST" });
      const body = (await response.json()) as { jobs?: AutomationJob[]; runs?: AutomationRun[]; detail?: string };
      if (!response.ok) throw new Error(body.detail || "巡檢執行失敗");
      setJobs(body.jobs ?? []); setRuns(body.runs ?? []);
      record("automation.run", "巡檢工作完成", job.jobType, "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "巡檢執行失敗";
      setError(message); record("automation.run", "巡檢工作失敗", job.jobType, "failure");
    } finally { setRunning(""); }
  };
  const openResult = async (run: AutomationRun) => {
    setDetailLoading(run.id); setError("");
    try {
      const response = await fetch(`/api/automation/runs/${run.id}`, { cache: "no-store" });
      const body = (await response.json()) as AutomationRunDetail & { detail?: string };
      if (!response.ok) throw new Error(body.detail || "無法讀取巡檢結果");
      setDetail(body);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "無法讀取巡檢結果"); }
    finally { setDetailLoading(""); }
  };
  const labels: Record<AutomationRun["jobType"], string> = { asset_inventory: "資產盤點", patch_inventory: "更新風險", security_baseline: "安全基準" };
  return <section className="automation-page">
    <div className="card automation-heading"><small>BACKGROUND INSPECTION OBSERVABILITY</small><h2>自動巡檢排程中心</h2><p>集中查看每次排程與手動巡檢的結果、主機成功率、耗時及下一次執行時間。</p></div>
    {error && <div className="card log-error">{error}</div>}
    <div className="automation-jobs">{jobs.map(job => {
      const active = runs.some(run => run.jobType === job.jobType && run.status === "running");
      return <article className="card automation-job" key={job.jobType}><header><div><small>{job.jobType.toUpperCase()}</small><h3>{job.name}</h3></div><span className={job.enabled ? "enabled" : "disabled"}>{job.enabled ? "已啟用" : "已停用"}</span></header><dl><div><dt>執行間隔</dt><dd>{job.intervalHours} 小時</dd></div><div><dt>上次完成</dt><dd>{job.lastCompletedAt ? new Date(job.lastCompletedAt).toLocaleString("zh-TW", { hour12: false }) : "尚未完成"}</dd></div><div><dt>下次執行</dt><dd>{job.dueNow ? "等待執行" : job.nextRunAt ? new Date(job.nextRunAt).toLocaleString("zh-TW", { hour12: false }) : "已停用"}</dd></div></dl>{canManage && <button className="create" disabled={Boolean(running) || active} onClick={() => void runNow(job)}>{running === job.jobType || active ? "執行中…" : "立即執行"}</button>}</article>;
    })}</div>
    <div className="card automation-history"><header className="alert-section-head"><div><small>LAST 50 RUNS</small><h2>巡檢執行紀錄</h2></div><button className="table-action" onClick={() => void load()}>重新整理</button></header><div className="data-table"><table><thead><tr><th>工作</th><th>觸發方式</th><th>狀態</th><th>主機結果</th><th>耗時</th><th>執行者</th><th>開始時間</th><th>操作</th></tr></thead><tbody>{runs.map(run => <tr key={run.id}><td><strong>{labels[run.jobType]}</strong>{run.error && <small>{run.error}</small>}</td><td>{run.triggerType === "scheduled" ? "系統排程" : "手動"}</td><td><span className={`automation-status ${run.status}`}>{run.status === "running" ? "執行中" : run.status === "success" ? "成功" : run.status === "partial" ? "部分失敗" : "失敗"}</span></td><td>{run.succeededHosts}/{run.totalHosts} 成功{run.failedHosts ? ` · ${run.failedHosts} 失敗` : ""}</td><td>{run.durationMs == null ? "—" : `${(run.durationMs / 1000).toFixed(1)} 秒`}</td><td>{run.requestedBy}</td><td>{new Date(run.startedAt).toLocaleString("zh-TW", { hour12: false })}</td><td><button className="table-action" disabled={detailLoading === run.id} onClick={() => void openResult(run)}>{detailLoading === run.id ? "讀取中…" : "查看結果"}</button></td></tr>)}</tbody></table></div>{!runs.length && <div className="empty-state"><strong>尚無巡檢執行紀錄</strong></div>}</div>
    {detail && <div className="modal-layer"><section className="modal automation-result-modal"><button className="close" onClick={() => setDetail(null)}>×</button><small>INSPECTION EVIDENCE</small><h2>{labels[detail.run.jobType]}結果</h2><p>{new Date(detail.run.startedAt).toLocaleString("zh-TW", { hour12: false })} · {detail.run.succeededHosts}/{detail.run.totalHosts} 台成功 · {detail.run.durationMs == null ? "尚未完成" : `${(detail.run.durationMs / 1000).toFixed(1)} 秒`}</p><div className="automation-result-hosts">{detail.results.map(result => <article key={result.hostId} className={result.status}><header><div><strong>{result.hostName}</strong><small>{result.address}</small></div><span>{result.status === "success" ? "成功" : "失敗"}</span></header>{result.error ? <p className="result-error">{result.error}</p> : detail.run.jobType === "asset_inventory" ? <><div className="result-kpis"><span><strong>{result.snapshot?.listeningPorts?.length || 0}</strong>監聽項目</span><span><strong>{result.snapshot?.enabledServices?.length || 0}</strong>啟用服務</span><span><strong>{result.snapshot?.interactiveUsers?.length || 0}</strong>互動帳號</span></div><div className={result.changes?.changed ? "result-change changed" : "result-change stable"}>{result.changes?.baseline ? "已建立第一份基準快照" : result.changes?.changed ? `偵測到 ${Object.keys(result.changes.fields || {}).length} 類資產變更：${Object.keys(result.changes.fields || {}).join("、")}` : "與上一份快照相比沒有漂移"}</div>{result.snapshotSha256 && <code>SHA-256 {result.snapshotSha256}</code>}</> : detail.run.jobType === "patch_inventory" ? <><div className="result-kpis"><span><strong>{result.pendingCount || 0}</strong>待更新</span><span><strong>{result.securityCount || 0}</strong>安全更新</span><span><strong>{result.cveCount || 0}</strong>相關 CVE</span></div>{result.rebootRequired && <div className="result-change changed">需要重新開機</div>}<div className="result-list">{result.securityPackages?.slice(0, 20).map(pkg => <div key={`${pkg.name}-${pkg.candidateVersion}`}><strong>{pkg.name}</strong><small>{pkg.candidateVersion} · {pkg.cves?.join("、") || "未取得 CVE"}</small></div>)}{!result.securityPackages?.length && <small>沒有辨識到安全更新套件</small>}</div></> : <><div className="result-kpis"><span><strong>{result.score ?? 0}</strong>安全分數</span><span><strong>{result.checks?.filter(item => item.status === "fail").length || 0}</strong>未通過</span><span><strong>{result.checks?.filter(item => item.status === "warn").length || 0}</strong>提醒</span></div><div className="result-list">{result.checks?.filter(item => item.status !== "pass").map(check => <div key={check.key}><strong>{check.status === "fail" ? "×" : "!"} {check.label}</strong><small>{check.evidence}</small>{check.recommendation && <small>{check.recommendation}</small>}</div>)}{!result.checks?.some(item => item.status !== "pass") && <small>所有基準項目均通過</small>}</div></>}</article>)}</div>{!detail.results.length && <div className="empty-state"><strong>這次執行尚未產生主機結果</strong><small>{detail.run.error || "工作可能仍在執行中。"}</small></div>}<div className="modal-actions"><button onClick={() => setDetail(null)}>關閉</button></div></section></div>}
  </section>;
}

type AssetSnapshot = {
  hostname?: string; osName?: string; kernelVersion?: string;
  interfaces?: string[]; listeningPorts?: string[]; enabledServices?: string[];
  interactiveUsers?: string[]; installedPackageCount?: number;
};
type AssetChanges = {
  baseline?: boolean; changed?: boolean;
  fields?: Record<string, { added?: string[]; removed?: string[]; before?: unknown; after?: unknown }>;
};
type AssetHost = {
  hostId: string; hostName: string; address: string; scanId?: string | null;
  status: "success" | "failed" | "never"; snapshot: AssetSnapshot; changes: AssetChanges;
  snapshotSha256?: string | null; error?: string | null; checkedBy?: string | null;
  checkedAt?: string | null; historyCount: number;
};
type AssetPolicy = {
  enabled: boolean; intervalHours: number; notifyDrift: boolean;
  lastStartedAt?: string | null; lastCompletedAt?: string | null; updatedAt?: string | null;
};

function AssetInventory({ canManage, record }: {
  canManage: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [hosts, setHosts] = useState<AssetHost[]>([]);
  const [policy, setPolicy] = useState<AssetPolicy | null>(null);
  const [policyOpen, setPolicyOpen] = useState(false);
  const [scanning, setScanning] = useState("");
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    const response = await fetch("/api/asset-inventory", { cache: "no-store" });
    const body = (await response.json()) as { hosts?: AssetHost[]; policy?: AssetPolicy; detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取資產盤點");
    setHosts(body.hosts ?? []);
    setPolicy(body.policy ?? null);
  }, []);
  useEffect(() => { void load().catch(reason => setError(reason instanceof Error ? reason.message : "載入失敗")); }, [load]);
  const scan = async (hostId?: string) => {
    setScanning(hostId || "all"); setError("");
    record("assets.scan", hostId ? "執行單一主機資產盤點" : "執行全部主機資產盤點", hostId, "requested");
    try {
      const response = await fetch("/api/asset-inventory/scan", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hostId: hostId || null }) });
      const body = (await response.json()) as { hosts?: AssetHost[]; policy?: AssetPolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "資產盤點失敗");
      setHosts(body.hosts ?? []); setPolicy(body.policy ?? policy); record("assets.scan", "資產盤點完成", hostId, "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "資產盤點失敗";
      setError(message); record("assets.scan", "資產盤點失敗", hostId, "failure");
    } finally { setScanning(""); }
  };
  const savePolicy = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError("");
    const form = new FormData(event.currentTarget);
    const payload = { enabled: form.get("enabled") === "on", intervalHours: Number(form.get("intervalHours")), notifyDrift: form.get("notifyDrift") === "on" };
    try {
      const response = await fetch("/api/asset-inventory/policy", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const body = (await response.json()) as { policy?: AssetPolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "盤點政策儲存失敗");
      setPolicy(body.policy ?? null); setPolicyOpen(false);
      record("assets.policy.update", "更新資產自動盤點政策", "asset-inventory", "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "盤點政策儲存失敗";
      setError(message); record("assets.policy.update", "更新資產自動盤點政策", "asset-inventory", "failure");
    }
  };
  const fieldNames: Record<string, string> = { interfaces: "網路介面", listeningPorts: "監聽連接埠", enabledServices: "啟用服務", interactiveUsers: "互動式帳號", hostname: "主機名稱", osName: "作業系統", kernelVersion: "Kernel", installedPackageCount: "套件數量" };
  return <section className="assets-page">
    <div className="card asset-heading"><div><small>READ-ONLY ASSET & DRIFT INVENTORY</small><h2>主機資產盤點</h2><p>保存唯讀 SSH 快照，並比較監聽連接埠、啟用服務、互動式帳號與系統版本的變化。</p>{policy && <span className={`asset-policy-state ${policy.enabled ? "enabled" : "disabled"}`}>自動盤點：{policy.enabled ? `啟用 · 每 ${policy.intervalHours} 小時` : "停用"}{policy.lastCompletedAt ? ` · 上次完成 ${new Date(policy.lastCompletedAt).toLocaleString("zh-TW", { hour12: false })}` : " · 尚未完成排程盤點"}</span>}</div>{canManage && <div className="asset-heading-actions"><button onClick={() => setPolicyOpen(true)}>盤點政策</button><button className="create" onClick={() => void scan()} disabled={Boolean(scanning)}>{scanning === "all" ? "盤點中…" : "盤點全部主機"}</button></div>}</div>
    {error && <div className="card log-error">{error}</div>}
    <div className="asset-hosts">{hosts.map(host => {
      const snapshot = host.snapshot || {}; const fields = host.changes?.fields || {}; const changeCount = Object.keys(fields).length;
      return <article className="card asset-host" key={host.hostId}>
        <header><div><small>{host.address}</small><h3>{host.hostName}</h3></div><div className="asset-actions"><span className={`asset-state ${host.status} ${host.changes?.changed ? "changed" : ""}`}>{host.status === "failed" ? "失敗" : host.status === "never" ? "未盤點" : host.changes?.baseline ? "基準快照" : host.changes?.changed ? `${changeCount} 類變更` : "無漂移"}</span>{canManage && <button className="table-action" onClick={() => void scan(host.hostId)} disabled={Boolean(scanning)}>{scanning === host.hostId ? "盤點中…" : "重新盤點"}</button>}</div></header>
        {host.status === "success" ? <><div className="asset-facts"><span><small>OS</small><strong>{snapshot.osName || "—"}</strong></span><span><small>Kernel</small><strong>{snapshot.kernelVersion || "—"}</strong></span><span><small>監聽項目</small><strong>{snapshot.listeningPorts?.length || 0}</strong></span><span><small>啟用服務</small><strong>{snapshot.enabledServices?.length || 0}</strong></span><span><small>互動帳號</small><strong>{snapshot.interactiveUsers?.length || 0}</strong></span><span><small>已安裝套件</small><strong>{snapshot.installedPackageCount || 0}</strong></span></div>
          {host.changes?.baseline ? <div className="asset-baseline">第一份快照已保存；下一次盤點開始比較漂移。</div> : host.changes?.changed ? <div className="asset-drift"><strong>偵測到設定漂移</strong>{Object.entries(fields).map(([key, value]) => <div key={key}><span>{fieldNames[key] || key}</span>{value.added?.map(item => <code className="added" key={`a-${item}`}>＋ {item}</code>)}{value.removed?.map(item => <code className="removed" key={`r-${item}`}>－ {item}</code>)}{"before" in value && <code>{String(value.before ?? "—")} → {String(value.after ?? "—")}</code>}</div>)}</div> : <div className="asset-stable">✓ 與上一份成功快照相比沒有漂移</div>}
          <div className="asset-details">{(["interfaces", "listeningPorts", "enabledServices", "interactiveUsers"] as const).map(key => <details key={key}><summary>{fieldNames[key]}（{snapshot[key]?.length || 0}）</summary><pre>{snapshot[key]?.join("\n") || "—"}</pre></details>)}</div>
          <footer>快照 {host.historyCount} 份 · {host.checkedBy || "系統"} · {host.checkedAt ? new Date(host.checkedAt).toLocaleString("zh-TW", { hour12: false }) : "—"}{host.snapshotSha256 && <code>SHA-256 {host.snapshotSha256}</code>}</footer></> : <div className="empty-state"><strong>{host.status === "failed" ? "資產盤點失敗" : "尚未建立資產快照"}</strong><small>{host.error || "按下重新盤點後，中央只會執行唯讀查詢。"}</small></div>}
      </article>;
    })}</div>
    {policyOpen && policy && <div className="modal-layer"><form className="modal asset-policy-modal" onSubmit={savePolicy}><button type="button" className="close" onClick={() => setPolicyOpen(false)}>×</button><small>AUTOMATIC ASSET INVENTORY</small><h2>自動盤點與漂移告警</h2><p>中央會依排程透過唯讀 SSH 建立快照。偵測到新變更時會建立告警，並可使用既有通知管道發送。</p><label className="inline-check"><input name="enabled" type="checkbox" defaultChecked={policy.enabled} /><span>啟用定期自動盤點</span></label><label>盤點間隔（小時）<input name="intervalHours" type="number" min="1" max="168" defaultValue={policy.intervalHours} required /><small>可設定 1–168 小時</small></label><label className="inline-check"><input name="notifyDrift" type="checkbox" defaultChecked={policy.notifyDrift} /><span>偵測到漂移時發送通知</span></label><div className="modal-actions"><button type="button" onClick={() => setPolicyOpen(false)}>取消</button><button className="create">儲存政策</button></div></form></div>}
  </section>;
}

type PatchHost = {
  hostId: string; hostName: string; address: string;
  status: "success" | "failed" | "never";
  kernelVersion?: string | null; rebootRequired: boolean;
  rebootPackages: string[]; unattendedUpgrades?: string | null;
  pendingCount: number; osCodename?: string | null; securityCount: number; cveCount: number;
  riskSummary: { high?: number; medium?: number; normal?: number };
  securitySourceStatus?: string | null;
  packages: Array<{
    name: string; currentVersion: string; candidateVersion: string; architecture: string;
    isSecurity?: boolean; risk?: "high" | "medium" | "normal";
    cves?: string[]; notices?: string[]; securityPockets?: string[];
  }>;
  truncated: boolean; error?: string | null; checkedBy?: string | null; checkedAt?: string | null;
};
type PatchPolicy = {
  enabled: boolean; intervalHours: number; securityThreshold: number;
  notifySecurityUpdates: boolean; lastStartedAt?: string | null; lastCompletedAt?: string | null;
};

function PatchInventory({
  canManage,
  record,
}: {
  canManage: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [hosts, setHosts] = useState<PatchHost[]>([]);
  const [policy, setPolicy] = useState<PatchPolicy | null>(null);
  const [policyOpen, setPolicyOpen] = useState(false);
  const [scanning, setScanning] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const response = await fetch("/api/patch-inventory", { cache: "no-store" });
    const body = (await response.json()) as { hosts?: PatchHost[]; policy?: PatchPolicy; detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取更新盤點");
    setHosts(body.hosts ?? []);
    setPolicy(body.policy ?? null);
  }, []);

  useEffect(() => { void load().catch((reason) => setError(reason instanceof Error ? reason.message : "載入失敗")); }, [load]);

  const scan = async (hostId?: string) => {
    const target = hostId || "all";
    setScanning(target); setError("");
    record("patch.scan", hostId ? "執行單一主機更新盤點" : "執行全部主機更新盤點", hostId, "requested");
    try {
      const response = await fetch("/api/patch-inventory/scan", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ hostId: hostId || null }),
      });
      const body = (await response.json()) as { hosts?: PatchHost[]; policy?: PatchPolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "更新盤點失敗");
      setHosts(body.hosts ?? []);
      setPolicy(body.policy ?? policy);
      record("patch.scan", "更新盤點完成", hostId, "success");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "更新盤點失敗");
      record("patch.scan", "更新盤點失敗", hostId, "failure");
    } finally { setScanning(""); }
  };

  const savePolicy = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError("");
    const form = new FormData(event.currentTarget);
    const payload = { enabled: form.get("enabled") === "on", intervalHours: Number(form.get("intervalHours")), securityThreshold: Number(form.get("securityThreshold")), notifySecurityUpdates: form.get("notifySecurityUpdates") === "on" };
    try {
      const response = await fetch("/api/patch-inventory/policy", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const body = (await response.json()) as { policy?: PatchPolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "更新盤點政策儲存失敗");
      setPolicy(body.policy ?? null); setPolicyOpen(false);
      record("patch.policy.update", "更新自動安全更新盤點政策", "patch-inventory", "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "更新盤點政策儲存失敗";
      setError(message); record("patch.policy.update", "更新自動安全更新盤點政策", "patch-inventory", "failure");
    }
  };

  const totalPending = hosts.reduce((sum, host) => sum + host.pendingCount, 0);
  const totalSecurity = hosts.reduce((sum, host) => sum + (host.securityCount || 0), 0);
  const totalCves = hosts.reduce((sum, host) => sum + (host.cveCount || 0), 0);
  const highRisk = hosts.reduce((sum, host) => sum + (host.riskSummary?.high || 0), 0);
  const rebootCount = hosts.filter((host) => host.rebootRequired).length;

  return (
    <section className="patch-page">
      <div className="card patch-heading">
        <div className="page-heading"><div><small>APT + CANONICAL SECURITY INTELLIGENCE</small><h2>Linux 更新與 CVE 風險</h2><p>以現有 APT 索引辨識更新，再用 Canonical 公告補上 USN、CVE 與維運優先級；全程不安裝套件。</p>{policy && <span className={`patch-policy-state ${policy.enabled ? "enabled" : "disabled"}`}>自動盤點：{policy.enabled ? `啟用 · 每 ${policy.intervalHours} 小時 · ${policy.securityThreshold} 項安全更新觸發告警` : "停用"}{policy.lastCompletedAt ? ` · 上次完成 ${new Date(policy.lastCompletedAt).toLocaleString("zh-TW", { hour12: false })}` : ""}</span>}</div>{canManage && <div className="patch-heading-actions"><button onClick={() => setPolicyOpen(true)}>更新政策</button><button className="create" onClick={() => void scan()} disabled={Boolean(scanning)}>{scanning === "all" ? "全部盤點中…" : "盤點全部主機"}</button></div>}</div>
        {error && <div className="log-error">{error}</div>}
        <div className="patch-summary security-risk-summary"><span><strong>{totalPending}</strong>待更新套件</span><span><strong className={totalSecurity ? "warn" : "ok"}>{totalSecurity}</strong>安全更新</span><span><strong className={highRisk ? "danger" : "ok"}>{highRisk}</strong>高優先級</span><span><strong>{totalCves}</strong>相關 CVE</span><span><strong className={rebootCount ? "warn" : "ok"}>{rebootCount}</strong>需重新開機</span></div>
      </div>

      <div className="patch-hosts">
        {hosts.map((host) => (
          <article className="card patch-host" key={host.hostId}>
            <header><div><small>{host.address}</small><h3>{host.hostName}</h3></div><div className="patch-actions"><span className={`patch-state ${host.status}`}>{host.status === "success" ? "已盤點" : host.status === "failed" ? "失敗" : "尚未盤點"}</span>{canManage && <button className="table-action" onClick={() => void scan(host.hostId)} disabled={Boolean(scanning)}>{scanning === host.hostId ? "盤點中…" : "重新盤點"}</button>}</div></header>
            {host.status === "success" ? <><div className="patch-facts security-facts"><span><small>Kernel</small><strong>{host.kernelVersion}</strong></span><span><small>安全更新</small><strong className={host.securityCount ? "danger" : "ok"}>{host.securityCount || 0} 項</strong></span><span><small>相關 CVE</small><strong>{host.cveCount || 0}</strong></span><span><small>重新開機</small><strong className={host.rebootRequired ? "danger" : "ok"}>{host.rebootRequired ? "需要" : "不需要"}</strong></span></div><div className={`security-source ${host.securitySourceStatus?.startsWith("canonical") ? "complete" : "partial"}`}><strong>{host.securitySourceStatus?.startsWith("canonical") ? "Canonical 公告比對完成" : "CVE 資料未完成"}</strong><span>{host.securitySourceStatus?.startsWith("canonical") ? `${host.osCodename || "Ubuntu"} · 維運優先級不是 CVSS 分數。` : "目前只使用主機上的 APT／Ubuntu Pro 資訊，不會把缺少的 CVE 誤判為零風險。"}</span></div>{host.rebootPackages.length > 0 && <div className="reboot-packages"><strong>觸發重新開機的套件</strong><span>{host.rebootPackages.join("、")}</span></div>}<details open={Boolean(host.securityCount)}><summary>查看待更新套件（{host.packages.length}{host.truncated ? "+" : ""}）</summary><div className="data-table security-package-table"><table><thead><tr><th>優先級</th><th>套件</th><th>版本</th><th>安全情報</th></tr></thead><tbody>{host.packages.map((pkg) => <tr key={`${pkg.name}-${pkg.architecture}`}><td><span className={`package-risk ${pkg.risk || "normal"}`}>{pkg.risk === "high" ? "高" : pkg.risk === "medium" ? "中" : "一般"}</span></td><td><strong>{pkg.name}</strong><small>{pkg.architecture || "—"}</small></td><td><code>{pkg.currentVersion || "—"}</code><small>→ {pkg.candidateVersion || "—"}</small></td><td>{pkg.isSecurity ? <><strong className="security-update-label">安全更新</strong><small>{pkg.notices?.join("、") || pkg.securityPockets?.join("、") || "APT Security"}</small><div className="cve-list">{pkg.cves?.slice(0, 8).map((cve) => <a key={cve} href={`https://ubuntu.com/security/${cve}`} target="_blank" rel="noreferrer">{cve}</a>)}{(pkg.cves?.length || 0) > 8 && <span>＋{(pkg.cves?.length || 0) - 8}</span>}</div></> : <span className="regular-update-label">一般更新</span>}</td></tr>)}</tbody></table></div>{!host.packages.length && <div className="empty-state"><strong>目前沒有待更新套件</strong></div>}</details><footer>盤點者：{host.checkedBy || "系統"} · {host.checkedAt ? new Date(host.checkedAt).toLocaleString("zh-TW", { hour12: false }) : "—"}</footer></> : <div className="empty-state"><strong>{host.status === "failed" ? "無法完成更新盤點" : "尚未取得更新狀態"}</strong><small>{host.error || "按下重新盤點後，中央會透過 SSH 執行唯讀查詢。"}</small></div>}
          </article>
        ))}
      </div>
      {!hosts.length && <div className="card empty-state page-empty"><strong>目前沒有受管主機</strong></div>}
      {policyOpen && policy && <div className="modal-layer"><form className="modal patch-policy-modal" onSubmit={savePolicy}><button type="button" className="close" onClick={() => setPolicyOpen(false)}>×</button><small>AUTOMATIC PATCH RISK INVENTORY</small><h2>自動更新風險盤點</h2><p>中央只讀取 APT 與 Canonical 安全資訊，不會安裝套件。達到門檻時會建立告警並沿用現有通知管道。</p><label className="inline-check"><input name="enabled" type="checkbox" defaultChecked={policy.enabled} /><span>啟用定期自動盤點</span></label><label>盤點間隔（小時）<input name="intervalHours" type="number" min="1" max="168" defaultValue={policy.intervalHours} required /></label><label>安全更新告警門檻<input name="securityThreshold" type="number" min="1" max="1000" defaultValue={policy.securityThreshold} required /><small>單台主機達到此數量就建立告警</small></label><label className="inline-check"><input name="notifySecurityUpdates" type="checkbox" defaultChecked={policy.notifySecurityUpdates} /><span>告警發生與恢復時發送通知</span></label><div className="modal-actions"><button type="button" onClick={() => setPolicyOpen(false)}>取消</button><button className="create">儲存政策</button></div></form></div>}
    </section>
  );
}

type BaselineCheck = {
  key: string; label: string; status: "pass" | "warn" | "fail";
  evidence: string; recommendation: string;
};
type BaselineHistory = {
  scanId: string; status: "success" | "failed"; score: number;
  checks: BaselineCheck[]; error?: string | null; checkedBy?: string | null; checkedAt: string;
};
type BaselineComparison = {
  previousAt: string; scoreDelta: number; improved: number; regressed: number;
  changes: Array<{ key: string; label: string; from: BaselineCheck["status"]; to: BaselineCheck["status"]; direction: "improved" | "regressed" }>;
};
type BaselineHost = {
  hostId: string; hostName: string; address: string;
  status: "success" | "failed" | "never"; score: number;
  checks: BaselineCheck[]; error?: string | null; checkedBy?: string | null; checkedAt?: string | null;
  history: BaselineHistory[]; comparison?: BaselineComparison | null;
};
type BaselinePolicy = {
  enabled: boolean; intervalHours: number; minimumScore: number; notifyRegression: boolean;
  lastStartedAt?: string | null; lastCompletedAt?: string | null;
};

function BaselineTrend({ host }: { host: BaselineHost }) {
  const successful = (host.history || []).filter((item) => item.status === "success");
  const comparison = host.comparison;
  return <div className="baseline-trend">
    <header><div><small>LAST 12 SCANS</small><strong>安全分數趨勢</strong></div>{comparison ? <span className={comparison.scoreDelta > 0 ? "improved" : comparison.scoreDelta < 0 ? "regressed" : "stable"}>{comparison.scoreDelta > 0 ? "+" : ""}{comparison.scoreDelta} 分</span> : <span className="stable">建立基準中</span>}</header>
    <div className="baseline-bars">{successful.map((scan) => <div key={scan.scanId} title={`${new Date(scan.checkedAt).toLocaleString("zh-TW", { hour12: false })} · ${scan.score} 分`}><i style={{ height: `${Math.max(4, scan.score)}%` }} className={scan.score >= 80 ? "good" : scan.score >= 60 ? "medium" : "poor"} /><small>{scan.score}</small></div>)}</div>
    {comparison ? <div className="baseline-diff"><span className="improved">改善 {comparison.improved}</span><span className="regressed">退步 {comparison.regressed}</span>{comparison.changes.slice(0, 4).map((change) => <small key={change.key}>{change.label}：{change.from} → {change.to}</small>)}{!comparison.changes.length && <small>與上一次相比，檢查結果沒有變化。</small>}</div> : <p>至少完成兩次檢查後，才會顯示前後差異。</p>}
  </div>;
}

function SecurityBaselines({
  canManage,
  record,
}: {
  canManage: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [hosts, setHosts] = useState<BaselineHost[]>([]);
  const [policy, setPolicy] = useState<BaselinePolicy | null>(null);
  const [policyOpen, setPolicyOpen] = useState(false);
  const [scanning, setScanning] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const response = await fetch("/api/security-baselines", { cache: "no-store" });
    const body = (await response.json()) as { hosts?: BaselineHost[]; policy?: BaselinePolicy; detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取安全基準");
    setHosts(body.hosts ?? []);
    setPolicy(body.policy ?? null);
  }, []);
  useEffect(() => { void load().catch((reason) => setError(reason instanceof Error ? reason.message : "載入失敗")); }, [load]);

  const scan = async (hostId?: string) => {
    setScanning(hostId || "all"); setError("");
    record("security.baseline.scan", hostId ? "執行單一主機安全基準盤點" : "執行全部主機安全基準盤點", hostId, "requested");
    try {
      const response = await fetch("/api/security-baselines/scan", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ hostId: hostId || null }),
      });
      const body = (await response.json()) as { hosts?: BaselineHost[]; policy?: BaselinePolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "安全基準盤點失敗");
      setHosts(body.hosts ?? []);
      setPolicy(body.policy ?? policy);
      record("security.baseline.scan", "安全基準盤點完成", hostId, "success");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "安全基準盤點失敗");
      record("security.baseline.scan", "安全基準盤點失敗", hostId, "failure");
    } finally { setScanning(""); }
  };

  const savePolicy = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError("");
    const form = new FormData(event.currentTarget);
    const payload = { enabled: form.get("enabled") === "on", intervalHours: Number(form.get("intervalHours")), minimumScore: Number(form.get("minimumScore")), notifyRegression: form.get("notifyRegression") === "on" };
    try {
      const response = await fetch("/api/security-baselines/policy", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const body = (await response.json()) as { policy?: BaselinePolicy; detail?: string };
      if (!response.ok) throw new Error(body.detail || "安全基準政策儲存失敗");
      setPolicy(body.policy ?? null); setPolicyOpen(false);
      record("security.baseline.policy.update", "更新自動安全基準政策", "security-baseline", "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "安全基準政策儲存失敗";
      setError(message); record("security.baseline.policy.update", "更新自動安全基準政策", "security-baseline", "failure");
    }
  };

  const completed = hosts.filter((host) => host.status === "success");
  const averageScore = completed.length ? Math.round(completed.reduce((sum, host) => sum + host.score, 0) / completed.length) : 0;
  const failedChecks = completed.reduce((sum, host) => sum + host.checks.filter((item) => item.status === "fail").length, 0);
  const warningChecks = completed.reduce((sum, host) => sum + host.checks.filter((item) => item.status === "warn").length, 0);

  return <section className="baseline-page">
    <div className="card baseline-heading"><div className="page-heading"><div><small>READ-ONLY LINUX SECURITY BASELINE</small><h2>Linux 主機安全基準</h2><p>檢查常見 Linux 防護設定並保存證據；這是實驗室基線，不代表完整 CIS 認證。</p>{policy && <span className={`baseline-policy-state ${policy.enabled ? "enabled" : "disabled"}`}>自動檢查：{policy.enabled ? `啟用 · 每 ${policy.intervalHours} 小時 · 最低 ${policy.minimumScore} 分` : "停用"}{policy.lastCompletedAt ? ` · 上次完成 ${new Date(policy.lastCompletedAt).toLocaleString("zh-TW", { hour12: false })}` : ""}</span>}</div>{canManage && <div className="baseline-heading-actions"><button onClick={() => setPolicyOpen(true)}>基準政策</button><button className="create" onClick={() => void scan()} disabled={Boolean(scanning)}>{scanning === "all" ? "全部檢查中…" : "檢查全部主機"}</button></div>}</div>{error && <div className="log-error">{error}</div>}<div className="baseline-summary"><span><strong>{averageScore}</strong>平均分數</span><span><strong>{completed.length}</strong>已完成主機</span><span><strong className={warningChecks ? "warn" : "ok"}>{warningChecks}</strong>提醒項目</span><span><strong className={failedChecks ? "danger" : "ok"}>{failedChecks}</strong>未通過項目</span></div></div>
    <div className="baseline-hosts">{hosts.map((host) => <article className="card baseline-host" key={host.hostId}><header><div><small>{host.address}</small><h3>{host.hostName}</h3></div><div className="baseline-actions"><span className={`baseline-score ${host.score >= 80 ? "good" : host.score >= 60 ? "medium" : "poor"}`}>{host.status === "success" ? `${host.score} 分` : host.status === "failed" ? "失敗" : "未檢查"}</span>{canManage && <button className="table-action" onClick={() => void scan(host.hostId)} disabled={Boolean(scanning)}>{scanning === host.hostId ? "檢查中…" : "重新檢查"}</button>}</div></header>{host.status === "success" ? <><BaselineTrend host={host} /><div className="baseline-checks">{host.checks.map((check) => <div className={check.status} key={check.key}><span>{check.status === "pass" ? "✓" : check.status === "warn" ? "!" : "×"}</span><div><strong>{check.label}</strong><small>{check.evidence}</small>{check.recommendation && <p>{check.recommendation}</p>}</div></div>)}</div><footer>檢查者：{host.checkedBy || "系統"} · {host.checkedAt ? new Date(host.checkedAt).toLocaleString("zh-TW", { hour12: false }) : "—"}</footer></> : <div className="empty-state"><strong>{host.status === "failed" ? "安全基準檢查失敗" : "尚未執行安全基準檢查"}</strong><small>{host.error || "此檢查只讀取設定與服務狀態，不會修改主機。"}</small></div>}</article>)}</div>
    {policyOpen && policy && <div className="modal-layer"><form className="modal baseline-policy-modal" onSubmit={savePolicy}><button type="button" className="close" onClick={() => setPolicyOpen(false)}>×</button><small>AUTOMATIC SECURITY BASELINE</small><h2>自動安全基準政策</h2><p>定期執行唯讀安全檢查。分數低於門檻或檢查項目退步時建立告警，不會自動修改 Linux 設定。</p><label className="inline-check"><input name="enabled" type="checkbox" defaultChecked={policy.enabled} /><span>啟用定期自動檢查</span></label><label>檢查間隔（小時）<input name="intervalHours" type="number" min="1" max="168" defaultValue={policy.intervalHours} required /></label><label>最低安全分數<input name="minimumScore" type="number" min="0" max="100" defaultValue={policy.minimumScore} required /></label><label className="inline-check"><input name="notifyRegression" type="checkbox" defaultChecked={policy.notifyRegression} /><span>低於門檻、項目退步與恢復時發送通知</span></label><div className="modal-actions"><button type="button" onClick={() => setPolicyOpen(false)}>取消</button><button className="create">儲存政策</button></div></form></div>}
  </section>;
}

function Hosts({
  rows,
  openLogs,
  openTerminal,
  removeHost,
  onAdd,
  canManage,
  canTerminal,
}: {
  rows: HostRow[];
  openLogs: (hostId: string) => void;
  openTerminal: (host: HostRow) => void;
  removeHost: (host: HostRow) => void;
  onAdd: () => void;
  canManage: boolean;
  canTerminal: boolean;
}) {
  const healthy = rows.filter((host) => host.state === "healthy").length;
  return (
    <section className="card page-card">
      <div className="page-heading">
        <div>
          <small>LIVE SSH PROBES</small>
          <h2>受管 Linux 主機</h2>
          <p>可以自動建立 linux-agent，或加入已完成金鑰設定的主機。</p>
        </div>
        {canManage && (
          <button className="create" onClick={onAdd}>
            ＋ 新增主機
          </button>
        )}
      </div>
      <div className="toolbar">
        <div className="tabs">
          <button className="selected">全部 {rows.length}</button>
          <button>正常 {healthy}</button>
          <button>異常 {rows.length - healthy}</button>
        </div>
        <small>資料每 10 秒更新</small>
      </div>
      <div className="data-table">
        <table>
          <thead>
            <tr>
              <th>主機</th>
              <th>作業系統</th>
              <th>CPU</th>
              <th>RAM</th>
              <th>DISK</th>
              <th>UPTIME</th>
              <th>失敗服務</th>
              <th>狀態</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((host) => (
              <tr key={host.id}>
                <td>
                  <strong>{host.name}</strong>
                  <small>{host.ip}</small>
                </td>
                <td>{host.os}</td>
                <td>
                  <MetricBar value={host.cpu} />
                  {host.cpu}%
                </td>
                <td>
                  <MetricBar value={host.ram} />
                  {host.ram}%
                </td>
                <td>
                  <MetricBar value={host.disk} />
                  {host.disk}%
                </td>
                <td>{formatUptime(host.uptimeSeconds)}</td>
                <td>{host.failedServices?.length ?? 0}</td>
                <td>
                  <State value={host.state} />
                </td>
                <td>
                  <span className="row-actions">
                    <button
                      className="table-action"
                      data-target={host.name}
                      onClick={() => openLogs(host.id)}
                    >
                      查日誌
                    </button>
                    {canTerminal && (
                      <button
                        className="table-action console-action"
                        data-target={host.name}
                        onClick={() => openTerminal(host)}
                      >
                        SSH 終端
                      </button>
                    )}
                    {canManage && (
                      <button
                        className="table-action danger-action"
                        data-target={host.name}
                        onClick={() => removeHost(host)}
                      >
                        刪除
                      </button>
                    )}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 && (
        <div className="empty-state page-empty">
          <strong>沒有符合搜尋條件的主機</strong>
        </div>
      )}
    </section>
  );
}

type CentralLogEvent={id:number;hostId:string;hostName:string;occurredAt?:string|null;priority:string;unit?:string|null;identifier?:string|null;processId?:string|null;transport?:string|null;message:string};
type CentralLogStatus={policy:{retentionDays:number;intervalSeconds:number;failureThreshold:number};totalEvents:number;oldestAt?:string|null;newestAt?:string|null;units:string[];hosts:Array<{hostId:string;hostName:string;address:string;lastAttemptAt?:string|null;lastSuccessAt?:string|null;lastEventAt?:string|null;lastEventCount:number;consecutiveFailures:number;lastError?:string|null;storedEvents:number}>};

function Logs({
  hosts,
  initialHost,
  record,
}: {
  hosts: HostRow[];
  initialHost: string;
  record: (
    type: string,
    action: string,
    target?: string,
    result?: string,
  ) => void;
}) {
  const [hostId, setHostId] = useState(initialHost);
  const [priority,setPriority]=useState("warning");
  const [limit,setLimit]=useState("200");
  const [lines, setLines] = useState<string[]>([]);
  const [events,setEvents]=useState<CentralLogEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [source, setSource] = useState<"live" | "central">("central");
  const [unit,setUnit]=useState(""); const [queryText,setQueryText]=useState("");
  const [fromAt,setFromAt]=useState(""); const [toAt,setToAt]=useState("");
  const [status,setStatus]=useState<CentralLogStatus|null>(null); const [policyOpen,setPolicyOpen]=useState(false);

  const loadStatus=useCallback(async()=>{const response=await fetch("/api/logs/status",{cache:"no-store"});const body=await response.json();if(!response.ok)throw new Error(body.detail||"無法取得集中日誌狀態");setStatus(body);},[]);
  useEffect(()=>{void loadStatus().catch(reason=>setError(reason instanceof Error?reason.message:"狀態載入失敗"));},[loadStatus]);

  useEffect(() => {
    setHostId(initialHost);
  }, [initialHost]);
  useEffect(() => {
    if (hosts.length && hostId!=="all" && !hosts.some((host) => host.id === hostId))
      setHostId(hosts[0].id);
  }, [hostId, hosts]);

  const query = async (event: FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    record(
      "logs.query",
      `查詢 ${priority} 日誌`,
      `${hostId}:${limit}`,
      "requested",
    );
    try {
      const params=new URLSearchParams({priority,limit});
      let endpoint="";
      if(source==="central"){
        params.set("hostId",hostId||"all"); if(unit)params.set("unit",unit); if(queryText)params.set("q",queryText);
        if(fromAt)params.set("from",new Date(fromAt).toISOString());if(toAt)params.set("to",new Date(toAt).toISOString());endpoint=`/api/logs/search?${params}`;
      }else endpoint=`/api/hosts/${encodeURIComponent(hostId)}/logs?${params}&source=live`;
      const response = await fetch(endpoint,{ cache: "no-store" });
      const payload = (await response.json()) as {
        lines?: string[];
        events?:CentralLogEvent[];
        detail?: string;
      };
      if (!response.ok) throw new Error(payload.detail || "日誌查詢失敗");
      setLines(payload.lines ?? []);
      setEvents(payload.events??[]);
      record(
        "logs.query.complete",
        `取得 ${payload.events?.length ?? payload.lines?.length ?? 0} 行日誌`,
        hostId,
        "success",
      );
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "日誌查詢失敗";
      setError(message);
      record("logs.query.complete", "日誌查詢失敗", hostId, "failure");
    } finally {
      setLoading(false);
    }
  };
  const collect=async()=>{setLoading(true);setError("");const controller=new AbortController();const timer=window.setTimeout(()=>controller.abort(),40_000);try{const response=await fetch("/api/logs/collect",{method:"POST",signal:controller.signal});const body=await response.json();if(!response.ok)throw new Error(body.detail||"採集失敗");await loadStatus();}catch(reason){setError(reason instanceof DOMException&&reason.name==="AbortError"?"採集超過 40 秒，已停止等待；請檢查採集狀態與 API 日誌":reason instanceof Error?reason.message:"採集失敗");}finally{window.clearTimeout(timer);setLoading(false);}};
  const exportCsv=()=>{const params=new URLSearchParams({priority,hostId:hostId||"all"});if(unit)params.set("unit",unit);if(queryText)params.set("q",queryText);if(fromAt)params.set("from",new Date(fromAt).toISOString());if(toAt)params.set("to",new Date(toAt).toISOString());window.location.href=`/api/logs/export.csv?${params}`;};
  const saveLogPolicy=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();const form=new FormData(event.currentTarget);const response=await fetch("/api/logs/policy",{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify({retentionDays:Number(form.get("retentionDays")),intervalSeconds:Number(form.get("intervalSeconds")),failureThreshold:Number(form.get("failureThreshold"))})});const body=await response.json();if(!response.ok){setError(body.detail||"政策儲存失敗");return;}setPolicyOpen(false);await loadStatus();};

  return (
    <section className="card page-card logs-page">
      <div className="page-heading">
        <div>
          <small>SYSTEMD JOURNAL</small>
          <h2>遠端日誌查詢</h2>
          <p>可查詢 PostgreSQL 集中保存的 journal，或透過 SSH 即時唯讀查詢；均不修改遠端主機。</p>
        </div><div className="heading-actions"><button className="secondary-action" onClick={()=>setPolicyOpen(true)}>保存與採集政策</button><button className="secondary-action" onClick={()=>void collect()} disabled={loading}>立即採集</button>{source==="central"&&<button className="create" onClick={exportCsv}>匯出 CSV</button>}</div>
      </div>
      {status&&<div className="security-summary log-summary"><span><strong>{status.totalEvents}</strong>已保存事件</span><span><strong>{status.hosts.filter(item=>item.consecutiveFailures===0&&item.lastSuccessAt).length}/{status.hosts.length}</strong>採集正常</span><span><strong>{status.policy.intervalSeconds} 秒</strong>採集間隔</span><span><strong>{status.policy.retentionDays} 天</strong>保存期限</span></div>}
      <form className="log-controls" onSubmit={query}>
        <label>資料來源<select value={source} onChange={event => setSource(event.target.value as "live" | "central")}><option value="central">集中日誌</option><option value="live">即時 SSH</option></select></label>
        <label>
          主機
          <select
            name="日誌主機"
            value={hostId}
            onChange={(event) => setHostId(event.target.value)}
          >
            {source==="central"&&<option value="all">全部主機</option>}
            {hosts.map((host) => (
              <option key={host.id} value={host.id}>
                {host.name} · {host.ip}
              </option>
            ))}
          </select>
        </label>
        <label>
          最低等級
          <select name="日誌等級" value={priority} onChange={event=>setPriority(event.target.value)}>
            <option value="emerg">緊急 emerg</option>
            <option value="alert">警報 alert</option>
            <option value="crit">嚴重 crit</option>
            <option value="err">錯誤 err</option>
            <option value="warning">警告 warning</option>
            <option value="notice">通知 notice</option>
            <option value="info">資訊 info</option>
            <option value="debug">除錯 debug</option>
          </select>
        </label>
        <label>
          筆數
          <select name="日誌筆數" value={limit} onChange={event=>setLimit(event.target.value)}>
            <option value="20">20</option>
            <option value="50">50</option>
            <option value="100">100</option>
            <option value="200">200</option>
            {source==="central"&&<><option value="500">500</option><option value="1000">1000</option></>}
          </select>
        </label>
        {source==="central"&&<><label>systemd 服務<select value={unit} onChange={event=>setUnit(event.target.value)}><option value="">全部服務</option>{status?.units.map(value=><option key={value} value={value}>{value}</option>)}</select></label><label>關鍵字<input value={queryText} onChange={event=>setQueryText(event.target.value)} placeholder="訊息或 identifier" /></label><label>開始時間<input type="datetime-local" value={fromAt} onChange={event=>setFromAt(event.target.value)} /></label><label>結束時間<input type="datetime-local" value={toAt} onChange={event=>setToAt(event.target.value)} /></label></>}
        <button className="create" type="submit" disabled={loading || !hostId}>
          {loading ? "查詢中…" : "查詢日誌"}
        </button>
      </form>
      {error && <div className="log-error">{error}</div>}
      {source==="central"&&status&&<div className="log-collector-grid">{status.hosts.map(item=><article key={item.hostId} className={item.consecutiveFailures?"failed":"healthy"}><strong>{item.hostName}</strong><span>{item.storedEvents} 筆</span><small>{item.consecutiveFailures?`連續失敗 ${item.consecutiveFailures} 次：${item.lastError||"未知"}`:item.lastSuccessAt?`最後成功 ${new Date(item.lastSuccessAt).toLocaleString("zh-TW",{hour12:false})}`:"尚未採集"}</small></article>)}</div>}
      <div className="log-output" aria-live="polite">
        {source==="central"&&events.length ? (<div className="data-table log-events-table"><table><thead><tr><th>時間</th><th>主機</th><th>等級</th><th>服務／程序</th><th>訊息</th></tr></thead><tbody>{events.map(event=><tr key={event.id}><td>{event.occurredAt?new Date(event.occurredAt).toLocaleString("zh-TW",{hour12:false}):"—"}</td><td><strong>{event.hostName}</strong></td><td><span className={`log-priority p${event.priority}`}>{event.priority}</span></td><td><strong>{event.unit||event.identifier||"—"}</strong><small>{event.processId?`PID ${event.processId}`:""} {event.transport||""}</small></td><td className="log-message">{event.message}</td></tr>)}</tbody></table></div>) : lines.length ? (
          <pre>{lines.join("\n")}</pre>
        ) : (
          <div className="empty-state">
            <strong>{loading ? "正在讀取日誌" : "尚未執行查詢"}</strong>
            <small>選擇主機、等級與筆數後按下「查詢日誌」。</small>
          </div>
        )}
      </div>
      {policyOpen&&status&&<div className="modal-layer"><form className="modal" onSubmit={saveLogPolicy}><button type="button" className="close" onClick={()=>setPolicyOpen(false)}>×</button><small>CENTRAL LOG POLICY</small><h2>集中日誌保存與採集政策</h2><p>設定會保存在 PostgreSQL。縮短保存期限後，下一次採集會清除超過期限的事件。</p><label>保存天數<input name="retentionDays" type="number" min="1" max="365" defaultValue={status.policy.retentionDays} required /></label><label>採集間隔（秒）<input name="intervalSeconds" type="number" min="60" max="3600" defaultValue={status.policy.intervalSeconds} required /></label><label>連續失敗告警門檻<input name="failureThreshold" type="number" min="1" max="20" defaultValue={status.policy.failureThreshold} required /></label><div className="modal-actions"><button type="button" onClick={()=>setPolicyOpen(false)}>取消</button><button className="create">儲存政策</button></div></form></div>}
    </section>
  );
}

type AlertRule = {
  id: string;
  name: string;
  metric: "availability" | "cpu" | "ram" | "disk" | "failed_services" | "log_collection" | "asset_drift" | "security_updates" | "security_baseline" | "capacity_forecast";
  threshold: number;
  consecutiveSamples: number;
  severity: "warning" | "critical";
  enabled: boolean;
};
type AlertEvent = {
  id: string;
  ruleId: string;
  ruleName: string;
  hostId: string;
  hostName: string;
  status: "firing" | "acknowledged" | "resolved";
  severity: "warning" | "critical";
  message: string;
  startedAt: string;
  resolvedAt?: string | null;
  taskCount?: number;
  assigneeId?: string | null;
  assigneeName?: string | null;
  resolutionSummary?: string;
  resolutionReason?: string;
  closedAt?: string | null;
};
type IncidentDetail = AlertEvent & { closedBy?: string | null; timeline: Array<{ id:string; eventType:string; message:string; actor:string; createdAt:string }> };
type MonitoringStats = {
  active: number;
  critical: number;
  resolved24h: number;
  samples: number;
  lastCollectedAt?: string | null;
  intervalSeconds: number;
  retentionDays: number;
};
type MetricSample = {
  collectedAt: string;
  state: HostRow["state"];
  cpu: number;
  ram: number;
  disk: number;
  failedServices: number;
};
type NotificationChannel = {
  id: "telegram" | "line" | "sms" | "webhook" | "email";
  name: string;
  enabled: boolean;
  destination: string;
};
type NotificationDelivery = {
  id: string;
  alertEventId?: string | null;
  channel: "telegram" | "line" | "sms" | "webhook" | "email";
  kind: "firing" | "resolved" | "test" | "backup_failed";
  status: "sent" | "failed" | "suppressed";
  destination: string;
  message: string;
  responseDetail?: string | null;
  attemptedAt: string;
};
type NotificationRetry = {
  id: string;
  channel: NotificationChannel["id"];
  kind: NotificationDelivery["kind"];
  status: "queued" | "sending" | "sent" | "failed";
  attemptCount: number;
  maxAttempts: number;
  nextAttemptAt: string;
  lastError?: string | null;
  createdAt: string;
};

const alertMetricNames: Record<AlertRule["metric"], string> = {
  availability: "主機離線",
  cpu: "CPU 使用率",
  ram: "記憶體使用率",
  disk: "磁碟使用率",
  failed_services: "失敗服務數",
  log_collection: "集中日誌採集失敗",
  asset_drift: "主機資產設定漂移",
  security_updates: "安全更新待處理",
  security_baseline: "主機安全基準分數",
  capacity_forecast: "容量預測天數",
};

type GovernancePolicy={quietEnabled:boolean;quietStartHour:number;quietEndHour:number;criticalBypass:boolean};
type AlertSilence={id:string;name:string;hostId?:string|null;ruleId?:string|null;startsAt:string;endsAt:string;reason:string;active:boolean};
function NotificationGovernance({canManage,hosts,rules}:{canManage:boolean;hosts:HostRow[];rules:AlertRule[]}){
 const [policy,setPolicy]=useState<GovernancePolicy|null>(null);const [silences,setSilences]=useState<AlertSilence[]>([]);const [error,setError]=useState("");const [open,setOpen]=useState(false);
 const load=useCallback(async()=>{const response=await fetch("/api/notifications/governance",{cache:"no-store"});const body=await response.json();if(!response.ok)throw new Error(body.detail||"無法讀取通知治理");setPolicy(body.policy);setSilences(body.silences||[])},[]);useEffect(()=>{void load().catch(reason=>setError(reason instanceof Error?reason.message:"載入失敗"))},[load]);
 const save=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();if(!policy)return;const response=await fetch("/api/notifications/governance",{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify(policy)});const body=await response.json();if(!response.ok){setError(body.detail||"儲存失敗");return}setPolicy(body.policy);setSilences(body.silences||[])};
 const create=async(event:FormEvent<HTMLFormElement>)=>{event.preventDefault();const data=new FormData(event.currentTarget);const response=await fetch("/api/notifications/silences",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:data.get("name"),hostId:data.get("hostId")||null,ruleId:data.get("ruleId")||null,startsAt:new Date(String(data.get("startsAt"))).toISOString(),endsAt:new Date(String(data.get("endsAt"))).toISOString(),reason:data.get("reason")})});const body=await response.json();if(!response.ok){setError(body.detail||"建立失敗");return}setPolicy(body.policy);setSilences(body.silences||[]);setOpen(false)};
 const remove=async(id:string)=>{const response=await fetch(`/api/notifications/silences/${id}`,{method:"DELETE"});if(!response.ok){setError("刪除靜音失敗");return}await load()};
 return <div className="card governance-center"><header className="alert-section-head"><div><small>NOTIFICATION GOVERNANCE</small><h2>安靜時段與告警靜音</h2></div>{canManage&&<button className="create" onClick={()=>setOpen(true)}>＋ 新增靜音</button>}</header>{error&&<div className="log-error">{error}</div>}{policy&&<form className="governance-policy" onSubmit={save}><label className="inline-check"><input type="checkbox" checked={policy.quietEnabled} onChange={e=>setPolicy({...policy,quietEnabled:e.target.checked})}/><span>啟用全域 UTC 安靜時段</span></label><label>開始<input type="number" min="0" max="23" value={policy.quietStartHour} onChange={e=>setPolicy({...policy,quietStartHour:Number(e.target.value)})}/></label><label>結束<input type="number" min="0" max="23" value={policy.quietEndHour} onChange={e=>setPolicy({...policy,quietEndHour:Number(e.target.value)})}/></label><label className="inline-check"><input type="checkbox" checked={policy.criticalBypass} onChange={e=>setPolicy({...policy,criticalBypass:e.target.checked})}/><span>重大告警略過安靜時段</span></label>{canManage&&<button className="secondary-action">儲存政策</button>}</form>}<div className="silence-list">{silences.map(item=><article key={item.id}><div><strong>{item.name}</strong><small>{item.hostId||"全部主機"} · {item.ruleId||"全部規則"} · {item.reason}</small></div><span className={`channel-state ${item.active?"enabled":"disabled"}`}>{item.active?"作用中":"已到期"}</span><time>{new Date(item.endsAt).toLocaleString("zh-TW",{hour12:false})}</time>{canManage&&<button onClick={()=>void remove(item.id)}>刪除</button>}</article>)}</div>{open&&<div className="modal-shell"><form className="modal silence-modal" onSubmit={create}><header><div><small>TIME-BOUND SILENCE</small><h2>新增告警靜音</h2></div><button type="button" onClick={()=>setOpen(false)}>×</button></header><label>名稱<input name="name" required/></label><label>主機<select name="hostId"><option value="">全部主機</option>{hosts.map(h=><option key={h.id} value={h.id}>{h.name}</option>)}</select></label><label>告警規則<select name="ruleId"><option value="">全部規則</option>{rules.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select></label><label>開始<input name="startsAt" type="datetime-local" required/></label><label>結束<input name="endsAt" type="datetime-local" required/></label><label>原因<input name="reason" required/></label><footer><button type="button" onClick={()=>setOpen(false)}>取消</button><button className="create">建立靜音</button></footer></form></div>}</div>;
}

type EscalationPolicy={enabled:boolean;warningIntervalMinutes:number;criticalIntervalMinutes:number;maxReminders:number;criticalEscalateAfterMinutes:number};
function NotificationEscalation({canManage}:{canManage:boolean}){const [policy,setPolicy]=useState<EscalationPolicy|null>(null);const [history,setHistory]=useState<any[]>([]);const [error,setError]=useState("");const load=useCallback(async()=>{const r=await fetch("/api/notifications/escalation",{cache:"no-store"});const b=await r.json();if(!r.ok)throw new Error(b.detail||"載入失敗");setPolicy(b.policy);setHistory(b.history||[])},[]);useEffect(()=>{void load().catch(e=>setError(e.message))},[load]);const save=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();if(!policy)return;const r=await fetch("/api/notifications/escalation",{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify(policy)});const b=await r.json();if(!r.ok){setError(b.detail||"儲存失敗");return}setPolicy(b.policy);setHistory(b.history||[])};return <div className="card escalation-center"><header className="alert-section-head"><div><small>UNACKNOWLEDGED ALERT ESCALATION</small><h2>再次提醒與重大告警升級</h2></div></header>{error&&<div className="log-error">{error}</div>}{policy&&<form className="escalation-policy" onSubmit={save}><label className="inline-check"><input type="checkbox" checked={policy.enabled} onChange={e=>setPolicy({...policy,enabled:e.target.checked})}/><span>啟用再次提醒</span></label><label>警告間隔<input type="number" min="5" value={policy.warningIntervalMinutes} onChange={e=>setPolicy({...policy,warningIntervalMinutes:Number(e.target.value)})}/></label><label>重大間隔<input type="number" min="1" value={policy.criticalIntervalMinutes} onChange={e=>setPolicy({...policy,criticalIntervalMinutes:Number(e.target.value)})}/></label><label>最大次數<input type="number" min="1" max="20" value={policy.maxReminders} onChange={e=>setPolicy({...policy,maxReminders:Number(e.target.value)})}/></label><label>重大升級<input type="number" min="1" value={policy.criticalEscalateAfterMinutes} onChange={e=>setPolicy({...policy,criticalEscalateAfterMinutes:Number(e.target.value)})}/></label>{canManage&&<button className="secondary-action">儲存政策</button>}</form>}<div className="data-table"><table><thead><tr><th>主機</th><th>等級</th><th>提醒</th><th>狀態</th><th>成功管道</th><th>時間</th></tr></thead><tbody>{history.map(item=><tr key={item.id}><td><strong>{item.hostName}</strong></td><td>{item.escalated?"重大升級":item.severity}</td><td>第 {item.reminderNumber} 次</td><td>{item.status}</td><td>{item.deliveryCount}</td><td>{new Date(item.attemptedAt).toLocaleString("zh-TW",{hour12:false})}</td></tr>)}</tbody></table></div>{!history.length&&<div className="empty-state"><strong>尚無再次提醒紀錄</strong><small>告警超過設定間隔仍未確認時會自動建立。</small></div>}</div>}

function NotificationRouting({canManage,hosts,rules}:{canManage:boolean;hosts:HostRow[];rules:AlertRule[]}){
 const [routes,setRoutes]=useState<any[]>([]);const [channels,setChannels]=useState<any[]>([]);const [editing,setEditing]=useState<any|null>(null);const [open,setOpen]=useState(false);const [error,setError]=useState("");
 const load=useCallback(async()=>{const r=await fetch("/api/notification-routes",{cache:"no-store"});const b=await r.json();if(!r.ok)throw new Error(b.detail||"載入失敗");setRoutes(b.routes||[]);setChannels(b.channels||[])},[]);useEffect(()=>{void load().catch(e=>setError(e.message))},[load]);
 const begin=(route:any|null)=>{setEditing(route);setOpen(true);setError("")};
 const save=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();const d=new FormData(e.currentTarget);const payload={name:d.get("name"),enabled:d.get("enabled")==="on",priority:Number(d.get("priority")),severity:d.get("severity")||null,hostId:d.get("hostId")||null,ruleId:d.get("ruleId")||null,channels:d.getAll("channels"),titleTemplate:d.get("titleTemplate"),bodyTemplate:d.get("bodyTemplate")};const r=await fetch(editing?`/api/notification-routes/${editing.id}`:"/api/notification-routes",{method:editing?"PUT":"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload)});const b=await r.json();if(!r.ok){setError(b.detail||"儲存失敗");return}setRoutes(b.routes||[]);setChannels(b.channels||[]);setOpen(false)};
 const remove=async(id:string)=>{const r=await fetch(`/api/notification-routes/${id}`,{method:"DELETE"});if(!r.ok){setError("刪除失敗");return}await load()};
 return <div className="card routing-center"><header className="alert-section-head"><div><small>PRIORITY ROUTING & TEMPLATES</small><h2>告警通知路由</h2><p>由最小優先序開始比對；沒有符合規則時使用所有已啟用管道。</p></div>{canManage&&<button className="create" onClick={()=>begin(null)}>＋ 新增路由</button>}</header>{error&&<div className="log-error">{error}</div>}<div className="data-table"><table><thead><tr><th>優先序</th><th>名稱</th><th>條件</th><th>通知管道</th><th>範本</th><th>狀態</th><th>操作</th></tr></thead><tbody>{routes.map(route=><tr key={route.id}><td><strong>{route.priority}</strong></td><td>{route.name}</td><td>{route.severity||"全部等級"} · {hosts.find(h=>h.id===route.hostId)?.name||"全部主機"} · {rules.find(r=>r.id===route.ruleId)?.name||"全部規則"}</td><td>{route.channels.map((id:string)=>channels.find(c=>c.id===id)?.name||id).join("、")}</td><td><small>{route.titleTemplate}</small></td><td>{route.enabled?"啟用":"停用"}</td><td>{canManage&&<div className="access-actions"><button onClick={()=>begin(route)}>修改</button><button onClick={()=>void remove(route.id)}>刪除</button></div>}</td></tr>)}</tbody></table></div>{!routes.length&&<div className="empty-state"><strong>目前使用預設備援路由</strong><small>所有已啟用通知管道都會收到告警。</small></div>}{open&&<div className="modal-shell"><form className="modal route-modal" onSubmit={save}><header><div><small>NOTIFICATION ROUTE</small><h2>{editing?"修改路由":"新增路由"}</h2></div><button type="button" onClick={()=>setOpen(false)}>×</button></header><label>名稱<input name="name" defaultValue={editing?.name||"重大告警路由"} required/></label><label>優先順序<input name="priority" type="number" min="1" max="9999" defaultValue={editing?.priority||100} required/></label><label>等級<select name="severity" defaultValue={editing?.severity||""}><option value="">全部等級</option><option value="warning">警告</option><option value="critical">重大</option></select></label><label>主機<select name="hostId" defaultValue={editing?.hostId||""}><option value="">全部主機</option>{hosts.map(h=><option key={h.id} value={h.id}>{h.name}</option>)}</select></label><label>告警規則<select name="ruleId" defaultValue={editing?.ruleId||""}><option value="">全部規則</option>{rules.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select></label><fieldset><legend>通知管道</legend>{channels.map(channel=><label className="inline-check" key={channel.id}><input type="checkbox" name="channels" value={channel.id} defaultChecked={editing?editing.channels.includes(channel.id):channel.enabled}/><span>{channel.name}（{channel.enabled?"已設定":"尚未設定"}）</span></label>)}</fieldset><label>標題範本<input name="titleTemplate" defaultValue={editing?.titleTemplate||"[Linux AI] {{severity}} - {{host}}"} required/></label><label>內容範本<textarea name="bodyTemplate" defaultValue={editing?.bodyTemplate||"{{message}}\n規則：{{rule}}"} required/></label><label className="inline-check"><input name="enabled" type="checkbox" defaultChecked={editing?.enabled??true}/><span>啟用此路由</span></label><small className="template-help">可使用：&#123;&#123;severity&#125;&#125;、&#123;&#123;host&#125;&#125;、&#123;&#123;rule&#125;&#125;、&#123;&#123;message&#125;&#125;、&#123;&#123;kind&#125;&#125;</small><footer><button type="button" onClick={()=>setOpen(false)}>取消</button><button className="create">儲存路由</button></footer></form></div>}</div>
}

function NotificationTestLab({canManage,hosts,rules}:{canManage:boolean;hosts:HostRow[];rules:AlertRule[]}){
 const [runs,setRuns]=useState<any[]>([]);const [error,setError]=useState("");const [busy,setBusy]=useState(false);
 const load=useCallback(async()=>{const r=await fetch("/api/notification-tests",{cache:"no-store"});const b=await r.json();if(!r.ok)throw new Error(b.detail||"載入失敗");setRuns(b.runs||[])},[]);
 useEffect(()=>{void load().catch(e=>setError(e.message))},[load]);
 const run=async(e:FormEvent<HTMLFormElement>)=>{e.preventDefault();setBusy(true);setError("");const data=new FormData(e.currentTarget);const r=await fetch("/api/notification-tests",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({name:data.get("name"),severity:data.get("severity"),hostId:data.get("hostId")||null,ruleId:data.get("ruleId")||null,deliveryRequested:data.get("deliveryRequested")==="on"})});const b=await r.json().catch(()=>({}));setBusy(false);if(!r.ok){setError(b.detail||"測試失敗");return}await load()};
 const remove=async(id:string)=>{const r=await fetch(`/api/notification-tests/${id}`,{method:"DELETE"});if(!r.ok){setError("刪除失敗");return}await load()};
 const clear=async()=>{const r=await fetch("/api/notification-tests",{method:"DELETE"});if(!r.ok){setError("清除失敗");return}await load()};
 return <div className="card notification-test-lab"><header className="alert-section-head"><div><small>ISOLATED NOTIFICATION TEST LAB</small><h2>通知與治理測試</h2><p>測試資料不會進入正式告警、SLO、MTTA、MTTR 或報表。</p></div>{canManage&&runs.length>0&&<button onClick={()=>void clear()}>清除歷史</button>}</header>{error&&<div className="log-error">{error}</div>}{canManage&&<form className="notification-test-form" onSubmit={run}><label>測試名稱<input name="name" defaultValue="通知鏈路驗證" required/></label><label>等級<select name="severity"><option value="warning">警告</option><option value="critical">重大</option></select></label><label>主機範圍<select name="hostId"><option value="">全部主機</option>{hosts.map(h=><option key={h.id} value={h.id}>{h.name}</option>)}</select></label><label>規則範圍<select name="ruleId"><option value="">全部規則</option>{rules.map(r=><option key={r.id} value={r.id}>{r.name}</option>)}</select></label><label className="inline-check"><input name="deliveryRequested" type="checkbox"/><span>實際發送到已啟用管道</span></label><button className="create" disabled={busy}>{busy?"測試中…":"執行隔離測試"}</button></form>}<div className="notification-test-runs">{runs.map(item=><article key={item.id}><header><div><strong>{item.name}</strong><small>{item.severity} · {new Date(item.createdAt).toLocaleString("zh-TW",{hour12:false})}</small></div><span className={`automation-status ${item.status==="completed"?"success":"failed"}`}>{item.status==="completed"?"完成":"失敗"}</span>{canManage&&<button onClick={()=>void remove(item.id)}>刪除</button>}</header><div className="notification-test-steps">{item.steps.map((step:any)=><span key={step.key} className={step.status}><strong>{step.label}</strong><small>{step.detail}</small></span>)}</div>{item.result.suppressed&&<p className="test-suppressed">通知已抑制：{item.result.suppressionReason}</p>}</article>)}</div>{!runs.length&&<div className="empty-state"><strong>尚無隔離測試</strong><small>先以模擬模式確認治理判定，再視需要勾選實際發送。</small></div>}</div>
}

function Alerts({
  hosts,
  canManage,
  canRequest,
  canTaskRead,
  record,
}: {
  hosts: HostRow[];
  canManage: boolean;
  canRequest: boolean;
  canTaskRead: boolean;
  record: (
    type: string,
    action: string,
    target?: string,
    result?: string,
  ) => void;
}) {
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [alertEvents, setAlertEvents] = useState<AlertEvent[]>([]);
  const [channels, setChannels] = useState<NotificationChannel[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [retries, setRetries] = useState<NotificationRetry[]>([]);
  const [stats, setStats] = useState<MonitoringStats>({
    active: 0,
    critical: 0,
    resolved24h: 0,
    samples: 0,
    intervalSeconds: 60,
    retentionDays: 30,
  });
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.id ?? "");
  const [trendRange,setTrendRange]=useState<"24h"|"7d"|"30d"|"90d">("24h");
  const [samples, setSamples] = useState<MetricSample[]>([]);
  const [editingRule, setEditingRule] = useState<AlertRule | "new" | null>(null);
  const [loading, setLoading] = useState(false);
  const [testingNotification, setTestingNotification] = useState(false);
  const [alertTask, setAlertTask] = useState<AlertEvent | null>(null);
  const [alertRunbooks, setAlertRunbooks] = useState<SafeRunbook[]>([]);
  const [alertTaskRunbook, setAlertTaskRunbook] = useState("");
  const [alertTaskNote, setAlertTaskNote] = useState("");
  const [alertTaskBusy, setAlertTaskBusy] = useState(false);
  const [alertHistory, setAlertHistory] = useState<{ alert: AlertEvent; tasks: MaintenanceTask[] } | null>(null);
  const [alertHistoryBusy, setAlertHistoryBusy] = useState(false);
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [incidentUsers, setIncidentUsers] = useState<Array<{id:string;username:string;displayName:string}>>([]);
  const [incidentNote, setIncidentNote] = useState("");
  const [incidentBusy, setIncidentBusy] = useState(false);
  const [error, setError] = useState("");

  const loadMonitoring = useCallback(async () => {
    const response = await fetch("/api/monitoring", { cache: "no-store" });
    const body = (await response.json()) as {
      rules?: AlertRule[];
      events?: AlertEvent[];
      stats?: MonitoringStats;
      channels?: NotificationChannel[];
      deliveries?: NotificationDelivery[];
      retries?: NotificationRetry[];
      detail?: string;
    };
    if (!response.ok) throw new Error(body.detail || "無法讀取告警資料");
    setRules(body.rules ?? []);
    setAlertEvents(body.events ?? []);
    setChannels(body.channels ?? []);
    setDeliveries(body.deliveries ?? []);
    setRetries(body.retries ?? []);
    if (body.stats) setStats(body.stats);
  }, []);

  const loadMetrics = useCallback(async (hostId: string) => {
    if (!hostId) return setSamples([]);
    const response = await fetch(
      `/api/hosts/${encodeURIComponent(hostId)}/metric-trends?range=${trendRange}`,
      { cache: "no-store" },
    );
    const body = (await response.json()) as {
      samples?: MetricSample[];
      detail?: string;
    };
    if (!response.ok) throw new Error(body.detail || "無法讀取歷史資料");
    setSamples(body.samples ?? []);
  }, [trendRange]);

  useEffect(() => {
    if (!selectedHost && hosts.length) setSelectedHost(hosts[0].id);
  }, [hosts, selectedHost]);
  useEffect(() => {
    void loadMonitoring().catch((reason) =>
      setError(reason instanceof Error ? reason.message : "載入失敗"),
    );
    const timer = window.setInterval(
      () => void loadMonitoring().catch(() => undefined),
      15_000,
    );
    return () => window.clearInterval(timer);
  }, [loadMonitoring]);
  useEffect(() => {
    void loadMetrics(selectedHost).catch((reason) =>
      setError(reason instanceof Error ? reason.message : "載入失敗"),
    );
  }, [loadMetrics, selectedHost, stats.samples, trendRange]);

  const collect = async () => {
    setLoading(true);
    setError("");
    record("alerts.collect", "立即執行背景採集", undefined, "requested");
    try {
      const response = await fetch("/api/monitoring/collect", { method: "POST" });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "採集失敗");
      await loadMonitoring();
      record("alerts.collect", "背景採集完成", undefined, "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "採集失敗";
      setError(message);
      record("alerts.collect", "背景採集失敗", undefined, "failure");
    } finally {
      setLoading(false);
    }
  };

  const saveRule = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editingRule) return;
    const form = new FormData(event.currentTarget);
    const payload = {
      name: form.get("name"),
      metric: form.get("metric"),
      threshold: Number(form.get("threshold")),
      consecutiveSamples: Number(form.get("consecutiveSamples")),
      severity: form.get("severity"),
      enabled: editingRule === "new" ? true : form.has("enabled"),
    };
    const path =
      editingRule === "new"
        ? "/api/alert-rules"
        : `/api/alert-rules/${encodeURIComponent(editingRule.id)}`;
    try {
      const response = await fetch(path, {
        method: editingRule === "new" ? "POST" : "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "儲存規則失敗");
      record(
        "alerts.rule.save",
        editingRule === "new" ? "新增告警規則" : "修改告警規則",
        String(payload.name),
        "success",
      );
      setEditingRule(null);
      await loadMonitoring();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "儲存規則失敗");
    }
  };

  const removeRule = async (rule: AlertRule) => {
    if (!window.confirm(`確定刪除告警規則「${rule.name}」嗎？`)) return;
    try {
      const response = await fetch(
        `/api/alert-rules/${encodeURIComponent(rule.id)}`,
        { method: "DELETE" },
      );
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail || "刪除規則失敗");
      }
      record("alerts.rule.delete", "刪除告警規則", rule.name, "success");
      await loadMonitoring();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "刪除規則失敗");
    }
  };

  const acknowledge = async (alert: AlertEvent) => {
    try {
      const response = await fetch(
        `/api/alert-events/${encodeURIComponent(alert.id)}/acknowledge`,
        { method: "POST" },
      );
      if (!response.ok) {
        const body = (await response.json()) as { detail?: string };
        throw new Error(body.detail || "確認告警失敗");
      }
      record("alerts.acknowledge", "確認告警", alert.message, "success");
      await loadMonitoring();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "確認告警失敗");
    }
  };

  const openAlertTask = async (alert: AlertEvent) => {
    setError("");
    try {
      const response = await fetch(`/api/alert-events/${encodeURIComponent(alert.id)}/runbooks`, { cache: "no-store" });
      const body = (await response.json()) as { runbooks?: SafeRunbook[]; detail?: string };
      if (!response.ok) throw new Error(body.detail || "無法讀取告警可用 Runbook");
      const options = body.runbooks ?? [];
      setAlertTask(alert); setAlertRunbooks(options); setAlertTaskRunbook(options[0]?.id ?? ""); setAlertTaskNote("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "無法建立告警維運任務");
    }
  };

  const createAlertTask = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!alertTask || !alertTaskRunbook) return;
    setAlertTaskBusy(true); setError("");
    try {
      const response = await fetch(`/api/alert-events/${encodeURIComponent(alertTask.id)}/tasks`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ runbookId: alertTaskRunbook, note: alertTaskNote }),
      });
      const body = (await response.json()) as { title?: string; detail?: string };
      if (!response.ok) throw new Error(body.detail || "建立維運任務失敗");
      record("tasks.create_from_alert", "由告警建立受控維運任務", body.title || alertTask.ruleName, "success");
      setAlertTask(null); await loadMonitoring();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "建立維運任務失敗");
    } finally { setAlertTaskBusy(false); }
  };

  const openAlertHistory = async (alert: AlertEvent) => {
    setAlertHistoryBusy(true); setError("");
    try {
      const response = await fetch(`/api/alert-events/${encodeURIComponent(alert.id)}/tasks`, { cache: "no-store" });
      const body = (await response.json()) as { tasks?: MaintenanceTask[]; detail?: string };
      if (!response.ok) throw new Error(body.detail || "無法讀取告警處理歷程");
      setAlertHistory({ alert, tasks: body.tasks ?? [] });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "無法讀取告警處理歷程");
    } finally { setAlertHistoryBusy(false); }
  };

  const openIncident = async (alert: AlertEvent) => {
    setIncidentBusy(true); setError("");
    try {
      const requests: Promise<Response>[] = [fetch(`/api/alert-events/${encodeURIComponent(alert.id)}/incident`, { cache:"no-store" })];
      if (canManage) requests.push(fetch("/api/incidents/assignees", { cache:"no-store" }));
      const responses = await Promise.all(requests);
      const detail = (await responses[0].json()) as IncidentDetail & {detail?:string};
      if (!responses[0].ok) throw new Error(detail.detail || "無法讀取事件紀錄");
      if (responses[1]) { const users = (await responses[1].json()) as {users?:typeof incidentUsers}; if (responses[1].ok) setIncidentUsers(users.users ?? []); }
      setIncident(detail); setIncidentNote("");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "無法讀取事件紀錄"); }
    finally { setIncidentBusy(false); }
  };

  const addIncidentNote = async () => {
    if (!incident || !incidentNote.trim()) return;
    setIncidentBusy(true);
    try {
      const response = await fetch(`/api/alert-events/${encodeURIComponent(incident.id)}/timeline`, { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({message:incidentNote}) });
      const body = (await response.json()) as IncidentDetail & {detail?:string};
      if (!response.ok) throw new Error(body.detail || "新增紀錄失敗"); setIncident(body); setIncidentNote(""); await loadMonitoring();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "新增紀錄失敗"); }
    finally { setIncidentBusy(false); }
  };

  const closeIncident = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!incident) return;
    const form = new FormData(event.currentTarget); setIncidentBusy(true);
    try {
      const response = await fetch(`/api/alert-events/${encodeURIComponent(incident.id)}/close`, { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({summary:form.get("summary"),reason:form.get("reason"),assigneeId:form.get("assigneeId") || null}) });
      const body = (await response.json()) as IncidentDetail & {detail?:string};
      if (!response.ok) throw new Error(body.detail || "事件結案失敗"); setIncident(body); record("alerts.close","告警事件結案",incident.ruleName,"success"); await loadMonitoring();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "事件結案失敗"); }
    finally { setIncidentBusy(false); }
  };

  const testNotifications = async () => {
    setTestingNotification(true);
    setError("");
    record("alerts.notification.test", "發送測試通知", undefined, "requested");
    try {
      const response = await fetch("/api/notifications/test", { method: "POST" });
      const body = (await response.json()) as { allSent?: boolean; detail?: string };
      if (!response.ok) throw new Error(body.detail || "測試通知失敗");
      if (!body.allSent) throw new Error("部分通知管道傳送失敗，請查看傳送紀錄");
      record("alerts.notification.test", "測試通知已送達", undefined, "success");
      await loadMonitoring();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "測試通知失敗";
      setError(message);
      record("alerts.notification.test", "測試通知失敗", undefined, "failure");
      await loadMonitoring().catch(() => undefined);
    } finally {
      setTestingNotification(false);
    }
  };

  const recentSamples = samples.slice(-60);
  const trend = (metric: "cpu" | "ram" | "disk") => {
    const values = samples.map((sample) => sample[metric]);
    return {
      current: values.at(-1) ?? 0,
      average: values.length
        ? Math.round(values.reduce((sum, value) => sum + value, 0) / values.length)
        : 0,
      max: values.length ? Math.max(...values) : 0,
    };
  };
  const selected = hosts.find((host) => host.id === selectedHost);
  const notificationChannelName = (channel: NotificationChannel["id"]) => ({
    telegram: "Telegram",
    line: "LINE",
    sms: "SMS Gateway",
    webhook: "Webhook",
    email: "Email",
  })[channel];

  return (
    <section className="alerts-page">
      <div className="card alert-heading">
        <div className="page-heading">
          <div>
            <small>BACKGROUND MONITOR</small>
            <h2>告警中心</h2>
            <p>
              每 {stats.intervalSeconds} 秒背景採集，歷史資料保留 {stats.retentionDays} 天。
            </p>
          </div>
          {canManage && (
            <div className="heading-actions">
              <button
                className="secondary-action"
                onClick={() => void collect()}
                disabled={loading}
              >
                {loading ? "採集中…" : "立即採集"}
              </button>
              <button className="create" onClick={() => setEditingRule("new")}>
                ＋ 新增規則
              </button>
            </div>
          )}
        </div>
        {error && <div className="log-error">{error}</div>}
        <div className="alert-kpis">
          <span><strong>{stats.active}</strong>進行中告警</span>
          <span><strong>{stats.critical}</strong>嚴重告警</span>
          <span><strong>{stats.resolved24h}</strong>24 小時已恢復</span>
          <span><strong>{stats.samples}</strong>歷史樣本</span>
        </div>
      </div>

      <div className="card notification-center">
        <header className="alert-section-head">
          <div>
            <small>OUTBOUND NOTIFICATIONS</small>
            <h2>通知管道</h2>
          </div>
          {canManage && (
            <button
              className="secondary-action"
              onClick={() => void testNotifications()}
              disabled={testingNotification || !channels.some((channel) => channel.enabled)}
            >
              {testingNotification ? "傳送中…" : "發送測試通知"}
            </button>
          )}
        </header>
        <div className="notification-grid">
          {channels.map((channel) => (
            <article key={channel.id} className="notification-channel">
              <div>
                <strong>{channel.name}</strong>
                <small>{channel.destination}</small>
              </div>
              <span className={`channel-state ${channel.enabled ? "enabled" : "disabled"}`}>
                {channel.enabled ? "已啟用" : "尚未設定"}
              </span>
            </article>
          ))}
        </div>
        <p className="notification-help">
          通知憑證只由中央主機的 .env 載入；UI、稽核紀錄與資料庫都不會顯示金鑰。
        </p>
        <div className="data-table notification-history">
          <table>
            <thead><tr><th>管道</th><th>類型</th><th>目的地</th><th>狀態</th><th>結果</th><th>時間</th></tr></thead>
            <tbody>
              {deliveries.map((delivery) => (
                <tr key={delivery.id}>
                  <td><strong>{notificationChannelName(delivery.channel)}</strong></td>
                  <td>{delivery.kind === "firing" ? "告警發生" : delivery.kind === "resolved" ? "告警恢復" : delivery.kind === "backup_failed" ? "備份失敗" : "測試"}</td>
                  <td>{delivery.destination}</td>
                  <td><span className={`delivery-status ${delivery.status}`}>{delivery.status === "sent" ? "已送出" : delivery.status === "suppressed" ? "已抑制" : "失敗"}</span></td>
                  <td>{delivery.responseDetail || "—"}</td>
                  <td>{new Date(delivery.attemptedAt).toLocaleString("zh-TW", { hour12: false })}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {deliveries.length === 0 && <div className="empty-state"><strong>尚無通知傳送紀錄</strong></div>}
        {retries.length > 0 && (
          <div className="data-table notification-retries">
            <table>
              <thead><tr><th>重試管道</th><th>狀態</th><th>次數</th><th>錯誤</th><th>下次／更新時間</th></tr></thead>
              <tbody>
                {retries.map((retry) => (
                  <tr key={retry.id}>
                    <td><strong>{notificationChannelName(retry.channel)}</strong></td>
                    <td><span className={`retry-status ${retry.status}`}>{retry.status === "queued" ? "等待重試" : retry.status === "sending" ? "傳送中" : retry.status === "sent" ? "已補送" : "最終失敗"}</span></td>
                    <td>{retry.attemptCount} / {retry.maxAttempts}</td>
                    <td>{retry.lastError || "—"}</td>
                    <td>{new Date(retry.nextAttemptAt).toLocaleString("zh-TW", { hour12: false })}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <NotificationGovernance canManage={canManage} hosts={hosts} rules={rules} />
      <NotificationEscalation canManage={canManage} />
      <NotificationRouting canManage={canManage} hosts={hosts} rules={rules} />
      <NotificationTestLab canManage={canManage} hosts={hosts} rules={rules} />

      <div className="card alert-trends">
        <header className="alert-section-head">
          <div>
            <small>{trendRange.toUpperCase()} HISTORY</small>
            <h2>資源趨勢</h2>
          </div>
          <div className="trend-selectors"><select value={trendRange} onChange={event=>setTrendRange(event.target.value as typeof trendRange)}><option value="24h">24 小時</option><option value="7d">7 天</option><option value="30d">30 天</option><option value="90d">90 天</option></select><select
            value={selectedHost}
            onChange={(event) => setSelectedHost(event.target.value)}
          >
            {hosts.map((host) => (
              <option key={host.id} value={host.id}>{host.name} · {host.ip}</option>
            ))}
          </select></div>
        </header>
        <div className="trend-grid">
          {(["cpu", "ram", "disk"] as const).map((metric) => {
            const values = trend(metric);
            return (
              <article key={metric}>
                <header>
                  <span>{metric.toUpperCase()}</span>
                  <strong>{values.current}%</strong>
                </header>
                <div className="trend-bars" aria-label={`${metric} 最近趨勢`}>
                  {recentSamples.map((sample) => (
                    <i
                      key={`${metric}-${sample.collectedAt}`}
                      className={sample[metric] >= 80 ? "hot" : ""}
                      style={{ height: `${Math.max(3, sample[metric])}%` }}
                    />
                  ))}
                </div>
                <footer>平均 {values.average}% · 最高 {values.max}%</footer>
              </article>
            );
          })}
        </div>
        {samples.length === 0 && (
          <div className="empty-state">
            <strong>{selected?.name ?? "主機"} 尚無歷史樣本</strong>
            <small>背景採集完成後會開始顯示趨勢。</small>
          </div>
        )}
      </div>

      <div className="card alert-events">
        <header className="alert-section-head">
          <div><small>ALERT LIFECYCLE</small><h2>告警事件</h2></div>
        </header>
        <div className="data-table">
          <table>
            <thead><tr><th>狀態</th><th>嚴重度</th><th>主機</th><th>事件</th><th>開始時間</th><th>操作</th></tr></thead>
            <tbody>
              {alertEvents.map((alert) => (
                <tr key={alert.id}>
                  <td><span className={`alert-status ${alert.status}`}>{alert.status === "firing" ? "告警中" : alert.status === "acknowledged" ? "已確認" : "已恢復"}</span></td>
                  <td><span className={`alert-severity ${alert.severity}`}>{alert.severity === "critical" ? "嚴重" : "警告"}</span></td>
                  <td><strong>{alert.hostName}</strong></td>
                  <td><strong>{alert.ruleName}</strong><small>{alert.message}</small></td>
                  <td>{new Date(alert.startedAt).toLocaleString("zh-TW", { hour12: false })}</td>
                  <td><span className="row-actions">
                    {canManage && alert.status === "firing" && <button className="table-action" onClick={() => void acknowledge(alert)}>確認</button>}
                    {canRequest && alert.status !== "resolved" && <button className="table-action" onClick={() => void openAlertTask(alert)}>建立任務{alert.taskCount ? ` (${alert.taskCount})` : ""}</button>}
                    {canTaskRead && <button className="table-action" onClick={() => void openAlertHistory(alert)} disabled={alertHistoryBusy}>處理歷程{alert.taskCount ? ` (${alert.taskCount})` : ""}</button>}
                    <button className="table-action" onClick={() => void openIncident(alert)} disabled={incidentBusy}>事件紀錄</button>
                  </span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {alertEvents.length === 0 && <div className="empty-state"><strong>目前沒有告警事件</strong></div>}
      </div>

      <div className="card alert-rules">
        <header className="alert-section-head">
          <div><small>DETERMINISTIC RULES</small><h2>告警規則</h2></div>
        </header>
        <div className="data-table">
          <table>
            <thead><tr><th>規則</th><th>監控項目</th><th>門檻</th><th>連續樣本</th><th>等級</th><th>狀態</th><th>操作</th></tr></thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id}>
                  <td><strong>{rule.name}</strong></td>
                  <td>{alertMetricNames[rule.metric]}</td>
                  <td>{rule.metric === "availability" ? "離線" : rule.metric === "failed_services" ? `${rule.threshold} 個` : rule.metric === "log_collection" ? `${rule.consecutiveSamples} 次` : rule.metric === "asset_drift" ? "偵測到變更" : rule.metric === "security_updates" ? `${rule.threshold} 項` : rule.metric === "security_baseline" ? `${rule.threshold} 分` : rule.metric === "capacity_forecast" ? `${rule.threshold} 天內` : `${rule.threshold}%`}</td>
                  <td>{rule.consecutiveSamples} 次</td>
                  <td><span className={`alert-severity ${rule.severity}`}>{rule.severity === "critical" ? "嚴重" : "警告"}</span></td>
                  <td>{rule.enabled ? "啟用" : "停用"}</td>
                  <td>{canManage && <span className="row-actions"><button className="table-action" onClick={() => setEditingRule(rule)}>修改</button>{!["log_collection","asset_drift","security_updates","security_baseline","capacity_forecast"].includes(rule.metric)&&<button className="table-action danger-action" onClick={() => void removeRule(rule)}>刪除</button>}</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {editingRule && (
        <div className="modal-layer">
          <form className="modal" onSubmit={saveRule}>
            <button type="button" className="close" onClick={() => setEditingRule(null)}>×</button>
            <small>ALERT RULE</small>
            <h2>{editingRule === "new" ? "新增告警規則" : "修改告警規則"}</h2>
            <p>必須連續達到指定次數才建立告警，短暫波動不會立即通知。</p>
            <label>規則名稱<input name="name" defaultValue={editingRule === "new" ? "" : editingRule.name} required /></label>
            <label>監控項目<select name="metric" defaultValue={editingRule === "new" ? "cpu" : editingRule.metric} disabled={editingRule!=="new"&&["log_collection","asset_drift","security_updates","security_baseline","capacity_forecast"].includes(editingRule.metric)}>{Object.entries(alertMetricNames).filter(([value])=>editingRule!=="new"||!["log_collection","asset_drift","security_updates","security_baseline","capacity_forecast"].includes(value)).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>{editingRule!=="new"&&["log_collection","asset_drift","security_updates","security_baseline","capacity_forecast"].includes(editingRule.metric)&&<input type="hidden" name="metric" value={editingRule.metric} />}</label>
            <div className="form-pair">
              <label>門檻值<input name="threshold" type="number" min="0" step="0.1" defaultValue={editingRule === "new" ? 80 : editingRule.threshold} required /></label>
              <label>連續樣本<input name="consecutiveSamples" type="number" min="1" max="60" defaultValue={editingRule === "new" ? 2 : editingRule.consecutiveSamples} required /></label>
            </div>
            <label>嚴重度<select name="severity" defaultValue={editingRule === "new" ? "warning" : editingRule.severity}><option value="warning">警告</option><option value="critical">嚴重</option></select></label>
            {editingRule !== "new" && <label className="inline-check"><input name="enabled" type="checkbox" defaultChecked={editingRule.enabled} />啟用這條規則</label>}
            <div className="modal-actions"><button type="button" onClick={() => setEditingRule(null)}>取消</button><button className="create">確認儲存</button></div>
          </form>
        </div>
      )}
      {alertTask && (
        <div className="modal-layer">
          <form className="modal" onSubmit={createAlertTask}>
            <button type="button" className="close" onClick={() => setAlertTask(null)}>×</button>
            <small>ALERT → CONTROLLED MAINTENANCE</small>
            <h2>由告警建立維運任務</h2>
            <p><strong>{alertTask.hostName}</strong> · {alertTask.ruleName}<br />只會顯示這個告警允許的固定 Runbook；不支援任意 Shell 指令。</p>
            <label>受控 Runbook
              <select value={alertTaskRunbook} onChange={(event) => setAlertTaskRunbook(event.target.value)} required>
                {alertRunbooks.map((item) => <option key={item.id} value={item.id}>{item.title} · {item.risk === "high" ? "高風險" : item.risk === "medium" ? "中風險" : "低風險"}</option>)}
              </select>
            </label>
            {alertRunbooks.find((item) => item.id === alertTaskRunbook) && <div className="runbook-preview"><strong>{alertRunbooks.find((item) => item.id === alertTaskRunbook)?.description}</strong><code>{alertRunbooks.find((item) => item.id === alertTaskRunbook)?.commandPreview}</code><small>{alertRunbooks.find((item) => item.id === alertTaskRunbook)?.verification}</small></div>}
            <label>補充說明（選填）<textarea value={alertTaskNote} onChange={(event) => setAlertTaskNote(event.target.value)} maxLength={500} placeholder="例如：發現時間、影響範圍或處理原因" /></label>
            <p className="form-hint">建立後會出現在「維運任務」，並依風險套用既有的核准、執行與驗證流程。</p>
            <div className="modal-actions"><button type="button" onClick={() => setAlertTask(null)} disabled={alertTaskBusy}>取消</button><button className="create" disabled={alertTaskBusy || !alertTaskRunbook}>{alertTaskBusy ? "建立中…" : "建立受控任務"}</button></div>
          </form>
        </div>
      )}
      {alertHistory && (
        <div className="modal-layer">
          <div className="modal wide-modal">
            <button type="button" className="close" onClick={() => setAlertHistory(null)}>×</button>
            <small>ALERT RESPONSE EVIDENCE</small>
            <h2>告警處理歷程</h2>
            <p><strong>{alertHistory.alert.hostName}</strong> · {alertHistory.alert.ruleName}<br />{alertHistory.alert.message}</p>
            <div className="data-table">
              <table>
                <thead><tr><th>Runbook</th><th>狀態</th><th>申請／核准</th><th>驗證</th><th>完成時間</th></tr></thead>
                <tbody>{alertHistory.tasks.map((task) => <tr key={task.id}><td><strong>{task.title}</strong><small>{task.requestNote}</small></td><td><span className={`task-status ${task.status}`}>{task.status}</span></td><td>{task.requestedBy}<small>{task.approvedBy ? `核准：${task.approvedBy}` : "尚未核准"}</small></td><td>{task.verificationStatus === "passed" ? "已通過" : task.verificationStatus === "failed" ? "失敗" : "待驗證"}<small>{task.outputSha256 ? `SHA-256 ${task.outputSha256.slice(0, 12)}…` : "尚無輸出雜湊"}</small></td><td>{task.completedAt ? new Date(task.completedAt).toLocaleString("zh-TW", { hour12: false }) : "尚未完成"}</td></tr>)}</tbody>
              </table>
            </div>
            {!alertHistory.tasks.length && <div className="empty-state"><strong>此告警尚未建立維運任務</strong><small>可依權限使用「建立任務」選擇對應的固定 Runbook。</small></div>}
            <div className="modal-actions"><button type="button" onClick={() => setAlertHistory(null)}>關閉</button></div>
          </div>
        </div>
      )}
      {incident && <div className="modal-layer"><form className="modal wide-modal incident-modal" onSubmit={closeIncident}><button type="button" className="close" onClick={() => setIncident(null)}>×</button><small>INCIDENT LIFECYCLE</small><h2>事件時間線與結案</h2><p><strong>{incident.hostName}</strong> · {incident.ruleName}<br />{incident.message}</p><div className="incident-timeline">{incident.timeline.map(item=><article key={item.id}><span /><div><strong>{item.actor} · {item.eventType}</strong><p>{item.message}</p><small>{new Date(item.createdAt).toLocaleString("zh-TW",{hour12:false})}</small></div></article>)}{!incident.timeline.length&&<div className="empty-state"><strong>尚無人工處理紀錄</strong></div>}</div>{canManage&&<div className="incident-note"><textarea value={incidentNote} onChange={event=>setIncidentNote(event.target.value)} placeholder="新增調查或處理紀錄" maxLength={2000}/><button type="button" onClick={()=>void addIncidentNote()} disabled={incidentBusy||!incidentNote.trim()}>新增紀錄</button></div>}{incident.closedAt?<div className="incident-resolution"><strong>已結案 · {incident.resolutionReason}</strong><p>{incident.resolutionSummary}</p><small>負責人 {incident.assigneeName||"—"} · {new Date(incident.closedAt).toLocaleString("zh-TW",{hour12:false})}</small></div>:canManage&&<fieldset className="incident-close"><legend>事件結案</legend><label>負責人<select name="assigneeId" defaultValue={incident.assigneeId||""}><option value="">目前操作人員</option>{incidentUsers.map(user=><option key={user.id} value={user.id}>{user.displayName} · @{user.username}</option>)}</select></label><label>結案原因<input name="reason" minLength={2} maxLength={500} required placeholder="例如：服務恢復、誤報、完成修復"/></label><label>處理結果<textarea name="summary" minLength={3} maxLength={2000} required placeholder="說明根因、處理方式與驗證結果"/></label><div className="modal-actions"><button type="button" onClick={()=>setIncident(null)}>取消</button><button className="create" disabled={incidentBusy}>{incidentBusy?"結案中…":"確認結案"}</button></div></fieldset>}</form></div>}
    </section>
  );
}

type BackupJob = {
  id: string;
  kind: "scheduled" | "manual";
  status: "queued" | "running" | "success" | "failed";
  filename?: string | null;
  sizeBytes?: number | null;
  sha256?: string | null;
  restoreVerified: boolean;
  recoveryFilename?: string | null;
  recoverySizeBytes?: number | null;
  recoverySha256?: string | null;
  recoveryVerified: boolean;
  detail?: string | null;
  requestedBy: string;
  requestedAt: string;
  completedAt?: string | null;
};
type ExternalWatchdog = {
  id: string;
  nodeName: string;
  status: "online" | "stale";
  lastReport: "healthy" | "recovered";
  lastOutageSeconds: number;
  lastRecoveredAt?: string | null;
  sourceAddress?: string | null;
  version: string;
  lastSeenAt: string;
};
type WatchdogOutage = {
  id: string;
  watchdogId: string;
  nodeName: string;
  startedAt: string;
  recoveredAt: string;
  durationSeconds: number;
};
type StandbyPreflight = {
  id: string; hostId: string; hostName: string; address: string; ready: boolean;
  checkedBy: string; checkedAt: string;
  result: { facts: Record<string, string | number | boolean>; checks: Array<{ key: string; label: string; passed: boolean }>; error?: string | null };
};
type ReplicationStatus = {
  role: "primary" | "standby";
  enabled: boolean;
  streaming: boolean;
  replicas: Array<{
    applicationName: string; clientAddress?: string | null; state: string; syncState: string;
    sentLsn?: string | null; replayLsn?: string | null; lagBytes: number;
    writeLagSeconds?: number | null; flushLagSeconds?: number | null; replayLagSeconds?: number | null;
  }>;
  slots: Array<{ slotName: string; slotType: string; active: boolean; restartLsn?: string | null; walStatus?: string | null }>;
};

type RetentionPolicy = { dataset:string; retentionDays:number; protected:boolean; updatedAt:string };
const retentionLabels:Record<string,string> = {
  audit_events:"稽核事件",alert_events:"已結案告警",maintenance_tasks:"已結束維運任務",
  host_metrics:"主機效能樣本",automation_runs:"巡檢執行紀錄",inventory_scans:"資產／修補／安全掃描",
  login_events:"登入紀錄",central_logs:"中央日誌",
};

function RetentionCenter({canManage}:{canManage:boolean}) {
  const [policies,setPolicies]=useState<RetentionPolicy[]>([]);
  const [preview,setPreview]=useState<Record<string,number>|null>(null);
  const [busy,setBusy]=useState(false); const [error,setError]=useState("");
  const load=useCallback(async()=>{const response=await fetch("/api/retention",{cache:"no-store"});const body=await response.json() as {policies?:RetentionPolicy[];detail?:string};if(!response.ok)throw new Error(body.detail||"無法讀取保存政策");setPolicies(body.policies??[]);},[]);
  useEffect(()=>{void load().catch(reason=>setError(reason instanceof Error?reason.message:"載入失敗"));},[load]);
  const save=async()=>{setBusy(true);setError("");try{const response=await fetch("/api/retention",{method:"PUT",headers:{"content-type":"application/json"},body:JSON.stringify({policies:policies.filter(item=>!item.protected)})});const body=await response.json() as {policies?:RetentionPolicy[];detail?:string};if(!response.ok)throw new Error(body.detail||"儲存失敗");setPolicies(body.policies??[]);}catch(reason){setError(reason instanceof Error?reason.message:"儲存失敗");}finally{setBusy(false)}};
  const run=async(commit:boolean)=>{if(commit&&!window.confirm("確定刪除超過保存期限的歷史資料？稽核資料不會刪除。"))return;setBusy(true);setError("");try{const response=await fetch(`/api/retention/${commit?"run":"preview"}`,{method:"POST"});const body=await response.json() as {result?:Record<string,number>;detail?:string};if(!response.ok)throw new Error(body.detail||"執行失敗");setPreview(body.result??{});await load();}catch(reason){setError(reason instanceof Error?reason.message:"執行失敗");}finally{setBusy(false)}};
  return <div className="card retention-center"><header className="alert-section-head"><div><small>DATA RETENTION POLICY</small><h2>資料保存與自動清理</h2></div>{canManage&&<div className="retention-actions"><button className="secondary-action" disabled={busy} onClick={()=>void run(false)}>預覽清理</button><button className="secondary-action" disabled={busy} onClick={()=>void save()}>儲存期限</button><button className="create" disabled={busy} onClick={()=>void run(true)}>{busy?"處理中…":"立即清理"}</button></div>}</header>{error&&<div className="log-error">{error}</div>}<div className="retention-grid">{policies.map((item,index)=><label key={item.dataset}><span><strong>{retentionLabels[item.dataset]||item.dataset}</strong><small>{item.protected?"受保護，不自動刪除":preview?`預計清理 ${preview[item.dataset]||0} 筆`:"超過期限後每日清理"}</small></span><input type="number" min={1} max={3650} disabled={!canManage||item.protected||busy} value={item.retentionDays} onChange={event=>setPolicies(current=>current.map((row,rowIndex)=>rowIndex===index?{...row,retentionDays:Number(event.target.value)}:row))}/><em>天</em></label>)}</div></div>;
}

function Backups({
  hosts,
  canManage,
  record,
}: {
  hosts: HostRow[];
  canManage: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [jobs, setJobs] = useState<BackupJob[]>([]);
  const [watchdogs, setWatchdogs] = useState<ExternalWatchdog[]>([]);
  const [watchdogOutages, setWatchdogOutages] = useState<WatchdogOutage[]>([]);
  const [preflights, setPreflights] = useState<StandbyPreflight[]>([]);
  const [replication, setReplication] = useState<ReplicationStatus>({ role: "primary", enabled: false, streaming: false, replicas: [], slots: [] });
  const standbyRef = useRef<HTMLSelectElement>(null);
  const [checkingStandby, setCheckingStandby] = useState(false);
  const [settings, setSettings] = useState({ intervalHours: 24, retentionDays: 7, watchdogStaleSeconds: 120, watchdogConfigured: false });
  const [healthy, setHealthy] = useState(false);
  const [requesting, setRequesting] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const [response, preflightResponse, replicationResponse] = await Promise.all([
      fetch("/api/backups", { cache: "no-store" }),
      fetch("/api/standby-preflights", { cache: "no-store" }),
      fetch("/api/replication/status", { cache: "no-store" }),
    ]);
    const body = (await response.json()) as {
      jobs?: BackupJob[];
      watchdogs?: ExternalWatchdog[];
      watchdogOutages?: WatchdogOutage[];
      settings?: { intervalHours: number; retentionDays: number; watchdogStaleSeconds: number; watchdogConfigured: boolean };
      healthy?: boolean;
      detail?: string;
    };
    if (!response.ok) throw new Error(body.detail || "無法讀取備份狀態");
    const preflightBody = (await preflightResponse.json()) as { checks?: StandbyPreflight[]; detail?: string };
    if (!preflightResponse.ok) throw new Error(preflightBody.detail || "無法讀取冷備檢查");
    const replicationBody = (await replicationResponse.json()) as ReplicationStatus & { detail?: string };
    if (!replicationResponse.ok) throw new Error(replicationBody.detail || "無法讀取資料庫複寫狀態");
    setJobs(body.jobs ?? []);
    setWatchdogs(body.watchdogs ?? []);
    setWatchdogOutages(body.watchdogOutages ?? []);
    setPreflights(preflightBody.checks ?? []);
    setReplication(replicationBody);
    if (body.settings) setSettings(body.settings);
    setHealthy(Boolean(body.healthy));
  }, []);

  useEffect(() => {
    void load().catch((reason) => setError(reason instanceof Error ? reason.message : "載入失敗"));
    const timer = window.setInterval(() => void load().catch(() => undefined), 10_000);
    return () => window.clearInterval(timer);
  }, [load]);

  const createBackup = async () => {
    setRequesting(true);
    setError("");
    record("backup.create", "要求立即備份", undefined, "requested");
    try {
      const response = await fetch("/api/backups", { method: "POST" });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "無法建立備份工作");
      record("backup.create", "備份工作已排入佇列", undefined, "success");
      await load();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "建立備份失敗";
      setError(message);
      record("backup.create", "備份工作建立失敗", undefined, "failure");
    } finally {
      setRequesting(false);
    }
  };

  const checkStandby = async () => {
    const hostId = standbyRef.current?.value;
    if (!hostId) return;
    setCheckingStandby(true); setError("");
    try {
      const response = await fetch(`/api/standby-preflights/${encodeURIComponent(hostId)}`, { method: "POST" });
      const body = (await response.json()) as StandbyPreflight & { detail?: string };
      if (!response.ok) throw new Error(body.detail || "冷備主機檢查失敗");
      record("standby.preflight", "執行冷備主機唯讀檢查", body.hostName, body.ready ? "success" : "warning");
      await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "冷備主機檢查失敗"); }
    finally { setCheckingStandby(false); }
  };

  const successful = jobs.filter((job) => job.status === "success");
  const retained = successful.filter((job) => job.filename).length;
  const latest = successful[0];
  const recoveryReady = Boolean(latest?.restoreVerified && latest?.recoveryVerified);
  const statusLabel = (status: BackupJob["status"]) => ({
    queued: "排隊中",
    running: "執行中",
    success: "成功",
    failed: "失敗",
  })[status];
  const formatBytes = (value?: number | null) => {
    if (!value) return "—";
    if (value >= 1024 ** 3) return `${(value / 1024 ** 3).toFixed(1)} GB`;
    if (value >= 1024 ** 2) return `${(value / 1024 ** 2).toFixed(1)} MB`;
    return `${Math.ceil(value / 1024)} KB`;
  };

  return (
    <section className="backups-page">
      <div className="card backup-heading">
        <div className="page-heading">
          <div>
            <small>CONTROL PLANE DISASTER RECOVERY</small>
            <h2>中央備份與災難復原</h2>
            <p>每 {settings.intervalHours} 小時備份 PostgreSQL、Git 設定歷史與 SSH known_hosts，保留 {settings.retentionDays} 天；資料庫會實際還原驗證。</p>
          </div>
          {canManage && (
            <button
              className="create"
              onClick={() => void createBackup()}
              disabled={requesting || jobs.some((job) => ["queued", "running"].includes(job.status))}
            >
              {requesting ? "建立中…" : "立即備份"}
            </button>
          )}
        </div>
        {error && <div className="log-error">{error}</div>}
        <div className="backup-kpis">
          <span><strong className={healthy ? "ok" : "warn"}>{healthy ? "正常" : "待驗證"}</strong>整體復原狀態</span>
          <span><strong>{retained}</strong>目前保存檔案</span>
          <span><strong>{jobs.filter((job) => job.status === "failed").length}</strong>失敗工作</span>
          <span><strong>{latest?.completedAt ? new Date(latest.completedAt).toLocaleDateString("zh-TW") : "—"}</strong>最近成功</span>
        </div>
      </div>

      <RetentionCenter canManage={canManage} />

      <div className="card recovery-readiness">
        <header className="alert-section-head"><div><small>COLD STANDBY READINESS</small><h2>冷備復原資料</h2></div><span className={`backup-status ${recoveryReady ? "success" : "running"}`}>{recoveryReady ? "資料齊備" : "等待新備份"}</span></header>
        <div className="recovery-checks"><article><strong>{latest?.restoreVerified ? "✓" : "—"}</strong><span>PostgreSQL 備份<small>已執行暫存資料庫還原演練</small></span></article><article><strong>{latest?.recoveryVerified ? "✓" : "—"}</strong><span>Git 設定歷史<small>{latest?.recoveryFilename || "下一份備份開始封存"}</small></span></article><article><strong>{latest?.recoveryVerified ? "✓" : "—"}</strong><span>SSH 主機信任<small>known_hosts；不包含 SSH 私鑰</small></span></article><article><strong>!</strong><span>仍需離機保存<small>SSH 私鑰與中央 .env 必須由管理者另外保管</small></span></article></div>
        {latest?.recoverySha256 && <footer><span>復原封存：{formatBytes(latest.recoverySizeBytes)} · SHA-256 {latest.recoverySha256}</span>{canManage && <div><a href={`/api/backups/${encodeURIComponent(latest.id)}/download/database`} onClick={() => record("backup.download", "下載 PostgreSQL 備份", latest.id, "requested")}>下載資料庫</a><a href={`/api/backups/${encodeURIComponent(latest.id)}/download/recovery`} onClick={() => record("backup.download", "下載中央復原封存", latest.id, "requested")}>下載復原封存</a></div>}</footer>}
      </div>

      <div className="card standby-preflight">
        <header className="alert-section-head"><div><small>READ-ONLY STANDBY PREFLIGHT</small><h2>冷備主機就緒檢查</h2></div>{canManage && <div className="preflight-control"><select ref={standbyRef} defaultValue=""><option value="" disabled>選擇受管主機</option>{hosts.map((host) => <option key={host.id} value={host.id}>{host.name} · {host.ip}</option>)}</select><button className="create" onClick={() => void checkStandby()} disabled={checkingStandby}>{checkingStandby ? "檢查中…" : "執行唯讀檢查"}</button></div>}</header>
        <div className="preflight-results">{preflights.slice(0, 4).map((check) => <article key={check.id}><header><div><strong>{check.hostName}</strong><small>{check.address} · {new Date(check.checkedAt).toLocaleString("zh-TW", { hour12: false })}</small></div><span className={`backup-status ${check.ready ? "success" : "failed"}`}>{check.ready ? "可作為冷備" : "尚未就緒"}</span></header>{check.result.error ? <p>{check.result.error}</p> : <ul>{check.result.checks.map((item) => <li key={item.key} className={item.passed ? "passed" : "missing"}><span>{item.passed ? "✓" : "×"}</span>{item.label}</li>)}</ul>}</article>)}</div>
        {!preflights.length && <div className="empty-state"><strong>尚未執行冷備主機檢查</strong><small>只讀取系統資源與安裝狀態，不會安裝或修改任何內容。</small></div>}
        <footer className="standby-preparation"><div><strong>需要準備冷備機？</strong><small>先調整 VM 至至少 2 CPU／2 GB RAM／20 GB 可用空間，再把專案複製到候選主機並由管理者本地執行。</small></div><code>sudo sh deploy/prepare-cold-standby.sh &lt;管理帳號&gt;</code><span>高風險安裝不會由中央遠端執行</span></footer>
      </div>

      <div className="card replication-center">
        <header className="alert-section-head">
          <div><small>POSTGRESQL STREAMING REPLICATION</small><h2>資料庫串流複寫</h2></div>
          <span className={`backup-status ${replication.streaming ? "success" : replication.enabled ? "running" : "failed"}`}>
            {replication.streaming ? "串流中" : replication.enabled ? "等待備援連線" : "尚未啟用"}
          </span>
        </header>
        <div className="replication-kpis">
          <article><small>本機角色</small><strong>{replication.role === "primary" ? "Primary 主資料庫" : "Standby 備援資料庫"}</strong></article>
          <article><small>Physical Slot</small><strong>{replication.slots.length}</strong></article>
          <article><small>串流連線</small><strong>{replication.replicas.filter((item) => item.state === "streaming").length}</strong></article>
          <article><small>最大延遲</small><strong>{replication.replicas.length ? formatBytes(Math.max(...replication.replicas.map((item) => item.lagBytes))) : "—"}</strong></article>
        </div>
        {replication.slots.length > 0 ? (
          <div className="replication-records">
            {replication.slots.map((slot) => {
              const replica = replication.replicas.find((item) => item.state === "streaming");
              return <article key={slot.slotName}><div><strong>{slot.slotName}</strong><small>{slot.slotType} · WAL {slot.walStatus || "未知"}</small></div><span className={`watchdog-status ${slot.active ? "online" : "stale"}`}>{slot.active ? "已連線" : "未連線"}</span><div><strong>{replica?.clientAddress || "—"}</strong><small>{replica ? `${replica.syncState} · 延遲 ${formatBytes(replica.lagBytes)}` : "等待 Standby 啟動"}</small></div></article>;
            })}
          </div>
        ) : (
          <div className="empty-state"><strong>目前仍使用單一 PostgreSQL</strong><small>平台正常運作；準備第二台中央主機後，再由管理者啟用 Physical Streaming Replication。</small></div>
        )}
        <footer className="replication-guide">
          <div><strong>安全啟用順序</strong><small>先建立 VirtualBox Snapshot 與最新備份，再限制只有備援 IP 能連入 5432。</small></div>
          <code>sh deploy/configure-postgres-primary.sh &lt;備援IP&gt;</code>
          <code>docker compose -f compose.standby.yaml up -d</code>
        </footer>
      </div>

      <div className="card watchdog-center">
        <header className="alert-section-head">
          <div><small>OUT-OF-BAND AVAILABILITY</small><h2>外部存活監控</h2></div>
        </header>
        <div className="watchdog-grid">
          {watchdogs.map((watchdog) => (
            <article key={watchdog.id} className="watchdog-node">
              <div>
                <strong>{watchdog.nodeName}</strong>
                <small>{watchdog.sourceAddress || "未知來源"} · {watchdog.id}</small>
              </div>
              <div>
                <span className={`watchdog-status ${watchdog.status}`}>{watchdog.status === "online" ? "心跳正常" : "心跳逾時"}</span>
                <small>最後回報 {new Date(watchdog.lastSeenAt).toLocaleString("zh-TW", { hour12: false })}</small>
                {watchdog.lastRecoveredAt && <small>上次中斷 {watchdog.lastOutageSeconds} 秒</small>}
              </div>
            </article>
          ))}
        </div>
        {watchdogs.length === 0 && (
          <div className="empty-state">
            <strong>{settings.watchdogConfigured ? "尚未收到外部 Watchdog 心跳" : "尚未設定外部 Watchdog Token"}</strong>
            <small>把 Watchdog 部署在 server-1 或 server-2，中央離線時仍能獨立通知。</small>
          </div>
        )}
        {watchdogOutages.length > 0 && (
          <div className="data-table watchdog-history">
            <table>
              <thead><tr><th>監控節點</th><th>中斷開始</th><th>恢復時間</th><th>持續時間</th><th>結果</th></tr></thead>
              <tbody>
                {watchdogOutages.map((outage) => (
                  <tr key={outage.id}>
                    <td><strong>{outage.nodeName}</strong><small>{outage.watchdogId}</small></td>
                    <td>{new Date(outage.startedAt).toLocaleString("zh-TW", { hour12: false })}</td>
                    <td>{new Date(outage.recoveredAt).toLocaleString("zh-TW", { hour12: false })}</td>
                    <td>{outage.durationSeconds} 秒</td>
                    <td><span className="watchdog-status online">已恢復</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card backup-history">
        <header className="alert-section-head">
          <div><small>BACKUP AND RESTORE DRILLS</small><h2>備份與還原驗證紀錄</h2></div>
        </header>
        <div className="data-table">
          <table>
            <thead><tr><th>狀態</th><th>類型</th><th>檔案</th><th>容量</th><th>還原驗證</th><th>要求者</th><th>時間</th><th>匯出</th></tr></thead>
            <tbody>
              {jobs.map((job) => (
                <tr key={job.id}>
                  <td><span className={`backup-status ${job.status}`}>{statusLabel(job.status)}</span></td>
                  <td>{job.kind === "scheduled" ? "自動排程" : "手動"}</td>
                  <td><strong>{job.filename || "—"}</strong><small>{job.sha256 ? `DB ${job.sha256.slice(0, 12)}… · DR ${job.recoverySha256?.slice(0, 12) || "待建立"}… · ${job.detail ?? ""}` : job.detail}</small></td>
                  <td>{formatBytes(job.sizeBytes)}</td>
                  <td>{job.restoreVerified && job.recoveryVerified ? <span className="verify-ok">✓ DB＋DR 通過</span> : job.restoreVerified ? "僅 DB 通過" : "—"}</td>
                  <td>{job.requestedBy}</td>
                  <td>{new Date(job.requestedAt).toLocaleString("zh-TW", { hour12: false })}</td>
                  <td>{canManage && job.status === "success" && job.filename ? <div className="backup-downloads"><a href={`/api/backups/${encodeURIComponent(job.id)}/download/database`}>DB</a>{job.recoveryFilename && <a href={`/api/backups/${encodeURIComponent(job.id)}/download/recovery`}>DR</a>}</div> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {jobs.length === 0 && <div className="empty-state"><strong>背景服務啟動後會建立第一份自動備份</strong></div>}
      </div>
    </section>
  );
}

function Audit({ events, stats }: { events: UiEvent[]; stats: AuditStats }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const filtered = useMemo(
    () =>
      events.filter((event) => {
        const matchesText =
          `${event.actorName} ${event.eventType} ${event.action} ${event.page} ${event.target ?? ""}`
            .toLowerCase()
            .includes(query.toLowerCase());
        const matchesCategory =
          category === "all" || event.eventType.startsWith(category);
        return matchesText && matchesCategory;
      }),
    [category, events, query],
  );

  return (
    <section className="card page-card">
      <div className="page-heading">
        <div>
          <small>POSTGRESQL EVENT STREAM</small>
          <h2>完整 UI 行為稽核</h2>
          <p>
            以下內容直接讀取 PostgreSQL，不包含密碼、Token、私鑰或查詢原文。
          </p>
        </div>
      </div>
      <div className="audit-kpis">
        <span>
          <strong>{stats.todayEvents}</strong>今日事件
        </span>
        <span>
          <strong>{stats.totalEvents}</strong>累計事件
        </span>
        <span>
          <strong>{stats.activeSessions24h}</strong>24 小時 Session
        </span>
        <span>
          <strong>{stats.chainVerified ? "OK" : "異常"}</strong>雜湊鏈
        </span>
      </div>
      <div className="audit-filter">
        <input
          name="稽核搜尋"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="搜尋事件、頁面、操作…"
        />
        <select
          name="事件分類"
          value={category}
          onChange={(event) => setCategory(event.target.value)}
        >
          <option value="all">全部事件</option>
          <option value="ui.">UI 行為</option>
          <option value="navigation.">頁面切換</option>
          <option value="logs.">日誌查詢</option>
          <option value="session.">Session</option>
          <option value="hosts.">主機同步</option>
        </select>
      </div>
      <div className="data-table">
        <table>
          <thead>
            <tr>
              <th>時間</th>
              <th>使用者</th>
              <th>事件類型</th>
              <th>操作</th>
              <th>頁面／目標</th>
              <th>結果</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((event) => (
              <tr key={event.id}>
                <td className="mono">
                  {new Date(event.occurredAt).toLocaleString("zh-TW", {
                    hour12: false,
                  })}
                </td>
                <td>{event.actorName}</td>
                <td>
                  <code>{event.eventType}</code>
                </td>
                <td>{event.action}</td>
                <td>
                  <strong>{event.page}</strong>
                  <small>{event.target}</small>
                </td>
                <td>
                  <span className="result">{event.result}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filtered.length === 0 && (
        <div className="empty-state page-empty">
          <strong>沒有符合條件的稽核事件</strong>
        </div>
      )}
      <footer className="audit-foot">
        <span>▣</span>事件由 PostgreSQL 持久保存，API 會驗證 SHA-256
        雜湊鏈完整性。
      </footer>
    </section>
  );
}

type DiagnosticResult = {
  summary: string;
  risk: "low" | "medium" | "high";
  findings: Array<{ title: string; explanation: string; evidenceRefs: string[] }>;
  actions: Array<{ title: string; rationale: string; risk: "low" | "medium" | "high"; command: string }>;
  limitations: string[];
};
type Diagnostic = {
  id: string;
  hostId: string;
  hostName: string;
  status: "running" | "completed" | "failed";
  model: string;
  evidence: Array<{ id: string; title: string; content: string }>;
  result?: DiagnosticResult | null;
  redactionCount: number;
  error?: string | null;
  requestedBy: string;
  requestedAt: string;
  completedAt?: string | null;
};

function Diagnostics({
  hosts,
  canManage,
  record,
}: {
  hosts: HostRow[];
  canManage: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [selectedHost, setSelectedHost] = useState(hosts[0]?.id ?? "");
  const [selectedId, setSelectedId] = useState("");
  const [configured, setConfigured] = useState(false);
  const [mode, setMode] = useState<"local" | "openai">("local");
  const [model, setModel] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const response = await fetch("/api/diagnostics", { cache: "no-store" });
    const body = (await response.json()) as {
      configured?: boolean;
      mode?: "local" | "openai";
      openaiConfigured?: boolean;
      model?: string;
      diagnostics?: Diagnostic[];
      detail?: string;
    };
    if (!response.ok) throw new Error(body.detail || "無法讀取 AI 診斷歷史");
    setConfigured(Boolean(body.configured));
    setMode(body.mode === "openai" ? "openai" : "local");
    setModel(body.model ?? "");
    setDiagnostics(body.diagnostics ?? []);
    setSelectedId((current) => current || body.diagnostics?.[0]?.id || "");
  }, []);

  useEffect(() => {
    if (!selectedHost && hosts.length) setSelectedHost(hosts[0].id);
  }, [hosts, selectedHost]);
  useEffect(() => {
    void load().catch((reason) =>
      setError(reason instanceof Error ? reason.message : "載入失敗"),
    );
  }, [load]);

  const run = async () => {
    if (!selectedHost) return;
    setRunning(true);
    setError("");
    const hostName = hosts.find((host) => host.id === selectedHost)?.name ?? selectedHost;
    record("ai.diagnostic.request", "要求 AI 主機診斷", hostName, "requested");
    try {
      const response = await fetch(
        `/api/hosts/${encodeURIComponent(selectedHost)}/diagnostics`,
        { method: "POST" },
      );
      const body = (await response.json()) as Diagnostic & { detail?: string };
      if (!response.ok) throw new Error(body.detail || "AI 診斷失敗");
      await load();
      setSelectedId(body.id);
      record("ai.diagnostic.complete", "AI 主機診斷完成", hostName, "success");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "AI 診斷失敗";
      setError(message);
      record("ai.diagnostic.complete", "AI 主機診斷失敗", hostName, "failure");
      await load().catch(() => undefined);
    } finally {
      setRunning(false);
    }
  };

  const selected = diagnostics.find((item) => item.id === selectedId) ?? diagnostics[0];
  const riskText = { low: "低", medium: "中", high: "高" };
  return (
    <section className="diagnostics-page">
      <div className="card diagnostic-heading">
        <div className="page-heading">
          <div>
            <small>EVIDENCE-BASED AI ANALYSIS</small>
            <h2>AI 主機診斷</h2>
            <p>免費本機規則或選用 OpenAI 分析真實 SSH 探測與 warning 日誌；建議不會自動執行。</p>
          </div>
          <div className="heading-actions diagnostic-controls">
            <select
              aria-label="AI 診斷主機"
              value={selectedHost}
              onChange={(event) => setSelectedHost(event.target.value)}
            >
              {hosts.map((host) => <option key={host.id} value={host.id}>{host.name} · {host.ip}</option>)}
            </select>
            {canManage && (
              <button className="create" onClick={() => void run()} disabled={running || !configured || !selectedHost}>
                {running ? "蒐集與分析中…" : mode === "local" ? "執行免費診斷" : "執行 AI 診斷"}
              </button>
            )}
          </div>
        </div>
        <div className={`ai-config ${configured ? "ready" : "missing"}`}>
          <strong>{mode === "local" ? `免費本機規則 · ${model}` : configured ? `OpenAI · ${model}` : "OpenAI 模式尚未設定"}</strong>
          <span>{mode === "local" ? "不呼叫外部 AI、不產生 API 費用；結果由固定門檻與關鍵字規則產生" : "送出前會遮罩常見密碼、Token、私鑰與 Email"}</span>
        </div>
        {error && <div className="log-error">{error}</div>}
      </div>

      <div className="diagnostic-layout">
        <div className="card diagnostic-history">
          <header className="alert-section-head"><div><small>HISTORY</small><h2>診斷歷史</h2></div></header>
          {diagnostics.map((item) => (
            <button key={item.id} className={selected?.id === item.id ? "active" : ""} onClick={() => setSelectedId(item.id)}>
              <span><strong>{item.hostName}</strong><small>{new Date(item.requestedAt).toLocaleString("zh-TW", { hour12: false })}</small></span>
              <i className={`diagnostic-status ${item.status}`}>{item.status === "completed" ? "完成" : item.status === "failed" ? "失敗" : "分析中"}</i>
            </button>
          ))}
          {!diagnostics.length && <div className="empty-state"><strong>尚無診斷紀錄</strong><small>選擇主機後執行第一次分析。</small></div>}
        </div>

        <div className="card diagnostic-detail">
          {!selected ? (
            <div className="empty-state page-empty"><strong>請先建立診斷</strong></div>
          ) : selected.status === "failed" ? (
            <div className="empty-state page-empty"><strong>診斷失敗</strong><small>{selected.error}</small></div>
          ) : selected.result ? (
            <>
              <header className="diagnostic-summary">
                <div><small>{selected.hostName} · {selected.model}</small><h2>{selected.result.summary}</h2></div>
                <span className={`risk-badge ${selected.result.risk}`}>風險 {riskText[selected.result.risk]}</span>
              </header>
              <section className="diagnostic-section">
                <h3>診斷發現</h3>
                {selected.result.findings.map((finding, index) => (
                  <article key={`${finding.title}-${index}`}>
                    <strong>{finding.title}</strong><p>{finding.explanation}</p>
                    <div className="evidence-refs">{finding.evidenceRefs.map((ref) => <code key={ref}>{ref}</code>)}</div>
                  </article>
                ))}
              </section>
              <section className="diagnostic-section actions">
                <h3>人工審查建議</h3>
                {selected.result.actions.map((action, index) => (
                  <article key={`${action.title}-${index}`}>
                    <div><strong>{action.title}</strong><span className={`risk-badge ${action.risk}`}>{riskText[action.risk]}風險</span></div>
                    <p>{action.rationale}</p>{action.command && <pre>{action.command}</pre>}
                  </article>
                ))}
              </section>
              <details className="diagnostic-evidence">
                <summary>查看送出證據（已遮罩 {selected.redactionCount} 處）</summary>
                {selected.evidence.map((item) => <article key={item.id}><strong>{item.id} · {item.title}</strong><pre>{item.content}</pre></article>)}
              </details>
              {selected.result.limitations.length > 0 && <footer className="diagnostic-limit">限制：{selected.result.limitations.join("；")}</footer>}
            </>
          ) : (
            <div className="empty-state page-empty"><strong>診斷仍在處理</strong></div>
          )}
        </div>
      </div>
    </section>
  );
}

type SafeRunbook = {
  id: string;
  title: string;
  description: string;
  commandPreview: string;
  risk: "low" | "medium" | "high";
  approvalPolicy: "single" | "independent";
  verification: string;
  mutating: boolean;
};

type ConfigVersion = {
  id: string;
  shortId: string;
  actor: string;
  createdAt: string;
  message: string;
};

type ConfigVersionDetail = {
  id: string;
  changedSections: string[];
  snapshot: Record<string, unknown>;
};

type ConfigRestoreRequest = {
  id: string;
  versionId: string;
  status: "pending" | "approved" | "rejected" | "applying" | "applied" | "failed";
  note: string;
  decisionNote: string;
  requestedById: string;
  requestedBy: string;
  approvedBy?: string | null;
  appliedBy?: string | null;
  beforeVersionId?: string | null;
  result?: Record<string, unknown> | null;
  error?: string | null;
  requestedAt: string;
};

function ConfigVersions({
  canManage,
  currentUserId,
  record,
}: {
  canManage: boolean;
  currentUserId: string;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [versions, setVersions] = useState<ConfigVersion[]>([]);
  const [restoreRequests, setRestoreRequests] = useState<ConfigRestoreRequest[]>([]);
  const [selected, setSelected] = useState<ConfigVersionDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState("");
  const [error, setError] = useState("");

  const selectVersion = useCallback(async (version: ConfigVersion) => {
    setError("");
    const response = await fetch(`/api/config-versions/${encodeURIComponent(version.id)}`, { cache: "no-store" });
    const body = (await response.json()) as ConfigVersionDetail & { detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取設定版本");
    setSelected(body);
  }, []);

  const load = useCallback(async () => {
    const [response, restoresResponse] = await Promise.all([
      fetch("/api/config-versions", { cache: "no-store" }),
      fetch("/api/config-restore-requests", { cache: "no-store" }),
    ]);
    const body = (await response.json()) as { versions?: ConfigVersion[]; detail?: string };
    const restoresBody = (await restoresResponse.json()) as { requests?: ConfigRestoreRequest[]; detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取設定版控");
    if (!restoresResponse.ok) throw new Error(restoresBody.detail || "無法讀取回滾申請");
    const rows = body.versions ?? [];
    setVersions(rows);
    setRestoreRequests(restoresBody.requests ?? []);
    if (rows.length) await selectVersion(rows[0]);
  }, [selectVersion]);

  useEffect(() => { void load().catch((reason) => setError(reason instanceof Error ? reason.message : "載入失敗")); }, [load]);

  const snapshot = async () => {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/config-versions/snapshot", { method: "POST" });
      const body = (await response.json()) as { version?: ConfigVersion; detail?: string };
      if (!response.ok) throw new Error(body.detail || "建立設定快照失敗");
      record("config.snapshot", "建立設定版本快照", body.version?.shortId, "success");
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "建立設定快照失敗");
    } finally {
      setBusy(false);
    }
  };

  const requestRestore = async () => {
    if (!selected || !window.confirm(`確定申請回滾至版本 ${selected.id.slice(0, 12)} 嗎？\n送出後必須由另一位管理者核准。`)) return;
    const note = window.prompt("請輸入回滾原因", "還原中央設定至已驗證版本") ?? "";
    setActionBusy("request"); setError("");
    try {
      const response = await fetch(`/api/config-versions/${encodeURIComponent(selected.id)}/restore-requests`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ note }) });
      const body = (await response.json()) as ConfigRestoreRequest & { detail?: string };
      if (!response.ok) throw new Error(body.detail || "建立回滾申請失敗");
      record("config.restore.request", "申請設定回滾", selected.id.slice(0, 12), "requested");
      await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "建立回滾申請失敗"); }
    finally { setActionBusy(""); }
  };

  const restoreAction = async (item: ConfigRestoreRequest, action: "approve" | "reject" | "apply") => {
    let note = "";
    if (action === "reject") note = window.prompt("請輸入拒絕原因", "") ?? "";
    if (action === "apply" && window.prompt("此操作會變更中央設定。請輸入 RESTORE 確認", "") !== "RESTORE") return;
    setActionBusy(`${item.id}:${action}`); setError("");
    try {
      const response = await fetch(`/api/config-restore-requests/${encodeURIComponent(item.id)}/${action}`, { method: "POST", headers: { "content-type": "application/json" }, body: action === "apply" ? undefined : JSON.stringify({ note }) });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "回滾操作失敗");
      record(`config.restore.${action}`, action === "approve" ? "核准設定回滾" : action === "reject" ? "拒絕設定回滾" : "執行設定回滾", item.versionId.slice(0, 12), "success");
      await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "回滾操作失敗"); }
    finally { setActionBusy(""); }
  };

  const sectionNames: Record<string, string> = {
    hosts: "受管主機", alertRules: "告警規則", groups: "權限群組",
    passwordPolicy: "密碼規則", runbookPolicy: "Runbook 政策", formatVersion: "格式版本",
  };
  return (
    <section className="versions-page">
      <div className="card version-heading page-heading">
        <div><small>LOCAL GIT CONFIGURATION HISTORY</small><h2>設定版控</h2><p>重要設定異動會自動建立 Git 版本；快照不包含密碼、私鑰或通知 Token。</p></div>
        {canManage && <button className="create" onClick={() => void snapshot()} disabled={busy}>{busy ? "建立中…" : "建立手動快照"}</button>}
      </div>
      {error && <div className="card log-error">{error}</div>}
      <div className="version-layout">
        <aside className="card version-history">
          <header><small>VERSION HISTORY</small><strong>{versions.length} 個版本</strong></header>
          {versions.map((version) => <button key={version.id} className={selected?.id === version.id ? "active" : ""} onClick={() => void selectVersion(version).catch((reason) => setError(reason instanceof Error ? reason.message : "讀取失敗"))}><span><strong>{version.message}</strong><small>{new Date(version.createdAt).toLocaleString("zh-TW", { hour12: false })} · {version.actor}</small></span><code>{version.shortId}</code></button>)}
        </aside>
        <article className="card version-detail">
          {selected ? <><header><div><small>COMMIT {selected.id.slice(0, 12)}</small><h2>版本內容</h2></div><span>完整性已由 Git 驗證</span></header><div className="changed-sections"><strong>本次異動區塊</strong>{selected.changedSections.map((section) => <span key={section}>{sectionNames[section] || section}</span>)}</div>{canManage && <div className="restore-request-bar"><p>回滾只變更中央設定；執行前會自動建立目前版本快照。</p><button onClick={() => void requestRestore()} disabled={actionBusy === "request"}>{actionBusy === "request" ? "送出中…" : "申請回滾至此版本"}</button></div>}<details open><summary>查看無敏感資料設定快照</summary><pre>{JSON.stringify(selected.snapshot, null, 2)}</pre></details></> : <div className="empty-state page-empty"><strong>尚無設定版本</strong></div>}
        </article>
      </div>
      <section className="card restore-requests"><header><div><small>FOUR-EYES RESTORE WORKFLOW</small><h2>回滾申請</h2></div><span>{restoreRequests.length} 筆</span></header>{restoreRequests.map((item) => <article key={item.id}><div><code>{item.versionId.slice(0, 12)}</code><strong>{item.note || "未填寫回滾原因"}</strong><small>{new Date(item.requestedAt).toLocaleString("zh-TW", { hour12: false })} · 申請者 {item.requestedBy}</small></div><span className={`restore-status ${item.status}`}>{({ pending: "待核准", approved: "已核准", rejected: "已拒絕", applying: "套用中", applied: "已完成", failed: "失敗" } as const)[item.status]}</span><div className="restore-actions">{item.status === "pending" && canManage && item.requestedById !== currentUserId && <><button onClick={() => void restoreAction(item, "reject")}>拒絕</button><button className="secondary-action" onClick={() => void restoreAction(item, "approve")}>核准</button></>}{item.status === "pending" && item.requestedById === currentUserId && <small>等待其他管理者核准</small>}{item.status === "approved" && canManage && <button className="create" onClick={() => void restoreAction(item, "apply")} disabled={actionBusy === `${item.id}:apply`}>{actionBusy === `${item.id}:apply` ? "套用中…" : "執行回滾"}</button>}</div>{(item.result || item.error) && <details><summary>查看結果</summary><pre>{item.error || JSON.stringify(item.result, null, 2)}</pre></details>}</article>)}{!restoreRequests.length && <div className="empty-state"><strong>尚無回滾申請</strong></div>}</section>
    </section>
  );
}

type MaintenanceTask = {
  id: string;
  hostId: string;
  hostName: string;
  runbookId: string;
  title: string;
  commandPreview: string;
  riskLevel: "low" | "medium" | "high";
  approvalPolicy: "single" | "independent";
  verificationMethod: string;
  verificationStatus: "pending" | "passed" | "failed";
  outputSha256?: string | null;
  durationMs?: number | null;
  sourceAlertId?: string | null;
  retryOf?: string | null;
  attempt: number;
  timeoutSeconds: number;
  heartbeatAt?: string | null;
  cancelRequestedAt?: string | null;
  requestNote: string;
  decisionNote: string;
  status: "pending" | "approved" | "queued" | "rejected" | "running" | "succeeded" | "failed" | "cancelled" | "timed_out";
  output?: string | null;
  error?: string | null;
  requestedBy: string;
  approvedBy?: string | null;
  requestedAt: string;
  approvalExpiresAt?: string | null;
  completedAt?: string | null;
};

type MaintenanceReadiness = {
  hostId: string;
  hostName: string;
  address: string;
  status: "ready" | "missing" | "overprivileged" | "unreachable" | "unsupported";
  ready: boolean;
  missingCommands: string[];
  unexpectedGrantCount: number;
  detail: string;
};

function MaintenanceTasks({
  hosts,
  canRequest,
  canApprove,
  canExecute,
  record,
}: {
  hosts: HostRow[];
  canRequest: boolean;
  canApprove: boolean;
  canExecute: boolean;
  record: (type: string, action: string, target?: string, result?: string) => void;
}) {
  const [runbooks, setRunbooks] = useState<SafeRunbook[]>([]);
  const [tasks, setTasks] = useState<MaintenanceTask[]>([]);
  const [hostId, setHostId] = useState(hosts[0]?.id ?? "");
  const runbookRef = useRef<HTMLSelectElement>(null);
  const [selectedRunbookId, setSelectedRunbookId] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [readiness, setReadiness] = useState<MaintenanceReadiness[]>([]);
  const [readinessLoading, setReadinessLoading] = useState(false);
  const [approvalTtlMinutes, setApprovalTtlMinutes] = useState(60);
  const [taskFilter, setTaskFilter] = useState("all");
  const [taskPage, setTaskPage] = useState(1);

  const load = useCallback(async () => {
    const response = await fetch("/api/tasks", { cache: "no-store" });
    const body = (await response.json()) as { runbooks?: SafeRunbook[]; tasks?: MaintenanceTask[]; approvalTtlMinutes?: number; detail?: string };
    if (!response.ok) throw new Error(body.detail || "無法讀取維運任務");
    setRunbooks(body.runbooks ?? []);
    setTasks(body.tasks ?? []);
    setApprovalTtlMinutes(body.approvalTtlMinutes ?? 60);
  }, []);
  const loadReadiness = useCallback(async () => {
    setReadinessLoading(true);
    try {
      const response = await fetch("/api/tasks/readiness", { cache: "no-store" });
      const body = (await response.json()) as { hosts?: MaintenanceReadiness[]; detail?: string };
      if (!response.ok) throw new Error(body.detail || "無法檢查維運權限");
      setReadiness(body.hosts ?? []);
    } finally {
      setReadinessLoading(false);
    }
  }, []);
  useEffect(() => {
    if (!hostId && hosts.length) setHostId(hosts[0].id);
  }, [hostId, hosts]);
  useEffect(() => {
    void load().catch((reason) => setError(reason instanceof Error ? reason.message : "載入失敗"));
  }, [load]);
  useEffect(() => {
    void loadReadiness().catch((reason) => setError(reason instanceof Error ? reason.message : "維運權限檢查失敗"));
  }, [loadReadiness]);

  const createTask = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const runbookId = runbookRef.current?.value ?? "";
    if (!runbookId) {
      setError("請選擇要執行的安全 Runbook");
      return;
    }
    setBusy("create");
    setError("");
    try {
      const response = await fetch("/api/tasks", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ hostId, runbookId, note }),
      });
      const body = (await response.json()) as MaintenanceTask & { detail?: string };
      if (!response.ok) throw new Error(body.detail || "建立任務失敗");
      record("tasks.create", "建立安全維運任務", body.title, "success");
      setNote("");
      await load();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "建立任務失敗");
    } finally {
      setBusy("");
    }
  };

  const transition = async (task: MaintenanceTask, action: "approve" | "reject" | "execute") => {
    let confirmation = "";
    if (action === "execute" && task.riskLevel === "high") {
      confirmation = window.prompt(`「${task.title}」會修改遠端主機。請輸入 EXECUTE 確認執行：`, "")?.trim() ?? "";
      if (!confirmation) return;
      if (confirmation !== "EXECUTE") { setError("確認文字不正確，未執行高風險任務"); return; }
    } else if (action === "execute" && !window.confirm(`確定執行已核准的 Runbook「${task.title}」嗎？`)) return;
    const decisionNote = action === "reject" ? window.prompt("請輸入拒絕原因（可留空）", "") ?? "" : "";
    setBusy(`${task.id}:${action}`);
    setError("");
    try {
      const response = await fetch(`/api/tasks/${encodeURIComponent(task.id)}/${action}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: action === "execute" ? JSON.stringify({ confirmation }) : JSON.stringify({ note: decisionNote }),
      });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "任務操作失敗");
      const labels = { approve: "核准維運任務", reject: "拒絕維運任務", execute: "執行安全維運任務" };
      record(`tasks.${action}`, labels[action], task.title, "success");
      await load();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "任務操作失敗";
      setError(message);
      record(`tasks.${action}`, "維運任務操作失敗", task.title, "failure");
      await load().catch(() => undefined);
    } finally {
      setBusy("");
    }
  };

  const controlTask = async (task: MaintenanceTask, action: "cancel" | "retry") => {
    if (action === "cancel" && !window.confirm(`確定取消「${task.title}」嗎？`)) return;
    setBusy(`${task.id}:${action}`); setError("");
    try {
      const response = await fetch(`/api/tasks/${encodeURIComponent(task.id)}/${action}`, { method: "POST" });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "任務控制失敗");
      record(`tasks.${action}`, action === "cancel" ? "取消維運任務" : "重試維運任務", task.title, "success");
      await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "任務控制失敗"); }
    finally { setBusy(""); }
  };

  const recoverStuck = async () => {
    setBusy("recover"); setError("");
    try {
      const response = await fetch("/api/tasks/recover-stuck", { method: "POST" });
      const body = (await response.json()) as { recovered?: number; detail?: string };
      if (!response.ok) throw new Error(body.detail || "卡住任務回收失敗");
      record("tasks.recover_stuck", "回收卡住的維運任務", `${body.recovered || 0} 筆`, "success"); await load();
    } catch (reason) { setError(reason instanceof Error ? reason.message : "卡住任務回收失敗"); }
    finally { setBusy(""); }
  };

  const selectedRunbook = runbooks.find((item) => item.id === selectedRunbookId);
  const statusText: Record<MaintenanceTask["status"], string> = {
    pending: "待核准", approved: "已核准", queued: "排隊中", rejected: "已拒絕",
    running: "執行中", succeeded: "成功", failed: "失敗", cancelled: "已取消", timed_out: "已逾時",
  };
  const riskText = { low: "低風險", medium: "中風險", high: "高風險" } as const;
  const approvalExpired = (task: MaintenanceTask) => Boolean(task.approvalExpiresAt && new Date(task.approvalExpiresAt).getTime() <= Date.now());
  const filteredTasks = tasks.filter((task) => taskFilter === "all" || task.status === taskFilter);
  const taskPageSize = 8;
  const taskPages = Math.max(1, Math.ceil(filteredTasks.length / taskPageSize));
  const visibleTasks = filteredTasks.slice((taskPage - 1) * taskPageSize, taskPage * taskPageSize);
  return (
    <section className="tasks-page">
      <div className="card task-heading">
        <div className="page-heading">
          <div><small>APPROVED CONTROLLED RUNBOOKS</small><h2>安全維運任務</h2><p>只允許中央預先定義的檢查與修復，不接受任意命令；寫入操作需獨立核准並執行前後驗證。</p></div>
          <div className="heading-actions"><button className="secondary-action" onClick={() => void recoverStuck()} disabled={busy === "recover"}>{busy === "recover" ? "回收中…" : "回收卡住任務"}</button><button className="secondary-action" onClick={() => void loadReadiness().catch((reason) => setError(reason instanceof Error ? reason.message : "維運權限檢查失敗"))} disabled={readinessLoading}>{readinessLoading ? "檢查中…" : "重新檢查權限"}</button></div>
        </div>
        <div className="task-kpis">
          <span><strong>{tasks.filter((item) => item.status === "pending").length}</strong>待核准</span>
          <span><strong>{tasks.filter((item) => item.status === "approved").length}</strong>已核准</span>
          <span><strong>{tasks.filter((item) => item.status === "succeeded").length}</strong>執行成功</span>
          <span><strong>{tasks.filter((item) => item.status === "failed").length}</strong>執行失敗</span>
        </div>
        <div className="task-risk-policy"><span><i className="risk-badge low">低風險</i>單一核准</span><span><i className="risk-badge medium">中風險</i>需由另一位使用者核准</span><span><i className="risk-badge high">高風險</i>固定修復 Runbook＋另一人核准</span><span>核准後 {approvalTtlMinutes} 分鐘內有效</span></div>
        <div className="maintenance-readiness">{readiness.map((item) => <article key={item.hostId} className={item.ready ? "ready" : "blocked"}><span>{item.ready ? "✓" : "!"}</span><div><strong>{item.hostName} · {item.address}</strong><small>{item.detail}{item.missingCommands.length ? ` · 缺少 ${item.missingCommands.length} 條` : ""}</small></div></article>)}{!readiness.length && !readinessLoading && <small>尚未取得主機維運權限狀態</small>}</div>
      </div>
      {canRequest && (
        <form className="card task-request" onSubmit={createTask}>
          <label>目標主機<select value={hostId} onChange={(event) => setHostId(event.target.value)}>{hosts.map((host) => <option key={host.id} value={host.id}>{host.name} · {host.ip}</option>)}</select></label>
          <label>安全 Runbook（共 {runbooks.length} 個）<select ref={runbookRef} name="runbookId" defaultValue="" onChange={(event) => setSelectedRunbookId(event.currentTarget.value)}><option value="" disabled>請選擇 Runbook</option>{runbooks.map((runbook) => <option key={runbook.id} value={runbook.id}>{runbook.mutating ? "[寫入] " : "[唯讀] "}{runbook.title}</option>)}</select></label>
          <label className="task-note">申請說明<input value={note} onChange={(event) => setNote(event.target.value)} maxLength={500} placeholder="例如：確認告警發生後的資源狀態" /></label>
          <button className="create" disabled={!hostId || !selectedRunbookId || busy === "create"}>{busy === "create" ? "建立中…" : "建立待核准任務"}</button>
          {selectedRunbook && <div className="runbook-preview"><div><span className={`risk-badge ${selectedRunbook.risk}`}>{riskText[selectedRunbook.risk]}</span><strong>{selectedRunbook.mutating ? "受控寫入 · " : "唯讀 · "}{selectedRunbook.description}</strong><small>{selectedRunbook.approvalPolicy === "independent" ? "需獨立核准" : "單一核准"} · {selectedRunbook.verification}</small></div><code>{selectedRunbook.commandPreview}</code></div>}
        </form>
      )}
      {error && <div className="card log-error">{error}</div>}
      <div className="list-toolbar card"><label>狀態篩選<select value={taskFilter} onChange={(event) => { setTaskFilter(event.target.value); setTaskPage(1); }}><option value="all">全部狀態</option>{Object.entries(statusText).map(([value,label]) => <option key={value} value={value}>{label}</option>)}</select></label><span>共 {filteredTasks.length} 筆</span></div>
      <div className="task-records">
        {visibleTasks.map((task) => (
          <article className="card task-record" key={task.id}>
            <header><div><small>{task.hostName} · {new Date(task.requestedAt).toLocaleString("zh-TW", { hour12: false })}</small><h3>{task.title}</h3></div><div className="task-badges"><span className={`risk-badge ${task.riskLevel}`}>{riskText[task.riskLevel]}</span><span className={`task-status ${task.status === "approved" && approvalExpired(task) ? "expired" : task.status}`}>{task.status === "approved" && approvalExpired(task) ? "核准過期" : statusText[task.status]}</span></div></header>
            <p>{task.requestNote || "未填寫申請說明"} · 第 {task.attempt || 1} 次{task.retryOf ? "（重試）" : ""}</p>
            <code className="command-preview">{task.commandPreview}</code>
            <dl><div><dt>申請者</dt><dd>{task.requestedBy}</dd></div><div><dt>核准者</dt><dd>{task.approvedBy || "—"}</dd></div><div><dt>核准政策</dt><dd>{task.approvalPolicy === "independent" ? "獨立核准" : "單一核准"}</dd></div><div><dt>核准有效期限</dt><dd>{task.approvalExpiresAt ? new Date(task.approvalExpiresAt).toLocaleString("zh-TW", { hour12: false }) : "—"}</dd></div><div><dt>執行驗證</dt><dd>{task.verificationStatus === "passed" ? "通過" : task.verificationStatus === "failed" ? "失敗" : "尚未執行"}{task.durationMs != null ? ` · ${task.durationMs} ms` : ""}</dd></div></dl>
            {task.decisionNote && <p className="decision-note">審核說明：{task.decisionNote}</p>}
            <div className="task-record-actions">
              {task.status === "pending" && canApprove && <><button onClick={() => void transition(task, "reject")}>拒絕</button><button className="secondary-action" onClick={() => void transition(task, "approve")}>核准</button></>}
              {task.status === "approved" && approvalExpired(task) && <small>核准已過期，請重新建立任務</small>}
              {task.status === "approved" && !approvalExpired(task) && canExecute && <button className="create" onClick={() => void transition(task, "execute")} disabled={busy === `${task.id}:execute`}>{busy === `${task.id}:execute` ? "執行中…" : task.riskLevel === "high" ? "確認並執行高風險任務" : "執行已核准任務"}</button>}
              {["pending","approved","queued","running"].includes(task.status) && canExecute && <button className="danger-action" onClick={() => void controlTask(task,"cancel")} disabled={busy === `${task.id}:cancel`}>{busy === `${task.id}:cancel` ? "取消中…" : "取消任務"}</button>}
              {["failed","timed_out","cancelled"].includes(task.status) && canRequest && <button className="secondary-action" onClick={() => void controlTask(task,"retry")} disabled={busy === `${task.id}:retry`}>{busy === `${task.id}:retry` ? "建立中…" : "安全重試"}</button>}
            </div>
            {(task.output || task.error) && <details><summary>查看執行結果與完整性資訊</summary><p className="verification-method">{task.verificationMethod}{task.outputSha256 && <code>SHA-256 {task.outputSha256}</code>}</p><pre>{task.output || task.error}</pre></details>}
          </article>
        ))}
        {!tasks.length && <div className="card empty-state page-empty"><strong>尚無維運任務</strong><small>從預先定義的安全 Runbook 建立第一筆申請。</small></div>}
      </div>
      {filteredTasks.length > taskPageSize && <div className="pagination"><button disabled={taskPage <= 1} onClick={() => setTaskPage((page) => page - 1)}>上一頁</button><span>{taskPage} / {taskPages}</span><button disabled={taskPage >= taskPages} onClick={() => setTaskPage((page) => page + 1)}>下一頁</button></div>}
    </section>
  );
}

type AccessGroup = {
  id: string;
  name: string;
  permissions: string[];
  systemGroup: boolean;
};
type AccessUser = {
  id: string;
  username: string;
  displayName: string;
  enabled: boolean;
  groups: Array<{ id: string; name: string }>;
};
type PasswordPolicy = {
  minLength: number;
  requireUpper: boolean;
  requireLower: boolean;
  requireNumber: boolean;
  requireSpecial: boolean;
  updatedAt: string;
};
const permissionNames: Record<string, string> = {
  "*": "全部權限",
  "hosts.read": "查看主機",
  "hosts.manage": "管理主機",
  "logs.read": "查詢日誌",
  "terminal.open": "SSH 終端",
  "audit.read": "查看稽核",
  "access.manage": "帳號管理",
  "alerts.read": "查看告警",
  "alerts.manage": "管理告警",
  "backup.read": "查看備份",
  "backup.manage": "執行備份",
  "ai.read": "查看 AI 診斷",
  "ai.manage": "執行 AI 診斷",
  "tasks.read": "查看維運任務",
  "tasks.request": "申請維運任務",
  "tasks.approve": "核准維運任務",
  "tasks.execute": "執行維運任務",
};

function generateTemporaryPassword(policy: PasswordPolicy | null) {
  const sets = ["ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz", "23456789", "!@#$%^&*_-+="];
  const length = Math.max(12, policy?.minLength ?? 12);
  const randomCharacter = (characters: string) => {
    const value = crypto.getRandomValues(new Uint32Array(1))[0];
    return characters[value % characters.length];
  };
  const characters = sets.map(randomCharacter);
  const pool = sets.join("");
  while (characters.length < length) characters.push(randomCharacter(pool));
  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swap = crypto.getRandomValues(new Uint32Array(1))[0] % (index + 1);
    [characters[index], characters[swap]] = [characters[swap], characters[index]];
  }
  return characters.join("");
}

function Access({
  section,
  record,
  currentUserId,
}: {
  section: "users" | "groups";
  record: (
    type: string,
    action: string,
    target?: string,
    result?: string,
  ) => void;
  currentUserId: string;
}) {
  const [users, setUsers] = useState<AccessUser[]>([]);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [policy, setPolicy] = useState<PasswordPolicy | null>(null);
  const [editingUser, setEditingUser] = useState<AccessUser | null>(null);
  const [resetUser, setResetUser] = useState<AccessUser | null>(null);
  const [editingGroup, setEditingGroup] = useState<AccessGroup | null>(null);
  const [addUserOpen, setAddUserOpen] = useState(false);
  const [addGroupOpen, setAddGroupOpen] = useState(false);
  const [policyOpen, setPolicyOpen] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const load = useCallback(async () => {
    const response = await fetch("/api/access", { cache: "no-store" });
    const body = (await response.json()) as {
      users?: AccessUser[];
      groups?: AccessGroup[];
      passwordPolicy?: PasswordPolicy;
      detail?: string;
    };
    if (!response.ok) throw new Error(body.detail || "無法讀取帳號資料");
    setUsers(body.users ?? []);
    setGroups(body.groups ?? []);
    setPolicy(body.passwordPolicy ?? null);
  }, []);
  useEffect(() => {
    void load().catch((reason) =>
      setError(reason instanceof Error ? reason.message : "載入失敗"),
    );
  }, [load]);

  const createUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setNotice("");
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const payload = {
      username: form.get("username"),
      displayName: form.get("displayName"),
      password: form.get("password"),
      groupId: form.get("groupId"),
    };
    const response = await fetch("/api/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = (await response.json()) as { detail?: string };
    if (!response.ok) {
      setError(body.detail || "新增使用者失敗");
      record(
        "access.user.create",
        "新增平台使用者失敗",
        String(payload.username),
        "failure",
      );
      return;
    }
    formElement.reset();
    setAddUserOpen(false);
    setNotice("使用者已建立");
    record(
      "access.user.create",
      "新增平台使用者",
      String(payload.username),
      "success",
    );
    await load();
  };
  const createGroup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setNotice("");
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const payload = {
      name: form.get("name"),
      permissions: form.getAll("permissions"),
    };
    const response = await fetch("/api/groups", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = (await response.json()) as { detail?: string };
    if (!response.ok) {
      setError(body.detail || "新增群組失敗");
      record(
        "access.group.create",
        "新增權限群組失敗",
        String(payload.name),
        "failure",
      );
      return;
    }
    formElement.reset();
    setAddGroupOpen(false);
    setNotice("群組已建立");
    record(
      "access.group.create",
      "新增權限群組",
      String(payload.name),
      "success",
    );
    await load();
  };

  const request = async (path: string, method: string, body?: unknown) => {
    setError("");
    setNotice("");
    const response = await fetch(path, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const payload =
      response.status === 204
        ? {}
        : ((await response.json()) as { detail?: string });
    if (!response.ok) throw new Error(payload.detail || "操作失敗");
    await load();
  };
  const saveUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editingUser) return;
    const form = new FormData(event.currentTarget);
    try {
      await request(`/api/users/${editingUser.id}`, "PUT", {
        displayName: form.get("displayName"),
        groupId: form.get("groupId"),
      });
      record(
        "access.user.update",
        "修改平台使用者",
        editingUser.username,
        "success",
      );
      setEditingUser(null);
      setNotice("使用者資料已更新");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "修改失敗");
    }
  };
  const resetPassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!resetUser) return;
    try {
      await request(`/api/users/${resetUser.id}/reset-password`, "POST", {
        password: generatedPassword,
      });
      record(
        "access.user.password",
        "重設使用者密碼",
        resetUser.username,
        "success",
      );
      setResetUser(null);
      setGeneratedPassword("");
      setNotice(
        resetUser.id === currentUserId
          ? "密碼已更新"
          : "密碼已重設，該使用者的既有 Session 已登出",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "重設失敗");
    }
  };
  const openResetPassword = (user: AccessUser) => {
    setError("");
    setGeneratedPassword(generateTemporaryPassword(policy));
    setResetUser(user);
  };
  const closeResetPassword = () => {
    setResetUser(null);
    setGeneratedPassword("");
  };
  const toggleLock = async (user: AccessUser) => {
    if (
      !window.confirm(
        `確定要${user.enabled ? "鎖定" : "解鎖"} ${user.displayName} 嗎？`,
      )
    )
      return;
    try {
      await request(`/api/users/${user.id}/lock`, "POST", {
        locked: user.enabled,
      });
      record(
        "access.user.lock",
        user.enabled ? "鎖定使用者" : "解鎖使用者",
        user.username,
        "success",
      );
      setNotice(
        user.enabled ? "使用者已鎖定並登出既有 Session" : "使用者已解鎖",
      );
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "操作失敗");
    }
  };
  const removeUser = async (user: AccessUser) => {
    if (
      !window.confirm(
        `確定永久刪除 ${user.displayName}（@${user.username}）嗎？`,
      )
    )
      return;
    try {
      await request(`/api/users/${user.id}`, "DELETE");
      record("access.user.delete", "刪除平台使用者", user.username, "success");
      setNotice("使用者已刪除");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "刪除失敗");
    }
  };
  const saveGroup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editingGroup) return;
    const form = new FormData(event.currentTarget);
    try {
      await request(`/api/groups/${editingGroup.id}`, "PUT", {
        name: form.get("name"),
        permissions: form.getAll("permissions"),
      });
      record(
        "access.group.update",
        "修改權限群組",
        editingGroup.name,
        "success",
      );
      setEditingGroup(null);
      setNotice("群組已更新");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "修改失敗");
    }
  };
  const removeGroup = async (group: AccessGroup) => {
    if (!window.confirm(`確定刪除群組「${group.name}」嗎？`)) return;
    try {
      await request(`/api/groups/${group.id}`, "DELETE");
      record("access.group.delete", "刪除權限群組", group.name, "success");
      setNotice("群組已刪除");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "刪除失敗");
    }
  };
  const savePolicy = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await request("/api/password-policy", "PUT", {
        minLength: Number(form.get("minLength")),
        requireUpper: form.has("requireUpper"),
        requireLower: form.has("requireLower"),
        requireNumber: form.has("requireNumber"),
        requireSpecial: form.has("requireSpecial"),
      });
      record("access.password.policy", "更新密碼規則", undefined, "success");
      setPolicyOpen(false);
      setNotice("密碼規則已更新，會套用到新增使用者與密碼重設");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "更新失敗");
    }
  };

  const permissionChecks = (selected: string[]) =>
    Object.entries(permissionNames)
      .filter(([key]) => key !== "*")
      .map(([key, label]) => (
        <label className="permission-check" key={key}>
          <input
            type="checkbox"
            name="permissions"
            value={key}
            defaultChecked={selected.includes(key)}
          />
          {label}
        </label>
      ));
  return (
    <>
      <section className={`access-page ${section}`}>
        <div className="card page-card">
          <div className="page-heading">
            <div>
              <small>POSTGRESQL RBAC</small>
              <h2>{section === "users" ? "用戶管理" : "群組管理"}</h2>
              <p>
                {section === "users"
                  ? "管理帳號、鎖定狀態、重設密碼與密碼規則。"
                  : "管理群組名稱與平台操作權限。"}
              </p>
            </div>
            <div className="heading-actions">
              {section === "users" && (
                <button
                  className="secondary-action"
                  onClick={() => setPolicyOpen(true)}
                >
                  密碼規則
                </button>
              )}
              <button
                className="create"
                onClick={() =>
                  section === "users"
                    ? setAddUserOpen(true)
                    : setAddGroupOpen(true)
                }
              >
                ＋ {section === "users" ? "新增使用者" : "新增群組"}
              </button>
            </div>
          </div>
          {error && <div className="log-error">{error}</div>}
          {notice && <div className="access-notice">{notice}</div>}
        </div>
        <div className="card access-list user-list">
          <header>
            <small>PLATFORM USERS</small>
            <h2>目前使用者</h2>
          </header>
          <div className="access-columns user-columns" aria-hidden="true">
            <span />
            <span>使用者</span>
            <span>所屬群組</span>
            <span>狀態</span>
            <span>操作</span>
          </div>
          {users.map((user) => (
            <div className="access-row" key={user.id}>
              <span>{user.displayName.slice(0, 1)}</span>
              <div>
                <strong>{user.displayName}</strong>
                <small>@{user.username}</small>
              </div>
              <div className="user-groups">
                <small>所屬群組</small>
                <strong>
                  {user.groups.map((group) => group.name).join("、") ||
                    "尚未加入群組"}
                </strong>
              </div>
              <i className={user.enabled ? "enabled" : ""}>
                {user.enabled ? "啟用" : "鎖定"}
              </i>
              <div className="access-actions">
                <button onClick={() => setEditingUser(user)}>修改</button>
                <button onClick={() => openResetPassword(user)}>
                  {user.id === currentUserId ? "修改密碼" : "重設密碼"}
                </button>
                {user.id !== currentUserId && (
                  <button onClick={() => void toggleLock(user)}>
                    {user.enabled ? "Lock" : "解鎖"}
                  </button>
                )}
                {user.id !== currentUserId && (
                  <button
                    className="danger-action"
                    onClick={() => void removeUser(user)}
                  >
                    刪除
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
        <div className="card access-list group-list">
          <header>
            <small>PERMISSION GROUPS</small>
            <h2>目前群組</h2>
          </header>
          <div className="access-columns group-columns" aria-hidden="true">
            <span>群組名稱</span>
            <span>授予權限</span>
            <span>操作</span>
          </div>
          {[...groups]
            .sort((left, right) => {
              if (left.id === "administrators") return -1;
              if (right.id === "administrators") return 1;
              return left.name.localeCompare(right.name, "zh-Hant");
            })
            .map((group) => (
              <div className="group-row" key={group.id}>
                <div>
                  <strong>{group.name}</strong>
                  <small>
                    {group.id === "administrators"
                      ? "受保護的系統管理員群組"
                      : group.systemGroup
                        ? "系統預設群組"
                        : "自訂群組"}
                  </small>
                </div>
                <p>
                  {group.permissions
                    .map(
                      (permission) => permissionNames[permission] || permission,
                    )
                    .join(" · ")}
                </p>
                {group.id !== "administrators" && (
                  <div className="access-actions">
                    <button onClick={() => setEditingGroup(group)}>
                      修改
                    </button>
                    <button
                      className="danger-action"
                      onClick={() => void removeGroup(group)}
                    >
                      刪除
                    </button>
                  </div>
                )}
              </div>
            ))}
        </div>
      </section>
      {addUserOpen && (
        <div className="modal-layer">
          <form className="modal" onSubmit={createUser}>
            <button
              type="button"
              className="close"
              onClick={() => setAddUserOpen(false)}
            >
              ×
            </button>
            <small>CREATE USER</small>
            <h2>新增使用者</h2>
            <p>填寫完成並按下確認後，才會建立平台帳號。</p>
            <label>
              登入帳號
              <input name="username" minLength={3} autoFocus required />
            </label>
            <label>
              顯示名稱
              <input name="displayName" required />
            </label>
            <label>
              初始密碼
              <input
                data-private
                name="password"
                type="password"
                minLength={policy?.minLength ?? 10}
                autoComplete="new-password"
                required
              />
            </label>
            <label>
              加入群組
              <select name="groupId" required>
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="modal-actions">
              <button type="button" onClick={() => setAddUserOpen(false)}>
                取消
              </button>
              <button className="create">確認新增</button>
            </div>
          </form>
        </div>
      )}
      {addGroupOpen && (
        <div className="modal-layer">
          <form className="modal" onSubmit={createGroup}>
            <button
              type="button"
              className="close"
              onClick={() => setAddGroupOpen(false)}
            >
              ×
            </button>
            <small>CREATE GROUP</small>
            <h2>新增群組</h2>
            <p>設定群組名稱與權限，按下確認後才會建立群組。</p>
            <label>
              群組名稱
              <input name="name" autoFocus required />
            </label>
            <fieldset className="modal-permissions">
              <legend>授予權限</legend>
              {permissionChecks([])}
            </fieldset>
            <div className="modal-actions">
              <button type="button" onClick={() => setAddGroupOpen(false)}>
                取消
              </button>
              <button className="create">確認新增</button>
            </div>
          </form>
        </div>
      )}
      {policyOpen && policy && (
        <div className="modal-layer">
          <form
            className="modal"
            key={policy.updatedAt}
            onSubmit={savePolicy}
          >
            <button
              type="button"
              className="close"
              onClick={() => setPolicyOpen(false)}
            >
              ×
            </button>
            <small>PASSWORD POLICY</small>
            <h2>密碼規則</h2>
            <p>此規則會套用到新增使用者及重設密碼。</p>
            <label>
              最小密碼長度
              <input
                name="minLength"
                type="number"
                min="8"
                max="128"
                defaultValue={policy.minLength}
                required
              />
            </label>
            <fieldset className="modal-permissions">
              <legend>必要字元</legend>
              <label className="permission-check">
                <input
                  type="checkbox"
                  name="requireUpper"
                  defaultChecked={policy.requireUpper}
                />
                英文大寫 A-Z
              </label>
              <label className="permission-check">
                <input
                  type="checkbox"
                  name="requireLower"
                  defaultChecked={policy.requireLower}
                />
                英文小寫 a-z
              </label>
              <label className="permission-check">
                <input
                  type="checkbox"
                  name="requireNumber"
                  defaultChecked={policy.requireNumber}
                />
                數字 0-9
              </label>
              <label className="permission-check">
                <input
                  type="checkbox"
                  name="requireSpecial"
                  defaultChecked={policy.requireSpecial}
                />
                特殊符號
              </label>
            </fieldset>
            <div className="modal-actions">
              <button type="button" onClick={() => setPolicyOpen(false)}>
                取消
              </button>
              <button className="create">儲存密碼規則</button>
            </div>
          </form>
        </div>
      )}
      {editingUser && (
        <div className="modal-layer">
          <form className="modal" onSubmit={saveUser}>
            <button
              type="button"
              className="close"
              onClick={() => setEditingUser(null)}
            >
              ×
            </button>
            <small>EDIT USER</small>
            <h2>修改使用者</h2>
            <p>@{editingUser.username}</p>
            <label>
              顯示名稱
              <input
                name="displayName"
                defaultValue={editingUser.displayName}
                required
              />
            </label>
            <label>
              群組
              <select
                name="groupId"
                defaultValue={editingUser.groups[0]?.id}
                required
              >
                {groups.map((group) => (
                  <option key={group.id} value={group.id}>
                    {group.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="modal-actions">
              <button type="button" onClick={() => setEditingUser(null)}>
                取消
              </button>
              <button className="create">儲存修改</button>
            </div>
          </form>
        </div>
      )}
      {resetUser && (
        <div className="modal-layer">
          <form className="modal" onSubmit={resetPassword}>
            <button
              type="button"
              className="close"
              onClick={closeResetPassword}
            >
              ×
            </button>
            <small>RESET PASSWORD</small>
            <h2>重設密碼</h2>
            <p>
              系統已為 {resetUser.displayName}（@{resetUser.username}）產生
              {Math.max(12, policy?.minLength ?? 12)} 碼臨時密碼。按下確認前，原密碼不會變更。
            </p>
            <label>
              新的臨時密碼
              <input
                data-private
                type="text"
                value={generatedPassword}
                readOnly
              />
            </label>
            <button
              type="button"
              className="secondary-action"
              onClick={() =>
                setGeneratedPassword(generateTemporaryPassword(policy))
              }
            >
              重新產生密碼
            </button>
            <div className="modal-actions">
              <button type="button" onClick={closeResetPassword}>
                取消
              </button>
              <button className="create">確認重設密碼</button>
            </div>
          </form>
        </div>
      )}
      {editingGroup && (
        <div className="modal-layer">
          <form className="modal" onSubmit={saveGroup}>
            <button
              type="button"
              className="close"
              onClick={() => setEditingGroup(null)}
            >
              ×
            </button>
            <small>EDIT GROUP</small>
            <h2>修改群組</h2>
            <label>
              群組名稱
              <input name="name" defaultValue={editingGroup.name} required />
            </label>
            <fieldset className="modal-permissions">
              <legend>授予權限</legend>
              {permissionChecks(editingGroup.permissions)}
            </fieldset>
            <div className="modal-actions">
              <button type="button" onClick={() => setEditingGroup(null)}>
                取消
              </button>
              <button className="create">儲存修改</button>
            </div>
          </form>
        </div>
      )}
    </>
  );
}

function AddHostModal({
  close,
  onCreated,
  record,
}: {
  close: () => void;
  onCreated: () => Promise<void>;
  record: (
    type: string,
    action: string,
    target?: string,
    result?: string,
  ) => void;
}) {
  const [mode, setMode] = useState<"automatic" | "existing">("automatic");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [inspection, setInspection] = useState<{
    target: string;
    hostname: string;
    fingerprint: string;
  } | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const base = {
      name: String(form.get("name") || ""),
      address: String(form.get("address") || ""),
      port: Number(form.get("port") || 22),
      group: String(form.get("group") || "LAB / MANAGED"),
    };
    const target = `${base.address}:${base.port}`;
    record(
      "hosts.create.request",
      mode === "automatic" ? "提交主機自動佈署" : "提交已設定主機",
      base.address,
      "requested",
    );
    try {
      if (mode === "automatic" && inspection?.target !== target) {
        const inspectResponse = await fetch("/api/hosts/bootstrap/inspect", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            address: base.address,
            port: base.port,
            adminUser: String(form.get("adminUser") || ""),
            password: String(form.get("password") || ""),
          }),
        });
        const inspectBody = (await inspectResponse.json()) as {
          detail?: string;
          hostname?: string;
          fingerprint?: string;
        };
        if (!inspectResponse.ok || !inspectBody.fingerprint)
          throw new Error(inspectBody.detail || "首次 SSH 驗證失敗");
        setInspection({
          target,
          hostname: inspectBody.hostname || base.name,
          fingerprint: inspectBody.fingerprint,
        });
        record(
          "hosts.bootstrap.fingerprint",
          "取得待確認 SSH 主機指紋",
          base.address,
          "success",
        );
        return;
      }

      const endpoint =
        mode === "automatic" ? "/api/hosts/bootstrap" : "/api/hosts";
      const payload =
        mode === "automatic"
          ? {
              ...base,
              adminUser: String(form.get("adminUser") || ""),
              password: String(form.get("password") || ""),
              expectedFingerprint: inspection?.fingerprint,
            }
          : { ...base, user: String(form.get("user") || "linux-agent") };
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = (await response.json()) as { detail?: string };
      if (!response.ok) throw new Error(body.detail || "新增主機失敗");
      record(
        "hosts.create.complete",
        mode === "automatic" ? "自動佈署並新增主機成功" : "新增主機成功",
        base.address,
        "success",
      );
      await onCreated();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "新增主機失敗";
      setError(message);
      record("hosts.create.complete", "新增主機失敗", base.address, "failure");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-layer" role="presentation">
      <form
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label="新增 Linux 主機"
        onSubmit={submit}
      >
        <button
          type="button"
          className="close"
          aria-label="關閉新增主機"
          onClick={close}
        >
          ×
        </button>
        <small>SSH VERIFIED ENROLLMENT</small>
        <h2>新增 Linux 主機</h2>
        <div className="mode-tabs">
          <button
            type="button"
            className={mode === "automatic" ? "selected" : ""}
            onClick={() => {
              setMode("automatic");
              setInspection(null);
              setError("");
            }}
          >
            自動佈署
          </button>
          <button
            type="button"
            className={mode === "existing" ? "selected" : ""}
            onClick={() => {
              setMode("existing");
              setInspection(null);
              setError("");
            }}
          >
            已有 linux-agent
          </button>
        </div>
        <p>
          {mode === "automatic"
            ? "使用一次性 sudo 帳號建立 linux-agent、安裝中央公鑰並設定日誌權限。密碼不會保存。"
            : "使用已設定的中央金鑰與 known_hosts 驗證，成功後寫入 PostgreSQL。"}
        </p>
        {error && <div className="modal-error">{error}</div>}
        {inspection && (
          <div className="fingerprint">
            <small>請核對第三台主機上的 SSH 指紋</small>
            <strong>{inspection.hostname}</strong>
            <code>{inspection.fingerprint}</code>
            <span>確認一致後，再按一次下方按鈕完成佈署。</span>
          </div>
        )}
        <label>
          顯示名稱
          <input name="name" placeholder="server-3" required />
        </label>
        <label>
          IP 位址
          <input
            name="address"
            inputMode="decimal"
            placeholder="192.168.0.154"
            required
          />
        </label>
        <div className="form-pair">
          <label>
            SSH Port
            <input
              name="port"
              type="number"
              min="1"
              max="65535"
              defaultValue="22"
              required
            />
          </label>
          {mode === "automatic" ? (
            <label>
              首次設定帳號
              <input name="adminUser" placeholder="nickc" required />
            </label>
          ) : (
            <label>
              SSH 帳號
              <input name="user" defaultValue="linux-agent" required />
            </label>
          )}
        </div>
        {mode === "automatic" && (
          <label>
            首次設定密碼
            <input
              data-private
              name="password"
              type="password"
              autoComplete="new-password"
              required
            />
          </label>
        )}
        <label>
          主機群組
          <input name="group" defaultValue="LAB / MANAGED" required />
        </label>
        <div className="modal-actions">
          <button type="button" onClick={close}>
            取消
          </button>
          <button className="create" type="submit" disabled={saving}>
            {saving
              ? "正在處理…"
              : mode === "automatic"
                ? inspection
                  ? "確認指紋並佈署"
                  : "連線並檢查指紋"
                : "驗證並新增"}
          </button>
        </div>
      </form>
    </div>
  );
}

function TerminalModal({
  host,
  close,
  record,
}: {
  host: HostRow;
  close: () => void;
  record: (
    type: string,
    action: string,
    target?: string,
    result?: string,
  ) => void;
}) {
  const mount = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState("正在建立 SSH 連線…");

  useEffect(() => {
    if (!mount.current) return;
    record("terminal.open", "開啟 SSH 終端連線", host.name, "requested");
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontSize: 13,
      fontFamily: "var(--font-mono), ui-monospace, monospace",
      theme: {
        background: "#08110e",
        foreground: "#c7ded4",
        cursor: "#b8f243",
        selectionBackground: "#2c5947",
      },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(mount.current);
    fit.fit();
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(
      `${protocol}//${window.location.host}/api/hosts/${encodeURIComponent(host.id)}/terminal`,
    );
    socket.binaryType = "arraybuffer";
    const sendSize = () => {
      if (socket.readyState === WebSocket.OPEN)
        socket.send(
          JSON.stringify({
            type: "resize",
            cols: terminal.cols,
            rows: terminal.rows,
          }),
        );
    };
    socket.onmessage = (event) => {
      if (typeof event.data !== "string") {
        terminal.write(new Uint8Array(event.data));
        return;
      }
      const message = JSON.parse(event.data) as {
        type?: string;
        detail?: string;
      };
      if (message.type === "ready") {
        setStatus(`已連線：linux-agent@${host.ip}`);
        record("terminal.ready", "SSH 終端連線成功", host.name, "success");
        sendSize();
      }
      if (message.type === "error") {
        setStatus(`連線失敗：${message.detail || "未知錯誤"}`);
        record("terminal.error", "SSH 終端連線失敗", host.name, "failure");
      }
    };
    socket.onerror = () => setStatus("WebSocket 連線失敗");
    socket.onclose = () =>
      setStatus((current) =>
        current.startsWith("連線失敗") ? current : "SSH 連線已關閉",
      );
    const input = terminal.onData((data) => {
      if (socket.readyState === WebSocket.OPEN)
        socket.send(JSON.stringify({ type: "input", data }));
    });
    const observer = new ResizeObserver(() => {
      fit.fit();
      sendSize();
    });
    observer.observe(mount.current);
    return () => {
      observer.disconnect();
      input.dispose();
      socket.close();
      terminal.dispose();
      record("terminal.close", "關閉 SSH 終端連線", host.name, "success");
    };
  }, [host, record]);

  return (
    <div className="modal-layer terminal-layer" role="presentation">
      <section
        className="terminal-modal"
        role="dialog"
        aria-modal="true"
        aria-label={`${host.name} SSH 終端`}
      >
        <header>
          <div>
            <small>WEB SSH CONSOLE</small>
            <strong>{host.name}</strong>
            <span>{status}</span>
          </div>
          <button aria-label="關閉 SSH 終端" onClick={close}>
            ×
          </button>
        </header>
        <div className="terminal-security">
          終端內容與按鍵不寫入 UI 稽核；連線開啟、成功、失敗與關閉會保留紀錄。
        </div>
        <div ref={mount} className="terminal-screen" data-private />
      </section>
    </div>
  );
}
