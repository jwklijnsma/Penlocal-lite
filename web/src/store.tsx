import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, ApiError, AuthError, enc } from "./api";
import { isActive, type Approval, type Job, type KeyItem, type ScopeItem, type Status } from "./types";
import { kindLabel, plural } from "./util";

export interface Toast {
  id: number;
  text: string;
  link?: { label: string; href?: string; onClick?: () => void };
  kind?: "ok" | "bad";
}

/** An approval together with the run it belongs to. */
export interface PendingApproval extends Approval {
  job: Job;
}

interface Ctx {
  authed: boolean | null;
  setAuthed: (v: boolean) => void;
  status: Status | null;
  scopes: ScopeItem[];
  keys: KeyItem[];
  jobs: Job[];
  approvals: PendingApproval[];
  /** Bumped per run whenever it changes state, so open pages reload their data. */
  jobVersion: Record<string, number>;
  toasts: Toast[];
  toast: (t: Omit<Toast, "id">, ms?: number) => void;
  dismiss: (id: number) => void;
  refreshScopes: () => Promise<void>;
  refreshJobs: () => Promise<void>;
  refreshStatus: () => Promise<void>;
  startJob: (body: Record<string, unknown>) => Promise<Job | null>;
  stopJob: (id: string) => Promise<void>;
  stopAll: () => Promise<void>;
  decide: (a: PendingApproval, approve: boolean) => Promise<void>;
  operator: string;
  setOperator: (v: string) => void;
  handleError: (err: unknown) => void;
}

const AppContext = createContext<Ctx | null>(null);

export function useApp(): Ctx {
  const c = useContext(AppContext);
  if (!c) throw new Error("useApp outside AppProvider");
  return c;
}

// ------------------------------------------------------------------ routing

export type Route =
  | { page: "home" }
  | { page: "new" }
  | { page: "scope"; id: string; tab: string }
  | { page: "run"; id: string; tab: string };

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (parts[0] === "new") return { page: "new" };
  if (parts[0] === "scope" && parts[1]) return { page: "scope", id: parts[1], tab: parts[2] || "overview" };
  if (parts[0] === "run" && parts[1]) return { page: "run", id: parts[1], tab: parts[2] || "live" };
  return { page: "home" };
}

export function href(r: Route): string {
  switch (r.page) {
    case "home":
      return "#/";
    case "new":
      return "#/new";
    case "scope":
      return `#/scope/${enc(r.id)}${r.tab && r.tab !== "overview" ? "/" + r.tab : ""}`;
    case "run":
      return `#/run/${enc(r.id)}${r.tab && r.tab !== "live" ? "/" + r.tab : ""}`;
  }
}

export function go(r: Route): void {
  location.hash = href(r);
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseRoute(location.hash));
  useEffect(() => {
    const on = () => setRoute(parseRoute(location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

// ------------------------------------------------------------------ provider

let toastSeq = 0;

export function AppProvider({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [scopes, setScopes] = useState<ScopeItem[]>([]);
  const [keys, setKeys] = useState<KeyItem[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [jobVersion, setJobVersion] = useState<Record<string, number>>({});
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [operator, setOperatorState] = useState<string>(() => {
    try {
      return localStorage.getItem("penlocal:operator") || "";
    } catch {
      return "";
    }
  });
  const prev = useRef<Map<string, string>>(new Map());

  const setOperator = useCallback((v: string) => {
    setOperatorState(v);
    try {
      localStorage.setItem("penlocal:operator", v);
    } catch {
      /* ignore */
    }
  }, []);

  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const toast = useCallback(
    (t: Omit<Toast, "id">, ms = 6000) => {
      const id = ++toastSeq;
      setToasts((list) => [...list.slice(-3), { ...t, id }]);
      window.setTimeout(() => dismiss(id), ms);
    },
    [dismiss],
  );

  const handleError = useCallback(
    (err: unknown) => {
      if (err instanceof AuthError) return setAuthed(false);
      let text = (err as Error)?.message || String(err);
      if (err instanceof ApiError && Array.isArray(err.data?.errors)) text += ": " + err.data.errors.join(" · ");
      toast({ text, kind: "bad" }, 9000);
    },
    [toast],
  );

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api<Status>("status"));
      setAuthed(true);
    } catch (err) {
      if (err instanceof AuthError) setAuthed(false);
    }
  }, []);

  const refreshScopes = useCallback(async () => {
    try {
      const r = await api<{ scopes: ScopeItem[]; keys: KeyItem[] }>("scopes");
      setScopes(r.scopes);
      setKeys(r.keys);
    } catch (err) {
      if (err instanceof AuthError) setAuthed(false);
    }
  }, []);

  const refreshJobs = useCallback(async () => {
    try {
      const r = await api<{ jobs: Job[] }>("jobs");
      setJobs(r.jobs);
      // Toast when a run finishes, bump versions so open pages reload.
      const bumped: string[] = [];
      for (const j of r.jobs) {
        const key = `${j.status}:${j.pending_approvals}`;
        const before = prev.current.get(j.id);
        if (before !== undefined && before !== key) bumped.push(j.id);
        if (before && before.startsWith("running") && !isActive(j)) {
          const ok = j.status === "done";
          toast({
            text: `${kindLabel(j)} on ${j.scope_name} ${ok ? "finished" : j.status}${ok && j.kind !== "plan" ? `: ${plural(j.summary.findings ?? 0, "finding")}` : ""}.`,
            kind: ok ? "ok" : "bad",
            link: { label: "Open", onClick: () => go({ page: "run", id: j.id, tab: j.kind === "plan" ? "plan" : "findings" }) },
          }, 10000);
        }
        prev.current.set(j.id, key);
      }
      if (bumped.length) setJobVersion((v) => {
        const n = { ...v };
        for (const id of bumped) n[id] = (n[id] || 0) + 1;
        return n;
      });
      // Pull the pending approvals of every run that has some.
      const waiting = r.jobs.filter((j) => j.pending_approvals > 0);
      const lists = await Promise.all(
        waiting.map((j) => api<{ approvals: Approval[] }>(`jobs/${enc(j.id)}?since=999999999`).then((d) => d.approvals.map((a) => ({ ...a, job: j }))).catch(() => [])),
      );
      setApprovals(lists.flat());
    } catch (err) {
      if (err instanceof AuthError) setAuthed(false);
    }
  }, [toast]);

  // First load + polling: fast while something runs, slow when idle.
  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);
  useEffect(() => {
    if (!authed) return;
    refreshScopes();
    refreshJobs();
  }, [authed, refreshScopes, refreshJobs]);
  const busy = jobs.some(isActive);
  useEffect(() => {
    if (!authed) return;
    const t = window.setInterval(refreshJobs, busy ? 1500 : 8000);
    return () => window.clearInterval(t);
  }, [authed, busy, refreshJobs]);
  useEffect(() => {
    if (!authed) return;
    const t = window.setInterval(refreshStatus, 20000);
    return () => window.clearInterval(t);
  }, [authed, refreshStatus]);

  // The tab title shouts when a human is needed.
  useEffect(() => {
    document.title = approvals.length ? `(${approvals.length}) Approval needed · PenLocal-lite` : "PenLocal-lite";
  }, [approvals.length]);

  const startJob = useCallback(
    async (body: Record<string, unknown>) => {
      try {
        const job = await api<Job>("jobs", { method: "POST", body: { operator, ...body } });
        await refreshJobs();
        return job;
      } catch (err) {
        handleError(err);
        return null;
      }
    },
    [operator, refreshJobs, handleError],
  );

  const stopJob = useCallback(
    async (id: string) => {
      try {
        await api(`jobs/${enc(id)}/stop`, { method: "POST" });
        toast({ text: "Emergency stop sent. No further commands will run.", kind: "bad" });
        await refreshJobs();
      } catch (err) {
        handleError(err);
      }
    },
    [refreshJobs, handleError, toast],
  );

  const stopAll = useCallback(async () => {
    try {
      const r = await api<{ stopped: number }>("stop-all", { method: "POST" });
      toast({ text: `Emergency stop: ${plural(r.stopped, "run")} halted.`, kind: "bad" });
      await refreshJobs();
    } catch (err) {
      handleError(err);
    }
  }, [refreshJobs, handleError, toast]);

  const decide = useCallback(
    async (a: PendingApproval, approve: boolean) => {
      setApprovals((list) => list.filter((x) => x.id !== a.id));
      try {
        await api(`jobs/${enc(a.job.id)}/approvals/${enc(a.id)}`, { method: "POST", body: { approve, operator } });
      } catch (err) {
        handleError(err);
      }
      refreshJobs();
    },
    [operator, refreshJobs, handleError],
  );

  return (
    <AppContext.Provider
      value={{
        authed, setAuthed, status, scopes, keys, jobs, approvals, jobVersion, toasts, toast, dismiss,
        refreshScopes, refreshJobs, refreshStatus, startJob, stopJob, stopAll, decide, operator, setOperator, handleError,
      }}
    >
      {children}
    </AppContext.Provider>
  );
}
