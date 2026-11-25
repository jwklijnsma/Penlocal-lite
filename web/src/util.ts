import { SEVS, type Counts, type Job } from "./types";

export function ago(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return "never";
  const s = Math.max(0, now - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function dur(s: number | null | undefined): string {
  if (s == null) return "";
  s = Math.round(s);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(s / 3600)}h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")}m`;
}

export function size(n: number | null | undefined): string {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

export function total(c: Counts | null | undefined): number {
  return c ? SEVS.reduce((a, s) => a + (c[s] || 0), 0) : 0;
}

export function plural(n: number, word: string, many = word + "s"): string {
  return `${n} ${n === 1 ? word : many}`;
}

export function kindLabel(j: Pick<Job, "kind">): string {
  return j.kind === "plan" ? "Plan" : j.kind === "demo" ? "Demo" : "Engagement";
}

export function jobElapsed(j: Job, now = Date.now() / 1000): number | null {
  if (!j.started) return null;
  return (j.finished ?? now) - j.started;
}

export function statusText(j: Job): string {
  const p = j.progress;
  switch (j.status) {
    case "queued":
      return j.position ? `waiting · #${j.position} in the queue` : "waiting";
    case "running":
      if (j.pending_approvals) return `waiting for your approval (${j.pending_approvals})`;
      if (p.phase === "plan") return "planning: building the threat model";
      if (p.phase === "execute") {
        const runs = p.runs > 1 ? `run ${p.run}/${p.runs} · ` : "";
        return `${runs}task ${Math.min(p.started, p.total || p.started)}/${p.total || "?"} · ${plural(p.commands, "command")}`;
      }
      if (p.phase === "verify") return `verifying ${plural(p.candidates, "candidate")} against the audit log`;
      if (p.phase === "assess") return "assessing: dedupe, chains, score";
      return "running";
    case "done":
      if (j.kind === "plan") return `plan ready · ${plural(j.summary.tasks ?? 0, "task")}`;
      return `${plural(j.summary.findings ?? 0, "finding")} · score ${j.summary.score ?? 0}`;
    case "stopped":
      return "emergency stop" + (j.summary.findings != null ? ` · ${plural(j.summary.findings, "finding")} so far` : "");
    case "cancelled":
      return "cancelled before it started";
    case "interrupted":
      return "interrupted (server restart)";
    case "failed":
      return "failed";
  }
}

export function progressPct(j: Job): number | null {
  if (!["queued", "running"].includes(j.status)) return 100;
  if (j.status === "queued") return 0;
  const p = j.progress;
  // plan 0-10%, execute 10-85%, verify 85-95%, assess 95-100%
  if (p.phase === "plan") return null;
  if (p.phase === "execute" && p.total) return 10 + Math.round((75 * Math.max(0, p.started - 1)) / p.total);
  if (p.phase === "verify") return 88;
  if (p.phase === "assess") return 96;
  return null;
}

export function dotClass(j: Job): string {
  if (j.status === "running") return j.pending_approvals ? "wait" : "run";
  if (j.status === "queued") return "wait";
  if (j.status === "done") return "ok";
  if (j.status === "failed" || j.status === "stopped") return "bad";
  return "";
}

export function logClass(text: string): string {
  const s = text.trim();
  if (s.startsWith("$ ")) return "l-cmd";
  if (/^\[(error|stop)\]/.test(s)) return "l-bad";
  if (/^\[approval\]/.test(s)) return "l-warn";
  if (/^\[candidate\]/.test(s)) return "l-ok";
  if (/^\[(planner|verifier|assessor|run |web)/.test(s)) return "l-head";
  return "";
}

/** Read and write per-browser conveniences; storage can be missing or throw. */
export function stored<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem("penlocal:" + key);
    return v === null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}
export function store(key: string, value: unknown): void {
  try {
    localStorage.setItem("penlocal:" + key, JSON.stringify(value));
  } catch {
    /* private mode etc. */
  }
}
