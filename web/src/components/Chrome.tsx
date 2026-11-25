import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, AuthError } from "../api";
import { go, useApp, type PendingApproval } from "../store";
import { isActive } from "../types";

function Popover({ label, dot, children, title }: { label: ReactNode; dot: string; children: ReactNode; title?: string }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => box.current && !box.current.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", away);
    window.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      window.removeEventListener("keydown", esc);
    };
  }, [open]);
  return (
    <div className="model-picker" ref={box}>
      <button className="pill pill-button" aria-expanded={open} onClick={() => setOpen(!open)} title={title}>
        <span className={"dot " + dot} />
        {label}
        <span className="caret">▾</span>
      </button>
      {open && <div className="popover" role="dialog">{children}</div>}
    </div>
  );
}

export function TopBar() {
  const { status: st, jobs, approvals, stopAll } = useApp();
  const active = jobs.filter(isActive);
  const running = active.find((j) => j.status === "running");
  const [confirm, setConfirm] = useState(false);
  useEffect(() => {
    if (!confirm) return;
    const t = window.setTimeout(() => setConfirm(false), 4000);
    return () => window.clearTimeout(t);
  }, [confirm]);
  const roles = st ? Object.entries(st.roles) : [];
  const missing = roles.filter(([, r]) => !r.available).length;
  const tools = st ? Object.entries(st.tools) : [];
  const haveTools = tools.filter(([, ok]) => ok).length;
  return (
    <header className="topbar">
      <a className="brand" href="#/">
        <img src="/favicon.svg" alt="" /> PenLocal-lite <small>{st ? "v" + st.version : ""}</small>
      </a>
      <div className="status-pills">
        {st && (
          <>
            <Popover dot={!st.reachable ? "bad" : missing ? "warn" : "ok"} title={st.backend_error || st.endpoint}
              label={st.reachable ? `${st.backend}${missing ? ` · ${missing} model${missing > 1 ? "s" : ""} missing` : ""}` : `${st.backend} unreachable`}>
              <h3>Brain</h3>
              <p className="muted small">
                Backend <code>{st.backend}</code> at <code>{st.endpoint}</code>. Set in the config file, never from the browser.
              </p>
              {!st.reachable && <p className="hint-warn small">{st.backend_error}</p>}
              <table className="kv">
                <tbody>
                  {roles.map(([role, r]) => (
                    <tr key={role}>
                      <th>{role}</th>
                      <td className="mono">{r.model}</td>
                      <td><span className={"dot " + (r.available ? "ok" : "bad")} title={r.available ? "available" : "not found on the backend"} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {st.roles.verifier.model === st.roles.executor.model && st.backend !== "mock" && (
                <p className="hint-warn small">Verifier and executor use the same model: a different family catches more hallucinated findings.</p>
              )}
              {missing > 0 && st.backend === "ollama" && (
                <p className="muted small">On the Ollama machine: <code>ollama pull {roles.find(([, r]) => !r.available)?.[1].model}</code></p>
              )}
            </Popover>
            <Popover dot={st.runner === "docker" && !st.tools.docker ? "bad" : "ok"} label={`${st.runner} runner · ${haveTools}/${tools.length} tools`}>
              <h3>Sandbox</h3>
              <p className="muted small">
                Runner <code>{st.runner}</code>{st.runner === "docker" ? <> (image <code>{st.docker_image}</code>, a fresh container per task)</> : " (subprocess on this host: run the server from a throwaway VM)"}.
                Tools found on the server's PATH:
              </p>
              <div className="tool-grid">
                {tools.map(([t, ok]) => (
                  <span key={t} className={"tool " + (ok ? "on" : "off")}>{t}</span>
                ))}
              </div>
            </Popover>
          </>
        )}
        {approvals.length > 0 && (
          <a className="pill keep approvals-pill" href="#approvals" onClick={(e) => { e.preventDefault(); document.getElementById("approvals")?.scrollIntoView({ behavior: "smooth" }); }}>
            <span className="dot wait" /> {approvals.length} approval{approvals.length > 1 ? "s" : ""} needed
          </a>
        )}
        <button className={"pill keep jobs-pill" + (active.length ? " busy" : "")} onClick={() => running ? go({ page: "run", id: running.id, tab: "live" }) : go({ page: "home" })}>
          <span className={"dot " + (running ? "run" : active.length ? "wait" : "ok")} />
          {running ? `Running: ${running.scope_name}` : active.length ? "Waiting" : "Idle"}
          {active.length > 1 && <span className="count-badge">+{active.length - 1}</span>}
        </button>
        {active.length > 0 && (
          <button className={"btn small stop-btn" + (confirm ? " armed" : "")} onClick={() => (confirm ? (setConfirm(false), stopAll()) : setConfirm(true))}
            title="Emergency stop: halt every run before its next command">
            ■ {confirm ? "Click again to stop all" : "STOP ALL"}
          </button>
        )}
      </div>
    </header>
  );
}

/** Fixed dock with every risky step that waits for a human, on every page. */
export function ApprovalDock({ hideJob }: { hideJob?: string }) {
  const { approvals: all, decide, status } = useApp();
  // On a run's own page its approvals are shown inline already.
  const approvals = all.filter((a) => a.job.id !== hideJob);
  const [now, setNow] = useState(Date.now() / 1000);
  useEffect(() => {
    if (!approvals.length) return;
    const t = window.setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => window.clearInterval(t);
  }, [approvals.length]);
  if (!approvals.length) return null;
  return (
    <section className="approval-dock" id="approvals" aria-live="assertive">
      <header>
        <strong>Approval needed</strong>
        <span className="muted small">The run is paused on this step. Nothing runs until you decide{status?.approval_timeout ? `; no answer counts as Deny` : ""}.</span>
      </header>
      {approvals.slice(0, 4).map((a) => <ApprovalCard key={a.id} a={a} now={now} onDecide={decide} />)}
      {approvals.length > 4 && <p className="muted small">+{approvals.length - 4} more waiting</p>}
    </section>
  );
}

function ApprovalCard({ a, now, onDecide }: { a: PendingApproval; now: number; onDecide: (a: PendingApproval, ok: boolean) => void }) {
  const left = a.expires ? Math.max(0, Math.round(a.expires - now)) : null;
  return (
    <div className="approval">
      <div className="approval-main">
        <div className="small muted">
          <a href={`#/run/${encodeURIComponent(a.job.id)}`}>{a.job.scope_name}</a> · {a.reason}
        </div>
        <pre className="approval-cmd">$ {a.command}</pre>
      </div>
      <div className="approval-actions">
        {left !== null && <span className="muted small mono" title="Seconds until this is declined automatically">{Math.floor(left / 60)}:{String(left % 60).padStart(2, "0")}</span>}
        <button className="btn small" onClick={() => onDecide(a, false)}>Deny</button>
        <button className="btn small primary" onClick={() => onDecide(a, true)}>Approve &amp; run</button>
      </div>
    </div>
  );
}

export function Login() {
  const { setAuthed, refreshStatus } = useApp();
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      await api("login", { method: "POST", body: { token } });
      setToken("");
      setAuthed(true);
      refreshStatus();
    } catch (err) {
      setError(err instanceof AuthError ? "Wrong token." : (err as Error).message);
    }
  };
  return (
    <div className="center-box">
      <img src="/favicon.svg" alt="" width={44} height={44} />
      <h1>Access token needed</h1>
      <p>Open the link that <code>penlocal serve</code> printed in the terminal, or paste the token here.</p>
      <form onSubmit={submit}>
        <input type="password" placeholder="token" autoComplete="off" required autoFocus value={token} onChange={(e) => setToken(e.target.value)} />
        <button className="btn primary" type="submit">Sign in</button>
      </form>
      <div className="form-error">{error}</div>
    </div>
  );
}

export function Toasts() {
  const { toasts, dismiss } = useApp();
  if (!toasts.length) return null;
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={"toast" + (t.kind ? " " + t.kind : "")}>
          <span>{t.text}</span>
          {t.link && (t.link.href ? (
            <a href={t.link.href} onClick={() => dismiss(t.id)}>{t.link.label}</a>
          ) : (
            <button className="linklike" onClick={() => { t.link!.onClick?.(); dismiss(t.id); }}>{t.link.label}</button>
          ))}
          <button className="toast-x" onClick={() => dismiss(t.id)} aria-label="Dismiss">✕</button>
        </div>
      ))}
    </div>
  );
}

export function SevBar({ counts }: { counts?: Partial<Record<string, number>> }) {
  const sevs = ["critical", "high", "medium", "low", "info"];
  const n = sevs.reduce((a, s) => a + (counts?.[s] || 0), 0);
  if (!n) return null;
  return (
    <div className="sevbar" aria-hidden>
      {sevs.map((s) => (counts?.[s] ? <span key={s} style={{ width: `${(100 * (counts[s] || 0)) / n}%`, background: `var(--sev-${s})` }} /> : null))}
    </div>
  );
}
