import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, ApiError, enc } from "../api";
import { go, href, useApp } from "../store";
import type { ExplainResult, Job, ScopeDetail } from "../types";
import { ago, dotClass, dur, jobElapsed, kindLabel, plural, statusText, stored, store } from "../util";
import { SevBar } from "./Chrome";

const TABS = [
  ["overview", "Overview"],
  ["guardrail", "Guardrail"],
  ["edit", "Edit scope"],
] as const;

export function ScopePage({ id, tab }: { id: string; tab: string }) {
  const { handleError, jobVersion } = useApp();
  const [scope, setScope] = useState<ScopeDetail | null>(null);
  const [missing, setMissing] = useState(false);
  const load = useCallback(async () => {
    try {
      setScope(await api<ScopeDetail>(`scopes/${enc(id)}`));
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setMissing(true);
      else handleError(err);
    }
  }, [id, handleError]);
  const versions = Object.values(jobVersion).reduce((a, b) => a + b, 0);
  useEffect(() => {
    load();
  }, [load, versions]);

  if (missing) return <div className="empty"><h3>No scope called {id}</h3><p>It may have been renamed or removed from the scopes folder.</p></div>;
  if (!scope) return null;
  const eng = (scope.summary?.engagement || {}) as Record<string, string>;
  return (
    <>
      <div className="repo-head">
        <div className="repo-title">
          <h1>{scope.id}</h1>
          <div className="repo-sub">
            <span>{eng.client || "no client set"}</span>
            {eng.window && <span>window <code>{String(eng.window)}</code></span>}
            {eng.authorized_by ? <span>authorized by <code>{String(eng.authorized_by)}</code></span> : <span className="hint-warn">no authorized_by</span>}
            <span className="path mono">{scope.file}</span>
          </div>
        </div>
      </div>
      <div className="tabs" role="tablist">
        {TABS.map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} onClick={() => go({ page: "scope", id, tab: k })}>
            {label}
            {k === "overview" && scope.runs.length > 0 && <span className="count">{scope.runs.length}</span>}
          </button>
        ))}
      </div>
      {tab === "edit" ? (
        <ScopeEditor scope={scope} onSaved={(s) => setScope(s)} />
      ) : tab === "guardrail" ? (
        <Guardrail scopeId={scope.id} />
      ) : (
        <Overview scope={scope} />
      )}
    </>
  );
}

function Preflight({ errors, warnings }: { errors: string[]; warnings: string[] }) {
  if (!errors.length && !warnings.length) return <div className="callout">Pre-flight passes: the scope is bounded and the config is sane.</div>;
  return (
    <>
      {errors.length > 0 && (
        <div className="callout bad">
          <b>Runs are refused until this is fixed:</b>
          <ul className="errors">{errors.map((e) => <li key={e}>{e}</li>)}</ul>
        </div>
      )}
      {warnings.length > 0 && (
        <div className="callout warn">
          <ul className="plain">{warnings.map((w) => <li key={w}>{w}</li>)}</ul>
        </div>
      )}
    </>
  );
}

function Overview({ scope }: { scope: ScopeDetail }) {
  const s = scope.summary;
  const eng = (s?.engagement || {}) as Record<string, string>;
  return (
    <>
      <Preflight errors={scope.errors} warnings={scope.warnings} />
      {s && (
        <div className="grid-2">
          <div className="card">
            <div className="card-head"><h3>In scope</h3><span className="muted small">{plural(s.in_scope.length, "entry", "entries")}</span></div>
            <div className="card-body">
              <ul className="target-list">{s.in_scope.map((t) => <li key={t} className="mono">{t}</li>)}</ul>
              {s.clusters.length > 0 && (
                <>
                  <h4 className="mini-head">Cluster contexts</h4>
                  <ul className="target-list">{s.clusters.map((t) => <li key={t} className="mono">{t}</li>)}</ul>
                </>
              )}
            </div>
          </div>
          <div className="card">
            <div className="card-head"><h3>Out of scope</h3><span className="muted small">wins over in scope</span></div>
            <div className="card-body">
              {s.out_of_scope.length ? <ul className="target-list out">{s.out_of_scope.map((t) => <li key={t} className="mono">{t}</li>)}</ul> : <p className="muted small tight">Nothing excluded.</p>}
              {eng.goals && (
                <>
                  <h4 className="mini-head">Goals</h4>
                  <p className="small tight">{String(eng.goals)}</p>
                </>
              )}
            </div>
          </div>
        </div>
      )}
      <RunForm scope={scope} />
      <RunList runs={scope.runs} />
    </>
  );
}

export function RunList({ runs }: { runs: Job[] }) {
  if (!runs.length) return null;
  return (
    <div className="card">
      <div className="card-head"><h3>Runs</h3></div>
      <ul className="dl-list">
        {runs.map((j) => (
          <li key={j.id}>
            <a className="run-row" href={href({ page: "run", id: j.id, tab: "live" })}>
              <span className={"dot " + dotClass(j)} />
              <span className="run-row-main">
                <b>{kindLabel(j)}</b> <span className="muted small mono">{j.id}</span>
                <span className="small muted block">{ago(j.created)}{j.started ? ` · ${dur(jobElapsed(j))}` : ""} · {j.options.runs}× · {j.options.toolpacks.join(", ")}{j.operator ? ` · ${j.operator}` : ""}</span>
              </span>
              <span className="run-row-status small">{statusText(j)}<SevBar counts={j.summary.severity_counts} /></span>
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

function RunForm({ scope }: { scope: ScopeDetail }) {
  const { status: st, keys, startJob, operator, setOperator } = useApp();
  const [kind, setKind] = useState<"run" | "plan">("run");
  const d = st?.defaults;
  const [runs, setRuns] = useState(() => stored("runs", d?.runs ?? 1));
  const [workers, setWorkers] = useState(() => stored("workers", d?.workers ?? 1));
  const [runner, setRunner] = useState(() => stored("runner", d?.runner ?? "local"));
  const [packs, setPacks] = useState<string[]>(() => stored("packs:" + scope.id, d?.toolpacks ?? ["web"]));
  const [steps, setSteps] = useState(() => stored("steps", d?.max_steps ?? 12));
  const [models, setModels] = useState<Record<string, string>>({});
  const [context, setContext] = useState("");
  const [contexts, setContexts] = useState<{ path: string; name: string }[]>([]);
  const [key, setKey] = useState("");
  const [auto, setAuto] = useState(false);
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState<string[]>([]);
  useEffect(() => {
    if (st?.context_roots.length) api<{ contexts: { path: string; name: string }[] }>("contexts").then((r) => setContexts(r.contexts)).catch(() => {});
  }, [st?.context_roots.length]);
  if (!st) return null;
  const togglePack = (p: string) => setPacks((cur) => (cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p]));
  const authOk = kind === "plan" || phrase.trim() === st.auth_phrase;
  const blocked = scope.errors.length > 0 && kind === "run";
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setRefused([]);
    store("runs", runs);
    store("workers", workers);
    store("runner", runner);
    store("steps", steps);
    store("packs:" + scope.id, packs);
    const job = await startJob({
      kind, scope_id: scope.id, authorized: kind === "run" ? phrase.trim() : undefined,
      options: { runs, workers, runner, toolpacks: packs, max_steps: steps, models, context, key, auto_approve: auto },
    });
    setBusy(false);
    if (job) {
      setPhrase("");
      go({ page: "run", id: job.id, tab: "live" });
    }
  };
  return (
    <form className="card run-form" onSubmit={submit}>
      <div className="card-head">
        <h3>Start</h3>
        <div className="seg">
          <button type="button" aria-pressed={kind === "run"} onClick={() => setKind("run")}>Engagement</button>
          <button type="button" aria-pressed={kind === "plan"} onClick={() => setKind("plan")}>Plan only</button>
        </div>
        <span className="muted small">{kind === "run" ? "plan → execute → verify → assess → report" : "threat model and task list; no command runs"}</span>
      </div>
      <div className="opt-grid">
        <fieldset>
          <legend>Tool packs</legend>
          {Object.entries(st.toolpacks).map(([p, desc]) => (
            <label key={p} className="check" title={desc}>
              <input type="checkbox" checked={packs.includes(p)} onChange={() => togglePack(p)} /> <b>{p}</b> <span className="muted small ellip">{desc}</span>
            </label>
          ))}
          {packs.includes("openshift") && !packs.includes("kubernetes") && <p className="muted small">openshift includes kubernetes.</p>}
        </fieldset>
        {kind === "run" && (
          <fieldset>
            <legend>Scale</legend>
            <div className="field-row">
              <label className="field"><span title="Repeat the whole task set and merge the candidates">Runs (merged)</span>
                <input type="number" min={1} max={st.limits.runs} value={runs} onChange={(e) => setRuns(Math.max(1, +e.target.value || 1))} /></label>
              <label className="field"><span>Workers</span>
                <input type="number" min={1} max={st.limits.workers} value={workers} onChange={(e) => setWorkers(Math.max(1, +e.target.value || 1))} /></label>
            </div>
            <div className="field-row">
              <label className="field"><span>Runner</span>
                <select value={runner} onChange={(e) => setRunner(e.target.value)}>
                  <option value="local">local (subprocess)</option>
                  <option value="docker" disabled={!st.tools.docker}>docker (fresh box per task){st.tools.docker ? "" : " · not found"}</option>
                </select></label>
              <label className="field"><span>Max steps / task</span>
                <input type="number" min={1} max={50} value={steps} onChange={(e) => setSteps(Math.max(1, +e.target.value || 1))} /></label>
            </div>
            {workers > 1 && runner === "local" && <p className="hint-warn small">Several workers on the local runner run commands side by side on this host.</p>}
          </fieldset>
        )}
        <fieldset>
          <legend>Models</legend>
          {(kind === "run" ? (["planner", "executor", "verifier", "assessor"] as const) : (["planner"] as const)).map((role) => (
            <label key={role} className="field field-inline"><span>{role}</span>
              <select value={models[role] || ""} onChange={(e) => setModels({ ...models, [role]: e.target.value })}>
                <option value="">{st.roles[role].model} (config)</option>
                {st.models.filter((m) => m !== st.roles[role].model).map((m) => <option key={m} value={m}>{m}</option>)}
              </select></label>
          ))}
          {kind === "run" && (models.verifier || st.roles.verifier.model) === (models.executor || st.roles.executor.model) && st.backend !== "mock" && (
            <p className="hint-warn small">Pick a different family for the verifier.</p>
          )}
        </fieldset>
        <fieldset>
          <legend>Extras</legend>
          <label className="field"><span>White-box source context</span>
            <select value={context} onChange={(e) => setContext(e.target.value)} disabled={!contexts.length}>
              <option value="">{contexts.length ? "none (black-box)" : "off (start with --context-root)"}</option>
              {contexts.map((c) => <option key={c.path} value={c.path}>{c.name}</option>)}
            </select></label>
          {kind === "run" && (
            <label className="field"><span>Score against answer key</span>
              <select value={key} onChange={(e) => setKey(e.target.value)} disabled={!keys.length}>
                <option value="">{keys.length ? "no" : "no answer keys in the scopes folder"}</option>
                {keys.map((k) => <option key={k.id} value={k.id}>{k.id} ({k.count})</option>)}
              </select></label>
          )}
          {kind === "run" && st.allow_auto_approve && (
            <label className="check hint-warn"><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Auto-approve risky steps (lab only)</label>
          )}
        </fieldset>
      </div>
      {kind === "run" && (
        <div className="auth-box">
          <p className="small">
            You must have <b>explicit, written authorization</b> to test every target in this scope. The harness enforces scope, blocks destructive commands,
            logs everything and gates risky steps behind your approval, but staying inside the law and the engagement is on you.
          </p>
          <div className="field-row">
            <label className="field"><span>Operator (recorded in the audit log)</span>
              <input value={operator} onChange={(e) => setOperator(e.target.value)} placeholder="your name" autoComplete="name" /></label>
            <label className="field"><span>Type <code>{st.auth_phrase}</code> to continue</span>
              <input value={phrase} onChange={(e) => setPhrase(e.target.value)} className="mono" spellCheck={false} autoComplete="off" /></label>
          </div>
        </div>
      )}
      {refused.length > 0 && <ul className="errors">{refused.map((r) => <li key={r}>{r}</li>)}</ul>}
      <div className="form-actions">
        {blocked && <span className="hint-warn small">Fix the pre-flight errors first.</span>}
        <button className="btn primary" type="submit" disabled={busy || !authOk || blocked || !packs.length}>
          {busy ? "Starting…" : kind === "run" ? "Start engagement" : "Build plan"}
        </button>
      </div>
    </form>
  );
}

const DECISION_LABEL = { allow: "ALLOW", approve: "APPROVE", deny: "DENY" } as const;

export function Guardrail({ scopeId }: { scopeId: string }) {
  const { status: st, handleError } = useApp();
  const [cmds, setCmds] = useState(() =>
    stored("explain:" + scopeId, "nmap -sV 10.10.10.5\ncurl http://google.com\nhydra -l admin 10.10.10.5 ssh\nkubectl get pods -A\nkubectl delete namespace prod"),
  );
  const [packs, setPacks] = useState<string[]>(() => stored("packs:" + scopeId, st?.defaults.toolpacks ?? ["web"]));
  const [res, setRes] = useState<{ results: ExplainResult[]; toolpacks: string[] } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    store("explain:" + scopeId, cmds);
    try {
      setRes(await api("explain", { method: "POST", body: { scope_id: scopeId, toolpacks: packs, commands: cmds } }));
    } catch (err) {
      handleError(err);
    }
    setBusy(false);
  };
  const counts = res ? res.results.reduce((a, r) => ({ ...a, [r.decision]: (a[r.decision] || 0) + 1 }), {} as Record<string, number>) : {};
  return (
    <>
      <p className="muted section-intro">
        See exactly what the policy will allow, deny or hold for approval, without running a single command. Same rules as a real run, including the tool-pack policy.
      </p>
      <div className="card">
        <div className="card-body">
          <div className="filters">
            {st && Object.keys(st.toolpacks).map((p) => (
              <label key={p} className="check inline">
                <input type="checkbox" checked={packs.includes(p)} onChange={() => setPacks((c) => (c.includes(p) ? c.filter((x) => x !== p) : [...c, p]))} /> {p}
              </label>
            ))}
          </div>
          <label className="field"><span>Commands, one per line (# for comments)</span>
            <textarea className="cmd-input" rows={7} value={cmds} onChange={(e) => setCmds(e.target.value)} spellCheck={false}
              onKeyDown={(e) => (e.ctrlKey || e.metaKey) && e.key === "Enter" && run()} /></label>
          <div className="form-actions">
            {res && <span className="muted small">{(["allow", "approve", "deny"] as const).map((d) => `${counts[d] || 0} ${d}`).join(" · ")}</span>}
            <button className="btn primary" onClick={run} disabled={busy}>Classify <span className="kbd">Ctrl+⏎</span></button>
          </div>
        </div>
      </div>
      {res && (
        <div className="card">
          <ul className="verdicts">
            {res.results.map((r, i) => (
              <li key={i} className={"verdict v-" + r.decision}>
                <span className="v-tag">{DECISION_LABEL[r.decision]}</span>
                <div>
                  <code className="v-cmd">{r.command}</code>
                  <div className="small muted">↳ {r.reason}{r.targets.length ? <> · targets <span className="mono">{r.targets.join(", ")}</span></> : null}</div>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

const TEMPLATE = `# Engagement scope: only targets listed here are touched; everything else is denied.
in_scope:
  - 10.10.10.0/24
  - staging.example.internal

out_of_scope:
  - 10.10.10.1          # gateway: never touch

# For Kubernetes / OpenShift: in-scope kubeconfig contexts
# clusters:
#   - staging

engagement:
  client: "Example B.V."
  goals: >
    Identify auth, access-control and injection issues in the staging web app.
  authorized_by: "jane.doe@example.com"
  window: "2026-12-01 / 2026-12-05"

# Extra patterns, appended to the built-in defaults:
# denylist:
#   - "\\\\bsome-forbidden-tool\\\\b"
# risky:
#   - "\\\\bcustom-write-action\\\\b"
`;

function ScopeEditor({ scope, onSaved }: { scope: ScopeDetail; onSaved: (s: ScopeDetail) => void }) {
  const { handleError, refreshScopes, toast } = useApp();
  const [text, setText] = useState(scope.text);
  const [busy, setBusy] = useState(false);
  const dirty = text !== scope.text;
  useEffect(() => setText(scope.text), [scope.text]);
  const save = async () => {
    setBusy(true);
    try {
      const s = await api<ScopeDetail>(`scopes/${enc(scope.id)}`, { method: "POST", body: { text, modified: scope.modified } });
      onSaved(s);
      refreshScopes();
      toast({ text: `Saved ${s.file}.`, kind: "ok" });
    } catch (err) {
      handleError(err);
    }
    setBusy(false);
  };
  return (
    <>
      <p className="muted section-intro">This file is the guardrail. It is stored as <code>{scope.file}</code> in the scopes folder; runs take a copy when they start.</p>
      <div className="card">
        <div className="card-body">
          <textarea className="yaml-editor" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} rows={24}
            onKeyDown={(e) => (e.ctrlKey || e.metaKey) && e.key === "s" && (e.preventDefault(), save())} />
          <div className="form-actions">
            {dirty && <button className="btn" onClick={() => setText(scope.text)}>Revert</button>}
            <button className="btn primary" disabled={!dirty || busy} onClick={save}>Save <span className="kbd">Ctrl+S</span></button>
          </div>
        </div>
      </div>
      <Preflight errors={scope.errors} warnings={scope.warnings} />
    </>
  );
}

export function NewScope() {
  const { handleError, refreshScopes } = useApp();
  const [name, setName] = useState("");
  const [text, setText] = useState(TEMPLATE);
  const [busy, setBusy] = useState(false);
  const valid = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api(`scopes/${enc(name)}`, { method: "POST", body: { text, create: true } });
      await refreshScopes();
      go({ page: "scope", id: name, tab: "overview" });
    } catch (err) {
      handleError(err);
    }
    setBusy(false);
  };
  return (
    <form onSubmit={save}>
      <h1 className="page-title">New scope</h1>
      <p className="muted section-intro">The scope is the contract: <code>in_scope</code> lists what may be touched, <code>out_of_scope</code> wins over it, and anything a command targets outside it is denied before it runs.</p>
      <div className="card">
        <div className="card-body">
          <label className="field"><span>Name (file name in the scopes folder)</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="acme-staging-2026q4" className="mono" autoFocus required /></label>
          {name && !valid && <p className="hint-warn small">Letters, digits, dot, dash and underscore only.</p>}
          <textarea className="yaml-editor" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} rows={26} />
          <div className="form-actions">
            <a className="btn" href="#/">Cancel</a>
            <button className="btn primary" disabled={!valid || busy}>Create scope</button>
          </div>
        </div>
      </div>
    </form>
  );
}
