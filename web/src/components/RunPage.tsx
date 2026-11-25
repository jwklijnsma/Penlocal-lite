import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, enc, fileUrl } from "../api";
import { go, useApp } from "../store";
import { SEVS, isActive, type AuditEntry, type Benchmark, type Finding, type JobDetail, type Report, type Sev, type ThreatModel } from "../types";
import { ago, dotClass, dur, jobElapsed, kindLabel, logClass, plural, progressPct, size, statusText } from "../util";

const PHASES = ["plan", "execute", "verify", "assess"] as const;

export function RunPage({ id, tab }: { id: string; tab: string }) {
  const { handleError, jobVersion, stopJob, decide, approvals } = useApp();
  const [job, setJob] = useState<JobDetail | null>(null);
  const [missing, setMissing] = useState(false);
  const logRef = useRef<{ lines: JobDetail["log"]; next: number }>({ lines: [], next: 0 });
  const [, force] = useState(0);

  const load = useCallback(async () => {
    try {
      const d = await api<JobDetail>(`jobs/${enc(id)}?since=${logRef.current.next}`);
      if (logRef.current.next === 0 || d.log_next < logRef.current.next) logRef.current = { lines: d.log, next: d.log_next };
      else logRef.current = { lines: [...logRef.current.lines, ...d.log].slice(-20000), next: d.log_next };
      setJob(d);
      force((n) => n + 1);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setMissing(true);
      else handleError(err);
    }
  }, [id, handleError]);

  useEffect(() => {
    logRef.current = { lines: [], next: 0 };
    setJob(null);
    setMissing(false);
  }, [id]);
  useEffect(() => {
    load();
  }, [load, jobVersion[id]]);
  const active = job ? isActive(job) : false;
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(load, 1000);
    return () => window.clearInterval(t);
  }, [active, load]);

  if (missing) return <div className="empty"><h3>No such run</h3><p>It may have been deleted.</p></div>;
  if (!job) return null;
  const hasReport = job.downloads.some((d) => d.name === "report.json");
  const hasPlan = job.downloads.some((d) => d.name === "threat_model.json");
  const mine = approvals.filter((a) => a.job.id === job.id);
  const tabs: [string, string, number | null][] = [
    ["live", active ? "Live" : "Log", null],
    ["findings", "Findings", hasReport ? job.summary.findings ?? 0 : null],
    ["plan", "Plan", hasPlan ? job.summary.tasks ?? 0 : null],
    ["audit", "Audit log", null],
    ["benchmark", "Benchmark", null],
    ["files", "Downloads", job.downloads.length],
  ];
  const visible = tabs.filter(([k]) => (k === "findings" || k === "benchmark" ? job.kind !== "plan" : true));
  const el = jobElapsed(job);
  return (
    <>
      <div className="repo-head">
        <div className="repo-title">
          <h1><span className={"dot big " + dotClass(job)} /> {kindLabel(job)} · <a href={job.scope_id === "_demo" ? "#/" : `#/scope/${enc(job.scope_id)}`}>{job.scope_name}</a></h1>
          <div className="repo-sub">
            <span className="mono">{job.id}</span>
            <span>{ago(job.created)}{el != null ? ` · ${dur(el)}` : ""}</span>
            <span>{job.options.runs}× · {job.options.workers} worker{job.options.workers > 1 ? "s" : ""} · {job.options.runner} · {job.options.toolpacks.join(", ")}</span>
            {job.operator && <span>operator {job.operator}</span>}
          </div>
        </div>
        <div className="actions">
          {active && <button className="btn stop-btn" onClick={() => stopJob(job.id)}>■ Emergency stop</button>}
          {!active && <DeleteRun id={job.id} />}
        </div>
      </div>
      <div className="tabs" role="tablist">
        {visible.map(([k, label, n]) => (
          <button key={k} role="tab" aria-selected={tab === k} onClick={() => go({ page: "run", id, tab: k })}>
            {label}{n != null && <span className="count">{n}</span>}
          </button>
        ))}
      </div>
      {tab === "findings" ? <Findings job={job} /> :
        tab === "plan" ? <Plan job={job} /> :
        tab === "audit" ? <Audit job={job} /> :
        tab === "benchmark" ? <BenchmarkTab job={job} /> :
        tab === "files" ? <Files job={job} /> : (
        <>
          <StatusCard job={job} />
          {mine.length > 0 && (
            <div className="card approvals-inline">
              <div className="card-head"><h3>Waiting for you</h3></div>
              <div className="card-body">
                {mine.map((a) => (
                  <div className="approval" key={a.id}>
                    <div className="approval-main">
                      <div className="small muted">{a.reason}</div>
                      <pre className="approval-cmd">$ {a.command}</pre>
                    </div>
                    <div className="approval-actions">
                      <button className="btn small" onClick={() => decide(a, false)}>Deny</button>
                      <button className="btn small primary" onClick={() => decide(a, true)}>Approve &amp; run</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          <LogView lines={logRef.current.lines} follow={active} />
        </>
      )}
    </>
  );
}

function DeleteRun({ id }: { id: string }) {
  const { handleError, refreshJobs } = useApp();
  const [armed, setArmed] = useState(false);
  return (
    <button className="btn danger small" onBlur={() => setArmed(false)} onClick={async () => {
      if (!armed) return setArmed(true);
      try {
        await api(`jobs/${enc(id)}/delete`, { method: "POST" });
        await refreshJobs();
        history.back();
      } catch (err) {
        handleError(err);
      }
    }}>{armed ? "Delete run + audit log?" : "Delete"}</button>
  );
}

function StatusCard({ job }: { job: JobDetail }) {
  const pct = progressPct(job);
  const p = job.progress;
  const phaseIdx = PHASES.indexOf(p.phase as (typeof PHASES)[number]);
  const done = !isActive(job);
  return (
    <div className={"card job-card " + (job.status === "done" ? "done" : ["failed", "stopped"].includes(job.status) ? "failed" : "")}>
      <div className="card-head">
        <div className="job-status">
          <span className={"dot " + dotClass(job)} />
          <strong>{statusText(job)}</strong>
        </div>
        <span className="muted small" style={{ marginLeft: "auto" }}>{job.status}</span>
      </div>
      <div className="card-body">
        {job.kind !== "plan" && (
          <ol className="phases">
            {PHASES.map((ph, i) => (
              <li key={ph} className={done && job.status === "done" ? "done" : i < phaseIdx ? "done" : i === phaseIdx ? "now" : ""}>{ph}</li>
            ))}
            <li className={job.status === "done" ? "done" : ""}>report</li>
          </ol>
        )}
        <div className={"progress" + (pct === null ? " indeterminate" : job.status === "queued" ? " waiting" : "")}><div style={pct === null ? undefined : { width: pct + "%" }} /></div>
        <div className="progress-meta">
          <span>{plural(p.tasks, "task")}{p.runs > 1 ? ` × ${p.runs} runs` : ""}</span>
          <span>{plural(p.commands, "command")}</span>
          <span>{plural(p.candidates, "candidate")}</span>
          {job.summary.findings != null && <span>{plural(job.summary.findings, "verified finding")} · score {job.summary.score}</span>}
          {job.summary.benchmark && <span>recall {(job.summary.benchmark.recall * 100).toFixed(0)}% vs {job.summary.benchmark.key}</span>}
        </div>
        {job.error && <p className="errors">{job.error}</p>}
        {done && job.status === "done" && job.kind !== "plan" && (
          <div className="form-actions left">
            <button className="btn primary small" onClick={() => go({ page: "run", id: job.id, tab: "findings" })}>View findings</button>
            <a className="btn small" href={fileUrl(job.id, "report.html")}>Report (HTML)</a>
            <a className="btn small" href={fileUrl(job.id, "report.md")}>Report (Markdown)</a>
          </div>
        )}
      </div>
    </div>
  );
}

function LogView({ lines, follow }: { lines: JobDetail["log"]; follow: boolean }) {
  const ref = useRef<HTMLPreElement>(null);
  const stick = useRef(true);
  useEffect(() => {
    const el = ref.current;
    if (el && follow && stick.current) el.scrollTop = el.scrollHeight;
  }, [lines.length, follow]);
  return (
    <pre className="log tall" ref={ref} onScroll={(e) => {
      const el = e.currentTarget;
      stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    }}>
      {lines.length === 0 ? <span className="muted">Waiting for output…</span> : lines.map((l, i) => (
        <div key={i} className={logClass(l.text)}>{l.text}</div>
      ))}
    </pre>
  );
}

// ------------------------------------------------------------------ findings

function useResults(job: JobDetail) {
  const { handleError } = useApp();
  const [data, setData] = useState<{ report: Report | null; threat_model: ThreatModel | null } | null>(null);
  const [none, setNone] = useState(false);
  const ready = job.downloads.map((d) => d.name).join(",");
  useEffect(() => {
    api<{ report: Report | null; threat_model: ThreatModel | null }>(`jobs/${enc(job.id)}/results`)
      .then((d) => { setData(d); setNone(false); })
      .catch((err) => (err instanceof ApiError && err.status === 404 ? setNone(true) : handleError(err)));
  }, [job.id, ready, handleError]);
  return { data, none };
}

function Findings({ job }: { job: JobDetail }) {
  const { data, none } = useResults(job);
  const [sevs, setSevs] = useState<Set<Sev>>(new Set(SEVS));
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  if (none || (data && !data.report)) return <div className="empty"><h3>No findings yet</h3><p>{isActive(job) ? "They appear once the verifier and assessor are done." : "This run produced no report."}</p></div>;
  if (!data?.report) return null;
  const r = data.report;
  const counts = r.summary.severity_counts || {};
  const ql = q.trim().toLowerCase();
  const list = r.findings
    .filter((f) => sevs.has(f.severity))
    .filter((f) => !ql || `${f.title} ${f.description} ${f.component} ${f.cwe}`.toLowerCase().includes(ql))
    .sort((a, b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity));
  const byId = new Map(r.findings.map((f) => [f.id, f]));
  return (
    <>
      <div className="summary-row">
        {SEVS.map((s) => (
          <button key={s} className="sev-chip" aria-pressed={sevs.has(s)} onClick={() => {
            const n = new Set(sevs);
            if (n.has(s)) n.delete(s); else n.add(s);
            setSevs(n.size ? n : new Set(SEVS));
          }}>
            <span className="n">{counts[s] || 0}</span>
            <span className="l"><span className="sw" style={{ background: `var(--sev-${s})` }} />{s}</span>
          </button>
        ))}
        <div className="meta-chip">
          <div><b className="big-num">{r.summary.weighted_score}</b> weighted risk score</div>
          <div>{r.summary.duplicates_removed} duplicate{r.summary.duplicates_removed === 1 ? "" : "s"} merged · {job.summary.rejected ?? 0} rejected by the verifier</div>
        </div>
      </div>
      {r.chains.length > 0 && (
        <div className="card chains">
          <div className="card-head"><h3>Attack chains</h3><span className="muted small">findings that compound</span></div>
          <div className="card-body"><ul className="notes">
            {r.chains.map((c, i) => (
              <li key={i}>
                <span className={"sev sev-" + c.combined_severity}>{c.combined_severity}</span> <b>{c.name}</b>
                <p className="small tight">{c.explanation}</p>
                <div className="small muted">{c.finding_ids.map((fid) => byId.get(fid)?.title || fid).join(" → ")}</div>
              </li>
            ))}
          </ul></div>
        </div>
      )}
      <div className="filters">
        <input type="search" placeholder="Search findings" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {list.length === 0 ? (
        <div className="empty"><h3>{r.findings.length ? "Nothing matches the filter" : "No verified findings"}</h3>
          {!r.findings.length && <p>Every candidate was rejected or none were raised. One run of a local model misses a lot: try more runs.</p>}</div>
      ) : (
        <div className="file-group">
          {list.map((f) => <FindingRow key={f.id} job={job} f={f} open={open === f.id} onToggle={() => setOpen(open === f.id ? null : f.id)} />)}
        </div>
      )}
    </>
  );
}

function FindingRow({ job, f, open, onToggle }: { job: JobDetail; f: Finding; open: boolean; onToggle: () => void }) {
  return (
    <div className="finding">
      <button onClick={onToggle} aria-expanded={open}>
        <span className={"sev sev-" + f.severity}>{f.severity}</span>
        <span className="lineno">{f.cwe || "·"}</span>
        <span className="f-main">
          <span className="f-rule">{f.component}</span>
          <span className="f-msg">{f.title}</span>
        </span>
      </button>
      {open && (
        <div className="f-detail">
          <p className="pre-wrap">{f.description}</p>
          {f.recommendation && <div className="sugg"><b>Recommendation</b>{f.recommendation}</div>}
          {f.verifier_notes && <div className="facts"><span>Verifier: {f.verifier_notes}</span></div>}
          <Evidence jobId={job.id} ids={f.evidence_ids} />
        </div>
      )}
    </div>
  );
}

function Evidence({ jobId, ids }: { jobId: string; ids: string[] }) {
  const [entries, setEntries] = useState<Record<string, AuditEntry> | null>(null);
  useEffect(() => {
    if (!ids.length) return setEntries({});
    api<{ entries: Record<string, AuditEntry> }>(`jobs/${enc(jobId)}/evidence?ids=${enc(ids.join(","))}`).then((r) => setEntries(r.entries)).catch(() => setEntries({}));
  }, [jobId, ids.join(",")]);
  if (!ids.length) return <p className="hint-warn small">No evidence ids cited.</p>;
  if (!entries) return <p className="muted small">Loading evidence…</p>;
  return (
    <div className="evidence">
      <div className="mini-head">Evidence from the audit log</div>
      {ids.map((eid) => {
        const e = entries[eid];
        if (!e) return <div key={eid} className="hint-warn small mono">{eid}: missing from the audit log</div>;
        return <CommandBlock key={eid} e={e} />;
      })}
    </div>
  );
}

function CommandBlock({ e }: { e: AuditEntry }) {
  return (
    <div className="cmd-block">
      <div className="cmd-head mono">
        <span className="muted">{e.id}</span>
        <span className="cmd-text">$ {e.command}</span>
        <span className={"exit " + (e.exit_code === 0 ? "ok" : "bad")}>exit {e.exit_code}</span>
        {e.approved_by && e.approved_by !== "auto" && <span className="tag">{e.approved_by}</span>}
        <span className="muted">{e.duration_s != null ? `${e.duration_s}s` : ""}</span>
      </div>
      {(e.stdout || e.stderr) && (
        <pre className="code cmd-out">{e.stdout}{e.stderr ? <span className="l-warn">{(e.stdout ? "\n" : "") + "[stderr]\n" + e.stderr}</span> : null}</pre>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ plan

function Plan({ job }: { job: JobDetail }) {
  const { data, none } = useResults(job);
  if (none || (data && !data.threat_model)) return <div className="empty"><h3>No plan yet</h3><p>The planner is still working.</p></div>;
  if (!data?.threat_model) return null;
  const tm = data.threat_model;
  const classes = [...new Set(tm.tasks.map((t) => t.attack_class))];
  return (
    <>
      <div className="card">
        <div className="card-head"><h3>Threat model</h3><span className="muted small">{plural(tm.assets.length, "asset")} · {plural(tm.tasks.length, "task")} · {plural(classes.length, "attack class", "attack classes")}</span></div>
        <div className="card-body">
          <p className="tight">{tm.summary}</p>
          <div className="tool-grid">{tm.assets.map((a) => <span key={a} className="tool on">{a}</span>)}</div>
        </div>
      </div>
      <div className="card">
        <table className="tasks">
          <thead><tr><th>#</th><th>Component</th><th>Attack class</th><th>Objective</th></tr></thead>
          <tbody>
            {tm.tasks.map((t, i) => (
              <tr key={t.id}>
                <td className="num">{i + 1}</td>
                <td>{t.component}</td>
                <td><code>{t.attack_class}</code></td>
                <td>{t.objective}{t.rationale && <div className="small muted">{t.rationale}</div>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

// ------------------------------------------------------------------ audit

function Audit({ job }: { job: JobDetail }) {
  const { handleError } = useApp();
  const [kind, setKind] = useState("");
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [data, setData] = useState<{ total: number; counts: Record<string, number>; entries: AuditEntry[] } | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());
  const limit = 100;
  const active = isActive(job);
  const tick = active ? job.progress.commands : 0;
  useEffect(() => {
    const t = window.setTimeout(() => {
      api<{ total: number; counts: Record<string, number>; entries: AuditEntry[] }>(
        `jobs/${enc(job.id)}/audit?offset=${offset}&limit=${limit}&kind=${enc(kind)}&q=${enc(q)}`,
      ).then(setData).catch(handleError);
    }, q ? 250 : 0);
    return () => window.clearTimeout(t);
  }, [job.id, kind, q, offset, tick, job.status, handleError]);
  const all = data ? Object.values(data.counts).reduce((a, b) => a + b, 0) : 0;
  const kinds = useMemo(() => Object.entries(data?.counts || {}).sort((a, b) => b[1] - a[1]), [data?.counts]);
  return (
    <>
      <p className="muted section-intro">Append-only: every command with its full output, every block, approval and stop. Findings cite these ids.</p>
      <div className="filters">
        <div className="seg">
          <button aria-pressed={kind === ""} onClick={() => { setKind(""); setOffset(0); }}>all {all}</button>
          {kinds.map(([k, n]) => (
            <button key={k} aria-pressed={kind === k} onClick={() => { setKind(k); setOffset(0); }}>{k} {n}</button>
          ))}
        </div>
        <input type="search" placeholder="Search commands and output" value={q} onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
      </div>
      {!data ? null : data.entries.length === 0 ? (
        <div className="empty"><h3>Nothing here</h3></div>
      ) : (
        <div className="card audit-list">
          {data.entries.map((e) => {
            const isCmd = e.type === "command";
            const isOpen = open.has(e.id);
            return (
              <div key={e.id} className={"audit-row a-" + (isCmd ? "command" : e.kind)}>
                <button className="audit-head" onClick={() => {
                  const n = new Set(open);
                  if (n.has(e.id)) n.delete(e.id); else n.add(e.id);
                  setOpen(n);
                }}>
                  <span className="mono muted small">{new Date(e.ts * 1000).toLocaleTimeString([], { hour12: false })}</span>
                  <span className="a-kind">{isCmd ? "command" : e.kind}</span>
                  <span className="mono a-text">{isCmd ? `$ ${e.command}` : e.message}</span>
                  {isCmd && <span className={"exit " + (e.exit_code === 0 ? "ok" : "bad")}>{e.exit_code}</span>}
                </button>
                {isOpen && (isCmd ? <div className="audit-body"><CommandBlock e={e} /></div> : (
                  <pre className="code cmd-out audit-body">{JSON.stringify(Object.fromEntries(Object.entries(e).filter(([k]) => !["ts", "type"].includes(k))), null, 2)}</pre>
                ))}
              </div>
            );
          })}
        </div>
      )}
      {data && data.total > limit && (
        <div className="form-actions">
          <span className="muted small">{offset + 1}–{Math.min(offset + limit, data.total)} of {data.total}</span>
          <button className="btn small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>Previous</button>
          <button className="btn small" disabled={offset + limit >= data.total} onClick={() => setOffset(offset + limit)}>Next</button>
        </div>
      )}
    </>
  );
}

// ------------------------------------------------------------------ benchmark

function BenchmarkTab({ job }: { job: JobDetail }) {
  const { keys, handleError } = useApp();
  const [key, setKey] = useState(job.options.key || keys[0]?.id || "");
  const [res, setRes] = useState<Benchmark | null>(null);
  const hasReport = job.downloads.some((d) => d.name === "report.json");
  useEffect(() => {
    if (!key || !hasReport) return;
    api<Benchmark>(`jobs/${enc(job.id)}/benchmark?key=${enc(key)}`).then(setRes).catch(handleError);
  }, [job.id, key, hasReport, handleError]);
  if (!keys.length) return (
    <div className="empty"><h3>No answer keys</h3>
      <p>Put an answer key (a YAML file with a <code>vulnerabilities:</code> list, like <code>answer_key.example.yaml</code>) in the scopes folder to score runs the way the blog does: weighted recall, a critical counts about 5× a trivial issue.</p></div>
  );
  if (!hasReport) return <div className="empty"><h3>No report yet</h3></div>;
  return (
    <>
      <div className="filters">
        <label className="field field-inline plain-label"><span>Answer key</span>
          <select value={key} onChange={(e) => setKey(e.target.value)}>{keys.map((k) => <option key={k.id} value={k.id}>{k.id} ({k.count})</option>)}</select></label>
      </div>
      {res && (
        <>
          <div className="summary-row">
            <div className="sev-chip static"><span className="n">{(res.recall * 100).toFixed(0)}%</span><span className="l">weighted recall</span></div>
            <div className="sev-chip static"><span className="n">{res.found_weight}/{res.total_weight}</span><span className="l">weight found</span></div>
            <div className="sev-chip static"><span className="n">{res.false_positives}</span><span className="l">not in the key</span></div>
            {SEVS.filter((s) => res.per_severity[s]).map((s) => (
              <div key={s} className="sev-chip static"><span className="n">{res.per_severity[s].found}/{res.per_severity[s].total}</span><span className="l"><span className="sw" style={{ background: `var(--sev-${s})` }} />{s}</span></div>
            ))}
          </div>
          <div className="card">
            <table className="tasks">
              <thead><tr><th>Found</th><th>Severity</th><th>Expected</th><th>Component</th></tr></thead>
              <tbody>
                {res.matches.map((m) => (
                  <tr key={m.id}>
                    <td>{m.found ? <span className="exit ok">✓ found</span> : <span className="exit bad">missed</span>}</td>
                    <td><span className={"sev sev-" + m.severity}>{m.severity}</span></td>
                    <td><b className="mono small">{m.id}</b> {m.title}</td>
                    <td>{m.component}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

function Files({ job }: { job: JobDetail }) {
  if (!job.downloads.length) return <div className="empty"><h3>Nothing to download yet</h3></div>;
  return (
    <div className="card">
      <ul className="dl-list">
        {job.downloads.map((d) => (
          <li key={d.name}>
            <span><b>{d.label}</b> <span className="muted small mono">{d.name} · {size(d.bytes)}</span></span>
            <a className="btn small" href={fileUrl(job.id, d.name)}>Download</a>
          </li>
        ))}
      </ul>
    </div>
  );
}
