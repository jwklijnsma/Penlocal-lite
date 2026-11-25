import { useState } from "react";
import { go, href, useApp, type Route } from "../store";
import { ago, dotClass, kindLabel, statusText } from "../util";
import { SevBar } from "./Chrome";

export function Sidebar({ route }: { route: Route }) {
  const { scopes, jobs, startJob } = useApp();
  const [filter, setFilter] = useState("");
  const f = filter.trim().toLowerCase();
  const shown = scopes.filter((s) => !f || s.id.toLowerCase().includes(f) || s.client.toLowerCase().includes(f));
  const recent = jobs.slice(0, 8);
  const demo = async () => {
    const j = await startJob({ kind: "demo", options: { approval_demo: true } });
    if (j) go({ page: "run", id: j.id, tab: "live" });
  };
  return (
    <aside className="sidebar">
      <div className="upload-box">
        <a className="btn primary upload-btn" href={href({ page: "new" })}>+ New scope</a>
        <button className="btn upload-btn" style={{ marginTop: 8 }} onClick={demo} title="Full pipeline with the mock brain and harmless echo probes, incl. one step that needs your approval">
          ▶ Offline demo
        </button>
      </div>
      <h2>Scopes</h2>
      {scopes.length > 5 && <input className="search" type="search" placeholder="Filter scopes" value={filter} onChange={(e) => setFilter(e.target.value)} />}
      {scopes.length === 0 && <p className="empty-roots">No scope files yet. Create one: it is the contract that says what may be touched.</p>}
      <ul className="repo-list">
        {shown.map((s) => {
          const cur = (route.page === "scope" && route.id === s.id) || (route.page === "run" && jobs.find((j) => j.id === route.id)?.scope_id === s.id);
          const last = s.last_run;
          return (
            <li key={s.id}>
              <button aria-current={cur ? "true" : undefined} onClick={() => go({ page: "scope", id: s.id, tab: "overview" })}>
                <span className="repo-name">
                  {last && <span className={"dot " + dotClass(last)} />}
                  {s.id}
                  {s.broken && <span className="badge dirty">broken</span>}
                </span>
                <span className="repo-meta">
                  {s.client || "no client set"} · {s.targets} target{s.targets === 1 ? "" : "s"}{s.clusters ? ` · ${s.clusters} cluster${s.clusters > 1 ? "s" : ""}` : ""}
                </span>
                {last && <span className="repo-meta">{kindLabel(last)} {ago(last.created)}: {statusText(last)}</span>}
                <SevBar counts={last?.summary.severity_counts} />
              </button>
            </li>
          );
        })}
      </ul>
      {recent.length > 0 && (
        <>
          <h2 className="list-head">Recent runs</h2>
          <ul className="repo-list">
            {recent.map((j) => (
              <li key={j.id}>
                <button aria-current={route.page === "run" && route.id === j.id ? "true" : undefined} onClick={() => go({ page: "run", id: j.id, tab: "live" })}>
                  <span className="repo-name"><span className={"dot " + dotClass(j)} />{kindLabel(j)} · {j.scope_name}</span>
                  <span className="repo-meta">{ago(j.created)} · {statusText(j)}</span>
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
    </aside>
  );
}
