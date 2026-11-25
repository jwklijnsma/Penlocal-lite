import { ApprovalDock, Login, Toasts, TopBar } from "./components/Chrome";
import { RunPage } from "./components/RunPage";
import { NewScope, RunList, ScopePage } from "./components/ScopePage";
import { Sidebar } from "./components/Sidebar";
import { AppProvider, go, useApp, useRoute } from "./store";

function Home() {
  const { scopes, jobs, status, startJob } = useApp();
  const demo = async () => {
    const j = await startJob({ kind: "demo", options: { approval_demo: true } });
    if (j) go({ page: "run", id: j.id, tab: "live" });
  };
  return (
    <>
      <h1 className="page-title">Local-AI pentest harness</h1>
      <p className="muted section-intro">
        The model is only the brain. Every command it proposes goes through the scope gate and the denylist, risky steps wait for your approval,
        everything lands in the audit log, and a different model verifies each finding against that evidence.
      </p>
      <div className="grid-3">
        <a className="card tile" href="#/new">
          <b>1 · Write the scope</b>
          <span className="muted small">What may be touched, what never. It is the contract the guardrail enforces.</span>
        </a>
        <div className="card tile">
          <b>2 · Audit the guardrail</b>
          <span className="muted small">On a scope's Guardrail tab: see allow / deny / approve for any command, running nothing.</span>
        </div>
        <div className="card tile">
          <b>3 · Run, approve, review</b>
          <span className="muted small">Plan → execute → verify → assess. Approve risky steps as they come; stop everything with one click.</span>
        </div>
      </div>
      {scopes.length === 0 && (
        <div className="callout">
          No scopes in <code>{status?.scopes_dir}</code> yet. <a href="#/new">Create one</a>, or try the{" "}
          <button className="linklike" onClick={demo}>offline demo</button>: the whole pipeline with a mock brain and harmless echo probes, including one step that waits for your approval.
        </div>
      )}
      {jobs.length > 0 && (
        <>
          <h2 className="section-title">All runs</h2>
          <RunList runs={jobs.slice(0, 30)} />
        </>
      )}
    </>
  );
}

function Shell() {
  const { authed } = useApp();
  const route = useRoute();
  if (authed === null) return null;
  if (!authed) {
    return (
      <>
        <header className="topbar"><div className="brand"><img src="/favicon.svg" alt="" /> PenLocal-lite</div></header>
        <Login />
      </>
    );
  }
  return (
    <>
      <TopBar />
      <div className="layout">
        <Sidebar route={route} />
        <main>
          {route.page === "scope" ? <ScopePage key={route.id} id={route.id} tab={route.tab} /> :
            route.page === "run" ? <RunPage key={route.id} id={route.id} tab={route.tab} /> :
            route.page === "new" ? <NewScope /> : <Home />}
        </main>
      </div>
      <ApprovalDock hideJob={route.page === "run" ? route.id : undefined} />
      <Toasts />
    </>
  );
}

export default function App() {
  return (
    <AppProvider>
      <Shell />
    </AppProvider>
  );
}
