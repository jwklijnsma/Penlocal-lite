"""Offline tests for `penlocal serve` (penlocal/web): auth, scope files, the guardrail
audit, and full runs with the mock brain, including a risky step that waits for a
human and the emergency stop.

Run: python -m pytest tests/test_web.py   (no model server, no real targets)
"""
import json
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from penlocal.config import Config
from penlocal.web.server import AUTH_PHRASE, WebApp, make_server


class Client:
    def __init__(self, base: str, token: str | None = "t"):
        self.base, self.token = base, token

    def call(self, path, body=None, headers=None, raw=False):
        h = {"Content-Type": "application/json", "X-Penlocal": "1"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                payload = r.read()
                return r.status, (payload if raw else json.loads(payload or b"{}"))
        except urllib.error.HTTPError as e:
            payload = e.read()
            return e.code, (payload if raw else json.loads(payload or b"{}"))


def start(**kw):
    d = Path(tempfile.mkdtemp())
    (d / "scopes").mkdir()
    shutil.copy(ROOT / "scope.example.yaml", d / "scopes" / "lab.yaml")
    shutil.copy(ROOT / "answer_key.example.yaml", d / "scopes" / "key.yaml")
    cfg = Config()
    cfg.backend = "mock"
    app = WebApp(cfg, d / "scopes", d / "work", token="t", **kw)
    srv = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return app, srv, Client(f"http://127.0.0.1:{srv.server_address[1]}/api/"), d


def wait(c, jid, pred, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        _, det = c.call(f"jobs/{jid}")
        if pred(det):
            return det
        time.sleep(0.05)
    raise AssertionError(f"timed out; last state {det.get('status')} {det.get('progress')}")


def done(det):
    return det["status"] not in ("queued", "running")


def test_auth_and_csrf():
    _app, srv, c, _ = start()
    assert Client(c.base, None).call("status")[0] == 401
    assert Client(c.base, "wrong").call("status")[0] == 401
    assert c.call("status")[0] == 200
    # POSTs need the custom header, and a foreign Origin is refused
    assert c.call("explain", {"scope_id": "lab"}, headers={"X-Penlocal": ""})[0] == 403
    assert c.call("explain", {"scope_id": "lab"}, headers={"Origin": "http://evil.example"})[0] == 403
    srv.shutdown()


def test_scope_files_and_validation():
    _app, srv, c, _ = start()
    s, data = c.call("scopes")
    assert [x["id"] for x in data["scopes"]] == ["lab"]
    assert [k["id"] for k in data["keys"]] == ["key"]
    # traversal-shaped names are refused
    assert c.call("scopes/..%2Fetc")[0] in (400, 404)
    assert c.call("scopes/new", {"text": "in_scope: not-a-list\n", "create": True})[0] == 400
    assert c.call("scopes/new", {"text": "in_scope: [10.0.0.0/24]\nrisky: ['(']\n", "create": True})[0] == 400
    s, sc = c.call("scopes/new", {"text": "in_scope: [10.0.0.0/24]\n", "create": True})
    assert s == 200 and sc["summary"]["in_scope"] == ["10.0.0.0/24"]
    assert any("authorized_by" in w for w in sc["warnings"])
    assert c.call("scopes/new", {"text": "in_scope: [10.0.0.0/24]\n", "create": True})[0] == 409
    # a stale editor cannot overwrite a newer file
    assert c.call("scopes/new", {"text": "in_scope: [10.0.1.0/24]\n", "modified": 1.0})[0] == 409
    # an unbounded scope is a pre-flight error
    s, bad = c.call("scopes/wide", {"text": "in_scope: [0.0.0.0/0]\n", "create": True})
    assert s == 200 and bad["errors"]
    srv.shutdown()


def test_explain_matches_cli_policy():
    _app, srv, c, _ = start()
    s, r = c.call("explain", {"scope_id": "lab", "toolpacks": ["kubernetes"], "commands": [
        "nmap -sV 10.10.10.5", "curl http://google.com", "hydra -l admin 10.10.10.5 ssh",
        "kubectl delete namespace prod", "# a comment"]})
    assert s == 200
    assert [x["decision"] for x in r["results"]] == ["allow", "deny", "approve", "deny"]
    assert c.call("explain", {"scope_id": "lab", "toolpacks": ["nope"], "commands": ["id"]})[0] == 400
    srv.shutdown()


def test_run_needs_authorization_and_preflight():
    _app, srv, c, _ = start()
    s, err = c.call("jobs", {"kind": "run", "scope_id": "lab"})
    assert s == 403 and AUTH_PHRASE in err["error"]
    c.call("scopes/wide", {"text": "in_scope: [0.0.0.0/0]\n", "create": True})
    s, err = c.call("jobs", {"kind": "run", "scope_id": "wide", "authorized": AUTH_PHRASE})
    assert s == 400 and err["errors"]
    # options the server did not allow are refused
    s, _ = c.call("jobs", {"kind": "run", "scope_id": "lab", "authorized": AUTH_PHRASE,
                           "options": {"auto_approve": True}})
    assert s == 403
    s, _ = c.call("jobs", {"kind": "run", "scope_id": "lab", "authorized": AUTH_PHRASE,
                           "options": {"runs": 999}})
    assert s == 400
    s, _ = c.call("jobs", {"kind": "run", "scope_id": "lab", "authorized": AUTH_PHRASE,
                           "options": {"models": {"executor": "bad name; rm -rf /"}}})
    assert s == 400
    s, _ = c.call("jobs", {"kind": "run", "scope_id": "lab", "authorized": AUTH_PHRASE,
                           "options": {"context": "/etc"}})
    assert s == 400   # no --context-root configured
    srv.shutdown()


def test_full_run_reports_audit_benchmark():
    _app, srv, c, _ = start()
    s, job = c.call("jobs", {"kind": "run", "scope_id": "lab", "authorized": AUTH_PHRASE,
                             "operator": "tester", "options": {"runs": 2, "key": "key"}})
    assert s == 202
    det = wait(c, job["id"], done)
    assert det["status"] == "done", det.get("error")
    assert det["summary"]["findings"] >= 1 and "benchmark" in det["summary"]
    assert det["progress"]["runs"] == 2 and det["progress"]["started"] == 4
    names = {d["name"] for d in det["downloads"]}
    assert {"report.md", "report.json", "report.html", "audit.jsonl"} <= names
    _, res = c.call(f"jobs/{job['id']}/results")
    f = res["report"]["findings"][0]
    s, ev = c.call(f"jobs/{job['id']}/evidence?ids=" + ",".join(f["evidence_ids"]))
    assert all(e["type"] == "command" for e in ev["entries"].values()) and ev["entries"]
    _, audit = c.call(f"jobs/{job['id']}/audit?kind=authorization")
    assert audit["total"] == 1 and audit["entries"][0]["operator"] == "tester"
    s, b = c.call(f"jobs/{job['id']}/benchmark?key=key")
    assert s == 200 and b["total_weight"] == 12
    s, body = c.call(f"jobs/{job['id']}/files/report.md", raw=True)
    assert s == 200 and (b"PenLocal" in body or b"Findings" in body)
    assert c.call(f"jobs/{job['id']}/files/..%2F..%2Fetc%2Fpasswd", raw=True)[0] == 404
    srv.shutdown()


def test_plan_only_runs_no_commands():
    _app, srv, c, _ = start()
    _, job = c.call("jobs", {"kind": "plan", "scope_id": "lab"})
    det = wait(c, job["id"], done)
    assert det["status"] == "done" and det["summary"]["tasks"] == 2
    assert det["progress"]["commands"] == 0
    _, res = c.call(f"jobs/{job['id']}/results")
    assert len(res["threat_model"]["tasks"]) == 2
    srv.shutdown()


def test_risky_step_waits_for_a_human():
    _app, srv, c, _ = start()
    _, job = c.call("jobs", {"kind": "demo", "options": {"approval_demo": True}})
    det = wait(c, job["id"], lambda d: d["approvals"])
    a = det["approvals"][0]
    assert "POST" in a["command"] and det["pending_approvals"] == 1
    assert c.call(f"jobs/{job['id']}/approvals/{a['id']}", {"approve": "yes"})[0] == 400
    assert c.call(f"jobs/{job['id']}/approvals/{a['id']}", {"approve": False, "operator": "jw"})[0] == 200
    assert c.call(f"jobs/{job['id']}/approvals/{a['id']}", {"approve": True})[0] == 409
    det = wait(c, job["id"], done)
    assert det["status"] == "done"
    _, audit = c.call(f"jobs/{job['id']}/audit?kind=approval")
    assert audit["entries"][0]["decision"] == "declined" and audit["entries"][0]["by"] == "jw"
    _, audit = c.call(f"jobs/{job['id']}/audit?kind=skipped")
    assert audit["total"] == 1   # the sandbox never ran it
    srv.shutdown()


def test_approval_timeout_counts_as_deny():
    _app, srv, c, _ = start(approval_timeout=1)
    _, job = c.call("jobs", {"kind": "demo", "options": {"approval_demo": True}})
    det = wait(c, job["id"], done)
    assert det["status"] == "done"
    assert any("no answer in 1s" in ln["text"] for ln in det["log"])
    srv.shutdown()


def test_emergency_stop_and_history():
    app, srv, c, d = start()
    s, first = c.call("jobs", {"kind": "demo", "options": {"approval_demo": True}})
    s, second = c.call("jobs", {"kind": "plan", "scope_id": "lab"})
    wait(c, first["id"], lambda x: x["approvals"])
    assert c.call(f"jobs/{second['id']}")[1]["status"] == "queued"
    s, r = c.call("stop-all", {})
    assert r["stopped"] == 2
    det = wait(c, first["id"], done)
    assert det["status"] == "stopped" and not det["approvals"]
    assert c.call(f"jobs/{second['id']}")[1]["status"] == "cancelled"
    _, audit = c.call(f"jobs/{first['id']}/audit?kind=emergency_stop")
    assert audit["total"] == 1
    srv.shutdown()
    app.shutdown()
    # a new server sees the old runs
    app2 = WebApp(app.cfg, d / "scopes", d / "work", token="t")
    assert first["id"] in app2.jobs and app2.jobs[first["id"]].status == "stopped"
    app2.shutdown()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  FAIL  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
