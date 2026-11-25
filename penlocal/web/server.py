"""`penlocal serve`: a small self-hosted web UI on top of the harness.

Design notes
------------
* Standard library only (http.server), no CDN assets: it runs on an air-gapped box.
* Engagements run in-process, one at a time (they share the GPU), on a worker
  thread. That keeps the two things a pentest UI must get right in one place:
    - risky commands wait for a human: the Sandbox's approval callback parks the
      command in the job and blocks until someone clicks Approve or Deny in the
      browser (or the approval times out, which counts as Deny);
    - the emergency stop is the harness's own shared stop Event, so a click halts
      every worker before its next command and declines everything still waiting.
* Every run gets its own folder under <workdir>/runs/<job-id>/ with the audit log,
  the reports and a job.json, so history survives a restart of the server.
* Locked down by default, like `ansreview serve`: binds to 127.0.0.1, every API call
  needs the access token, POSTs need a custom header (no cross-site form posts), the
  backend and model endpoints come only from the config file / environment, scope
  files live only in the --scopes folder and source context only under --context-root.
* The browser cannot weaken the guardrail: a run needs the same typed
  "I AM AUTHORIZED" as the CLI, pre-flight errors refuse the run, and auto-approving
  risky steps is only offered when the server was started with --allow-auto-approve.
"""

from __future__ import annotations

import copy
import hmac
import ipaddress
import json
import os
import re
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Empty, Queue
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .. import __version__
from ..assessor import AssessmentReport
from ..benchmark import AnswerKey, score
from ..config import Config
from ..models import Finding, Severity
from ..report import to_html, to_json, to_markdown
from ..scope import Scope
from ..toolpacks import REGISTRY, merged_policy, resolve
from ..validation import preflight

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_FILES = {"/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                "/app.css": ("app.css", "text/css; charset=utf-8"),
                "/favicon.svg": ("favicon.svg", "image/svg+xml")}

COOKIE = "penlocal_token"
CSRF_HEADER = "X-Penlocal"
AUTH_PHRASE = "I AM AUTHORIZED"
MAX_BODY = 256 * 1024
MAX_SCOPE = 64 * 1024
MAX_LOG_LINES = 20000
MAX_PENDING = 10
MAX_OUTPUT = 20000           # chars of stdout/stderr per audit entry sent to the browser
MAX_COMMANDS = 200           # commands per explain request
KEEP_RUNS = 200              # newest runs listed
DEMO_SCOPE_ID = "_demo"

# Result files a run can offer for download: name -> (label, content type)
ARTIFACTS = {
    "report.md": ("Report (Markdown)", "text/markdown; charset=utf-8"),
    "report.html": ("Report (HTML)", "text/html; charset=utf-8"),
    "report.json": ("Report (JSON)", "application/json"),
    "audit.jsonl": ("Audit log (JSONL)", "application/x-ndjson"),
    "threat_model.json": ("Threat model (JSON)", "application/json"),
    "log.txt": ("Console log", "text/plain; charset=utf-8"),
}

# Tools worth showing in the status bar: what the executor can actually call.
TOOLS = ("nmap", "curl", "nikto", "sqlmap", "ffuf", "gobuster", "nuclei", "whatweb",
         "hydra", "kubectl", "oc", "kube-bench", "kubescape", "kubeaudit", "trivy",
         "popeye", "docker")

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
JOB_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
ROLES = ("planner", "executor", "verifier", "assessor")
ACTIVE = ("queued", "running")

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; "
                                "img-src 'self' data:; connect-src 'self'; "
                                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra: Any):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


# --------------------------------------------------------------------------- helpers

def _int(value, lo: int, hi: int, name: str, default: int) -> int:
    if value in (None, ""):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ApiError(400, f"{name} must be a number") from None
    if not lo <= n <= hi:
        raise ApiError(400, f"{name} must be between {lo} and {hi}")
    return n


def _toolpacks(value, default: list[str]) -> list[str]:
    if value in (None, "", []):
        return list(default)
    if not isinstance(value, list):
        raise ApiError(400, "toolpacks must be a list")
    out = []
    for p in value:
        name = str(p).strip().lower()
        if name not in REGISTRY:
            raise ApiError(400, f"unknown tool pack {name[:40]!r}; use one of {sorted(REGISTRY)}")
        if name not in out:
            out.append(name)
    return out


def _write_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _scope_summary(scope: Scope) -> dict:
    return {"in_scope": list(scope.in_scope), "out_of_scope": list(scope.out_of_scope),
            "clusters": list(scope.clusters), "engagement": scope.engagement or {}}


def _report_from_json(data: dict) -> AssessmentReport:
    findings = [
        Finding(title=f.get("title", ""), severity=Severity.coerce(f.get("severity", "info")),
                description=f.get("description", ""), component=f.get("component", ""),
                cwe=f.get("cwe", ""), evidence_ids=f.get("evidence_ids", []),
                verified=True, id=f.get("id", ""))
        for f in data.get("findings", [])
    ]
    return AssessmentReport(findings=findings, chains=data.get("chains", []))


# --------------------------------------------------------------------------- jobs

@dataclass
class Approval:
    id: str
    command: str
    reason: str
    created: float = field(default_factory=time.time)
    event: threading.Event = field(default_factory=threading.Event, repr=False)
    decision: bool | None = None
    decided_by: str = ""

    def public(self, timeout: int) -> dict:
        return {"id": self.id, "command": self.command, "reason": self.reason,
                "created": self.created,
                "expires": self.created + timeout if timeout else None}


@dataclass
class Job:
    id: str
    kind: str                       # run | plan | demo
    scope_id: str
    scope_name: str
    dir: Path
    options: dict = field(default_factory=dict)
    status: str = "queued"          # queued running done failed stopped cancelled interrupted
    created: float = field(default_factory=time.time)
    started: float | None = None
    finished: float | None = None
    error: str = ""
    operator: str = ""
    summary: dict = field(default_factory=dict)
    progress: dict = field(default_factory=lambda: {"phase": "queued", "run": 0, "runs": 1,
                                                    "tasks": 0, "started": 0, "total": 0,
                                                    "commands": 0, "candidates": 0})
    log: list = field(default_factory=list, repr=False)
    log_base: int = 0
    approvals: dict = field(default_factory=dict, repr=False)
    stop_requested: bool = False
    harness: Any = field(default=None, repr=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    PERSIST = ("id", "kind", "scope_id", "scope_name", "options", "status", "created",
               "started", "finished", "error", "operator", "summary", "progress")

    def to_disk(self) -> dict:
        return {k: getattr(self, k) for k in self.PERSIST}

    @classmethod
    def from_disk(cls, data: dict, path: Path) -> Job:
        job = cls(id=data["id"], kind=data.get("kind", "run"), scope_id=data.get("scope_id", ""),
                  scope_name=data.get("scope_name", ""), dir=path)
        for k in cls.PERSIST:
            if k in data and k not in ("id",):
                setattr(job, k, data[k])
        if job.status in ACTIVE:
            job.status = "interrupted"
            job.error = job.error or "the server stopped while this run was going"
        return job

    def save(self) -> None:
        _write_json(self.dir / "job.json", self.to_disk())

    def summary_public(self, timeout: int) -> dict:
        with self.lock:
            pending = [a.public(timeout) for a in self.approvals.values() if a.decision is None]
        d = self.to_disk()
        d["pending_approvals"] = len(pending)
        d["downloads"] = self.downloads()
        return d

    def downloads(self) -> list[dict]:
        out = []
        for name, (label, _ctype) in ARTIFACTS.items():
            p = self.dir / ("reports/" + name if name.startswith("report.") else name)
            if p.is_file():
                out.append({"name": name, "label": label, "bytes": p.stat().st_size})
        return out

    def add_log(self, text: str) -> None:
        line = {"t": time.time(), "text": str(text)}
        with self.lock:
            self.log.append(line)
            if len(self.log) > MAX_LOG_LINES:
                drop = len(self.log) - MAX_LOG_LINES
                del self.log[:drop]
                self.log_base += drop
        try:
            with (self.dir / "log.txt").open("a", encoding="utf-8") as fh:
                fh.write(time.strftime("%H:%M:%S ", time.localtime(line["t"])) + line["text"] + "\n")
        except OSError:
            pass
        self._track(line["text"])

    # The harness reports progress as console lines; turn the known ones into numbers.
    _PLAN_RE = re.compile(r"\[planner\] (\d+) task")
    _RUN_RE = re.compile(r"\[run (\d+)/(\d+)\]")

    def _track(self, text: str) -> None:
        p = self.progress
        s = text.strip()
        if s.startswith("[planner]") and "building" in s:
            p["phase"] = "plan"
        m = self._PLAN_RE.search(s)
        if m:
            p["tasks"] = int(m.group(1))
            p["total"] = p["tasks"] * max(1, int(p.get("runs") or 1))
        m = self._RUN_RE.search(s)
        if m:
            p["phase"] = "execute"
            p["run"], p["runs"] = int(m.group(1)), int(m.group(2))
        if s.startswith("[task]"):
            p["started"] = p.get("started", 0) + 1
        elif s.startswith("$ "):
            p["commands"] = p.get("commands", 0) + 1
        elif s.startswith("[candidate]"):
            p["candidates"] = p.get("candidates", 0) + 1
        elif s.startswith("[verifier]"):
            p["phase"] = "verify"
        elif s.startswith("[assessor]"):
            p["phase"] = "assess"


# --------------------------------------------------------------------------- app

class WebApp:
    def __init__(self, cfg: Config, scopes_dir: Path, workdir: Path,
                 context_roots: list[Path] | None = None, token: str | None = None,
                 no_auth: bool = False, allow_auto_approve: bool = False,
                 approval_timeout: int = 900, max_runs: int = 10, max_workers: int = 8):
        self.cfg = cfg
        self.scopes_dir = Path(scopes_dir).expanduser().resolve()
        self.workdir = Path(workdir).expanduser().resolve()
        self.runs_dir = self.workdir / "runs"
        self.context_roots = [Path(p).expanduser().resolve() for p in (context_roots or [])]
        self.token = token or secrets.token_urlsafe(24)
        self.no_auth = no_auth
        self.allow_auto_approve = allow_auto_approve
        self.approval_timeout = max(0, int(approval_timeout))
        self.max_runs = max_runs
        self.max_workers = max_workers
        self.scopes_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()
        self.queue: Queue[str] = Queue()
        self._models_cache: tuple[float, list[str], str] = (0.0, [], "")
        self._shutdown = threading.Event()
        self._load_history()
        self.worker = threading.Thread(target=self._work, name="penlocal-worker", daemon=True)
        self.worker.start()

    # ---- auth
    def check_token(self, token: str | None) -> bool:
        if self.no_auth:
            return True
        return bool(token) and hmac.compare_digest(str(token), self.token)

    # ---- status
    def _models(self) -> tuple[list[str], str]:
        now = time.time()
        ts, models, err = self._models_cache
        if now - ts < 15:
            return models, err
        models, err = [], ""
        if self.cfg.backend == "mock":
            models = ["mock"]
        else:
            try:
                import requests
                if self.cfg.backend == "ollama":
                    r = requests.get(f"{self.cfg.ollama_base_url.rstrip('/')}/api/tags", timeout=4)
                    r.raise_for_status()
                    models = sorted(m.get("name", "") for m in r.json().get("models", []))
                else:
                    r = requests.get(f"{self.cfg.api_base.rstrip('/')}/models", timeout=4,
                                     headers={"Authorization": f"Bearer {self.cfg.api_key}"})
                    r.raise_for_status()
                    models = sorted(m.get("id", "") for m in r.json().get("data", []))
            except Exception as exc:  # noqa: BLE001 - any failure means "unreachable"
                err = f"{exc.__class__.__name__}: {exc}"[:300]
        self._models_cache = (now, [m for m in models if m], err)
        return self._models_cache[1], err

    def _endpoint(self) -> str:
        if self.cfg.backend == "ollama":
            return self.cfg.ollama_base_url
        if self.cfg.backend == "openai-compat":
            return self.cfg.api_base
        return "offline (mock)"

    def server_status(self) -> dict:
        models, err = self._models()
        reachable = not err
        roles = {}
        for role, model in self.cfg.role_models().items():
            avail = (self.cfg.backend == "mock" or model in models
                     or (":" not in model and f"{model}:latest" in models))
            roles[role] = {"model": model, "available": bool(reachable and avail)}
        with self.lock:
            active = [j for j in self.jobs.values() if j.status in ACTIVE]
        running = next((j for j in active if j.status == "running"), None)
        return {
            "version": __version__,
            "backend": self.cfg.backend,
            "endpoint": self._endpoint(),
            "reachable": reachable,
            "backend_error": err,
            "models": models,
            "roles": roles,
            "runner": self.cfg.runner,
            "docker_image": self.cfg.docker_image,
            "defaults": {"runs": self.cfg.runs, "workers": self.cfg.workers,
                         "runner": self.cfg.runner, "toolpacks": list(self.cfg.toolpacks),
                         "max_steps": self.cfg.max_steps_per_task},
            "limits": {"runs": self.max_runs, "workers": self.max_workers},
            "toolpacks": {name: p.description for name, p in REGISTRY.items()},
            "tools": {t: bool(shutil.which(t)) for t in TOOLS},
            "allow_auto_approve": self.allow_auto_approve,
            "approval_timeout": self.approval_timeout,
            "auth_phrase": AUTH_PHRASE,
            "scopes_dir": str(self.scopes_dir),
            "workdir": str(self.workdir),
            "context_roots": [str(p) for p in self.context_roots],
            "active": len(active),
            "running": running.id if running else None,
        }

    # ---- scope files
    def _scope_path(self, scope_id: str) -> Path:
        if not ID_RE.match(scope_id or ""):
            raise ApiError(400, "invalid scope name (letters, digits, . _ - only)")
        for ext in (".yaml", ".yml"):
            p = self.scopes_dir / f"{scope_id}{ext}"
            if p.is_file():
                return p
        return self.scopes_dir / f"{scope_id}.yaml"

    def _yaml(self, text: str):
        if yaml is None:
            raise ApiError(500, "PyYAML is not installed")
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ApiError(400, f"not valid YAML: {exc}") from None
        if not isinstance(data, dict):
            raise ApiError(400, "the file must be a YAML mapping")
        return data

    def _files(self) -> list[tuple[str, Path, dict]]:
        out = []
        for p in sorted(self.scopes_dir.iterdir()):
            if p.suffix not in (".yaml", ".yml") or not p.is_file() or not ID_RE.match(p.stem):
                continue
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) if yaml else None
            except Exception:  # noqa: BLE001 - a broken file is shown as broken
                data = {"_broken": True}
            out.append((p.stem, p, data if isinstance(data, dict) else {"_broken": True}))
        return out

    def list_scopes(self) -> dict:
        scopes, keys = [], []
        last: dict[str, Job] = {}
        with self.lock:
            for j in sorted(self.jobs.values(), key=lambda j: j.created):
                last[j.scope_id] = j
        for sid, p, data in self._files():
            if "vulnerabilities" in data and "in_scope" not in data:
                keys.append({"id": sid, "file": p.name, "count": len(data.get("vulnerabilities") or [])})
                continue
            eng = data.get("engagement") or {}
            j = last.get(sid)
            scopes.append({
                "id": sid, "file": p.name, "broken": bool(data.get("_broken")),
                "client": str(eng.get("client") or "") if isinstance(eng, dict) else "",
                "targets": len(data.get("in_scope") or []),
                "clusters": len(data.get("clusters") or []),
                "modified": p.stat().st_mtime,
                "last_run": j.summary_public(self.approval_timeout) if j else None,
            })
        return {"scopes": scopes, "keys": keys}

    def _load_scope(self, scope_id: str) -> tuple[Scope, str]:
        if scope_id == DEMO_SCOPE_ID:
            return Scope(in_scope=["127.0.0.1", "demo.local"],
                         engagement={"client": "Offline demo", "authorized_by": "demo"}), "offline demo"
        p = self._scope_path(scope_id)
        if not p.is_file():
            raise ApiError(404, f"no scope {scope_id!r} in {self.scopes_dir}")
        try:
            return Scope.load(p), scope_id
        except Exception as exc:  # noqa: BLE001
            raise ApiError(400, f"scope file does not load: {exc}") from None

    def get_scope(self, scope_id: str) -> dict:
        p = self._scope_path(scope_id)
        if not p.is_file():
            raise ApiError(404, f"no scope {scope_id!r}")
        text = p.read_text(encoding="utf-8")
        out = {"id": scope_id, "file": p.name, "text": text, "modified": p.stat().st_mtime}
        try:
            scope = Scope.load(p)
            errors, warnings = preflight(self.cfg, scope)
            out.update(summary=_scope_summary(scope), errors=errors, warnings=warnings)
        except Exception as exc:  # noqa: BLE001
            out.update(summary=None, errors=[f"does not load: {exc}"], warnings=[])
        with self.lock:
            runs = [j for j in self.jobs.values() if j.scope_id == scope_id]
        runs.sort(key=lambda j: j.created, reverse=True)
        out["runs"] = [j.summary_public(self.approval_timeout) for j in runs]
        return out

    def save_scope(self, scope_id: str, body: dict) -> dict:
        text = body.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ApiError(400, "text is required")
        if len(text.encode("utf-8")) > MAX_SCOPE:
            raise ApiError(413, "scope file too large")
        data = self._yaml(text)
        if "in_scope" not in data:
            raise ApiError(400, "a scope file needs an in_scope list")
        for key in ("in_scope", "out_of_scope", "clusters", "denylist", "risky"):
            if key in data and data[key] is not None and not isinstance(data[key], list):
                raise ApiError(400, f"{key} must be a list")
        for key in ("denylist", "risky"):
            for pat in data.get(key) or []:
                try:
                    re.compile(str(pat))
                except re.error as exc:
                    raise ApiError(400, f"{key} pattern {str(pat)[:60]!r} is not a valid regex: {exc}") from None
        p = self._scope_path(scope_id)
        expected = body.get("modified")
        if body.get("create") and p.exists():
            raise ApiError(409, f"a scope called {scope_id!r} already exists")
        if expected and p.exists() and abs(p.stat().st_mtime - float(expected)) > 1e-6:
            raise ApiError(409, "the file changed on disk since you opened it; reload first")
        tmp = p.with_suffix(".tmp")
        tmp.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
        os.replace(tmp, p)
        return self.get_scope(scope_id)

    def _answer_key(self, key_id: str) -> AnswerKey:
        p = self._scope_path(key_id)
        if not p.is_file():
            raise ApiError(404, f"no answer key {key_id!r}")
        try:
            return AnswerKey.load(p)
        except Exception as exc:  # noqa: BLE001
            raise ApiError(400, f"answer key does not load: {exc}") from None

    # ---- guardrail audit
    def explain(self, body: dict) -> dict:
        sid = str(body.get("scope_id") or "")
        if body.get("text"):
            data = self._yaml(str(body["text"]))
            scope = Scope(in_scope=data.get("in_scope") or [], out_of_scope=data.get("out_of_scope"),
                          denylist=data.get("denylist"), risky=data.get("risky"),
                          engagement=data.get("engagement"), clusters=data.get("clusters"))
        else:
            scope, _ = self._load_scope(sid)
        packs = resolve(_toolpacks(body.get("toolpacks"), self.cfg.toolpacks))
        deny, risky, scanners = merged_policy(packs)
        scope.extend_policy(denylist=deny, risky=risky, scanners=scanners)
        cmds = body.get("commands") or []
        if isinstance(cmds, str):
            cmds = cmds.splitlines()
        cmds = [str(c).strip() for c in cmds if str(c).strip() and not str(c).lstrip().startswith("#")]
        if len(cmds) > MAX_COMMANDS:
            raise ApiError(400, f"at most {MAX_COMMANDS} commands at a time")
        results = []
        for c in cmds:
            r = scope.classify_command(c[:2000])
            results.append({"command": c[:2000], "decision": r.decision, "reason": r.reason,
                            "targets": r.targets})
        errors, warnings = preflight(self.cfg, scope)
        return {"toolpacks": [p.name for p in packs], "results": results,
                "errors": errors, "warnings": warnings}

    # ---- source context
    def contexts(self) -> list[dict]:
        out = []
        for root in self.context_roots:
            if not root.is_dir():
                continue
            out.append({"path": str(root), "name": root.name})
            for child in sorted(root.iterdir()):
                if child.is_dir() and not child.name.startswith("."):
                    out.append({"path": str(child), "name": f"{root.name}/{child.name}"})
        return out

    def _context_path(self, value: str) -> str | None:
        if not value:
            return None
        if not self.context_roots:
            raise ApiError(400, "source context is off: start the server with --context-root")
        p = Path(value).expanduser().resolve()
        if not any(p == r or r in p.parents for r in self.context_roots):
            raise ApiError(403, "context must be under one of the --context-root folders")
        if not p.exists():
            raise ApiError(404, "context path does not exist")
        return str(p)

    # ---- jobs
    def _new_id(self) -> str:
        return time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)

    def _load_history(self) -> None:
        for d in sorted(self.runs_dir.iterdir()) if self.runs_dir.is_dir() else []:
            data = _read_json(d / "job.json")
            if not data or not JOB_RE.match(str(data.get("id", ""))) or data["id"] != d.name:
                continue
            job = Job.from_disk(data, d)
            if job.status == "interrupted":
                job.save()
            self.jobs[job.id] = job

    def _options(self, kind: str, body: dict) -> dict:
        o = body.get("options") or {}
        if not isinstance(o, dict):
            raise ApiError(400, "options must be an object")
        opts = {
            "runs": _int(o.get("runs"), 1, self.max_runs, "runs", self.cfg.runs),
            "workers": _int(o.get("workers"), 1, self.max_workers, "workers", self.cfg.workers),
            "runner": str(o.get("runner") or self.cfg.runner),
            "toolpacks": _toolpacks(o.get("toolpacks"), self.cfg.toolpacks),
            "max_steps": _int(o.get("max_steps"), 1, 50, "max_steps", self.cfg.max_steps_per_task),
            "auto_approve": bool(o.get("auto_approve")),
            "context": self._context_path(str(o.get("context") or "").strip()),
            "models": {},
            "key": None,
        }
        if opts["runner"] not in ("local", "docker"):
            raise ApiError(400, "runner must be local or docker")
        if opts["auto_approve"] and not self.allow_auto_approve:
            raise ApiError(403, "auto-approving risky steps is off on this server "
                                "(start it with --allow-auto-approve for lab use)")
        models = o.get("models") or {}
        if not isinstance(models, dict):
            raise ApiError(400, "models must be an object")
        for role, name in models.items():
            if role not in ROLES:
                raise ApiError(400, f"unknown role {str(role)[:20]!r}")
            name = str(name or "").strip()
            if name:
                if not MODEL_RE.match(name):
                    raise ApiError(400, f"invalid model name for {role}")
                opts["models"][role] = name
        key = str(o.get("key") or "").strip()
        if key:
            self._answer_key(key)
            opts["key"] = key
        if kind == "plan":
            opts["runs"], opts["workers"], opts["auto_approve"] = 1, 1, False
        if kind == "demo":
            opts.update(runner="local", models={}, context=None, auto_approve=False,
                        approval_demo=bool(o.get("approval_demo")))
        return opts

    def _job_config(self, job: Job) -> Config:
        cfg = copy.deepcopy(self.cfg)
        o = job.options
        cfg.workdir = job.dir
        cfg.runs, cfg.workers, cfg.runner = o["runs"], o["workers"], o["runner"]
        cfg.toolpacks = list(o["toolpacks"])
        cfg.max_steps_per_task = o["max_steps"]
        for role, name in (o.get("models") or {}).items():
            setattr(cfg, f"{role}_model", name)
        if job.kind == "demo":
            cfg.backend = "mock"
            if o.get("approval_demo"):
                cfg.executor_model = "mock-approval"   # proposes one gated (harmless) step
        return cfg

    def start_job(self, body: dict) -> Job:
        kind = str(body.get("kind") or "run")
        if kind not in ("run", "plan", "demo"):
            raise ApiError(400, "kind must be run, plan or demo")
        sid = DEMO_SCOPE_ID if kind == "demo" else str(body.get("scope_id") or "")
        scope, name = self._load_scope(sid)
        opts = self._options(kind, body)
        operator = str(body.get("operator") or "").strip()[:120]
        if kind == "run":
            if str(body.get("authorized") or "").strip() != AUTH_PHRASE:
                raise ApiError(403, f"type {AUTH_PHRASE!r} to confirm you are authorized "
                                    "to test every target in this scope")
            cfg_probe = copy.deepcopy(self.cfg)
            cfg_probe.runs, cfg_probe.workers, cfg_probe.runner = opts["runs"], opts["workers"], opts["runner"]
            cfg_probe.toolpacks = opts["toolpacks"]
            errors, _ = preflight(cfg_probe, scope)
            if errors:
                raise ApiError(400, "pre-flight refused this run", errors=errors)
        with self.lock:
            waiting = sum(1 for j in self.jobs.values() if j.status == "queued")
            if waiting >= MAX_PENDING:
                raise ApiError(429, f"{waiting} runs are already waiting; try again later")
            jid = self._new_id()
            while jid in self.jobs:
                jid = self._new_id()
            d = self.runs_dir / jid
            d.mkdir(parents=True)
            job = Job(id=jid, kind=kind, scope_id=sid, scope_name=name, dir=d,
                      options=opts, operator=operator)
            job.progress["runs"] = opts["runs"]
            self.jobs[jid] = job
            job.save()
        if sid != DEMO_SCOPE_ID:
            shutil.copy2(self._scope_path(sid), d / "scope.yaml")
        self.queue.put(jid)
        return job

    def _ask(self, job: Job, command: str, reason: str) -> bool:
        """The Sandbox's approval callback: park the command until a human decides."""
        if job.stop_requested:
            return False
        if job.options.get("auto_approve"):
            job.add_log(f"[approval] auto-approved (lab mode): {command}")
            self._audit(job, "approval", command, decision="approved", by="auto (lab mode)", reason=reason)
            return True
        appr = Approval(id=secrets.token_hex(4), command=command, reason=reason)
        with job.lock:
            job.approvals[appr.id] = appr
        job.add_log(f"[approval] waiting for a human: {command}")
        decided = appr.event.wait(self.approval_timeout or None)
        if not decided:
            with job.lock:
                appr.decision, appr.decided_by = False, "timeout"
            job.add_log(f"[approval] no answer in {self.approval_timeout}s, declined: {command}")
        else:
            job.add_log(f"[approval] {'approved' if appr.decision else 'declined'} by "
                        f"{appr.decided_by or 'operator'}: {command}")
        self._audit(job, "approval", command, decision="approved" if appr.decision else "declined",
                    by=appr.decided_by or "operator", reason=reason)
        return bool(appr.decision)

    def _audit(self, job: Job, kind: str, message: str, **extra) -> None:
        h = job.harness
        if h is not None:
            try:
                h.audit.record_event(kind, message, **extra)
            except Exception:  # noqa: BLE001 - never let auditing kill the run
                pass

    def decide(self, job_id: str, approval_id: str, body: dict) -> dict:
        job = self._job(job_id)
        approve = body.get("approve")
        if not isinstance(approve, bool):
            raise ApiError(400, "approve must be true or false")
        who = str(body.get("operator") or "").strip()[:120] or "web operator"
        with job.lock:
            appr = job.approvals.get(approval_id)
            if not appr:
                raise ApiError(404, "no such approval")
            if appr.decision is not None:
                raise ApiError(409, f"already {'approved' if appr.decision else 'declined'}")
            appr.decision, appr.decided_by = approve, who
        appr.event.set()
        return {"ok": True}

    def _decline_all(self, job: Job, by: str) -> None:
        with job.lock:
            pending = [a for a in job.approvals.values() if a.decision is None]
            for a in pending:
                a.decision, a.decided_by = False, by
        for a in pending:
            a.event.set()

    def stop_job(self, job_id: str, reason: str = "stopped from the web UI") -> Job:
        job = self._job(job_id)
        if job.status == "queued":
            job.status, job.finished = "cancelled", time.time()
            job.save()
            return job
        if job.status != "running":
            raise ApiError(409, f"run is {job.status}")
        job.stop_requested = True
        job.add_log(f"[stop] emergency stop: {reason}")
        if job.harness is not None:
            job.harness.stop(reason)
        self._decline_all(job, "emergency stop")
        return job

    def stop_all(self) -> dict:
        n = 0
        with self.lock:
            active = [j for j in self.jobs.values() if j.status in ACTIVE]
        for j in active:
            try:
                self.stop_job(j.id, "STOP ALL from the web UI")
                n += 1
            except ApiError:
                pass
        return {"stopped": n}

    def delete_job(self, job_id: str) -> None:
        job = self._job(job_id)
        if job.status in ACTIVE:
            raise ApiError(409, "stop the run first")
        with self.lock:
            self.jobs.pop(job.id, None)
        shutil.rmtree(job.dir, ignore_errors=True)

    def _job(self, job_id: str) -> Job:
        with self.lock:
            job = self.jobs.get(job_id)
        if not job:
            raise ApiError(404, "no such run")
        return job

    def job_list(self) -> list[dict]:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: j.created, reverse=True)[:KEEP_RUNS]
        queued = sorted((j for j in jobs if j.status == "queued"), key=lambda j: j.created)
        pos = {j.id: i + 1 for i, j in enumerate(queued)}
        out = []
        for j in jobs:
            d = j.summary_public(self.approval_timeout)
            d["position"] = pos.get(j.id)
            out.append(d)
        return out

    def job_detail(self, job_id: str, since: int = 0) -> dict:
        job = self._job(job_id)
        d = job.summary_public(self.approval_timeout)
        with job.lock:
            if not job.log and since == 0 and (job.dir / "log.txt").is_file() and job.status not in ACTIVE:
                lines = (job.dir / "log.txt").read_text(encoding="utf-8", errors="replace").splitlines()
                lines = lines[-MAX_LOG_LINES:]
                d["log"] = [{"t": None, "text": ln[9:] if re.match(r"^\d\d:\d\d:\d\d ", ln) else ln}
                            for ln in lines]
                d["log_next"] = len(lines)
            else:
                start = max(0, since - job.log_base)
                d["log"] = job.log[start:]
                d["log_next"] = job.log_base + len(job.log)
            d["approvals"] = [a.public(self.approval_timeout)
                              for a in job.approvals.values() if a.decision is None]
        d["scope"] = None
        sp = job.dir / "scope.yaml"
        if sp.is_file():
            try:
                d["scope"] = _scope_summary(Scope.load(sp))
            except Exception:  # noqa: BLE001
                pass
        return d

    # ---- results
    def results(self, job_id: str) -> dict:
        job = self._job(job_id)
        report = _read_json(job.dir / "reports" / "report.json")
        threat = _read_json(job.dir / "threat_model.json")
        if report is None and threat is None:
            raise ApiError(404, "no results yet")
        return {"report": report, "threat_model": (report or {}).get("threat_model") or threat}

    def audit(self, job_id: str, offset: int, limit: int, kind: str, q: str) -> dict:
        job = self._job(job_id)
        p = job.dir / "audit.jsonl"
        entries = []
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict):
                    entries.append(e)
        def label(e):
            return "command" if e.get("type") == "command" else str(e.get("kind") or "event")
        counts: dict[str, int] = {}
        for e in entries:
            counts[label(e)] = counts.get(label(e), 0) + 1
        if kind:
            entries = [e for e in entries if label(e) == kind]
        if q:
            ql = q.lower()
            entries = [e for e in entries if ql in json.dumps(e, default=str).lower()]
        total = len(entries)
        page = []
        for e in entries[offset:offset + limit]:
            e = dict(e)
            for k in ("stdout", "stderr"):
                if isinstance(e.get(k), str) and len(e[k]) > MAX_OUTPUT:
                    e[k] = e[k][:MAX_OUTPUT] + f"\n…[{len(e[k]) - MAX_OUTPUT} more characters in audit.jsonl]"
            page.append(e)
        return {"total": total, "counts": counts, "entries": page}

    def evidence(self, job_id: str, ids: list[str]) -> dict:
        job = self._job(job_id)
        want = {i for i in ids if re.match(r"^(cmd|evt)_[0-9a-f]{8}$", i)}
        out = {}
        p = job.dir / "audit.jsonl"
        if want and p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if isinstance(e, dict) and e.get("id") in want:
                    for k in ("stdout", "stderr"):
                        if isinstance(e.get(k), str) and len(e[k]) > MAX_OUTPUT:
                            e[k] = e[k][:MAX_OUTPUT] + "\n…[truncated]"
                    out[e["id"]] = e
        return {"entries": out}

    def benchmark(self, job_id: str, key_id: str) -> dict:
        job = self._job(job_id)
        data = _read_json(job.dir / "reports" / "report.json")
        if data is None:
            raise ApiError(404, "this run has no report yet")
        res = score(self._answer_key(key_id), _report_from_json(data))
        return {
            "key": key_id, "recall": round(res.recall, 4),
            "found_weight": res.found_weight, "total_weight": res.total_weight,
            "false_positives": res.false_positives,
            "per_severity": {k: {"found": v[0], "total": v[1]} for k, v in res.per_severity().items()},
            "matches": [{"id": m.expected.id, "title": m.expected.title,
                         "severity": m.expected.severity.value, "component": m.expected.component,
                         "found": m.found, "finding_id": m.matched_finding_id} for m in res.matches],
        }

    def artifact(self, job_id: str, name: str) -> tuple[bytes, str]:
        job = self._job(job_id)
        if name not in ARTIFACTS:
            raise ApiError(404, "unknown file")
        p = job.dir / ("reports/" + name if name.startswith("report.") else name)
        if not p.is_file():
            raise ApiError(404, f"{name} has not been produced")
        return p.read_bytes(), ARTIFACTS[name][1]

    # ---- the worker
    def _work(self) -> None:
        while not self._shutdown.is_set():
            try:
                jid = self.queue.get(timeout=0.5)
            except Empty:
                continue
            job = self.jobs.get(jid)
            if job is None or job.status != "queued":
                continue
            self._run(job)

    def _run(self, job: Job) -> None:
        from ..cli import _load_context
        from ..harness import Harness

        job.status, job.started = "running", time.time()
        job.progress["phase"] = "plan"
        job.save()
        try:
            cfg = self._job_config(job)
            scope, _ = self._load_scope(job.scope_id) if job.scope_id == DEMO_SCOPE_ID else \
                (Scope.load(job.dir / "scope.yaml"), job.scope_id)
            o = job.options
            job.add_log(f"[web] {job.kind} on scope {job.scope_name!r} · backend={cfg.backend} · "
                        f"runs={cfg.runs} workers={cfg.workers} runner={cfg.runner} · "
                        f"packs={','.join(cfg.toolpacks)}")
            harness = Harness(cfg, scope, approval_fn=lambda c, r: self._ask(job, c, r),
                              observer=job.add_log)
            job.harness = harness
            if job.kind == "run":
                harness.audit.record_event(
                    "authorization", f"{AUTH_PHRASE} (web UI)",
                    operator=job.operator or "web operator",
                    authorized_by=(scope.engagement or {}).get("authorized_by", ""),
                    in_scope=list(scope.in_scope))
            if job.stop_requested:
                raise _Stopped()
            context = _load_context(o.get("context"))
            threat = harness.plan(context)
            _write_json(job.dir / "threat_model.json", threat.to_dict())
            job.summary = {"tasks": len(threat.tasks), "assets": len(threat.assets)}
            if job.kind == "plan":
                job.status = "done"
                return
            if job.stop_requested:
                raise _Stopped()
            candidates = harness.execute(threat)
            verified = harness.verify(candidates)
            report = harness.assess(verified)
            meta = {"runs": cfg.runs, "backend": cfg.backend, "executor": cfg.executor_model,
                    "verifier": cfg.verifier_model, "runner": cfg.runner, "workers": cfg.workers,
                    "toolpacks": cfg.toolpacks, "job": job.id, "stopped": job.stop_requested}
            cfg.ensure_dirs()
            (cfg.report_dir / "report.md").write_text(to_markdown(threat, report, meta))
            (cfg.report_dir / "report.json").write_text(to_json(threat, report, meta))
            (cfg.report_dir / "report.html").write_text(to_html(threat, report, meta))
            job.summary.update(findings=len(report.findings), score=report.weighted_score,
                               severity_counts=report.severity_counts(), chains=len(report.chains),
                               candidates=len(candidates),
                               rejected=sum(1 for f in verified if not f.verified))
            if o.get("key"):
                try:
                    b = self.benchmark(job.id, o["key"])
                    job.summary["benchmark"] = {"key": o["key"], "recall": b["recall"],
                                                "false_positives": b["false_positives"]}
                except ApiError as exc:
                    job.add_log(f"[benchmark] skipped: {exc.message}")
            job.status = "stopped" if job.stop_requested else "done"
            job.add_log(f"[web] finished: {job.summary.get('findings', 0)} finding(s), "
                        f"score {job.summary.get('score', 0)}")
        except _Stopped:
            job.status = "stopped"
        except Exception as exc:  # noqa: BLE001 - a broken run must not kill the server
            job.status = "stopped" if job.stop_requested else "failed"
            job.error = f"{exc.__class__.__name__}: {exc}"[:2000]
            job.add_log(f"[error] {job.error}")
        finally:
            self._decline_all(job, "run ended")
            job.progress["phase"] = job.status
            job.finished = time.time()
            job.harness = None
            job.save()

    def shutdown(self) -> None:
        self._shutdown.set()
        self.stop_all()


class _Stopped(Exception):
    pass


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = f"penlocal/{__version__}"
    protocol_version = "HTTP/1.1"

    @property
    def app(self) -> WebApp:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    # ---- low-level
    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, data, extra: dict | None = None):
        self._send(status, json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"),
                   "application/json; charset=utf-8", extra)

    def _token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None
        morsel = jar.get(COOKIE)
        return morsel.value if morsel else None

    def _cookie_header(self, token: str) -> str:
        return f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict"

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "request too large")
        self._raw = self.rfile.read(length) if length else b""

    def _body(self) -> dict:
        raw = getattr(self, "_raw", b"")
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            raise ApiError(400, "body must be JSON") from None
        if not isinstance(data, dict):
            raise ApiError(400, "body must be a JSON object")
        return data

    def _check_post(self):
        if self.headers.get(CSRF_HEADER) != "1":
            raise ApiError(403, f"missing {CSRF_HEADER} header")
        origin = self.headers.get("Origin")
        if origin and origin != "null" and urlsplit(origin).netloc != self.headers.get("Host", ""):
            raise ApiError(403, "cross-origin request refused")

    # ---- dispatch
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        url = urlsplit(self.path)
        path = url.path
        qs = parse_qs(url.query)
        try:
            if method == "POST":
                self._read_body()
            if method == "GET" and path in STATIC_FILES:
                return self._static(path, qs)
            if not path.startswith("/api/"):
                raise ApiError(404, "not found")
            if method == "POST":
                self._check_post()
            if path == "/api/login" and method == "POST":
                return self._login()
            if not self.app.check_token(self._token()):
                raise ApiError(401, "access token required")
            return self._api(method, path, qs)
        except ApiError as exc:
            self._json(exc.status, {"error": exc.message, **exc.extra})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # noqa: BLE001 - never leak a traceback page
            self._json(500, {"error": f"{exc.__class__.__name__}: {exc}"})

    def _static(self, path: str, qs: dict):
        name, ctype = STATIC_FILES[path]
        token = (qs.get("token") or [None])[0]
        if path == "/" and token:
            # Trade the token in the URL for a cookie and drop it from the address bar.
            if not self.app.check_token(token):
                raise ApiError(401, "wrong access token")
            self._send(303, b"", "text/plain", {"Location": "/",
                                                 "Set-Cookie": self._cookie_header(token)})
            return
        f = STATIC_DIR / name
        if not f.is_file():
            body = (b"<!doctype html><title>penlocal</title><p>The web UI bundle is missing. "
                    b"Build it with <code>cd web &amp;&amp; npm ci &amp;&amp; npm run build</code>.")
            return self._send(200 if name == "index.html" else 404, body, "text/html; charset=utf-8")
        self._send(200, f.read_bytes(), ctype)

    def _login(self):
        token = str(self._body().get("token") or "").strip()
        if not self.app.check_token(token):
            time.sleep(0.5)
            raise ApiError(401, "wrong access token")
        self._json(200, {"ok": True}, {"Set-Cookie": self._cookie_header(token)})

    def _api(self, method: str, path: str, qs: dict):
        app = self.app
        parts = [unquote(p) for p in path[len("/api/"):].split("/") if p]
        q = lambda k, d=None: (qs.get(k) or [d])[0]

        if method == "GET" and parts == ["status"]:
            return self._json(200, app.server_status())
        if method == "GET" and parts == ["scopes"]:
            return self._json(200, app.list_scopes())
        if len(parts) == 2 and parts[0] == "scopes":
            if method == "GET":
                return self._json(200, app.get_scope(parts[1]))
            return self._json(200, app.save_scope(parts[1], self._body()))
        if method == "POST" and parts == ["explain"]:
            return self._json(200, app.explain(self._body()))
        if method == "GET" and parts == ["contexts"]:
            return self._json(200, {"contexts": app.contexts()})
        if method == "POST" and parts == ["stop-all"]:
            return self._json(200, app.stop_all())
        if parts == ["jobs"]:
            if method == "GET":
                return self._json(200, {"jobs": app.job_list()})
            job = app.start_job(self._body())
            return self._json(202, job.summary_public(app.approval_timeout))
        if len(parts) >= 2 and parts[0] == "jobs":
            jid, rest = parts[1], parts[2:]
            if not JOB_RE.match(jid):
                raise ApiError(404, "no such run")
            if method == "GET" and rest == []:
                return self._json(200, app.job_detail(jid, _int(q("since"), 0, 10**9, "since", 0)))
            if method == "GET" and rest == ["results"]:
                return self._json(200, app.results(jid))
            if method == "GET" and rest == ["audit"]:
                return self._json(200, app.audit(
                    jid, _int(q("offset"), 0, 10**9, "offset", 0),
                    _int(q("limit"), 1, 500, "limit", 100),
                    str(q("kind", "") or "")[:40], str(q("q", "") or "")[:200]))
            if method == "GET" and rest == ["evidence"]:
                return self._json(200, app.evidence(jid, str(q("ids", "")).split(",")[:50]))
            if method == "GET" and rest == ["benchmark"]:
                return self._json(200, app.benchmark(jid, str(q("key", ""))))
            if method == "GET" and len(rest) == 2 and rest[0] == "files":
                data, ctype = app.artifact(jid, rest[1])
                fname = f"penlocal-{jid}-{rest[1]}"
                return self._send(200, data, ctype, {
                    "Content-Disposition": f"attachment; filename=\"{fname}\""})
            if method == "POST" and rest == ["stop"]:
                return self._json(200, app.stop_job(jid).summary_public(app.approval_timeout))
            if method == "POST" and rest == ["delete"]:
                app.delete_job(jid)
                return self._json(200, {"ok": True})
            if method == "POST" and len(rest) == 2 and rest[0] == "approvals":
                return self._json(200, app.decide(jid, rest[1], self._body()))
        raise ApiError(404, "not found")


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, app: WebApp, verbose: bool = False):
        host = addr[0]
        if ":" in host:
            import socket
            self.address_family = socket.AF_INET6
        super().__init__(addr, Handler)
        self.app = app
        self.verbose = verbose


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(app: WebApp, bind: str = "127.0.0.1", port: int = 8770,
                verbose: bool = False) -> _Server:
    if app.no_auth and not is_loopback(bind):
        raise SystemExit("--no-auth is only allowed when binding to a loopback address")
    return _Server((bind, port), app, verbose=verbose)


def serve(cfg: Config, scopes_dir: Path, workdir: Path, bind: str = "127.0.0.1",
          port: int = 8770, token: str | None = None, no_auth: bool = False,
          context_roots: list[Path] | None = None, allow_auto_approve: bool = False,
          approval_timeout: int = 900, open_browser: bool = False, verbose: bool = False) -> int:
    token = token or os.environ.get("PENLOCAL_WEB_TOKEN") or None
    app = WebApp(cfg, scopes_dir, workdir, context_roots=context_roots, token=token,
                 no_auth=no_auth, allow_auto_approve=allow_auto_approve,
                 approval_timeout=approval_timeout)
    httpd = make_server(app, bind, port, verbose)
    host = "localhost" if bind in ("127.0.0.1", "::1", "0.0.0.0", "::") else bind
    if ":" in host:
        host = f"[{host}]"
    url = f"http://{host}:{httpd.server_address[1]}/"
    link = url if no_auth else f"{url}?token={app.token}"
    print(f"penlocal web UI: {link}")
    print(f"  scopes:  {app.scopes_dir}")
    print(f"  runs:    {app.runs_dir}")
    print(f"  backend: {cfg.backend} ({app._endpoint()})")
    if not is_loopback(bind):
        print("  [warn] listening beyond loopback; put it behind TLS (a reverse proxy) and "
              "keep the token secret.")
    if allow_auto_approve:
        print("  [warn] --allow-auto-approve: the UI can auto-approve risky steps. Lab use only.")
    if open_browser:
        import webbrowser
        webbrowser.open(link)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping: emergency-stopping active runs…")
    finally:
        app.shutdown()
        httpd.server_close()
    return 0
