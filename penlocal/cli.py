"""Command-line entry point for PenLocal-lite."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .benchmark import AnswerKey, render as render_bench, score
from .config import Config
from .harness import Harness, cli_approval
from .llm import make_llm
from .report import to_html, to_json, to_markdown
from .scope import Decision, Scope
from .toolpacks import REGISTRY, merged_policy, resolve
from .validation import preflight

BANNER = r"""
  ____            _                    _        _ _ _
 |  _ \ ___ _ __ | |    ___   ___ __ _| |      | (_) |_ ___
 | |_) / _ \ '_ \| |   / _ \ / __/ _` | |______| | | __/ _ \
 |  __/  __/ | | | |__| (_) | (_| (_| | |______| | | ||  __/
 |_|   \___|_| |_|_____\___/ \___\__,_|_|      |_|_|\__\___|
   local-AI pentest harness · the model is only the brain
"""

AUTH_NOTICE = (
    "You must have explicit, written authorization to test every target in\n"
    "scope. This tool enforces scope, blocks destructive commands, logs\n"
    "everything, and gates risky steps behind your approval — but YOU are\n"
    "responsible for staying inside the law and the engagement."
)

_CODE_EXT = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php", ".md",
             ".yaml", ".yml", ".json", ".env", ".conf"}


def _apply_overrides(cfg: Config, args) -> Config:
    for attr in ("runs", "runner", "backend", "workers"):
        val = getattr(args, attr, None)
        if val:
            setattr(cfg, attr, val)
    if getattr(args, "toolpack", None):
        cfg.toolpacks = args.toolpack
    if getattr(args, "workdir", None):
        cfg.workdir = Path(args.workdir)
    return cfg


def _confirm_authorized(scope: Scope, assume_yes: bool) -> bool:
    print("In-scope targets:")
    for t in scope.in_scope:
        print(f"  - {t}")
    print("\n" + AUTH_NOTICE)
    if assume_yes:
        print("\n[--yes] authorization asserted by operator.")
        return True
    try:
        return input("\nType 'I AM AUTHORIZED' to continue: ").strip() == "I AM AUTHORIZED"
    except EOFError:
        return False


def _load_context(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(path)
    if p.is_file():
        return p.read_text(errors="ignore")
    if p.is_dir():
        chunks: list[str] = []
        for f in sorted(p.rglob("*")):
            if f.is_file() and f.suffix in _CODE_EXT:
                chunks.append(f"// {f}\n{f.read_text(errors='ignore')[:2000]}")
            if sum(len(c) for c in chunks) > 20000:
                break
        return "\n\n".join(chunks)
    return None


def _write_reports(cfg: Config, threat, report, meta, want_html: bool):
    cfg.ensure_dirs()
    md = to_markdown(threat, report, meta)
    (cfg.report_dir / "report.md").write_text(md)
    (cfg.report_dir / "report.json").write_text(to_json(threat, report, meta))
    if want_html:
        (cfg.report_dir / "report.html").write_text(to_html(threat, report, meta))
    return md


def _meta(cfg: Config) -> dict:
    return {"runs": cfg.runs, "backend": cfg.backend, "executor": cfg.executor_model,
            "verifier": cfg.verifier_model, "runner": cfg.runner, "workers": cfg.workers}


# --------------------------------------------------------------------------- #
#  commands
# --------------------------------------------------------------------------- #
def cmd_check(args) -> int:
    cfg = _apply_overrides(Config.load(args.config), args)
    where = cfg.ollama_base_url if cfg.backend == "ollama" else cfg.api_base
    print(f"Backend: {cfg.backend}  ({where})")
    for role, model in cfg.role_models().items():
        llm = make_llm(cfg.backend, model, base_url=cfg.ollama_base_url,
                       api_base=cfg.api_base, api_key=cfg.api_key)
        ok = llm.available()
        print(f"  {role:9s} {model:22s} {'reachable' if ok else 'NOT reachable'}")
    if cfg.verifier_model == cfg.executor_model and cfg.backend != "mock":
        print("\n[warn] verifier and executor use the same model; a different "
              "verifier model catches more hallucinations.")
    return 0


def cmd_plan(args) -> int:
    cfg = _apply_overrides(Config.load(args.config), args)
    harness = Harness(cfg, Scope.load(args.scope))
    tm = harness.plan(_load_context(args.context))
    print("\n" + tm.summary + "\n")
    for i, t in enumerate(tm.tasks, 1):
        print(f"{i:2d}. [{t.attack_class}] {t.component} — {t.objective}")
    return 0


def _preflight_or_abort(cfg: Config, scope: Scope | None) -> bool:
    """Print warnings, and refuse to run if there are hard errors."""
    errors, warnings = preflight(cfg, scope)
    for w in warnings:
        print(f"  [warn] {w}")
    for e in errors:
        print(f"  [ERROR] {e}")
    if errors:
        print("\nRefusing to run until the errors above are fixed.")
        return False
    return True


def _do_run(cfg: Config, args, scope: Scope):
    approval = (lambda c, r: True) if getattr(args, "auto_approve_risky", False) else cli_approval
    harness = Harness(cfg, scope, approval_fn=approval)
    threat, report = harness.run(_load_context(getattr(args, "context", None)))
    md = _write_reports(cfg, threat, report, _meta(cfg), getattr(args, "html", False))
    print("\n" + "=" * 60 + "\n" + md + "\n" + "=" * 60)
    print(f"\nReports: {cfg.report_dir}/  ·  audit: {cfg.audit_path}")
    return threat, report


def cmd_run(args) -> int:
    cfg = _apply_overrides(Config.load(args.config), args)
    scope = Scope.load(args.scope)
    if not _preflight_or_abort(cfg, scope):
        return 2
    if not _confirm_authorized(scope, args.yes):
        print("Authorization not confirmed. Aborting.")
        return 1
    _do_run(cfg, args, scope)
    return 0


def cmd_explain(args) -> int:
    """Audit the guardrail: show allow / deny / approve for candidate commands,
    without running anything. Use this to review scope coverage before a test."""
    cfg = _apply_overrides(Config.load(args.config), args)
    scope = Scope.load(args.scope)
    # Apply the same tool-pack policy the harness would, so `explain` reflects
    # exactly what a run will allow/deny/gate.
    packs = resolve(cfg.toolpacks)
    deny, risky, scanners = merged_policy(packs)
    scope.extend_policy(denylist=deny, risky=risky, scanners=scanners)
    print(f"Tool packs: {', '.join(p.name for p in packs)}")

    errors, warnings = preflight(cfg, scope)
    for w in warnings:
        print(f"  [warn] {w}")
    for e in errors:
        print(f"  [scope error] {e}")

    cmds: list[str] = list(args.cmd or [])
    if args.file:
        cmds += [ln.strip() for ln in Path(args.file).read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
    if not cmds:
        try:
            print("\nEnter commands to test (one per line, Ctrl-D to finish):")
            cmds = [ln.strip() for ln in sys.stdin.read().splitlines() if ln.strip()]
        except EOFError:
            cmds = []

    label = {Decision.ALLOW: "ALLOW  ", Decision.APPROVE: "APPROVE", Decision.DENY: "DENY   "}
    print()
    for c in cmds:
        r = scope.classify_command(c)
        tgts = f"  targets={r.targets}" if r.targets else ""
        print(f"  [{label[r.decision]}] {c}")
        print(f"             ↳ {r.reason}{tgts}")
    return 0


def cmd_demo(args) -> int:
    """Full pipeline, offline: mock brain + echo probes. Touches nothing real."""
    cfg = _apply_overrides(Config.load(args.config), args)
    cfg.backend = "mock"
    cfg.workdir = Path(args.workdir) if args.workdir else Path("./penlocal-demo")
    scope = Scope(in_scope=["127.0.0.1", "demo.local"])
    print("[demo] backend=mock — no model server, no real targets.\n")
    _preflight_or_abort(cfg, scope)  # demo surfaces warnings but never aborts
    threat, report = _do_run(cfg, args, scope)
    if args.key:
        res = score(AnswerKey.load(args.key), report)
        print("\n" + render_bench(res))
    return 0


def cmd_benchmark(args) -> int:
    cfg = _apply_overrides(Config.load(args.config), args)
    key = AnswerKey.load(args.key)
    if args.report:  # score an existing report.json
        import json
        from .models import Finding, Severity
        from .assessor import AssessmentReport
        data = json.loads(Path(args.report).read_text())
        findings = [
            Finding(title=f["title"], severity=Severity.coerce(f["severity"]),
                    description=f["description"], component=f.get("component", ""),
                    cwe=f.get("cwe", ""), evidence_ids=f.get("evidence_ids", []),
                    verified=True)
            for f in data.get("findings", [])
        ]
        report = AssessmentReport(findings=findings, chains=data.get("chains", []))
    else:
        scope = Scope.load(args.scope)
        if not _preflight_or_abort(cfg, scope):
            return 2
        if not _confirm_authorized(scope, args.yes):
            print("Authorization not confirmed. Aborting.")
            return 1
        _, report = _do_run(cfg, args, scope)
    print("\n" + render_bench(score(key, report)))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="penlocal",
                                description="Local-AI pentest harness (PenLocal-lite).")
    p.add_argument("--version", action="version", version=f"penlocal-lite {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--config")
        sp.add_argument("--backend", choices=["ollama", "openai-compat", "mock"])
        sp.add_argument("--runs", type=int)
        sp.add_argument("--workers", type=int, help="Parallel tasks within a run.")
        sp.add_argument("--runner", choices=["local", "docker"])
        sp.add_argument("--toolpack", action="append",
                        choices=sorted(REGISTRY.keys()),
                        help="Domain pack (repeatable): web, kubernetes, openshift.")
        sp.add_argument("--workdir")

    c = sub.add_parser("check", help="Check that models/backend are reachable.")
    common(c); c.set_defaults(func=cmd_check)

    pl = sub.add_parser("plan", help="Build and print the threat model only.")
    common(pl); pl.add_argument("--scope", required=True)
    pl.add_argument("--context"); pl.set_defaults(func=cmd_plan)

    r = sub.add_parser("run", help="Plan, execute, verify, assess, report.")
    common(r); r.add_argument("--scope", required=True)
    r.add_argument("--context"); r.add_argument("--html", action="store_true")
    r.add_argument("--yes", action="store_true")
    r.add_argument("--auto-approve-risky", action="store_true")
    r.set_defaults(func=cmd_run)

    d = sub.add_parser("demo", help="Run the whole pipeline offline (mock brain).")
    common(d); d.add_argument("--html", action="store_true", default=True)
    d.add_argument("--key", help="Optional answer key to also score the demo.")
    d.set_defaults(func=cmd_demo, auto_approve_risky=False, context=None)

    e = sub.add_parser("explain", help="Show allow/deny/approve for commands, run nothing.")
    common(e); e.add_argument("--scope", required=True)
    e.add_argument("--cmd", action="append", help="A command to classify (repeatable).")
    e.add_argument("--file", help="A file of commands to classify, one per line.")
    e.set_defaults(func=cmd_explain)

    b = sub.add_parser("benchmark", help="Score a run against a weighted answer key.")
    common(b); b.add_argument("--key", required=True)
    b.add_argument("--scope"); b.add_argument("--context")
    b.add_argument("--report", help="Score an existing report.json instead of running.")
    b.add_argument("--html", action="store_true")
    b.add_argument("--yes", action="store_true")
    b.add_argument("--auto-approve-risky", action="store_true")
    b.set_defaults(func=cmd_benchmark)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(BANNER)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
