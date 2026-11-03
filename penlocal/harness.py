"""Harness — the orchestrator that wires the five components together.

    plan  ->  for each task: execute in sandbox  ->  verify  ->  assess  ->  report

Two axes of scale, both faithful to the blog:
  * runs    — repeat the whole task set N times and merge candidates before
              verification, because one LLM run misses what another finds.
  * workers — run tasks within a run in parallel. Each task gets its OWN sandbox
              and runner; with the docker runner that is a fresh container per
              task, destroyed after — the "new sandbox per task" model.

A single shared stop Event is the emergency brake across every worker. Approval
prompts are serialized so parallel workers can't interleave on the terminal.
Model and harness stay separate: each role is any backend/model via make_llm.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from .assessor import AssessmentReport, Assessor
from .auditlog import AuditLog
from .config import Config
from .executor import Executor
from .llm import BaseLLM, make_llm
from .models import Finding, ThreatModel
from .planner import Planner
from .sandbox import (ApprovalFn, DockerRunner, EmergencyStop, LocalRunner,
                      Runner, Sandbox)
from .scope import Scope
from .toolpacks import merged_policy, planner_guidance, resolve
from .verifier import Verifier


def cli_approval(command: str, reason: str) -> bool:
    print(f"\n  [APPROVAL NEEDED] {reason}\n  $ {command}")
    try:
        return input("  Run it? [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


class Harness:
    def __init__(
        self,
        config: Config,
        scope: Scope,
        approval_fn: ApprovalFn = cli_approval,
        observer: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.cfg = config
        self.scope = scope
        self.observe = observer or print
        config.ensure_dirs()
        self.audit = AuditLog(config.audit_path)
        self._stop = threading.Event()

        # Apply selected tool packs: extend the policy (stricter) and collect
        # planner guidance (smarter). Idempotent per Harness instance.
        packs = resolve(config.toolpacks)
        deny, risky, scanners = merged_policy(packs)
        scope.extend_policy(denylist=deny, risky=risky, scanners=scanners)
        self._planner_guidance = planner_guidance(packs)
        self._pack_names = [p.name for p in packs]

        # Serialize approval + console output across parallel workers.
        self._io_lock = threading.Lock()
        base_approval = approval_fn

        def _locked_approval(cmd: str, reason: str) -> bool:
            with self._io_lock:
                return base_approval(cmd, reason)

        self.approval_fn = _locked_approval

        self.planner = Planner(self._llm(config.planner_model))
        self.verifier = Verifier(self._llm(config.verifier_model), self.audit)
        self.assessor = Assessor(self._llm(config.assessor_model))

    def _llm(self, model: str) -> BaseLLM:
        return make_llm(
            self.cfg.backend, model,
            base_url=self.cfg.ollama_base_url,
            api_base=self.cfg.api_base, api_key=self.cfg.api_key,
        )

    def _make_runner(self) -> Runner:
        if self.cfg.runner == "docker":
            return DockerRunner(self.cfg.docker_image)
        return LocalRunner()

    def _say(self, msg: str) -> None:
        with self._io_lock:
            self.observe(msg)

    # ---- phases ------------------------------------------------------------
    def plan(self, source_context: Optional[str] = None) -> ThreatModel:
        self.observe(f"[planner] building threat model... (packs: "
                     f"{', '.join(self._pack_names)})")
        tm = self.planner.build_threat_model(
            self.scope, source_context, extra_guidance=self._planner_guidance
        )
        self.audit.record_event("plan", tm.summary, task_count=len(tm.tasks))
        self.observe(f"[planner] {len(tm.tasks)} task(s) across {len(tm.assets)} asset(s).")
        return tm

    def _run_one_task(self, task, executor_llm: BaseLLM) -> list[Finding]:
        """One task in its own sandbox + runner (safe to call from a thread)."""
        if self._stop.is_set():
            return []
        runner = self._make_runner()
        sandbox = Sandbox(
            self.scope, self.audit, runner, self.approval_fn,
            timeout_s=self.cfg.command_timeout_s, stop_event=self._stop,
        )
        executor = Executor(
            executor_llm, sandbox, self.audit,
            max_steps=self.cfg.max_steps_per_task, observer=self._say,
        )
        self._say(f" [task] {task.component} / {task.attack_class}")
        runner.setup()
        try:
            return executor.run_task(task, self.scope.in_scope)
        except EmergencyStop:
            return []
        finally:
            runner.teardown()

    def execute(self, threat: ThreatModel) -> list[Finding]:
        executor_llm = self._llm(self.cfg.executor_model)
        candidates: list[Finding] = []
        for run_i in range(self.cfg.runs):
            if self._stop.is_set():
                break
            self.observe(f"\n[run {run_i + 1}/{self.cfg.runs}] "
                         f"({self.cfg.workers} worker(s), runner={self.cfg.runner})")
            if self.cfg.workers <= 1:
                for task in threat.tasks:
                    if self._stop.is_set():
                        break
                    candidates += self._run_one_task(task, executor_llm)
            else:
                with ThreadPoolExecutor(max_workers=self.cfg.workers) as pool:
                    futures = [pool.submit(self._run_one_task, t, executor_llm)
                               for t in threat.tasks]
                    for fut in as_completed(futures):
                        try:
                            candidates += fut.result()
                        except EmergencyStop:
                            pass
        return candidates

    def verify(self, candidates: list[Finding]) -> list[Finding]:
        self.observe(f"\n[verifier] checking {len(candidates)} candidate(s) "
                     f"with `{self.cfg.verifier_model}`...")
        verified = self.verifier.verify_all(candidates)
        kept = sum(1 for f in verified if f.verified)
        self.observe(f"[verifier] {kept} verified, {len(verified) - kept} rejected.")
        return verified

    def assess(self, verified: list[Finding]) -> AssessmentReport:
        self.observe("[assessor] deduping, weighting, looking for chains...")
        report = self.assessor.assess(verified)
        self.observe(f"[assessor] {len(report.findings)} final finding(s), "
                     f"score {report.weighted_score}, {len(report.chains)} chain(s).")
        return report

    def stop(self, reason: str = "operator halt") -> None:
        self._stop.set()
        self.audit.record_event("emergency_stop", reason)

    def run(self, source_context: Optional[str] = None) -> tuple[ThreatModel, AssessmentReport]:
        threat = self.plan(source_context)
        candidates = self.execute(threat)
        verified = self.verify(candidates)
        report = self.assess(verified)
        return threat, report
