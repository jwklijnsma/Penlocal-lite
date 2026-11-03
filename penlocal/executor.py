"""Executor — the per-task agent loop.

For one task, the executor model repeatedly proposes a single shell command.
The harness runs it through the Sandbox (scope + approval + audit) and feeds the
trimmed output back. The model may at any step record a candidate finding, which
MUST cite the audit-log ids of the commands that prove it. Findings are only
*candidates* here — the Verifier decides later whether the evidence holds.

The model never executes anything itself; it only emits JSON the harness acts on.
"""
from __future__ import annotations

from typing import Callable

from .auditlog import AuditLog
from .llm import LocalLLM
from .models import Finding, Severity, Task, TaskStatus
from .sandbox import EmergencyStop, Sandbox

EXECUTOR_SYSTEM = """You are the execution component of an authorized penetration
test harness, working one task at a time. You can only act by emitting ONE JSON
object per turn. The harness runs your command in a sandbox that enforces scope
and blocks destructive actions, and returns the output.

Respond with STRICT JSON, one of:
  {"thought": "...", "command": "<single shell command>"}
  {"thought": "...", "finding": {"title": "...", "severity":
     "info|low|medium|high|critical", "description": "...",
     "evidence_ids": ["cmd_xxxx", ...], "cwe": "CWE-nnn",
     "recommendation": "..."}}
  {"thought": "...", "done": true}

Rules:
- One command at a time. Prefer non-destructive, information-gathering steps.
- Only target hosts in scope. Do not attempt to leave the sandbox.
- A finding MUST cite evidence_ids that already appear in the transcript.
- Do not fabricate output or evidence. If unsure, gather more evidence.
- When the task's objective is met or exhausted, return {"done": true}.
"""

TASK_TEMPLATE = """Task: {objective}
Component: {component}
Attack class: {attack_class}
In-scope targets:
{targets}

Transcript so far:
{transcript}

Emit the next JSON action."""


class Executor:
    def __init__(
        self,
        llm: LocalLLM,
        sandbox: Sandbox,
        audit: AuditLog,
        max_steps: int = 12,
        observer: Callable[[str], None] | None = None,
    ) -> None:
        self.llm = llm
        self.sandbox = sandbox
        self.audit = audit
        self.max_steps = max_steps
        self.observe = observer or (lambda _m: None)

    def run_task(self, task: Task, in_scope: list[str]) -> list[Finding]:
        task.status = TaskStatus.RUNNING
        transcript: list[str] = []
        findings: list[Finding] = []
        targets = "\n".join(f"- {t}" for t in in_scope)

        for step in range(self.max_steps):
            user = TASK_TEMPLATE.format(
                objective=task.objective, component=task.component,
                attack_class=task.attack_class, targets=targets,
                transcript="\n".join(transcript[-40:]) or "(nothing yet)",
            )
            try:
                action = self.llm.chat_json(EXECUTOR_SYSTEM, user)
            except Exception as exc:  # malformed output — note and stop the task
                self.observe(f"  [executor] bad JSON, ending task: {exc}")
                break

            if action.get("done"):
                task.status = TaskStatus.DONE
                break

            if "finding" in action and action["finding"]:
                f = action["finding"]
                finding = Finding(
                    title=str(f.get("title", "untitled")),
                    severity=Severity.coerce(f.get("severity", "info")),
                    description=str(f.get("description", "")),
                    task_id=task.id,
                    component=task.component,
                    cwe=str(f.get("cwe", "")),
                    recommendation=str(f.get("recommendation", "")),
                    evidence_ids=[str(e) for e in f.get("evidence_ids", [])],
                )
                findings.append(finding)
                self.observe(f"  [candidate] {finding.severity.value.upper()}: {finding.title}")
                transcript.append(f"[recorded candidate finding: {finding.title}]")
                continue

            command = str(action.get("command", "")).strip()
            if not command:
                transcript.append("[no command produced]")
                continue

            self.observe(f"  $ {command}")
            try:
                result = self.sandbox.run(command, task_id=task.id)
            except EmergencyStop:
                task.status = TaskStatus.BLOCKED
                raise

            # Feed back a trimmed, id-tagged observation.
            body = result.combined_output
            if len(body) > 2500:
                body = body[:2500] + "\n...[truncated]"
            tag = result.id if result.approved_by not in ("blocked", "declined") else result.approved_by
            transcript.append(f"$ {command}\n[{tag}] (exit {result.exit_code})\n{body}")
        else:
            task.status = TaskStatus.DONE  # ran out of steps

        return findings
