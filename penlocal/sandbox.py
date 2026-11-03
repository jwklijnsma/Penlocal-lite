"""Sandbox — the only path from the model to anything real.

Every command flows through here. It is classified by the Scope policy, risky
commands are gated behind an approval callback (a human, by default), the
command then runs with a timeout, and the full result is written to the audit
log. A single `stop()` acts as the emergency brake described in the blog.

Two runners are provided:
  * LocalRunner  — subprocess on this host. Isolation is only as good as the
                   host; use a throwaway VM. Scope is still enforced in-process.
  * DockerRunner — one fresh container per task, destroyed after. Closer to the
                   "new sandbox per task" model; still bounded by the denylist.
"""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Callable, Optional

from .auditlog import AuditLog
from .models import CommandResult
from .scope import Decision, Scope

# Returns True to approve a risky command, False to skip it.
ApprovalFn = Callable[[str, str], bool]


def deny_all(_cmd: str, _reason: str) -> bool:
    return False


class EmergencyStop(RuntimeError):
    """Raised when the operator (or a tripwire) halts the engagement."""


class Runner:
    name = "base"

    def exec(self, command: str, timeout: int) -> tuple[int, str, str, float]:
        raise NotImplementedError

    def setup(self) -> None:  # per-task setup hook
        pass

    def teardown(self) -> None:  # per-task teardown hook
        pass


class LocalRunner(Runner):
    name = "local"

    def exec(self, command: str, timeout: int) -> tuple[int, str, str, float]:
        start = time.time()
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr, time.time() - start
        except subprocess.TimeoutExpired as exc:
            return 124, exc.stdout or "", f"timed out after {timeout}s", time.time() - start


class DockerRunner(Runner):
    name = "docker"

    def __init__(self, image: str = "kalilinux/kali-rolling", network: str = "host") -> None:
        self.image = image
        self.network = network
        self._container: Optional[str] = None

    def setup(self) -> None:
        name = f"penlocal_{int(time.time()*1000)}"
        subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", name,
             "--network", self.network, self.image, "sleep", "infinity"],
            capture_output=True, text=True, check=True,
        )
        self._container = name

    def teardown(self) -> None:
        if self._container:
            subprocess.run(["docker", "rm", "-f", self._container],
                           capture_output=True, text=True)
            self._container = None

    def exec(self, command: str, timeout: int) -> tuple[int, str, str, float]:
        if not self._container:
            self.setup()
        start = time.time()
        try:
            proc = subprocess.run(
                ["docker", "exec", self._container, "sh", "-lc", command],
                capture_output=True, text=True, timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr, time.time() - start
        except subprocess.TimeoutExpired as exc:
            return 124, exc.stdout or "", f"timed out after {timeout}s", time.time() - start


class Sandbox:
    def __init__(
        self,
        scope: Scope,
        audit: AuditLog,
        runner: Runner,
        approval_fn: ApprovalFn,
        timeout_s: int = 120,
        stop_event: Optional["threading.Event"] = None,
    ) -> None:
        self.scope = scope
        self.audit = audit
        self.runner = runner
        self.approval_fn = approval_fn
        self.timeout_s = timeout_s
        # Shared across every sandbox in an engagement so one stop halts them all.
        self._stop = stop_event or threading.Event()

    def stop(self, reason: str = "operator halt") -> None:
        self._stop.set()
        self.audit.record_event("emergency_stop", reason)

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def run(self, command: str, task_id: Optional[str] = None) -> CommandResult:
        if self._stop.is_set():
            raise EmergencyStop("Engagement halted; no further commands.")

        policy = self.scope.classify_command(command)
        approved_by = "auto"

        if policy.decision == Decision.DENY:
            self.audit.record_event("blocked", f"$ {command}", reason=policy.reason,
                                    task_id=task_id)
            return CommandResult(
                command=command, stdout="", stderr=f"[blocked] {policy.reason}",
                exit_code=126, duration_s=0.0, task_id=task_id,
                approved_by="blocked", runner=self.runner.name,
            )

        if policy.decision == Decision.APPROVE:
            ok = self.approval_fn(command, policy.reason)
            if not ok:
                self.audit.record_event("skipped", f"$ {command}",
                                        reason="operator declined", task_id=task_id)
                return CommandResult(
                    command=command, stdout="", stderr="[skipped] operator declined",
                    exit_code=125, duration_s=0.0, task_id=task_id,
                    approved_by="declined", runner=self.runner.name,
                )
            approved_by = "operator"

        code, out, err, dur = self.runner.exec(command, self.timeout_s)
        result = CommandResult(
            command=command, stdout=out, stderr=err, exit_code=code,
            duration_s=round(dur, 3), task_id=task_id, approved_by=approved_by,
            runner=self.runner.name,
        )
        self.audit.record_command(result)
        return result
