"""Core data structures shared across the harness."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        # Warpnet weights a critical ~5x a trivial finding; mirror that shape.
        return {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 4,
            "critical": 5,
        }[self.value]

    @classmethod
    def coerce(cls, value: str) -> "Severity":
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            return cls.INFO


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    BLOCKED = "blocked"
    FAILED = "failed"


@dataclass
class Task:
    """One unit of work: an attack class applied to one component."""
    component: str
    attack_class: str
    objective: str
    id: str = field(default_factory=lambda: _new_id("task"))
    rationale: str = ""
    status: TaskStatus = TaskStatus.PENDING

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ThreatModel:
    """The planner's output: scope understanding + the task breakdown."""
    summary: str
    assets: list[str]
    tasks: list[Task]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "assets": self.assets,
            "tasks": [t.to_dict() for t in self.tasks],
        }


@dataclass
class CommandResult:
    """The full record of one executed command — the atom of the audit log."""
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_s: float
    task_id: Optional[str] = None
    approved_by: str = "auto"
    runner: str = "local"
    id: str = field(default_factory=lambda: _new_id("cmd"))
    ts: float = field(default_factory=time.time)

    @property
    def combined_output(self) -> str:
        out = self.stdout or ""
        if self.stderr:
            out += ("\n[stderr]\n" + self.stderr)
        return out.strip()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A candidate or confirmed vulnerability, always tied back to evidence."""
    title: str
    severity: Severity
    description: str
    task_id: Optional[str] = None
    component: str = ""
    cwe: str = ""
    recommendation: str = ""
    # IDs of CommandResults in the audit log that back this finding.
    evidence_ids: list[str] = field(default_factory=list)
    verified: Optional[bool] = None
    verifier_notes: str = ""
    id: str = field(default_factory=lambda: _new_id("find"))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d
