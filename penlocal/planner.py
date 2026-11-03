"""Planner — turns a scope + optional source code into a threat model and tasks.

The blog keeps this phase close to the human: the planner proposes, but the
operator is expected to review what will and won't be tested. The output is a
structured task list (one component x attack-class per task) so coverage is
explicit.
"""
from __future__ import annotations

from typing import Optional

from .llm import LocalLLM
from .models import Task, ThreatModel
from .scope import Scope

PLANNER_SYSTEM = """You are the planning component of an authorized penetration
test harness. You translate an engagement scope into a threat model and a flat
list of concrete test tasks.

Rules:
- Only reason about the targets given in scope. Never invent new targets.
- Prefer breadth: cover each in-scope component against the relevant attack
  classes (e.g. recon, auth, access control, injection, SSRF, misconfig,
  secrets, dependency/CVE, business logic).
- Each task is ONE component against ONE attack class, with a crisp objective.
- Output STRICT JSON only, matching the requested schema. No prose.
"""

PLANNER_USER = """Engagement scope:
{scope_block}

{code_block}

Produce JSON with this exact shape:
{{
  "summary": "<2-3 sentence threat-model summary>",
  "assets": ["<key asset/component>", ...],
  "tasks": [
    {{"component": "...", "attack_class": "...",
      "objective": "...", "rationale": "..."}},
    ...
  ]
}}
Aim for {n_hint} well-scoped tasks."""


class Planner:
    def __init__(self, llm: LocalLLM) -> None:
        self.llm = llm

    def build_threat_model(
        self,
        scope: Scope,
        source_context: Optional[str] = None,
        task_hint: int = 10,
        extra_guidance: str = "",
    ) -> ThreatModel:
        scope_block = "\n".join(f"- {t}" for t in scope.in_scope)
        if scope.clusters:
            scope_block += "\nIn-scope clusters/contexts: " + ", ".join(scope.clusters)
        goals = scope.engagement.get("goals")
        if goals:
            scope_block += f"\n\nStated goals: {goals}"
        if extra_guidance:
            scope_block += "\n\n== Domain guidance ==\n" + extra_guidance

        code_block = ""
        if source_context:
            snippet = source_context[:6000]
            code_block = (
                "Source code / documentation excerpts were provided. Use them to "
                "target tests precisely:\n---\n" + snippet + "\n---"
            )

        data = self.llm.chat_json(
            PLANNER_SYSTEM,
            PLANNER_USER.format(
                scope_block=scope_block, code_block=code_block, n_hint=task_hint
            ),
        )
        tasks = [
            Task(
                component=str(t.get("component", "unknown")),
                attack_class=str(t.get("attack_class", "general")),
                objective=str(t.get("objective", "")),
                rationale=str(t.get("rationale", "")),
            )
            for t in data.get("tasks", [])
        ]
        return ThreatModel(
            summary=str(data.get("summary", "")),
            assets=[str(a) for a in data.get("assets", [])],
            tasks=tasks,
        )
