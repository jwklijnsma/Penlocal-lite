"""Assessor — the final judgement pass over verified findings.

Mirrors the blog's "Beoordelaar": drop duplicates, normalise severity, and look
for chains (individually minor issues that combine into something serious). It
also computes a weighted score so repeated runs can be compared.

Deduplication is done heuristically first (cheap, deterministic) and the chain
search is handed to the model, which only ever sees already-verified findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .llm import LocalLLM
from .models import Finding

ASSESSOR_SYSTEM = """You are the assessment component of a penetration test
harness. You are given a list of VERIFIED findings. Identify "attack chains":
sets of two or more findings that, combined, create a materially higher risk
than any one alone. Be conservative and concrete.

Return STRICT JSON:
  {"chains": [
     {"name": "...", "finding_ids": ["find_x", "find_y"],
      "combined_severity": "high|critical", "explanation": "..."}
  ]}
Return an empty list if there are no genuine chains."""


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", text.lower()).strip()


@dataclass
class AssessmentReport:
    findings: list[Finding]
    chains: list[dict] = field(default_factory=list)
    duplicates_removed: int = 0

    @property
    def weighted_score(self) -> int:
        return sum(f.severity.weight for f in self.findings)

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts


class Assessor:
    def __init__(self, llm: LocalLLM) -> None:
        self.llm = llm

    def dedupe(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        seen: dict[tuple[str, str], Finding] = {}
        removed = 0
        for f in findings:
            key = (_norm(f.title), f.component.lower())
            if key in seen:
                # keep the higher-severity one; merge evidence
                kept = seen[key]
                if f.severity.weight > kept.severity.weight:
                    f.evidence_ids = list(dict.fromkeys(kept.evidence_ids + f.evidence_ids))
                    seen[key] = f
                else:
                    kept.evidence_ids = list(dict.fromkeys(kept.evidence_ids + f.evidence_ids))
                removed += 1
            else:
                seen[key] = f
        return list(seen.values()), removed

    def find_chains(self, findings: list[Finding]) -> list[dict]:
        if len(findings) < 2:
            return []
        catalogue = "\n".join(
            f"- {f.id} [{f.severity.value}] {f.title} ({f.component}): {f.description[:160]}"
            for f in findings
        )
        try:
            data = self.llm.chat_json(
                ASSESSOR_SYSTEM, f"Verified findings:\n{catalogue}"
            )
            return data.get("chains", []) if isinstance(data, dict) else []
        except Exception:
            return []

    def assess(self, findings: list[Finding]) -> AssessmentReport:
        verified = [f for f in findings if f.verified]
        deduped, removed = self.dedupe(verified)
        deduped.sort(key=lambda f: f.severity.weight, reverse=True)
        chains = self.find_chains(deduped)
        return AssessmentReport(findings=deduped, chains=chains, duplicates_removed=removed)
