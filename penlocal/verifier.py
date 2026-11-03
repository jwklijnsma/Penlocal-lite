"""Verifier — a *different* model re-checks each finding against the audit log.

This is the anti-hallucination gate. The verifier never sees the executor's
reasoning, only the claimed finding and the raw evidence pulled from the audit
log by id. It answers: does this evidence actually support the claim? A finding
the executor invented, with no real command output behind it, fails here.
"""
from __future__ import annotations

from .auditlog import AuditLog
from .llm import LocalLLM
from .models import Finding, Severity

VERIFIER_SYSTEM = """You are the verification component of a penetration test
harness. You independently judge whether a claimed finding is supported by the
raw evidence captured in the audit log. You did not run the test and must not
assume anything beyond the evidence shown.

Return STRICT JSON:
  {"verified": true|false,
   "adjusted_severity": "info|low|medium|high|critical",
   "notes": "<one or two sentences: what the evidence does/doesn't show>"}

Mark verified=false if the evidence is missing, unrelated, inconclusive, or only
shows a normal/expected response. Do not be charitable; unproven is not verified.
"""

VERIFIER_USER = """Claimed finding:
  Title: {title}
  Severity claimed: {severity}
  Component: {component}
  Description: {description}

Evidence from the audit log (by id):
---
{evidence}
---

Judge it."""


class Verifier:
    def __init__(self, llm: LocalLLM, audit: AuditLog) -> None:
        self.llm = llm
        self.audit = audit

    def verify(self, finding: Finding) -> Finding:
        evidence = self.audit.evidence_text(finding.evidence_ids)
        if not finding.evidence_ids or not evidence.strip():
            finding.verified = False
            finding.verifier_notes = "No evidence ids cited / nothing in audit log."
            return finding

        try:
            verdict = self.llm.chat_json(
                VERIFIER_SYSTEM,
                VERIFIER_USER.format(
                    title=finding.title, severity=finding.severity.value,
                    component=finding.component, description=finding.description,
                    evidence=evidence,
                ),
            )
        except Exception as exc:
            finding.verified = False
            finding.verifier_notes = f"Verifier error: {exc}"
            return finding

        finding.verified = bool(verdict.get("verified"))
        finding.verifier_notes = str(verdict.get("notes", ""))
        adj = verdict.get("adjusted_severity")
        if adj:
            finding.severity = Severity.coerce(adj)
        return finding

    def verify_all(self, findings: list[Finding]) -> list[Finding]:
        return [self.verify(f) for f in findings]
