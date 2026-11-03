"""Benchmark — score a run against a weighted answer key, like the blog.

Warpnet's pentesters built an answer key of known vulnerabilities, weighted by
severity (a critical counts ~5x a trivial finding), and scored each model on how
much of that weight it recovered — merging repeated local runs. This module does
the same: it matches an assessment's final findings against an answer key and
reports weighted recall overall and per severity.

Matching is intentionally simple and transparent: an expected item is "found" if
any final finding is on the same component AND shares enough keyword signal with
it. You tune the key, not a black box.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from .assessor import AssessmentReport
from .models import Finding, Severity


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", text.lower()))


@dataclass
class ExpectedVuln:
    id: str
    title: str
    severity: Severity
    component: str = ""
    keywords: list[str] = field(default_factory=list)

    @property
    def signal(self) -> set[str]:
        return _tokens(self.title) | {k.lower() for k in self.keywords}


@dataclass
class MatchResult:
    expected: ExpectedVuln
    found: bool
    matched_finding_id: str = ""


@dataclass
class BenchmarkResult:
    matches: list[MatchResult]
    total_weight: int
    found_weight: int
    false_positives: int

    @property
    def recall(self) -> float:
        return (self.found_weight / self.total_weight) if self.total_weight else 0.0

    def per_severity(self) -> dict[str, tuple[int, int]]:
        """severity -> (found_count, total_count)."""
        out: dict[str, list[int]] = {}
        for m in self.matches:
            sev = m.expected.severity.value
            cell = out.setdefault(sev, [0, 0])
            cell[1] += 1
            if m.found:
                cell[0] += 1
        return {k: (v[0], v[1]) for k, v in out.items()}


class AnswerKey:
    def __init__(self, vulns: list[ExpectedVuln]) -> None:
        self.vulns = vulns

    @classmethod
    def load(cls, path: str | Path) -> "AnswerKey":
        if yaml is None:
            raise RuntimeError("PyYAML is required to load an answer key.")
        data = yaml.safe_load(Path(path).read_text()) or {}
        items = data.get("vulnerabilities", data if isinstance(data, list) else [])
        vulns = [
            ExpectedVuln(
                id=str(v.get("id", f"v{i}")),
                title=str(v.get("title", "")),
                severity=Severity.coerce(v.get("severity", "info")),
                component=str(v.get("component", "")),
                keywords=[str(k) for k in v.get("keywords", [])],
            )
            for i, v in enumerate(items)
        ]
        return cls(vulns)

    @property
    def total_weight(self) -> int:
        return sum(v.severity.weight for v in self.vulns)


def _finding_matches(expected: ExpectedVuln, finding: Finding, threshold: int = 2) -> bool:
    if expected.component and finding.component:
        if expected.component.lower() not in finding.component.lower() \
           and finding.component.lower() not in expected.component.lower():
            return False
    hay = _tokens(finding.title + " " + finding.description)
    overlap = expected.signal & hay
    # A single strong keyword hit also counts.
    strong = any(k.lower() in hay for k in expected.keywords)
    return strong or len(overlap) >= threshold


def score(key: AnswerKey, report: AssessmentReport) -> BenchmarkResult:
    findings = list(report.findings)
    matches: list[MatchResult] = []
    used: set[str] = set()
    for exp in key.vulns:
        hit = ""
        for f in findings:
            if f.id in used:
                continue
            if _finding_matches(exp, f):
                hit = f.id
                used.add(f.id)
                break
        matches.append(MatchResult(exp, bool(hit), hit))
    found_weight = sum(m.expected.severity.weight for m in matches if m.found)
    false_positives = len(findings) - len(used)
    return BenchmarkResult(
        matches=matches,
        total_weight=key.total_weight,
        found_weight=found_weight,
        false_positives=max(false_positives, 0),
    )


def render(result: BenchmarkResult) -> str:
    lines = ["Benchmark result", "=" * 40]
    lines.append(f"Weighted recall : {result.recall*100:5.1f}%  "
                 f"({result.found_weight}/{result.total_weight} weight)")
    lines.append(f"False positives : {result.false_positives}")
    lines.append("")
    order = ["critical", "high", "medium", "low", "info"]
    ps = result.per_severity()
    for sev in order:
        if sev in ps:
            found, total = ps[sev]
            lines.append(f"  {sev:9s} {found}/{total}")
    lines.append("")
    for m in result.matches:
        mark = "FOUND  " if m.found else "missed "
        lines.append(f"  [{mark}] {m.expected.severity.value:8s} {m.expected.title}")
    return "\n".join(lines)
