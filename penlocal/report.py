"""Render an assessment to Markdown and JSON."""
from __future__ import annotations

import json
from datetime import datetime

from .assessor import AssessmentReport
from .models import ThreatModel

_ORDER = ["critical", "high", "medium", "low", "info"]


def to_markdown(threat: ThreatModel, report: AssessmentReport, meta: dict) -> str:
    lines: list[str] = []
    lines.append(f"# PenLocal-lite report\n")
    lines.append(f"_Generated {datetime.now():%Y-%m-%d %H:%M} · "
                 f"{meta.get('runs', 1)} run(s) · executor `{meta.get('executor')}` · "
                 f"verifier `{meta.get('verifier')}`_\n")
    lines.append("> Findings are AI-generated and verified against an audit log. "
                 "A human pentester must still confirm impact before reporting.\n")

    counts = report.severity_counts()
    badge = " · ".join(f"{counts.get(s,0)} {s}" for s in _ORDER if counts.get(s))
    lines.append("## Summary\n")
    lines.append(threat.summary + "\n")
    lines.append(f"- **Verified findings:** {len(report.findings)}"
                 f"{(' (' + badge + ')') if badge else ''}")
    lines.append(f"- **Weighted risk score:** {report.weighted_score}")
    lines.append(f"- **Duplicates merged:** {report.duplicates_removed}")
    lines.append(f"- **Attack chains:** {len(report.chains)}\n")

    if report.chains:
        lines.append("## Attack chains\n")
        for c in report.chains:
            lines.append(f"### {c.get('name','(unnamed)')} "
                         f"— {c.get('combined_severity','').upper()}")
            lines.append(c.get("explanation", ""))
            lines.append(f"_Combines: {', '.join(c.get('finding_ids', []))}_\n")

    lines.append("## Findings\n")
    if not report.findings:
        lines.append("_No findings survived verification._\n")
    for f in report.findings:
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        if f.cwe:
            lines.append(f"**{f.cwe}** · component: `{f.component}`")
        else:
            lines.append(f"component: `{f.component}`")
        lines.append("")
        lines.append(f.description + "\n")
        if f.recommendation:
            lines.append(f"**Recommendation:** {f.recommendation}\n")
        if f.verifier_notes:
            lines.append(f"**Verifier:** {f.verifier_notes}")
        lines.append(f"**Evidence:** {', '.join(f.evidence_ids) or '—'}  "
                     f"(see `audit.jsonl`)\n")

    return "\n".join(lines)


_SEV_COLOR = {
    "critical": "#b4232c", "high": "#d9641e", "medium": "#c99a06",
    "low": "#2f7d4f", "info": "#4a6b8a",
}


def to_html(threat: ThreatModel, report: AssessmentReport, meta: dict) -> str:
    import html as _html
    from datetime import datetime as _dt

    counts = report.severity_counts()
    pills = "".join(
        f'<span class="pill" style="background:{_SEV_COLOR[s]}">{counts[s]} {s}</span>'
        for s in _ORDER if counts.get(s)
    )

    def esc(x: str) -> str:
        return _html.escape(str(x))

    chain_html = ""
    if report.chains:
        rows = "".join(
            f'<div class="chain"><h3>{esc(c.get("name","(unnamed)"))} '
            f'<span class="pill" style="background:{_SEV_COLOR.get(c.get("combined_severity","high"),"#555")}">'
            f'{esc(c.get("combined_severity","").upper())}</span></h3>'
            f'<p>{esc(c.get("explanation",""))}</p>'
            f'<p class="mono">combines: {esc(", ".join(c.get("finding_ids", [])))}</p></div>'
            for c in report.chains
        )
        chain_html = f"<h2>Attack chains</h2>{rows}"

    find_html = []
    for f in report.findings:
        rec = f'<p><b>Recommendation:</b> {esc(f.recommendation)}</p>' if f.recommendation else ""
        vn = f'<p class="verifier"><b>Verifier:</b> {esc(f.verifier_notes)}</p>' if f.verifier_notes else ""
        cwe = f' · {esc(f.cwe)}' if f.cwe else ""
        find_html.append(
            f'<div class="finding" style="border-left-color:{_SEV_COLOR[f.severity.value]}">'
            f'<h3><span class="pill" style="background:{_SEV_COLOR[f.severity.value]}">'
            f'{f.severity.value.upper()}</span> {esc(f.title)}</h3>'
            f'<p class="meta">component: <span class="mono">{esc(f.component)}</span>{cwe}</p>'
            f'<p>{esc(f.description)}</p>{rec}{vn}'
            f'<p class="mono ev">evidence: {esc(", ".join(f.evidence_ids) or "—")}</p></div>'
        )
    if not report.findings:
        find_html.append('<p><em>No findings survived verification.</em></p>')

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PenLocal-lite report</title><style>
:root{{color-scheme:light dark}}
body{{font:15px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
max-width:860px;margin:0 auto;padding:2rem 1.2rem;background:#fafafa;color:#1a1a1a}}
@media(prefers-color-scheme:dark){{body{{background:#14161a;color:#e6e6e6}}
.finding,.chain,.card{{background:#1e2127!important}}}}
h1{{margin:0 0 .2rem}} .sub{{color:#888;font-size:.85rem;margin-bottom:1rem}}
.note{{background:#fff4d6;color:#5a4a10;padding:.6rem .9rem;border-radius:8px;font-size:.9rem}}
@media(prefers-color-scheme:dark){{.note{{background:#3a3415;color:#f0e4b0}}}}
.pill{{display:inline-block;color:#fff;padding:.08rem .5rem;border-radius:999px;
font-size:.72rem;font-weight:700;letter-spacing:.03em;vertical-align:middle}}
.card{{background:#fff;border-radius:10px;padding:1rem 1.2rem;margin:1rem 0;
box-shadow:0 1px 3px rgba(0,0,0,.08)}}
.finding{{background:#fff;border-left:5px solid #ccc;border-radius:8px;
padding:.8rem 1.1rem;margin:.8rem 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.chain{{background:#fff;border-radius:8px;padding:.6rem 1.1rem;margin:.6rem 0;
box-shadow:0 1px 3px rgba(0,0,0,.06)}}
.meta{{color:#888;font-size:.85rem;margin:.1rem 0 .4rem}}
.mono{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem}}
.ev{{color:#999}} .verifier{{color:#6a6a6a;font-size:.9rem}}
h3{{margin:.3rem 0 .4rem;font-size:1.05rem}}
</style></head><body>
<h1>PenLocal-lite report</h1>
<div class="sub">Generated {_dt.now():%Y-%m-%d %H:%M} · {esc(meta.get('runs',1))} run(s)
· backend <span class="mono">{esc(meta.get('backend',''))}</span>
· executor <span class="mono">{esc(meta.get('executor',''))}</span>
· verifier <span class="mono">{esc(meta.get('verifier',''))}</span></div>
<div class="note">Findings are AI-generated and verified against an audit log.
A human pentester must still confirm impact before reporting.</div>
<div class="card"><h2 style="margin-top:0">Summary</h2>
<p>{esc(threat.summary)}</p>
<p>{pills}</p>
<p><b>Verified findings:</b> {len(report.findings)} &nbsp;·&nbsp;
<b>Weighted risk score:</b> {report.weighted_score} &nbsp;·&nbsp;
<b>Duplicates merged:</b> {report.duplicates_removed} &nbsp;·&nbsp;
<b>Chains:</b> {len(report.chains)}</p></div>
{chain_html}
<h2>Findings</h2>
{''.join(find_html)}
</body></html>"""


def to_json(threat: ThreatModel, report: AssessmentReport, meta: dict) -> str:
    return json.dumps(
        {
            "meta": meta,
            "threat_model": threat.to_dict(),
            "summary": {
                "weighted_score": report.weighted_score,
                "severity_counts": report.severity_counts(),
                "duplicates_removed": report.duplicates_removed,
            },
            "chains": report.chains,
            "findings": [f.to_dict() for f in report.findings],
        },
        indent=2,
    )
