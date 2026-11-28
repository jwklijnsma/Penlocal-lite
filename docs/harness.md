# The five harness components

| Blog component | Module | What it does |
|---|---|---|
| **Planner** | `planner.py` | Turns the scope (+ optional source code) into a threat model and a flat list of *component × attack-class* tasks, so coverage is explicit. |
| **Sandbox** | `sandbox.py` + `scope.py` | The only path from model to anything real. Enforces scope, hard-blocks a denylist (destructive / DoS / exfil / reverse-shell), gates risky steps behind human approval, runs with a timeout, has an emergency stop. `local` or fresh-`docker`-per-task runners. |
| **Auditlog** | `auditlog.py` | Append-only JSONL of every command with full output. Findings cite entry ids, so every claim traces back to what actually happened. |
| **Verifier** | `verifier.py` | A *different* model re-judges each finding against the raw audit evidence. Invented findings with no real output behind them fail here. |
| **Assessor** ("Beoordelaar") | `assessor.py` | Dedupes, normalises severity, hunts for attack **chains**, and computes a weighted risk score (critical ≈ 5× trivial, as in the blog). |

The per-task agent loop that sits between Planner and Verifier is `executor.py`.
`harness.py` wires it all together. **Model and harness are separate** — each
role is just a model handle (Ollama, an OpenAI-compatible server, or the mock)
pointed at whatever model you choose. See [Backends](backends.md).

```
 plan ─▶ for each task: execute (sandbox+audit) ─▶ verify ─▶ assess ─▶ report
   ▲                         │ risky step?                      │
 Planner                operator approval                  dedupe/chains/score
```

---
