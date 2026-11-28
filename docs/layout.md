# Layout

```
penlocal/
  config.py     roles → backend/models, limits, runner, runs, workers
  llm.py        backends: LocalLLM(Ollama) · OpenAICompatLLM · MockLLM + factory
  scope.py      scope + denylist/risky policy   ← the guardrail
  auditlog.py   append-only JSONL evidence store
  planner.py    threat model + task breakdown
  executor.py   per-task agent loop (emits JSON, never executes)
  sandbox.py    scope-gated runner (local/docker) + approval + shared stop
  verifier.py   second-model evidence check
  assessor.py   dedupe + severity + chains + score
  benchmark.py  weighted answer-key scorer (recall, per-severity, FPs)
  report.py     Markdown / JSON / HTML output
  validation.py pre-flight checks (bad backend, empty/unbounded scope, …)
  toolpacks.py  domain packs: web / kubernetes / openshift (planner + policy)
  harness.py    orchestrator (plan→execute→verify→assess), parallel + stop
  cli.py        `python -m penlocal {check,plan,explain,run,demo,benchmark,serve}`
  web/          `penlocal serve`: stdlib HTTP server + the built UI (static/)
web/            React + TypeScript source of the UI
tests/test_smoke.py   22 offline tests: guardrails, audit, dedupe, scoring,
                      backends, validation, k8s/openshift policy, and a full
                      end-to-end mock pipeline
tests/test_web.py     9 offline tests for the web UI: auth/CSRF, scope files,
                      explain, authorization + pre-flight, full runs, approvals,
                      approval timeout, emergency stop, history after restart
```

Run the offline tests with `python -m pytest tests/` (31 tests, no model server).

Install as a command with `pip install -e .` (then just `penlocal ...`), or grab a
wheel from the [releases](https://github.com/jwklijnsma/penlocal-lite/releases). `make help` lists the dev shortcuts.
