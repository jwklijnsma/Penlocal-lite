# Command line

```bash
# 1. confirm your local models are reachable
python -m penlocal check --config config.example.yaml

# 2. write a scope file (start from the example) — this is the guardrail
cp scope.example.yaml scope.yaml && $EDITOR scope.yaml

# 3. see the plan only (no commands run)
python -m penlocal plan --scope scope.yaml --context ./path/to/source

# 4. full run: plan → execute → verify → assess → report
python -m penlocal run --scope scope.yaml --context ./src --runs 3 --workers 4 --html

# 5. score a run against your pentesters' answer key (the blog's method)
python -m penlocal benchmark --scope scope.yaml --key answer_key.yaml
#    …or score a report you already produced:
python -m penlocal benchmark --report penlocal-run/reports/report.json --key answer_key.yaml
```

Outputs land in `./penlocal-run/reports/`: `report.md`, `report.json`,
`report.html`, plus the full `audit.jsonl`.

## Scale knobs

- `--runs N` — repeat the whole task set N times and merge candidates before
  verification. The blog's key finding: runs disagree hugely (one found 16% of
  an app's vulns, another 95%), so repetition is how a cheap local model reaches
  frontier-level recall. One local run counts the rest as missed.
- `--workers N` — run tasks within a run in parallel. Each task gets its **own**
  sandbox and runner; with `--runner docker` that's a fresh container per task,
  destroyed after — the blog's "new sandbox per task" model.

## Benchmark

`benchmark` reproduces the write-up's measurement: your pentesters write a
weighted answer key (`answer_key.example.yaml`) — a critical counts ~5× a
trivial issue — and the harness is scored on how much of that *weight* it
recovers, with per-severity breakdown and a false-positive count. That's how you
decide whether 3 merged runs of a local model match one run of a frontier model,
for a fraction of the cost and with no data leaving the box.

## White-box testing

Pass `--context <dir-or-file>` to feed source code to the planner. As the blog
notes, reading is the cheapest thing an LLM does, so testing *with* the source
is the default when it's available — it lets the planner aim each attack class
at the right component.

## The scope file is the contract

`scope.yaml` defines `in_scope` (CIDRs, hosts, URLs), `out_of_scope` (wins over
in-scope), and optional extra `denylist` / `risky` patterns appended to the
built-in defaults. Any command whose targets don't all resolve to in-scope
hosts is denied before it runs.
