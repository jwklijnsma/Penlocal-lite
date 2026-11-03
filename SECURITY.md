# Responsible use & rules of engagement

PenLocal-lite drives real security tools against real systems. That is only
lawful and ethical with explicit permission. This file is the short version of
the obligations that come with running it.

## Authorization is mandatory

Run this **only** against systems you own or have explicit, written authorization
to test. Unauthorized scanning or exploitation is illegal in most jurisdictions
(in the Netherlands, Art. 138ab Sr "computervredebreuk"; elsewhere e.g. the US
CFAA, the UK Computer Misuse Act). "It was an AI agent" is not a defense.

Before a run, have in writing:

- the exact in-scope targets (hosts, ranges, URLs, applications),
- what is explicitly **out** of scope,
- the test window (start/end),
- who authorized it, and their contact during the test,
- any data-handling rules (what may be read, what must never be exfiltrated).

Record the authorizer in your `scope.yaml` under `engagement.authorized_by`.
`penlocal run` warns when it is missing.

## What the harness enforces for you

These are safety rails, not a substitute for judgment:

- **Scope gate** — commands whose targets fall outside `in_scope` are denied.
- **Denylist** — destructive, DoS, exfiltration and reverse-shell shaped
  commands are hard-blocked and never run.
- **Approval gate** — brute-force, active-exploit and state-changing actions
  require a human `y` before running (`--auto-approve-risky` is for your own lab
  only).
- **Audit log** — every command and its full output is recorded; findings must
  cite that evidence.
- **Emergency stop** — `Harness.stop()` / `Sandbox.stop()` halts all workers.
- **Pre-flight** — `penlocal run` refuses an empty or unbounded (`0.0.0.0/0`)
  scope.

Inspect exactly what the policy will permit, before any engagement:

```bash
penlocal explain --scope scope.yaml --file candidate_commands.txt
```

## What this project will not do

It ships **no exploits, payloads, or weaponized tooling**. It orchestrates the
standard tools *you* install, under the gates above. It is a harness, not an
attack kit — please keep it that way in anything you add.

## Found a bug in the harness itself?

If you find a flaw in the guardrails (a scope bypass, a denylist gap), please
report it privately to the maintainer rather than filing a public issue with a
working bypass.
