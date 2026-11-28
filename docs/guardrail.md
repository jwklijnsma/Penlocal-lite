# Audit the guardrail before you run anything

Before an engagement, see exactly what the policy will allow, deny, or gate —
without running a single command:

```bash
python -m penlocal explain --scope scope.yaml \
  --cmd "nmap -sV 10.10.10.5" \
  --cmd "curl http://google.com" \
  --cmd "hydra -l admin 10.10.10.5 ssh"
#  [ALLOW  ] nmap -sV 10.10.10.5            ↳ In scope, no risky patterns.
#  [DENY   ] curl http://google.com         ↳ Target(s) out of scope.
#  [APPROVE] hydra -l admin 10.10.10.5 ssh  ↳ Risky action: needs operator approval.
```

`penlocal run` also pre-flights your config and scope, and **refuses** to start
on an empty or unbounded (`0.0.0.0/0`) scope.

---
