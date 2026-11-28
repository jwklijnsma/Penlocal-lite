# Try it in 10 seconds

```bash
pip install -r requirements.txt
python -m penlocal demo --key answer_key.example.yaml
```

The `demo` runs the **entire** pipeline — plan → execute → verify → assess →
report → benchmark — using the deterministic `mock` backend and harmless `echo`
probes. It proves the wiring and writes `report.md/json/html`. The mock brain is
intentionally dumb, so it recovers almost none of the answer key: that's the
scorer being honest, not rigged.
