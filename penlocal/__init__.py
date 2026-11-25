"""PenLocal-lite — a local-AI pentest harness.

Inspired by Warpnet's PenLocal. The LLM is "just the brain"; this package is
the harness around it: Planner, Sandbox (scope + human approval), Auditlog,
Verifier and Assessor. The model proposes actions; the harness decides what it
is allowed to see, run, and keep.

Use only against systems you are explicitly authorized to test.
"""

__version__ = "0.3.0"
