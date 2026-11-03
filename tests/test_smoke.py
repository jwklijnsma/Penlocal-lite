"""Offline smoke tests — exercise the harness logic that doesn't need Ollama.

Run: python -m pytest tests/test_smoke.py   (or just: python tests/test_smoke.py)
These cover the guardrails (scope/denylist), the audit log, and dedup/scoring —
the parts that must be correct regardless of which model is plugged in.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from penlocal.scope import Scope, Decision  # noqa: F401  (Decision used in tests)
from penlocal.auditlog import AuditLog
from penlocal.models import CommandResult, Finding, Severity
from penlocal.assessor import Assessor
from penlocal.sandbox import Sandbox, LocalRunner


def make_scope():
    return Scope(in_scope=["10.10.10.0/24", "testphp.vulnweb.com"],
                 out_of_scope=["10.10.10.1"])


def test_in_scope_targets():
    s = make_scope()
    assert s.is_target_in_scope("10.10.10.55")
    assert s.is_target_in_scope("http://testphp.vulnweb.com/login")
    assert not s.is_target_in_scope("10.10.10.1")       # out-of-scope wins
    assert not s.is_target_in_scope("example.com")      # not listed


def test_denylist_blocks_destructive():
    s = make_scope()
    assert s.classify_command("rm -rf / ").decision == Decision.DENY
    assert s.classify_command("nmap 10.10.10.5 --max-rate 99999").decision == Decision.DENY
    assert s.classify_command("nc 10.10.10.5 4444 -e /bin/sh").decision == Decision.DENY


def test_out_of_scope_denied():
    s = make_scope()
    assert s.classify_command("nmap -sV 8.8.8.8").decision == Decision.DENY
    assert s.classify_command("curl http://example.com").decision == Decision.DENY


def test_risky_needs_approval_and_safe_allowed():
    s = make_scope()
    assert s.classify_command("nmap -sV 10.10.10.5").decision == Decision.ALLOW
    assert s.classify_command("hydra -l admin 10.10.10.5 ssh").decision == Decision.APPROVE
    assert s.classify_command("curl -X POST http://testphp.vulnweb.com/x").decision == Decision.APPROVE


def test_sandbox_blocks_and_logs():
    s = make_scope()
    with tempfile.TemporaryDirectory() as d:
        audit = AuditLog(Path(d) / "audit.jsonl")
        box = Sandbox(s, audit, LocalRunner(), approval_fn=lambda c, r: False)
        # out of scope -> blocked, never executed
        res = box.run("nmap 8.8.8.8")
        assert res.exit_code == 126 and res.approved_by == "blocked"
        # risky -> approval denied -> skipped
        res2 = box.run("hydra -l a 10.10.10.5 ssh")
        assert res2.approved_by == "declined"
        # safe local echo actually runs and is logged
        res3 = box.run("echo scope-ok")
        assert res3.exit_code == 0 and "scope-ok" in res3.stdout
        assert audit.get(res3.id) is not None


def test_audit_evidence_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        audit = AuditLog(Path(d) / "audit.jsonl")
        cr = CommandResult(command="echo hi", stdout="hi", stderr="",
                           exit_code=0, duration_s=0.01)
        eid = audit.record_command(cr)
        txt = audit.evidence_text([eid])
        assert "echo hi" in txt and "hi" in txt


def test_dedupe_and_score():
    a = Assessor(llm=None)  # dedupe/score need no model
    f1 = Finding(title="SQL injection in login", severity=Severity.HIGH,
                 description="x", component="web", verified=True, evidence_ids=["cmd_1"])
    f2 = Finding(title="SQL Injection in Login!", severity=Severity.CRITICAL,
                 description="y", component="web", verified=True, evidence_ids=["cmd_2"])
    f3 = Finding(title="Missing security header", severity=Severity.LOW,
                 description="z", component="web", verified=True, evidence_ids=["cmd_3"])
    deduped, removed = a.dedupe([f1, f2, f3])
    assert removed == 1 and len(deduped) == 2
    # higher severity kept, evidence merged
    sqli = next(f for f in deduped if "sql" in f.title.lower())
    assert sqli.severity == Severity.CRITICAL
    assert set(sqli.evidence_ids) == {"cmd_1", "cmd_2"}
    assert Severity.CRITICAL.weight + Severity.LOW.weight == 6


def test_mock_llm_roles():
    from penlocal.llm import MockLLM
    m = MockLLM()
    plan = m.chat_json("You are the planning component.", "scope")
    assert plan["tasks"] and "summary" in plan
    # executor: first step is a command, then a finding citing a real cmd id
    step1 = m.chat_json("You are the execution component.", "Transcript so far:\n(nothing yet)")
    assert "command" in step1
    step2 = m.chat_json("You are the execution component.",
                        "Transcript so far:\n$ echo x\n[cmd_abcd1234] (exit 0)\nmock-probe")
    assert step2["finding"]["evidence_ids"] == ["cmd_abcd1234"]


def test_end_to_end_mock_pipeline():
    from penlocal.config import Config
    from penlocal.harness import Harness
    with tempfile.TemporaryDirectory() as d:
        cfg = Config(backend="mock", workdir=Path(d))
        scope = Scope(in_scope=["127.0.0.1", "demo.local"])
        harness = Harness(cfg, scope, approval_fn=lambda c, r: True, observer=lambda m: None)
        threat, report = harness.run()
        # planner made tasks, executor produced findings, verifier kept them,
        # each surviving finding cites real audit evidence.
        assert threat.tasks
        assert report.findings, "mock pipeline should surface verified findings"
        for f in report.findings:
            assert f.verified and f.evidence_ids
            assert all(harness.audit.get(e) for e in f.evidence_ids)


def test_end_to_end_parallel_matches_serial():
    from penlocal.config import Config
    from penlocal.harness import Harness
    def run(workers):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(backend="mock", workdir=Path(d), workers=workers)
            h = Harness(cfg, Scope(in_scope=["127.0.0.1"]),
                        approval_fn=lambda c, r: True, observer=lambda m: None)
            _, rep = h.run()
            return len(rep.findings)
    assert run(1) == run(3)  # parallelism changes speed, not the result count


def test_benchmark_scoring():
    from penlocal.benchmark import AnswerKey, ExpectedVuln, score
    from penlocal.assessor import AssessmentReport
    key = AnswerKey([
        ExpectedVuln("A", "SQL injection in login", Severity.CRITICAL,
                     component="web", keywords=["sql", "injection"]),
        ExpectedVuln("B", "Missing security headers", Severity.LOW,
                     component="web", keywords=["header", "csp"]),
    ])
    findings = [Finding(title="SQL injection in login form", severity=Severity.CRITICAL,
                        description="sqli via username", component="web frontend",
                        verified=True, evidence_ids=["cmd_1"])]
    report = AssessmentReport(findings=findings)
    res = score(key, report)
    assert res.found_weight == Severity.CRITICAL.weight      # only the crit matched
    assert res.total_weight == Severity.CRITICAL.weight + Severity.LOW.weight
    assert 0.8 < res.recall <= 1.0
    assert res.per_severity()["critical"] == (1, 1)
    assert res.per_severity()["low"] == (0, 1)


def test_validation_catches_bad_config_and_scope():
    from penlocal.config import Config
    from penlocal.validation import preflight, validate_scope
    bad = Config(backend="nope", runner="weird", runs=0, workers=0)
    errors, _ = preflight(bad, None)
    assert any("backend" in e for e in errors)
    assert any("runner" in e for e in errors)
    assert any("runs" in e for e in errors)
    # empty scope and wildcard scope are hard errors
    assert validate_scope(Scope(in_scope=[]))[0]
    assert validate_scope(Scope(in_scope=["0.0.0.0/0"]))[0]


def test_validation_warns_same_verifier_model():
    from penlocal.config import Config
    from penlocal.validation import validate_config
    cfg = Config(backend="ollama", executor_model="m", verifier_model="m")
    _, warnings = validate_config(cfg)
    assert any("verifier" in w for w in warnings)


def test_explain_classification_is_readonly():
    # `explain` must never execute; it only classifies. Verify the 3 verdicts.
    s = Scope(in_scope=["10.10.10.0/24"])
    assert s.classify_command("nmap -sV 10.10.10.5").decision == Decision.ALLOW
    assert s.classify_command("hydra -l a 10.10.10.5 ssh").decision == Decision.APPROVE
    assert s.classify_command("curl http://evil.example").decision == Decision.DENY


def _k8s_scope(clusters=None):
    from penlocal.toolpacks import merged_policy, resolve
    s = Scope(in_scope=["10.10.10.0/24", "api.cluster.internal"], clusters=clusters)
    deny, risky, scanners = merged_policy(resolve(["kubernetes"]))
    s.extend_policy(denylist=deny, risky=risky, scanners=scanners)
    return s


def test_toolpack_resolution_openshift_implies_k8s():
    from penlocal.toolpacks import resolve
    names = [p.name for p in resolve(["openshift"])]
    assert names == ["kubernetes", "openshift"]  # dep first, order preserved
    assert [p.name for p in resolve([])] == ["web"]


def test_k8s_readonly_allowed():
    s = _k8s_scope()
    for c in ["kubectl get pods -A", "kubectl describe node n1",
              "kubectl auth can-i --list", "kubectl auth can-i create pods"]:
        assert s.classify_command(c).decision == Decision.ALLOW, c


def test_k8s_statechanging_needs_approval():
    s = _k8s_scope()
    for c in ["kubectl create -f pod.yaml", "kubectl exec -it web -- sh",
              "kubectl run x --image=busybox --privileged",
              "kubectl port-forward svc/db 5432:5432", "kubectl delete pod web"]:
        assert s.classify_command(c).decision == Decision.APPROVE, c


def test_k8s_destructive_denied():
    s = _k8s_scope()
    for c in ["kubectl delete namespace prod", "kubectl drain node1",
              "kubectl delete pods --all", "kubectl cordon node2"]:
        assert s.classify_command(c).decision == Decision.DENY, c


def test_k8s_active_hunter_gated():
    s = _k8s_scope()
    assert s.classify_command("kube-hunter --active --remote 10.10.10.5").decision == Decision.APPROVE
    # passive kube-hunter and scanners are allowed (and not host-scope-blocked)
    assert s.classify_command("kube-bench run").decision == Decision.ALLOW
    assert s.classify_command("trivy image registry.example.com/app:1.2").decision == Decision.ALLOW


def test_cluster_context_scope():
    s = _k8s_scope(clusters=["staging"])
    assert s.classify_command("kubectl get pods --context staging").decision == Decision.ALLOW
    assert s.classify_command("kubectl get pods --context prod").decision == Decision.DENY


def test_openshift_policy():
    from penlocal.toolpacks import merged_policy, resolve
    s = Scope(in_scope=["api.ocp.internal"])
    deny, risky, scanners = merged_policy(resolve(["openshift"]))
    s.extend_policy(denylist=deny, risky=risky, scanners=scanners)
    assert s.classify_command("oc get scc").decision == Decision.ALLOW
    assert s.classify_command("oc adm policy who-can use scc privileged").decision == Decision.APPROVE
    assert s.classify_command("oc new-app --template=django-psql-example").decision == Decision.APPROVE
    assert s.classify_command("oc delete project prod").decision == Decision.DENY


def test_openai_compat_shape(monkeypatch=None):
    # Construct the client; no network call, just confirm it builds + factory.
    from penlocal.llm import make_llm, OpenAICompatLLM, MockLLM, LocalLLM
    assert isinstance(make_llm("mock", "m"), MockLLM)
    assert isinstance(make_llm("ollama", "qwen3:8b"), LocalLLM)
    assert isinstance(make_llm("openai-compat", "x", api_base="http://h/v1"), OpenAICompatLLM)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
