"""Tool packs — domain knowledge for the planner + domain policy for the gate.

A pack bundles two things, matching the two places the harness needs to know
about a technology:

  * planner_hint  — text injected into the planner prompt so it proposes the
                    right attack classes with the right (read-only-first) tools.
  * denylist / risky / scanners — extra command policy merged into the Scope.

Adding a pack therefore makes the harness *smarter* about a target type and, at
the same time, *stricter*: destructive cluster verbs become hard-denied and
state-changing ones require operator approval. No exploits are bundled — packs
only describe standard, operator-installed assessment tools.

Selected packs: Config.toolpacks (default ["web"]). "openshift" implies
"kubernetes".
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolPack:
    name: str
    description: str
    planner_hint: str = ""
    denylist: list[str] = field(default_factory=list)   # hard block (destructive)
    risky: list[str] = field(default_factory=list)      # approval required
    # First-token command names whose host/target is NOT checked against scope
    # (image/config scanners analyse artifacts or the local kubeconfig cluster,
    #  not an arbitrary network host).
    scanners: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
#  web — the baseline (defaults already live in scope.py; this just guides)
# --------------------------------------------------------------------------- #
WEB = ToolPack(
    name="web",
    description="Web application and host-level testing (baseline).",
    planner_hint=(
        "Target type: web applications / hosts. Attack classes to cover: recon "
        "(ports, headers, tech fingerprint), authentication, access control / "
        "IDOR, injection (SQLi, command, template), SSRF, misconfiguration, "
        "exposed secrets, dependency/CVE exposure, and business logic. "
        "Read-only-first tools: nmap -sV, curl/httpx for headers, nikto (gated), "
        "whatweb, testssl.sh."
    ),
)

# --------------------------------------------------------------------------- #
#  kubernetes
# --------------------------------------------------------------------------- #
KUBERNETES = ToolPack(
    name="kubernetes",
    description="Kubernetes cluster security assessment (kubectl + scanners).",
    planner_hint=(
        "Target type: a Kubernetes cluster. Plan READ-ONLY enumeration first, "
        "then flag anything that would change cluster state for a human. "
        "Attack classes to cover:\n"
        "- RBAC & privilege escalation: `kubectl auth can-i --list`, inspect "
        "ServiceAccount bindings, look for wildcard/cluster-admin grants, "
        "`create pods/exec`, `escalate`, `bind`, token-mountable SAs.\n"
        "- Exposed control-plane / node components: anonymous API server auth, "
        "kubelet read-only (10255) and authenticated (10250) ports, etcd (2379), "
        "exposed dashboard, metrics endpoints.\n"
        "- Workload hardening: privileged containers, hostPID/hostIPC/hostNetwork, "
        "hostPath mounts, docker.sock mounts, added capabilities, runAsRoot, "
        "missing securityContext, missing seccomp.\n"
        "- Secrets exposure: secrets in env vars/ConfigMaps, mounted SA tokens, "
        "image pull secrets.\n"
        "- Network segmentation: missing NetworkPolicies, lateral movement.\n"
        "- Supply chain: vulnerable images, unsigned images.\n"
        "- CIS/benchmark & misconfig scanners.\n"
        "Read-only-first tools: `kubectl get/describe/auth can-i`, kube-bench "
        "(CIS), kube-hunter (passive; --active is intrusive and must be gated), "
        "kubeaudit, kubescape scan, trivy (image/config/k8s), popeye. "
        "Prefer enumeration and scanners that report; never create, exec into, "
        "or delete workloads without explicit human approval."
    ),
    # Destructive / irreversible / cluster-wide → hard block.
    denylist=[
        r"\bkubectl\s+delete\b[^\n]*(--all\b|\bnamespaces?\b|\bns\b|\bnodes?\b|"
        r"\bpv\b|\bpersistentvolume|\bcrd\b|\bcustomresourcedefinition)",
        r"\bkubectl\s+(drain|cordon|taint)\b",
        r"\bkubectl\s+delete\b[^\n]*--force\b[^\n]*--grace-period\s*=?\s*0",
        r"\bkubectl\s+delete\b[^\n]*--grace-period\s*=?\s*0[^\n]*--force\b",
        r"\bkubectl\s+scale\b[^\n]*--replicas\s*=?\s*0\b[^\n]*--all\b",
    ],
    # State-changing / intrusive → operator approval.
    risky=[
        r"\bkubectl\s+(create|apply|run|replace|patch|edit|set|scale|rollout|"
        r"expose|label|annotate|cp|delete)\b",
        r"\bkubectl\s+(exec|attach|debug|port-forward|proxy)\b",
        r"\bkube-hunter\b[^\n]*--active\b",
        r"--privileged\b",
        r"hostPID\s*:\s*true|hostNetwork\s*:\s*true|hostIPC\s*:\s*true",
        r"privileged\s*:\s*true",
        r"/var/run/docker\.sock",
    ],
    scanners=["kube-bench", "kubeaudit", "kubescape", "trivy", "popeye",
              "grype", "syft"],
)

# --------------------------------------------------------------------------- #
#  openshift  (implies kubernetes)
# --------------------------------------------------------------------------- #
OPENSHIFT = ToolPack(
    name="openshift",
    description="OpenShift assessment (adds `oc`, SCC, routes, projects, builds).",
    planner_hint=(
        "Target type: an OpenShift cluster (Kubernetes plus OpenShift resources). "
        "In addition to the Kubernetes attack classes, cover:\n"
        "- Security Context Constraints (SCC): who can use `privileged`/`anyuid`; "
        "`oc get scc`, `oc adm policy who-can use scc privileged`.\n"
        "- Projects & RBAC: `oc whoami`, `oc get projects`, self-provisioner, "
        "role bindings per project.\n"
        "- Routes & exposure: `oc get routes` (TLS, edge/passthrough), exposed "
        "services, default/console routes.\n"
        "- Build & image pipeline: BuildConfigs, ImageStreams, source/webhook "
        "triggers, `oc start-build` (gated).\n"
        "- DeploymentConfigs and triggers.\n"
        "Read-only-first tools: `oc whoami`, `oc get/describe/status`, "
        "`oc adm policy who-can`, `oc adm top`, plus all Kubernetes scanners. "
        "`oc` verbs that create, change, exec, debug, start builds, or run "
        "`oc adm` administrative actions must be gated for human approval."
    ),
    denylist=[
        r"\boc\s+delete\b[^\n]*(--all\b|\bprojects?\b|\bnamespaces?\b|\bnodes?\b|"
        r"\bpv\b|\bpersistentvolume)",
        r"\boc\s+adm\s+drain\b",
        r"\boc\s+adm\s+cordon\b",
    ],
    risky=[
        r"\boc\s+(create|apply|new-app|new-project|new-build|run|replace|patch|"
        r"edit|set|scale|rollout|expose|label|annotate|cp|delete|import-image|"
        r"start-build|tag|rsh|exec|debug|port-forward|login)\b",
        r"\boc\s+adm\b",
    ],
    scanners=[],  # inherits kubernetes scanners
)


REGISTRY: dict[str, ToolPack] = {p.name: p for p in (WEB, KUBERNETES, OPENSHIFT)}
# Pack implies these other packs.
DEPS: dict[str, list[str]] = {"openshift": ["kubernetes"]}


def resolve(names: list[str]) -> list[ToolPack]:
    """Expand selected pack names (with dependencies), de-duplicated, in order."""
    seen: list[str] = []

    def add(n: str) -> None:
        n = n.strip().lower()
        if n not in REGISTRY or n in seen:
            return
        for dep in DEPS.get(n, []):
            add(dep)
        seen.append(n)

    for name in names or ["web"]:
        add(name)
    if not seen:
        seen = ["web"]
    return [REGISTRY[n] for n in seen]


def planner_guidance(packs: list[ToolPack]) -> str:
    hints = [p.planner_hint for p in packs if p.planner_hint]
    return "\n\n".join(hints)


def merged_policy(packs: list[ToolPack]) -> tuple[list[str], list[str], list[str]]:
    deny: list[str] = []
    risky: list[str] = []
    scanners: list[str] = []
    for p in packs:
        deny += p.denylist
        risky += p.risky
        scanners += p.scanners
    return deny, risky, scanners
