# Tool packs: Kubernetes and OpenShift

Tool packs teach the harness about a target type in two places at once: the
**planner** learns the right attack classes and (read-only-first) tools, and the
**policy** gets stricter for that type. Select with `--toolpack` (repeatable) or
`toolpacks:` in the config. `openshift` implies `kubernetes`.

| Pack | Planner learns | Policy adds |
|---|---|---|
| `web` (default) | recon, authn, access control, injection, SSRF, misconfig, secrets, CVEs | built-in defaults |
| `kubernetes` | RBAC & privesc, exposed kubelet/etcd/API, privileged pods & host mounts, secrets, NetworkPolicy gaps, image CVEs; tools: `kubectl get/describe/auth can-i`, kube-bench, kube-hunter, kubeaudit, kubescape, trivy, popeye | see below |
| `openshift` | + SCCs, projects, routes, BuildConfigs/ImageStreams, `oc adm`; tools: `oc whoami/get/describe`, `oc adm policy who-can` | + `oc` verb policy |

How the cluster policy classifies commands:

- **ALLOW** (read-only) — `kubectl get/describe/logs/auth can-i`, `oc get/whoami`,
  and the scanners (kube-bench, kubeaudit, kubescape, trivy, popeye) in report mode.
- **APPROVE** (needs a human) — anything state-changing or intrusive:
  `kubectl create/apply/run/patch/scale/exec/port-forward/delete`, `--privileged`
  or host-namespace pod specs, `kube-hunter --active`, all `oc new-app/start-build/adm`.
- **DENY** (hard block) — destructive, cluster-wide, irreversible:
  `kubectl delete namespace|node|--all`, `drain`, `cordon`, `taint`,
  `oc delete project`, force-delete with `--grace-period=0`.

Plus a cluster-context guard: set `clusters:` in your scope, and a `kubectl`/`oc`
command selecting an out-of-scope `--context` is denied before it runs.

```bash
# audit exactly what a cluster run would allow/deny/gate, running nothing:
python -m penlocal explain --scope scope.k8s.example.yaml --toolpack openshift \
  --cmd "kubectl get pods -A" \
  --cmd "kubectl delete namespace prod" \
  --cmd "oc adm policy who-can use scc privileged"

# a real cluster run (kubectl/oc + scanners must be installed and authorized):
python -m penlocal run --scope scope.k8s.example.yaml --toolpack kubernetes --runs 3 --html
```

No exploits are bundled — packs describe standard, operator-installed assessment
tools and run them under the same scope/approval/audit gates.
