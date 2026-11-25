# ARTEX integration

PenLocal-lite can connect to a separately deployed [ARTEX](https://github.com/BaaRai/ARTEX)
instance and display its operator-facing task, finding, evidence and report data through
PenLocal's authenticated API. ARTEX remains responsible for its own execution, scope,
approvals and audit trail.

## Configure

Set these environment variables on the PenLocal web server:

| Variable | Purpose |
|---|---|
| `PENLOCAL_ARTEX_URL` | ARTEX base URL, e.g. `http://artex.home:8787` |
| `PENLOCAL_ARTEX_TOKEN` | Optional ARTEX bearer token |
| `PENLOCAL_ARTEX_TIMEOUT` | Request timeout in seconds (1–20; default 5) |
| `PENLOCAL_ARTEX_TASKS_PATH` | Task-list API path (default `/api/tasks`) |
| `PENLOCAL_ARTEX_FINDINGS_PATH` | Findings API path (default `/api/findings`) |
| `PENLOCAL_ARTEX_EVIDENCE_PATH` | Evidence API path (default `/api/evidence`) |
| `PENLOCAL_ARTEX_REPORTS_PATH` | Reports API path (default `/api/reports`) |

The API paths are configurable because ARTEX's API surface can change between releases.
Use the paths exposed by the ARTEX version you deploy. The connector performs GET requests
only; it does not create tasks, dispatch agents, replay traffic, approve tool calls, or run
commands in ARTEX.

## PenLocal API

After configuration, the authenticated PenLocal API exposes:

- `GET /api/artex/status` — configured/reachable state and latency
- `GET /api/artex/tasks`
- `GET /api/artex/findings`
- `GET /api/artex/evidence`
- `GET /api/artex/reports`

All endpoints require the normal PenLocal access token. Upstream payloads are passed through
as JSON; an upstream failure is returned as a controlled gateway error. Responses are capped
at 2 MiB. Configure ARTEX on a private network or behind TLS; do not expose its token to the
browser.

## License boundary

ARTEX is distributed under AGPL-3.0; PenLocal-lite is MIT. This integration is an independent
HTTP client and does not vendor, copy, or link ARTEX source code. Deployments should review
both projects' licenses and their own distribution model.
