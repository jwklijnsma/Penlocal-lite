export const SEVS = ["critical", "high", "medium", "low", "info"] as const;
export type Sev = (typeof SEVS)[number];
export type Counts = Partial<Record<Sev, number>>;

export interface RoleModel {
  model: string;
  available: boolean;
}

export interface Status {
  version: string;
  backend: string;
  endpoint: string;
  reachable: boolean;
  backend_error: string;
  models: string[];
  roles: Record<"planner" | "executor" | "verifier" | "assessor", RoleModel>;
  runner: string;
  docker_image: string;
  defaults: { runs: number; workers: number; runner: string; toolpacks: string[]; max_steps: number };
  limits: { runs: number; workers: number };
  toolpacks: Record<string, string>;
  tools: Record<string, boolean>;
  allow_auto_approve: boolean;
  approval_timeout: number;
  auth_phrase: string;
  scopes_dir: string;
  workdir: string;
  context_roots: string[];
  active: number;
  running: string | null;
}

export type JobStatus = "queued" | "running" | "done" | "failed" | "stopped" | "cancelled" | "interrupted";
export type JobKind = "run" | "plan" | "demo";

export interface Progress {
  phase: string;
  run: number;
  runs: number;
  tasks: number;
  started: number;
  total: number;
  commands: number;
  candidates: number;
}

export interface Download {
  name: string;
  label: string;
  bytes: number;
}

export interface JobOptions {
  runs: number;
  workers: number;
  runner: string;
  toolpacks: string[];
  max_steps: number;
  auto_approve: boolean;
  context: string | null;
  models: Record<string, string>;
  key: string | null;
  approval_demo?: boolean;
}

export interface JobSummary {
  tasks?: number;
  assets?: number;
  findings?: number;
  score?: number;
  severity_counts?: Counts;
  chains?: number;
  candidates?: number;
  rejected?: number;
  benchmark?: { key: string; recall: number; false_positives: number };
}

export interface Job {
  id: string;
  kind: JobKind;
  scope_id: string;
  scope_name: string;
  options: JobOptions;
  status: JobStatus;
  created: number;
  started: number | null;
  finished: number | null;
  error: string;
  operator: string;
  summary: JobSummary;
  progress: Progress;
  pending_approvals: number;
  downloads: Download[];
  position?: number | null;
}

export interface Approval {
  id: string;
  command: string;
  reason: string;
  created: number;
  expires: number | null;
}

export interface LogLine {
  t: number | null;
  text: string;
}

export interface ScopeSummary {
  in_scope: string[];
  out_of_scope: string[];
  clusters: string[];
  engagement: Record<string, unknown>;
}

export interface JobDetail extends Job {
  log: LogLine[];
  log_next: number;
  approvals: Approval[];
  scope: ScopeSummary | null;
}

export interface ScopeItem {
  id: string;
  file: string;
  broken: boolean;
  client: string;
  targets: number;
  clusters: number;
  modified: number;
  last_run: Job | null;
}

export interface KeyItem {
  id: string;
  file: string;
  count: number;
}

export interface ScopeDetail {
  id: string;
  file: string;
  text: string;
  modified: number;
  summary: ScopeSummary | null;
  errors: string[];
  warnings: string[];
  runs: Job[];
}

export interface ExplainResult {
  command: string;
  decision: "allow" | "approve" | "deny";
  reason: string;
  targets: string[];
}

export interface Finding {
  id: string;
  title: string;
  severity: Sev;
  description: string;
  component: string;
  cwe: string;
  recommendation: string;
  evidence_ids: string[];
  verified: boolean | null;
  verifier_notes: string;
  task_id: string | null;
}

export interface Chain {
  name: string;
  finding_ids: string[];
  combined_severity: string;
  explanation: string;
}

export interface Task {
  id: string;
  component: string;
  attack_class: string;
  objective: string;
  rationale: string;
  status: string;
}

export interface ThreatModel {
  summary: string;
  assets: string[];
  tasks: Task[];
}

export interface Report {
  meta: Record<string, unknown>;
  threat_model: ThreatModel;
  summary: { weighted_score: number; severity_counts: Counts; duplicates_removed: number };
  chains: Chain[];
  findings: Finding[];
}

export interface AuditEntry {
  id: string;
  ts: number;
  type: "command" | "event";
  kind?: string;
  message?: string;
  command?: string;
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  duration_s?: number;
  approved_by?: string;
  runner?: string;
  task_id?: string | null;
  reason?: string;
  [k: string]: unknown;
}

export interface Benchmark {
  key: string;
  recall: number;
  found_weight: number;
  total_weight: number;
  false_positives: number;
  per_severity: Record<string, { found: number; total: number }>;
  matches: { id: string; title: string; severity: Sev; component: string; found: boolean; finding_id: string }[];
}

export const isActive = (j: Pick<Job, "status">) => j.status === "queued" || j.status === "running";
