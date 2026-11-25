import { describe, expect, it } from "vitest";
import { href, parseRoute } from "./store";
import type { Job } from "./types";
import { dur, logClass, progressPct, statusText } from "./util";

const job = (over: Partial<Job> = {}): Job => ({
  id: "20261125-101010-abcd", kind: "run", scope_id: "lab", scope_name: "lab",
  options: { runs: 1, workers: 1, runner: "local", toolpacks: ["web"], max_steps: 12, auto_approve: false, context: null, models: {}, key: null },
  status: "running", created: 0, started: 0, finished: null, error: "", operator: "", summary: {},
  progress: { phase: "execute", run: 1, runs: 1, tasks: 4, started: 3, total: 4, commands: 7, candidates: 1 },
  pending_approvals: 0, downloads: [], ...over,
});

describe("routes", () => {
  it("round-trips", () => {
    for (const r of [{ page: "home" }, { page: "new" }, { page: "scope", id: "acme.q4", tab: "guardrail" }, { page: "run", id: "20261125-101010-abcd", tab: "audit" }] as const)
      expect(parseRoute(href(r))).toEqual(r);
    expect(parseRoute("#/scope/x")).toEqual({ page: "scope", id: "x", tab: "overview" });
    expect(parseRoute("#/nonsense")).toEqual({ page: "home" });
  });
});

describe("status text", () => {
  it("shows the phase", () => {
    expect(statusText(job())).toBe("task 3/4 · 7 commands");
    expect(statusText(job({ pending_approvals: 1 }))).toMatch(/approval/);
    expect(statusText(job({ status: "done", summary: { findings: 2, score: 4 } }))).toBe("2 findings · score 4");
    expect(progressPct(job({ status: "done" }))).toBe(100);
    expect(progressPct(job({ progress: { ...job().progress, phase: "plan" } }))).toBeNull();
  });
  it("formats", () => {
    expect(dur(65)).toBe("1m 05s");
    expect(dur(3725)).toBe("1h 02m");
    expect(logClass("  $ nmap 10.0.0.1")).toBe("l-cmd");
    expect(logClass("[approval] waiting")).toBe("l-warn");
  });
});
