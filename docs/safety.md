# Safety model

- **Scope gate** — targets extracted from each command; all must be in scope.
- **Denylist (hard)** — `rm -rf`, `mkfs`, `dd`, fork bombs, DoS tooling,
  pipe-to-shell, reverse shells, abusive scan rates… blocked, never run.
- **Risky → approval** — brute-forcers, exploit frameworks, `sqlmap --dump`,
  state-changing HTTP, intrusive NSE scripts… only run after you say yes.
  (`--auto-approve-risky` exists for lab use; prompting is the default.)
- **Audit** — every command + output on disk; findings must cite evidence ids.
- **Different verifier model** — catches the executor's hallucinations.
- **Emergency stop** — `Sandbox.stop()` halts the engagement immediately.
- **Isolation** — `local` runner enforces scope in-process but shares the host;
  for real separation use `--runner docker` (fresh container per task) and run
  the whole thing from a throwaway VM.
