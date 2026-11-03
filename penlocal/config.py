"""Configuration: which backend/model plays which role, and where things live.

Model and harness are kept separate (as in PenLocal) so any model can be
plugged in per role. The *verifier* should be a different model than the
*executor*, so a hallucinated finding is less likely to survive review.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


DEFAULT_OLLAMA = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_OPENAI_BASE = os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1")


@dataclass
class Config:
    # Backend: "ollama" | "openai-compat" | "mock"
    backend: str = "ollama"
    ollama_base_url: str = DEFAULT_OLLAMA
    api_base: str = DEFAULT_OPENAI_BASE
    api_key: str = os.environ.get("OPENAI_API_KEY", "not-needed")

    # Roles can point at the same or different local models.
    planner_model: str = "qwen3:8b"
    executor_model: str = "qwen3:8b"
    verifier_model: str = "llama3.1:8b"   # deliberately a *different* family
    assessor_model: str = "qwen3:8b"

    # Agent-loop limits.
    max_steps_per_task: int = 12
    command_timeout_s: int = 120
    runs: int = 1                      # repeat + merge; 3 finds more than 1
    workers: int = 1                   # parallel tasks within a run

    # Domain tool packs guiding the planner + policy: web | kubernetes | openshift
    toolpacks: list[str] = field(default_factory=lambda: ["web"])

    # Sandbox runner: "local" (subprocess) or "docker".
    runner: str = "local"
    docker_image: str = "kalilinux/kali-rolling"

    # Approval policy.
    auto_approve_safe: bool = True

    # Output locations.
    workdir: Path = field(default_factory=lambda: Path("./penlocal-run"))

    @property
    def audit_path(self) -> Path:
        return self.workdir / "audit.jsonl"

    @property
    def report_dir(self) -> Path:
        return self.workdir / "reports"

    @classmethod
    def load(cls, path: str | os.PathLike | None) -> "Config":
        cfg = cls()
        if path is None:
            return cfg
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Config file not found: {p}")
        if yaml is None:
            raise RuntimeError("PyYAML is required to load a config file.")
        data: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
        for key, value in data.items():
            if key == "workdir":
                value = Path(value)
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        return cfg

    def ensure_dirs(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def role_models(self) -> dict[str, str]:
        return {
            "planner": self.planner_model,
            "executor": self.executor_model,
            "verifier": self.verifier_model,
            "assessor": self.assessor_model,
        }
