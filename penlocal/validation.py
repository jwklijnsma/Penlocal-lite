"""Pre-flight validation — fail loudly and early, before any command runs.

Catches the mistakes that are dangerous or just wasteful in a pentest harness:
an empty or wildcard scope, an unknown backend, a nonsensical worker/run count,
or a verifier that is the same model as the executor (which weakens the
hallucination check). Returns (errors, warnings); errors should stop a run.
"""
from __future__ import annotations

from .config import Config
from .scope import Scope
from .toolpacks import REGISTRY

_VALID_BACKENDS = {"ollama", "openai-compat", "mock"}
_VALID_RUNNERS = {"local", "docker"}
# Scope entries this broad would point the harness at the whole internet.
_DANGEROUS_SCOPE = {"0.0.0.0/0", "::/0", "*", "0.0.0.0", "any", "all"}


def validate_config(cfg: Config) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if cfg.backend not in _VALID_BACKENDS:
        errors.append(f"backend '{cfg.backend}' is not one of {sorted(_VALID_BACKENDS)}.")
    if cfg.runner not in _VALID_RUNNERS:
        errors.append(f"runner '{cfg.runner}' is not one of {sorted(_VALID_RUNNERS)}.")
    if cfg.runs < 1:
        errors.append(f"runs must be >= 1 (got {cfg.runs}).")
    if cfg.workers < 1:
        errors.append(f"workers must be >= 1 (got {cfg.workers}).")
    if cfg.max_steps_per_task < 1:
        errors.append(f"max_steps_per_task must be >= 1 (got {cfg.max_steps_per_task}).")
    if cfg.command_timeout_s < 1:
        errors.append(f"command_timeout_s must be >= 1 (got {cfg.command_timeout_s}).")
    for pack in cfg.toolpacks:
        if str(pack).lower() not in REGISTRY:
            errors.append(f"toolpack '{pack}' is not one of {sorted(REGISTRY)}.")

    if cfg.backend != "mock" and cfg.verifier_model == cfg.executor_model:
        warnings.append(
            "verifier and executor use the same model; a different verifier "
            "model catches more hallucinated findings."
        )
    if cfg.workers > 1 and cfg.runner == "local":
        warnings.append(
            "workers > 1 with the local runner runs commands concurrently on "
            "this host; use --runner docker for real per-task isolation."
        )
    return errors, warnings


def validate_scope(scope: Scope) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    if not scope.in_scope:
        errors.append("scope has no in_scope entries — nothing is authorized, "
                      "so every command would be denied.")
    for entry in scope.in_scope:
        if str(entry).strip().lower() in _DANGEROUS_SCOPE:
            errors.append(f"in_scope entry '{entry}' is far too broad; refusing "
                          f"to target an unbounded range.")

    if not scope.engagement.get("authorized_by"):
        warnings.append("scope has no engagement.authorized_by — record who "
                        "signed off on this test.")
    return errors, warnings


def preflight(cfg: Config, scope: Scope | None = None) -> tuple[list[str], list[str]]:
    errors, warnings = validate_config(cfg)
    if scope is not None:
        se, sw = validate_scope(scope)
        errors += se
        warnings += sw
    return errors, warnings
