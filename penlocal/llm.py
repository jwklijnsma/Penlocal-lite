"""Model backends — the "brain" is swappable, the harness is not.

Three backends implement one tiny interface (`chat`, `chat_json`, `available`):

  * LocalLLM        — a local Ollama server (default; data never leaves the box).
  * OpenAICompatLLM — any OpenAI-compatible /v1/chat/completions endpoint:
                      vLLM, llama.cpp --server, LM Studio, text-generation-webui.
                      Point it at localhost to stay fully local.
  * MockLLM         — deterministic, no network. Plays each harness role from the
                      system prompt so the whole pipeline runs offline for demos
                      and tests. It parses real audit ids out of the transcript,
                      so findings cite genuine evidence and verification is honest.

`make_llm(backend, model, ...)` builds the right one. Model and harness stay
separate: any role can point at any backend/model.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

import requests


class LLMError(RuntimeError):
    pass


class BaseLLM:
    """The whole contract the harness depends on."""

    model: str = "base"

    def chat(self, system: str, user: str, json_mode: bool = False,
             temperature: Optional[float] = None) -> str:
        raise NotImplementedError

    def chat_json(self, system: str, user: str) -> Any:
        raw = self.chat(system, user, json_mode=True, temperature=0.2)
        return extract_json(raw)

    def available(self) -> bool:
        return True


# --------------------------------------------------------------------------- #
#  Ollama
# --------------------------------------------------------------------------- #
class LocalLLM(BaseLLM):
    def __init__(self, model: str, base_url: str = "http://localhost:11434",
                 temperature: float = 0.6, timeout: int = 600) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.timeout = timeout

    def chat(self, system: str, user: str, json_mode: bool = False,
             temperature: Optional[float] = None) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": self.temperature if temperature is None else temperature},
        }
        if json_mode:
            payload["format"] = "json"
        try:
            resp = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(
                f"Could not reach Ollama at {self.base_url} for model '{self.model}': "
                f"{exc}. Is `ollama serve` running and `ollama pull {self.model}` done?"
            ) from exc
        return (resp.json().get("message") or {}).get("content", "").strip()

    def available(self) -> bool:
        try:
            return requests.get(f"{self.base_url}/api/tags", timeout=10).ok
        except requests.RequestException:
            return False


# --------------------------------------------------------------------------- #
#  OpenAI-compatible (vLLM / llama.cpp / LM Studio / TGI)
# --------------------------------------------------------------------------- #
class OpenAICompatLLM(BaseLLM):
    def __init__(self, model: str, api_base: str = "http://localhost:8000/v1",
                 api_key: str = "not-needed", temperature: float = 0.6,
                 timeout: int = 600) -> None:
        self.model = model
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout

    def chat(self, system: str, user: str, json_mode: bool = False,
             temperature: Optional[float] = None) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature if temperature is None else temperature,
            "stream": False,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        try:
            resp = requests.post(
                f"{self.api_base}/chat/completions",
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(
                f"Could not reach OpenAI-compatible server at {self.api_base} "
                f"for model '{self.model}': {exc}."
            ) from exc
        return resp.json()["choices"][0]["message"]["content"].strip()

    def available(self) -> bool:
        try:
            r = requests.get(f"{self.api_base}/models",
                             headers={"Authorization": f"Bearer {self.api_key}"}, timeout=10)
            return r.ok
        except requests.RequestException:
            return False


# --------------------------------------------------------------------------- #
#  Mock — deterministic, offline, plays every role
# --------------------------------------------------------------------------- #
_CMD_ID = re.compile(r"cmd_[0-9a-f]{8}")
_FIND_ID = re.compile(r"find_[0-9a-f]{8}")


class MockLLM(BaseLLM):
    """A scripted brain so the full harness runs with no model server.

    It keys off the role described in the system prompt and, for the executor,
    reads real `cmd_...` ids back out of the transcript so its findings cite
    actual audit entries. Nothing here fabricates evidence.
    """

    def __init__(self, model: str = "mock", findings_per_task: int = 1) -> None:
        self.model = model
        self.findings_per_task = findings_per_task

    def chat(self, system: str, user: str, json_mode: bool = False,
             temperature: Optional[float] = None) -> str:
        return json.dumps(self._respond(system, user))

    def chat_json(self, system: str, user: str) -> Any:
        return self._respond(system, user)

    def _respond(self, system: str, user: str) -> Any:
        s = system.lower()
        if "planning component" in s:
            return self._plan()
        if "execution component" in s:
            return self._execute(user)
        if "verification component" in s:
            return self._verify(user)
        if "assessment component" in s:
            return self._assess(user)
        return {"thought": "mock", "done": True}

    def _plan(self) -> dict:
        return {
            "summary": "Mock threat model: a small web app with an API behind it. "
                       "Tested for recon exposure and input-handling flaws.",
            "assets": ["web frontend", "REST API"],
            "tasks": [
                {"component": "web frontend", "attack_class": "recon",
                 "objective": "Enumerate exposed endpoints and headers.",
                 "rationale": "Baseline surface mapping."},
                {"component": "REST API", "attack_class": "input-validation",
                 "objective": "Probe input handling on the API.",
                 "rationale": "Injection-class issues are high impact."},
            ],
        }

    def _execute(self, user: str) -> dict:
        if "recorded candidate finding" in user:
            return {"thought": "Objective covered.", "done": True}
        cmd_ids = _CMD_ID.findall(user)
        if cmd_ids:
            # We have real evidence in the transcript — cite the latest id.
            return {
                "thought": "The probe returned a telling response; recording it.",
                "finding": {
                    "title": "Mock finding: verbose response surface",
                    "severity": "medium",
                    "description": "The probe output (see evidence) demonstrates the "
                                   "component responds in a way worth a human review.",
                    "evidence_ids": [cmd_ids[-1]],
                    "cwe": "CWE-200",
                    "recommendation": "Review the response and restrict as needed.",
                },
            }
        # model "mock-approval": on the API task, first propose a step the policy
        # gates behind a human (it is still a harmless echo), so the approval flow
        # can be tried without a model server. A decline falls back to the probe.
        if (self.model == "mock-approval" and "input-validation" in user
                and "[declined]" not in user):
            return {"thought": "Try a state-changing request; this needs sign-off.",
                    "command": 'echo "mock-probe: curl -X POST http://demo.local/api/users"'}
        # First step: emit a harmless, in-scope-agnostic probe that actually runs.
        return {"thought": "Start with a cheap probe.",
                "command": 'echo "mock-probe: harness pipeline is live"'}

    def _verify(self, user: str) -> dict:
        # Honest: verify only if real evidence text is present.
        block = user.split("Evidence from the audit log", 1)[-1]
        has_evidence = bool(_CMD_ID.search(block)) and "mock-probe" in block
        return {
            "verified": has_evidence,
            "adjusted_severity": "medium" if has_evidence else "info",
            "notes": ("Evidence present in audit log and consistent with the claim."
                      if has_evidence else "No supporting evidence found; rejected."),
        }

    def _assess(self, user: str) -> dict:
        ids = _FIND_ID.findall(user)
        if len(ids) >= 2:
            return {"chains": [{
                "name": "Recon + input handling",
                "finding_ids": ids[:2],
                "combined_severity": "high",
                "explanation": "Surface exposure plus weak input handling compound "
                               "into a more serious, chainable risk.",
            }]}
        return {"chains": []}


# --------------------------------------------------------------------------- #
#  factory + json helper
# --------------------------------------------------------------------------- #
def make_llm(backend: str, model: str, *, base_url: str = "http://localhost:11434",
             api_base: str = "http://localhost:8000/v1", api_key: str = "not-needed",
             temperature: float = 0.6) -> BaseLLM:
    backend = (backend or "ollama").lower()
    if backend == "ollama":
        return LocalLLM(model, base_url=base_url, temperature=temperature)
    if backend in ("openai", "openai-compat", "vllm", "llamacpp"):
        return OpenAICompatLLM(model, api_base=api_base, api_key=api_key, temperature=temperature)
    if backend == "mock":
        return MockLLM(model)
    raise LLMError(f"Unknown backend '{backend}'. Use ollama | openai-compat | mock.")


def extract_json(text: str) -> Any:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for open_c, close_c in (("{", "}"), ("[", "]")):
            start, end = text.find(open_c), text.rfind(close_c)
            if start != -1 and end > start:
                try:
                    return json.loads(text[start:end + 1])
                except json.JSONDecodeError:
                    continue
        raise LLMError(f"Model did not return valid JSON:\n{text[:800]}")
