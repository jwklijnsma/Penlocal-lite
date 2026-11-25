"""Read-only client for an independently hosted ARTEX instance.

PenLocal never starts ARTEX actions. This adapter only fetches operator-visible
ARTEX data over HTTP(S), keeping ARTEX's AGPL-3.0 code out of this MIT project.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


MAX_RESPONSE = 2 * 1024 * 1024
DEFAULT_ENDPOINTS = {
    "tasks": "/api/tasks",
    "findings": "/api/findings",
    "evidence": "/api/evidence",
    "reports": "/api/reports",
}


class ArtexError(RuntimeError):
    """An ARTEX request failed or returned an invalid response."""


@dataclass(frozen=True)
class ArtexConfig:
    base_url: str
    token: str = ""
    timeout: float = 5.0
    endpoints: dict[str, str] | None = None

    @classmethod
    def from_env(cls) -> "ArtexConfig | None":
        base = os.environ.get("PENLOCAL_ARTEX_URL", "").strip()
        if not base:
            return None
        try:
            timeout = max(1.0, min(float(os.environ.get("PENLOCAL_ARTEX_TIMEOUT", "5")), 20.0))
        except ValueError:
            timeout = 5.0
        endpoints = {
            key: os.environ.get(f"PENLOCAL_ARTEX_{key.upper()}_PATH", default)
            for key, default in DEFAULT_ENDPOINTS.items()
        }
        return cls(base, os.environ.get("PENLOCAL_ARTEX_TOKEN", ""), timeout, endpoints)


class ArtexClient:
    """Small allow-listed GET-only ARTEX API client."""

    def __init__(self, config: ArtexConfig):
        parsed = urlsplit(config.base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ArtexError("ARTEX URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ArtexError("ARTEX URL must not contain credentials, query or fragment")
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.endpoints = dict(DEFAULT_ENDPOINTS)
        if config.endpoints:
            self.endpoints.update(config.endpoints)
        for key, path in self.endpoints.items():
            if key not in DEFAULT_ENDPOINTS or not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
                raise ArtexError("ARTEX endpoint paths must be absolute local paths")

    def _get(self, path: str):
        url = self.base_url + path
        headers = {"Accept": "application/json", "User-Agent": "PenLocal-lite-ARTEX-connector/1.0"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        request = Request(url, headers=headers, method="GET")
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise ArtexError("ARTEX response exceeds 2 MiB limit")
                if response.status != 200:
                    raise ArtexError(f"ARTEX returned HTTP {response.status}")
        except HTTPError as exc:
            raise ArtexError(f"ARTEX returned HTTP {exc.code}") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise ArtexError(f"ARTEX is unreachable: {exc.__class__.__name__}") from None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ArtexError("ARTEX returned invalid JSON") from None

    def status(self) -> dict:
        started = time.monotonic()
        # A root health endpoint is optional; task-list connectivity is the
        # compatibility probe and can be overridden via PENLOCAL_ARTEX_TASKS_PATH.
        try:
            self._get(self.endpoints["tasks"])
            return {"configured": True, "reachable": True,
                    "latency_ms": round((time.monotonic() - started) * 1000)}
        except ArtexError as exc:
            return {"configured": True, "reachable": False, "error": str(exc)}

    def collection(self, name: str):
        if name not in self.endpoints:
            raise ArtexError("Unknown ARTEX resource")
        return self._get(self.endpoints[name])
