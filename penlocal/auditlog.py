"""Append-only audit log — every command and its full output, on disk.

Each finding later points back into this log by entry id, so a reviewer can
trace any claim to what actually happened. Hallucinated evidence has nowhere
to hide.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from .models import CommandResult


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            for entry in self._read_all():
                self._index[entry["id"]] = entry

    def _write(self, entry: dict[str, Any]) -> None:
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
            self._index[entry["id"]] = entry

    def record_command(self, result: CommandResult) -> str:
        entry = {"id": result.id, "ts": result.ts, "type": "command", **result.to_dict()}
        self._write(entry)
        return result.id

    def record_event(self, kind: str, message: str, **extra: Any) -> str:
        entry = {
            "id": f"evt_{uuid.uuid4().hex[:8]}",
            "ts": time.time(),
            "type": "event",
            "kind": kind,
            "message": message,
            **extra,
        }
        self._write(entry)
        return entry["id"]

    def get(self, entry_id: str) -> dict[str, Any] | None:
        return self._index.get(entry_id)

    def evidence_text(self, ids: Iterable[str], max_chars: int = 4000) -> str:
        """Reconstruct the evidence block a verifier should judge against."""
        chunks: list[str] = []
        for eid in ids:
            entry = self._index.get(eid)
            if not entry:
                chunks.append(f"[{eid}] <missing from audit log>")
                continue
            if entry.get("type") == "command":
                body = entry.get("stdout", "")
                if entry.get("stderr"):
                    body += "\n[stderr] " + entry["stderr"]
                chunks.append(
                    f"[{eid}] $ {entry.get('command','')}\n"
                    f"(exit {entry.get('exit_code')})\n{body.strip()}"
                )
            else:
                chunks.append(f"[{eid}] ({entry.get('kind')}) {entry.get('message')}")
        text = "\n\n".join(chunks)
        return text[:max_chars]

    def _read_all(self) -> list[dict[str, Any]]:
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out

    def all_commands(self) -> list[dict[str, Any]]:
        return [e for e in self._index.values() if e.get("type") == "command"]
