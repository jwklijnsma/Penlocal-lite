"""Scope and command policy — the guardrail at the heart of the harness.

This is the single gate between the model and anything real. It answers two
questions for every proposed command:

  1. Does it only touch targets that are explicitly in scope?
  2. Is the command itself allowed, forbidden, or risky-needs-approval?

The denylist is a hard stop (destructive / DoS / exfil patterns). Risky
patterns are allowed only after a human says yes. Everything is matched
conservatively: if a command's targets can't be resolved to in-scope hosts, it
is treated as out of scope.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None


class Decision(str):
    ALLOW = "allow"
    APPROVE = "approve"   # allowed, but a human must confirm
    DENY = "deny"


@dataclass
class PolicyResult:
    decision: str
    reason: str
    targets: list[str] = field(default_factory=list)


# Commands that must never run autonomously regardless of target. These are
# destructive, denial-of-service, or data-exfiltration shaped. Hard denied.
DEFAULT_DENYLIST = [
    r"\brm\s+-rf\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r":\(\)\s*\{",                 # fork bomb
    r"\bshutdown\b|\breboot\b|\bhalt\b",
    r"\b(hping3|t50|mhddos|slowloris)\b",   # DoS tooling
    r"--flood\b",
    r"\bnmap\b[^|]*-{1,2}(?:max-rate|min-rate)\s*\d{5,}",  # abusive rates
    r"\bcurl\b[^|]*\|\s*(ba)?sh\b",         # pipe-to-shell
    r"\bwget\b[^|]*\|\s*(ba)?sh\b",
    r"\b(nc|ncat|netcat)\b.*(?:^|\s)-e\b",  # reverse shells
    r"/dev/tcp/",
    r"\bchmod\s+-R\s+777\b",
]

# Allowed only after explicit human approval (writes / auth / active exploit).
DEFAULT_RISKY = [
    r"\b(hydra|medusa|patator|ncrack)\b",   # credential brute force
    r"\bsqlmap\b.*(--dump|--os-shell|--batch)",
    r"\bmsfconsole\b|\bmsfvenom\b|\bmeterpreter\b",
    r"\b(POST|PUT|DELETE|PATCH)\b",         # state-changing HTTP
    r"\bcurl\b.*-X\s*(POST|PUT|DELETE|PATCH)",
    r"--script=.*(exploit|brute|dos|intrusive)",
    r"\bnikto\b",
    r"\baircrack|airmon|airodump\b",
]


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


class Scope:
    def __init__(
        self,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        denylist: list[str] | None = None,
        risky: list[str] | None = None,
        engagement: dict[str, Any] | None = None,
        clusters: list[str] | None = None,
    ) -> None:
        self.in_scope = in_scope or []
        self.out_of_scope = out_of_scope or []
        self.engagement = engagement or {}
        # In-scope Kubernetes/OpenShift context names (kubeconfig contexts).
        self.clusters = [c.strip() for c in (clusters or []) if str(c).strip()]
        self._deny = [re.compile(p, re.IGNORECASE) for p in (denylist or DEFAULT_DENYLIST)]
        self._risky = [re.compile(p, re.IGNORECASE) for p in (risky or DEFAULT_RISKY)]
        # Command names whose target is not host-checked (image/config scanners).
        self._scanner_prefixes: set[str] = set()
        self._networks, self._hosts = self._parse_scope(self.in_scope)
        self._out_networks, self._out_hosts = self._parse_scope(self.out_of_scope)

    def extend_policy(self, denylist: list[str] | None = None,
                      risky: list[str] | None = None,
                      scanners: list[str] | None = None) -> None:
        """Merge extra policy (e.g. from tool packs) onto the built-in defaults."""
        self._deny += [re.compile(p, re.IGNORECASE) for p in (denylist or [])]
        self._risky += [re.compile(p, re.IGNORECASE) for p in (risky or [])]
        self._scanner_prefixes |= {s.lower() for s in (scanners or [])}

    # ---- loading -----------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        if yaml is None:
            raise RuntimeError("PyYAML is required to load a scope file.")
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            denylist=data.get("denylist"),
            risky=data.get("risky"),
            engagement=data.get("engagement", {}),
            clusters=data.get("clusters", []),
        )

    @staticmethod
    def _parse_scope(entries: list[str]) -> tuple[list[Any], set[str]]:
        networks: list[Any] = []
        hosts: set[str] = set()
        for raw in entries:
            entry = raw.strip()
            if not entry:
                continue
            # Normalise URLs down to their host.
            if "://" in entry:
                entry = urlparse(entry).hostname or entry
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass
            hosts.add(entry.lower().lstrip("*."))
        return networks, hosts

    # ---- target checks -----------------------------------------------------
    def is_target_in_scope(self, target: str) -> bool:
        t = target.strip().lower()
        if "://" in t:
            t = (urlparse(t).hostname or t)
        t = t.split(":")[0]  # drop port
        if not t:
            return False
        # explicit out-of-scope wins
        if self._matches(t, self._out_networks, self._out_hosts):
            return False
        return self._matches(t, self._networks, self._hosts)

    @staticmethod
    def _matches(target: str, networks: list[Any], hosts: set[str]) -> bool:
        if _looks_like_ip(target):
            ip = ipaddress.ip_address(target)
            if any(ip in net for net in networks):
                return True
        if target in hosts:
            return True
        # suffix match for subdomains of an in-scope apex
        return any(target == h or target.endswith("." + h) for h in hosts)

    # ---- command classification -------------------------------------------
    # crude token extractor: things that look like hosts/IPs/URLs
    _TARGET_RE = re.compile(
        r"(https?://[^\s'\"]+|(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?|"
        r"(?:[a-z0-9-]+\.)+[a-z]{2,})",
        re.IGNORECASE,
    )

    # File-ish suffixes that look like hostnames but aren't targets (e.g.
    # pod.yaml). Deliberately excludes TLD-colliding ones like .sh/.io/.md.
    _FILE_SUFFIXES = (".py", ".txt", ".json", ".yaml", ".yml", ".conf", ".cfg",
                      ".xml", ".csv", ".log", ".pem", ".crt", ".key", ".tpl")

    def extract_targets(self, command: str) -> list[str]:
        found = self._TARGET_RE.findall(command)
        return [f for f in dict.fromkeys(found)
                if not f.lower().endswith(self._FILE_SUFFIXES)]

    # kubectl/oc context selectors, e.g. --context=prod  or  use-context prod
    _CTX_RE = re.compile(r"(?:--context[=\s]+|use-context\s+)([^\s'\"]+)")

    @staticmethod
    def _first_token(cmd: str) -> str:
        try:
            import shlex
            parts = shlex.split(cmd)
        except ValueError:
            parts = cmd.split()
        # skip leading VAR=val env assignments
        for p in parts:
            if "=" in p and not p.startswith("-") and "/" not in p.split("=")[0]:
                continue
            return p.split("/")[-1].lower()
        return ""

    def classify_command(self, command: str) -> PolicyResult:
        cmd = command.strip()
        if not cmd:
            return PolicyResult(Decision.DENY, "Empty command.")

        for pat in self._deny:
            if pat.search(cmd):
                return PolicyResult(
                    Decision.DENY,
                    f"Matches denylist pattern /{pat.pattern}/ (destructive, "
                    f"DoS, or exfiltration shaped).",
                )

        # Kubernetes/OpenShift: if an explicit context is named and we have a
        # cluster allow-list, it must be in scope.
        if self.clusters and self._first_token(cmd) in ("kubectl", "oc"):
            m = self._CTX_RE.search(cmd)
            if m and m.group(1) not in self.clusters:
                return PolicyResult(
                    Decision.DENY,
                    f"Cluster context '{m.group(1)}' is not in the in-scope "
                    f"clusters {self.clusters}.",
                )

        # Image/config scanners analyse artifacts or the kubeconfig cluster, not
        # an arbitrary network host, so skip host-based scope extraction for them.
        if self._first_token(cmd) not in self._scanner_prefixes:
            targets = self.extract_targets(cmd)
            if targets:
                out = [t for t in targets if not self.is_target_in_scope(t)]
                if out:
                    return PolicyResult(
                        Decision.DENY,
                        f"Target(s) out of scope: {', '.join(out)}.",
                        targets,
                    )
        else:
            targets = []

        for pat in self._risky:
            if pat.search(cmd):
                return PolicyResult(
                    Decision.APPROVE,
                    f"Risky action (matches /{pat.pattern}/): needs operator "
                    f"approval before running.",
                    targets,
                )

        return PolicyResult(Decision.ALLOW, "In scope, no risky patterns.", targets)
