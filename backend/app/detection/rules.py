"""Detection rules. Each rule is a small class: declare metadata + default config, implement `evaluate`.

To add a rule: subclass `Rule`, set `rule_id/name/description/severity/mitre/default_config`, implement
`relevant(event)` (cheap pre-filter) and `evaluate(store, ref_time, config)` returning Findings, then add
it to `REGISTRY`. Its DB row is created automatically at startup. See docs/ARCHITECTURE.md.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from ..store import EventStore

MAX_IDS = 200


@dataclass
class Finding:
    rule_id: str
    correlation_key: str
    title: str
    severity: str
    source: str
    host: str
    first_seen: datetime
    last_seen: datetime
    count: int
    event_ids: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)


def _ts(e: dict) -> datetime:
    return datetime.fromisoformat(e["@timestamp"])


def _sample(events: list[dict], n: int = 5) -> list[dict]:
    keys = ("event_id", "@timestamp", "host", "user", "src_ip", "dst_ip", "dst_port", "action", "outcome", "message")
    return [
        {k: e.get(k) for k in keys if e.get(k) is not None} | {"message": (e.get("message") or "")[:200]}
        for e in events[:n]
    ]


class Rule:
    rule_id = ""
    name = ""
    description = ""
    severity = "medium"
    mitre: list[dict] = []
    default_config: dict[str, Any] = {}

    def relevant(self, event: dict) -> bool:
        raise NotImplementedError

    def evaluate(self, store: EventStore, ref: datetime, cfg: dict) -> list[Finding]:
        raise NotImplementedError

    @staticmethod
    def window(cfg: dict) -> timedelta:
        return timedelta(seconds=int(cfg["window_seconds"]))

    def _sliding(self, events: list[dict], threshold: int, win: timedelta, distinct=None) -> list[dict] | None:
        """Return the densest window of events (sorted) that meets the threshold, else None.
        `distinct` is an optional key function: the threshold then applies to distinct values."""
        evs = sorted(events, key=_ts)
        best: list[dict] | None = None
        lo = 0
        for hi in range(len(evs)):
            while _ts(evs[hi]) - _ts(evs[lo]) > win:
                lo += 1
            chunk = evs[lo : hi + 1]
            n = len({distinct(e) for e in chunk}) if distinct else len(chunk)
            if n >= threshold and (best is None or len(chunk) > len(best)):
                best = chunk
        return best


AUTH_FAIL_FILTER = {"category": ["authentication", "web"], "outcome": "failure"}


class BruteForce(Rule):
    rule_id = "SIEM-001"
    name = "Brute-force attempts"
    description = "Repeated failed SSH/application authentication from one source IP within a time window."
    severity = "high"
    mitre = [{"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"}]
    default_config = {"threshold": 5, "window_seconds": 120, "suppression_seconds": 900}

    @staticmethod
    def _is_app_auth_fail(e: dict) -> bool:
        if e.get("outcome") != "failure" or not e.get("src_ip"):
            return False
        if e.get("category") == "authentication":
            return e.get("action") in ("ssh_login", "ssh_invalid_user", "app_login")
        return (
            e.get("category") == "web"
            and (e.get("fields") or {}).get("status") in (401, 403)
            and (e.get("fields") or {}).get("auth_endpoint", True)
        )

    def relevant(self, event: dict) -> bool:
        return self._is_app_auth_fail(event)

    def evaluate(self, store, ref, cfg):
        evs = [e for e in store.fetch(ref - self.window(cfg), AUTH_FAIL_FILTER) if self._is_app_auth_fail(e)]
        groups: dict[str, list[dict]] = defaultdict(list)
        for e in evs:
            groups[e["src_ip"]].append(e)
        out = []
        for ip, g in groups.items():
            chunk = self._sliding(g, int(cfg["threshold"]), self.window(cfg))
            if chunk:
                users = sorted({e.get("user") for e in chunk if e.get("user")})
                out.append(
                    Finding(
                        self.rule_id,
                        f"{self.rule_id}|{ip}",
                        f"Brute-force from {ip}",
                        self.severity,
                        ip,
                        chunk[-1]["host"],
                        _ts(chunk[0]),
                        _ts(chunk[-1]),
                        len(chunk),
                        [e["event_id"] for e in chunk][-MAX_IDS:],
                        {
                            "attempts": len(chunk),
                            "window_seconds": cfg["window_seconds"],
                            "targeted_accounts": users[:20],
                            "threshold": cfg["threshold"],
                            "samples": _sample(chunk),
                        },
                    )
                )
        return out


class MultipleFailedLogins(Rule):
    rule_id = "SIEM-002"
    name = "Multiple failed logins"
    description = "Several failed logins against the same account on the same host (Windows, Linux or application)."
    severity = "medium"
    mitre = [{"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"}]
    default_config = {"threshold": 5, "window_seconds": 600, "suppression_seconds": 1800}

    @staticmethod
    def _ok(e: dict) -> bool:
        return (
            e.get("category") == "authentication"
            and e.get("outcome") == "failure"
            and bool(e.get("user"))
            and e.get("action") not in ("account_lockout",)
        )

    def relevant(self, event):
        return self._ok(event)

    def evaluate(self, store, ref, cfg):
        evs = [
            e
            for e in store.fetch(ref - self.window(cfg), {"category": "authentication", "outcome": "failure"})
            if self._ok(e)
        ]
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for e in evs:
            groups[(e["host"], e["user"].lower())].append(e)
        out = []
        for (host, user), g in groups.items():
            chunk = self._sliding(g, int(cfg["threshold"]), self.window(cfg))
            if chunk:
                ips = sorted({e["src_ip"] for e in chunk if e.get("src_ip")})
                out.append(
                    Finding(
                        self.rule_id,
                        f"{self.rule_id}|{host}|{user}",
                        f"Multiple failed logins for {user} on {host}",
                        self.severity,
                        ips[0] if ips else user,
                        host,
                        _ts(chunk[0]),
                        _ts(chunk[-1]),
                        len(chunk),
                        [e["event_id"] for e in chunk][-MAX_IDS:],
                        {
                            "account": user,
                            "failures": len(chunk),
                            "source_ips": ips[:20],
                            "threshold": cfg["threshold"],
                            "window_seconds": cfg["window_seconds"],
                            "samples": _sample(chunk),
                        },
                    )
                )
        return out


class PortScan(Rule):
    rule_id = "SIEM-003"
    name = "Port scanning"
    description = (
        "One source contacting many distinct destination ports on a target in a short window. "
        "Requires connection telemetry (firewall logs or Windows event 5156/5157 auditing)."
    )
    severity = "medium"
    mitre = [{"technique_id": "T1046", "technique": "Network Service Discovery", "tactic": "Discovery"}]
    default_config = {"distinct_ports": 15, "window_seconds": 60, "suppression_seconds": 900}

    def relevant(self, event):
        return event.get("category") == "network" and bool(event.get("src_ip")) and event.get("dst_port") is not None

    def evaluate(self, store, ref, cfg):
        evs = [e for e in store.fetch(ref - self.window(cfg), {"category": "network"}) if self.relevant(e)]
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for e in evs:
            groups[(e["src_ip"], e.get("dst_ip") or e["host"])].append(e)
        out = []
        for (src, dst), g in groups.items():
            chunk = self._sliding(g, int(cfg["distinct_ports"]), self.window(cfg), distinct=lambda e: e["dst_port"])
            if chunk:
                ports = sorted({e["dst_port"] for e in chunk})
                out.append(
                    Finding(
                        self.rule_id,
                        f"{self.rule_id}|{src}|{dst}",
                        f"Port scan from {src} against {dst}",
                        self.severity,
                        src,
                        chunk[-1]["host"],
                        _ts(chunk[0]),
                        _ts(chunk[-1]),
                        len(chunk),
                        [e["event_id"] for e in chunk][-MAX_IDS:],
                        {
                            "distinct_ports": len(ports),
                            "ports_sample": ports[:50],
                            "target": dst,
                            "window_seconds": cfg["window_seconds"],
                            "samples": _sample(chunk),
                        },
                    )
                )
        return out


class SuspiciousCommand(Rule):
    rule_id = "SIEM-004"
    name = "Suspicious command execution"
    description = (
        "Process/command lines matching configured suspicious patterns. Needs command-line telemetry "
        "(Windows 4688 with command-line auditing, Sysmon event 1, or Linux sudo/auditd logs)."
    )
    severity = "high"
    mitre = [{"technique_id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution"}]
    default_config = {
        "window_seconds": 300,
        "suppression_seconds": 900,
        "patterns": {
            "encoded_powershell": r"powershell(\.exe)?\s.*-(enc|encodedcommand)\s",
            "download_cradle": r"(iex|invoke-expression).*(downloadstring|net\.webclient)",
            "certutil_download": r"certutil(\.exe)?\s.*-urlcache",
            "shadow_copy_delete": r"vssadmin(\.exe)?\s+delete\s+shadows",
            "reverse_shell": r"(bash\s+-i\s+>&\s*/dev/tcp/|nc(\.exe)?\s+.*-e\s+/?\S*sh)",
            "pipe_to_shell": r"(curl|wget)\s+[^|]*\|\s*(ba)?sh",
            "credential_dump": r"(mimikatz|sekurlsa|procdump.*lsass)",
        },
    }

    def relevant(self, event):
        return bool(event.get("command_line"))

    def evaluate(self, store, ref, cfg):
        compiled = []
        for name, pat in (cfg.get("patterns") or {}).items():
            try:
                if len(pat) <= 300:
                    compiled.append((name, re.compile(pat, re.I)))
            except re.error:
                continue
        evs = [e for e in store.fetch(ref - self.window(cfg), {}) if e.get("command_line")]
        groups: dict[tuple, list[tuple[dict, str]]] = defaultdict(list)
        for e in evs:
            cmd = e["command_line"][:2048]
            for name, rx in compiled:
                if rx.search(cmd):
                    groups[(e["host"], (e.get("user") or "-").lower(), name)].append((e, name))
        out = []
        for (host, user, name), g in groups.items():
            chunk = [e for e, _ in sorted(g, key=lambda x: _ts(x[0]))]
            out.append(
                Finding(
                    self.rule_id,
                    f"{self.rule_id}|{host}|{user}|{name}",
                    f"Suspicious command ({name}) on {host}",
                    self.severity,
                    user,
                    host,
                    _ts(chunk[0]),
                    _ts(chunk[-1]),
                    len(chunk),
                    [e["event_id"] for e in chunk][-MAX_IDS:],
                    {
                        "matched_pattern": name,
                        "user": user,
                        "commands": [c["command_line"][:300] for c in chunk[:5]],
                        "samples": _sample(chunk),
                    },
                )
            )
        return out


class MalwareIndicator(Rule):
    rule_id = "SIEM-005"
    name = "Malware indicators"
    description = (
        "Events matching configured known-bad hashes, domains, IPs or process names (test indicators by default)."
    )
    severity = "critical"
    mitre: list[dict] = []  # indicator matches are not technique-specific; no mapping is claimed
    default_config = {
        "window_seconds": 300,
        "suppression_seconds": 3600,
        "hashes": [
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",  # EICAR test file SHA-256
            "44d88612fea8a8f36de82e1278abb02f",
        ],  # EICAR test file MD5
        "domains": ["malware-test.example.invalid"],
        "ips": ["203.0.113.66"],  # TEST-NET-3 documentation range
        "process_names": ["eicar.com"],
    }

    @staticmethod
    def _matches(e: dict, cfg: dict) -> list[str]:
        hits = []
        if e.get("file_hash") and e["file_hash"].lower() in {h.lower() for h in cfg.get("hashes", [])}:
            hits.append(f"hash:{e['file_hash'][:16]}…")
        dom = (e.get("domain") or "").lower()
        if dom and any(dom == d.lower() or dom.endswith("." + d.lower()) for d in cfg.get("domains", [])):
            hits.append(f"domain:{dom}")
        ips = set(cfg.get("ips", []))
        for k in ("src_ip", "dst_ip"):
            if e.get(k) in ips:
                hits.append(f"ip:{e[k]}")
        pn = (e.get("process_name") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
        if pn and pn in {p.lower() for p in cfg.get("process_names", [])}:
            hits.append(f"process:{pn}")
        return hits

    def relevant(self, event):
        return any(event.get(k) for k in ("file_hash", "domain", "dst_ip", "src_ip", "process_name"))

    def evaluate(self, store, ref, cfg):
        """One alert per host; the indicator list grows as more distinct indicators are seen."""
        groups: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
        for e in store.fetch(ref - self.window(cfg), {}):
            for h in self._matches(e, cfg):
                groups[e["host"]][h].append(e)
        out = []
        for host, by_ind in groups.items():
            chunk = {e["event_id"]: e for evs in by_ind.values() for e in evs}
            chunk_l = sorted(chunk.values(), key=_ts)
            inds = sorted(by_ind)
            out.append(
                Finding(
                    self.rule_id,
                    f"{self.rule_id}|{host}",
                    f"Malware indicators on {host} ({', '.join(inds[:3])}{'...' if len(inds) > 3 else ''})",
                    self.severity,
                    chunk_l[-1].get("src_ip") or host,
                    host,
                    _ts(chunk_l[0]),
                    _ts(chunk_l[-1]),
                    len(chunk_l),
                    [e["event_id"] for e in chunk_l][-MAX_IDS:],
                    {"indicators": inds[:50], "samples": _sample(chunk_l)},
                )
            )
        return out


REGISTRY: dict[str, Rule] = {
    r.rule_id: r for r in (BruteForce(), MultipleFailedLogins(), PortScan(), SuspiciousCommand(), MalwareIndicator())
}


def validate_rule_config(rule_id: str, cfg: dict) -> None:
    """Reject unknown keys, wrong types, out-of-range numbers and invalid/oversized regexes."""
    rule = REGISTRY.get(rule_id)
    if rule is None:
        raise ValueError("unknown rule")
    for k, v in cfg.items():
        if k not in rule.default_config:
            raise ValueError(f"unknown config key {k!r}")
        default = rule.default_config[k]
        if isinstance(v, bool) or not isinstance(v, type(default)):
            raise ValueError(f"{k!r} must be {type(default).__name__}")
        if isinstance(default, int) and not (1 <= v <= 86_400):
            raise ValueError(f"{k!r} must be between 1 and 86400")
        if isinstance(default, list) and (len(v) > 1000 or not all(isinstance(x, str) and len(x) <= 256 for x in v)):
            raise ValueError(f"{k!r} must be a list of short strings (max 1000)")
        if k == "patterns":
            for name, pat in v.items():
                if not isinstance(pat, str) or len(pat) > 300 or len(v) > 100:
                    raise ValueError("patterns must be short strings")
                try:
                    re.compile(pat)
                except re.error as e:
                    raise ValueError(f"invalid regex for {name!r}: {e}") from None
