"""Parsing and normalisation of raw records into the normalised event schema.

Supported inputs: Windows Security/Sysmon JSON, Linux auth/syslog text, Linux firewall (iptables)
log lines, Nginx access/error logs, Docker JSON logs, and generic structured JSON.
Every record either becomes a normalised event or a ParseError (never silently dropped).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

RAW_LIMIT = 4096
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


class ParseError(ValueError):
    pass


def now_utc() -> datetime:
    return datetime.now(UTC)


def parse_ts(value: Any, default: datetime | None = None) -> datetime:
    """Normalise many timestamp representations to an aware UTC datetime."""
    if value is None or value == "":
        return default or now_utc()
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        v = float(value)
        if v > 1e12:  # milliseconds
            v /= 1000.0
        dt = datetime.fromtimestamp(v, UTC)
    elif isinstance(value, str):
        s = value.strip()
        if re.fullmatch(r"\d+(\.\d+)?", s):
            return parse_ts(float(s), default)
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            dt = None
            for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y/%m/%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
            if dt is None:
                m = re.fullmatch(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)", s)
                if m:  # syslog has no year; assume current year
                    year = now_utc().year
                    dt = datetime.strptime(f"{year} {m[1]} {m[2]} {m[3]}", "%Y %b %d %H:%M:%S")
                else:
                    raise ParseError(f"unparseable timestamp: {s[:40]!r}") from None
    else:
        raise ParseError("unsupported timestamp type")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def valid_ip(value: Any) -> str | None:
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith("::ffff:"):
        v = v[7:]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def _int(value: Any) -> int | None:
    try:
        n = int(str(value))
        return n if 0 <= n <= 65535 else None
    except (TypeError, ValueError):
        return None


def event_id_for(ts: datetime, host: str, raw: str) -> str:
    """Deterministic ID -> retried batches are idempotent (same raw record dedupes)."""
    return hashlib.sha256(f"{ts.isoformat()}|{host}|{raw}".encode()).hexdigest()[:32]


def base_event(ts: datetime, host: str, source_type: str, raw: str) -> dict[str, Any]:
    return {
        "event_id": event_id_for(ts, host, raw),
        "@timestamp": ts.isoformat(),
        "host": host or "unknown",
        "source_type": source_type,
        "category": "system",
        "action": "unknown",
        "outcome": "unknown",
        "severity": "informational",
        "user": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "process_name": None,
        "command_line": None,
        "file_hash": None,
        "domain": None,
        "message": "",
        "raw": raw[:RAW_LIMIT],
        "fields": {},
        "geo": None,
        "synthetic": False,
        "detections": [],
    }


# ---------------------------------------------------------------- Windows
WIN_EVENTS = {
    4624: ("authentication", "logon", "success", "informational"),
    4625: ("authentication", "logon", "failure", "low"),
    4634: ("authentication", "logoff", "success", "informational"),
    4672: ("authentication", "privileged_logon", "success", "informational"),
    4688: ("process", "process_create", "success", "informational"),
    4720: ("iam", "user_created", "success", "medium"),
    4740: ("authentication", "account_lockout", "failure", "medium"),
    5156: ("network", "connection_allowed", "success", "informational"),
    5157: ("network", "connection_blocked", "failure", "informational"),
    7045: ("system", "service_installed", "success", "medium"),
}


# Positional StringInserts layouts (Fluent Bit winevtlog / classic event-log readers) for common Security events.
WIN_INSERTS = {
    4624: {1: "SubjectUserName", 5: "TargetUserName", 8: "LogonType", 18: "IpAddress"},
    4625: {1: "SubjectUserName", 5: "TargetUserName", 10: "LogonType", 19: "IpAddress"},
    4688: {1: "SubjectUserName", 5: "NewProcessName", 8: "CommandLine"},
    5156: {1: "Application", 3: "SourceAddress", 4: "SourcePort", 5: "DestAddress", 6: "DestPort"},
    5157: {1: "Application", 3: "SourceAddress", 4: "SourcePort", 5: "DestAddress", 6: "DestPort"},
}


def _inserts_to_data(eid: int, inserts: list) -> dict:
    return {name: inserts[i] for i, name in WIN_INSERTS.get(eid, {}).items() if i < len(inserts)}


def _win_data(rec: dict) -> dict:
    data = rec.get("EventData") or rec.get("event_data") or {}
    if isinstance(data, list):  # [{"Name": "x", "#text": "y"}]
        data = {d.get("Name"): d.get("#text") for d in data if isinstance(d, dict)}
    flat = {k: v for k, v in rec.items() if k not in ("EventData", "event_data", "System")}
    flat.update(data if isinstance(data, dict) else {})
    return flat


def parse_windows(rec: dict, host_hint: str, raw: str) -> dict:
    d = _win_data(rec)
    try:
        eid = int(rec.get("EventID") or rec.get("EventId") or d.get("EventID"))
    except (TypeError, ValueError) as e:
        raise ParseError("windows record missing numeric EventID") from e
    if isinstance(rec.get("StringInserts"), list) and not (rec.get("EventData") or rec.get("event_data")):
        d = {**d, **_inserts_to_data(eid, rec["StringInserts"])}
    channel = str(rec.get("Channel") or d.get("Channel") or "")
    ts = parse_ts(rec.get("TimeCreated") or rec.get("TimeGenerated") or rec.get("@timestamp") or rec.get("timestamp"))
    host = str(rec.get("Computer") or rec.get("ComputerName") or d.get("Computer") or host_hint)
    ev = base_event(ts, host, "windows", raw)
    ev["fields"] = {"event_code": eid, "channel": channel}
    if "Sysmon" in channel:
        ev["fields"]["sysmon"] = True
        if eid == 1:
            ev.update(category="process", action="process_create", outcome="success")
        elif eid == 3:
            ev.update(category="network", action="connection", outcome="success")
        else:
            ev.update(category="system", action=f"sysmon_{eid}")
    elif eid in WIN_EVENTS:
        cat, act, out, sev = WIN_EVENTS[eid]
        ev.update(category=cat, action=act, outcome=out, severity=sev)
    else:
        ev.update(category="system", action=f"windows_event_{eid}")
    user = d.get("TargetUserName") or d.get("User") or d.get("SubjectUserName")
    ev["user"] = str(user)[:128] if user and user != "-" else None
    ev["src_ip"] = valid_ip(d.get("IpAddress") or d.get("SourceAddress") or d.get("SourceIp"))
    ev["dst_ip"] = valid_ip(d.get("DestAddress") or d.get("DestinationIp"))
    ev["src_port"] = _int(d.get("SourcePort"))
    ev["dst_port"] = _int(d.get("DestPort") or d.get("DestinationPort"))
    ev["process_name"] = d.get("NewProcessName") or d.get("Image") or d.get("Application")
    ev["command_line"] = d.get("CommandLine")  # only present with command-line auditing / Sysmon
    hashes = d.get("Hashes")
    if isinstance(hashes, str):
        m = re.search(r"SHA256=([A-Fa-f0-9]{64})", hashes) or re.search(r"MD5=([A-Fa-f0-9]{32})", hashes)
        ev["file_hash"] = m[1].lower() if m else None
    ev["domain"] = d.get("QueryName") or d.get("DestinationHostname")
    if d.get("LogonType") is not None:
        ev["fields"]["logon_type"] = str(d["LogonType"])
    ev["message"] = f"Windows event {eid} {ev['action']} user={ev['user']} src={ev['src_ip']}"
    return ev


# ---------------------------------------------------------------- Linux
SSH_FAIL = re.compile(
    r"Failed (?P<method>\w[\w-]*) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
SSH_OK = re.compile(r"Accepted (?P<method>\w[\w-]*) for (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)")
SUDO = re.compile(r"(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.+)$")
SYSLOG = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s\d\d:\d\d:\d\d)|\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d)?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
FW = re.compile(
    r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\w+)(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
)


def parse_syslog(line: str, host_hint: str, ts_hint: datetime | None = None) -> dict:
    m = SYSLOG.match(line.strip())
    if m:
        ts, host, proc, msg = parse_ts(m["ts"]), m["host"], m["proc"], m["msg"]
    else:
        ts, host, proc, msg = ts_hint or now_utc(), host_hint, "unknown", line.strip()
    ev = base_event(ts, host, "linux", line)
    ev["process_name"] = proc
    ev["message"] = msg[:1024]
    ev["fields"] = {"program": proc}
    if f := SSH_FAIL.search(msg):
        ev.update(category="authentication", action="ssh_login", outcome="failure", severity="low")
        ev.update(user=f["user"], src_ip=valid_ip(f["ip"]), src_port=_int(f["port"]))
        ev["fields"]["method"] = f["method"]
    elif f := SSH_INVALID.search(msg):
        ev.update(category="authentication", action="ssh_invalid_user", outcome="failure", severity="low")
        ev.update(user=f["user"], src_ip=valid_ip(f["ip"]))
    elif f := SSH_OK.search(msg):
        ev.update(category="authentication", action="ssh_login", outcome="success")
        ev.update(user=f["user"], src_ip=valid_ip(f["ip"]), src_port=_int(f["port"]))
    elif proc == "sudo" and (f := SUDO.search(msg)):
        ev.update(category="process", action="sudo_command", outcome="success", user=f["user"])
        ev["command_line"] = f["cmd"].strip()
    elif f := FW.search(msg):
        ev.update(category="network", action="firewall_connection", outcome="unknown")
        ev.update(
            src_ip=valid_ip(f["src"]), dst_ip=valid_ip(f["dst"]), src_port=_int(f["spt"]), dst_port=_int(f["dpt"])
        )
        ev["fields"]["protocol"] = f["proto"]
    return ev


# ---------------------------------------------------------------- Nginx
NGINX_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
NGINX_ERROR = re.compile(
    r"^(?P<ts>\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(?P<level>\w+)\] \d+#\d+: (?:\*\d+ )?(?P<msg>.*?)(?:, client: (?P<ip>[0-9a-fA-F:.]+).*)?$"
)


def parse_nginx(line: str, host_hint: str) -> dict:
    line = line.strip()
    if m := NGINX_ACCESS.match(line):
        ts = parse_ts(m["ts"])
        ev = base_event(ts, host_hint, "nginx", line)
        status = int(m["status"])
        ev.update(category="web", action="http_request", src_ip=valid_ip(m["ip"]))
        ev["outcome"] = "failure" if status >= 400 else "success"
        ev["severity"] = "low" if status in (401, 403) else "informational"
        if m["user"] not in ("-", ""):
            ev["user"] = m["user"]
        ev["message"] = f"{m['method']} {m['path'][:200]} {status}"
        ev["fields"] = {
            "http_method": m["method"],
            "path": m["path"][:512],
            "status": status,
            "user_agent": (m["ua"] or "")[:256],
        }
        return ev
    if m := NGINX_ERROR.match(line):
        ts = parse_ts(m["ts"])
        ev = base_event(ts, host_hint, "nginx", line)
        ev.update(category="web", action="http_error", outcome="failure", src_ip=valid_ip(m["ip"]))
        ev["severity"] = "low" if m["level"] in ("error", "crit", "alert", "emerg") else "informational"
        ev["message"] = m["msg"][:512]
        ev["fields"] = {"level": m["level"]}
        return ev
    raise ParseError("unrecognised nginx line")


# ---------------------------------------------------------------- Generic JSON / Docker
def parse_generic(rec: dict, host_hint: str, raw: str, source_type: str = "json") -> dict:
    ts = parse_ts(rec.get("@timestamp") or rec.get("timestamp") or rec.get("time") or rec.get("ts"))
    host = str(rec.get("host") or rec.get("hostname") or host_hint)
    ev = base_event(ts, host, source_type, raw)
    for k in (
        "category",
        "action",
        "outcome",
        "user",
        "process_name",
        "command_line",
        "file_hash",
        "domain",
        "message",
    ):
        if rec.get(k) is not None:
            ev[k] = str(rec[k])[:2048]
    sev = str(rec.get("severity", "informational")).lower()
    ev["severity"] = sev if sev in SEVERITY_ORDER else "informational"
    for k in ("src_ip", "dst_ip"):
        ev[k] = valid_ip(rec.get(k))
    for k in ("src_port", "dst_port"):
        ev[k] = _int(rec.get(k))
    if isinstance(rec.get("fields"), dict):
        ev["fields"] = {str(k)[:64]: v for k, v in list(rec["fields"].items())[:50]}
    ev["synthetic"] = bool(rec.get("synthetic", False))
    return ev


def parse_docker(rec: dict, host_hint: str, raw: str) -> dict:
    text = str(rec.get("log") or rec.get("message") or "").rstrip("\n")
    ts = parse_ts(rec.get("time") or rec.get("@timestamp") or rec.get("date"))
    ev = base_event(ts, host_hint, "docker", raw)
    ev["message"] = text[:1024]
    ev["category"] = "container"
    ev["action"] = "container_log"
    ev["fields"] = {
        "container": str(rec.get("container_name") or rec.get("container_id") or "")[:128],
        "stream": rec.get("stream", ""),
    }
    if re.search(r"\b(error|fatal|panic|exception)\b", text, re.I):
        ev["severity"] = "low"
    return ev


# ---------------------------------------------------------------- Dispatcher
def detect_type(rec: dict | str, hint: str | None) -> str:
    if hint and hint not in ("auto", ""):
        return hint
    if isinstance(rec, dict):
        if "EventID" in rec or "EventId" in rec:
            return "windows"
        if "log" in rec and ("container_name" in rec or "container_id" in rec or "stream" in rec):
            return "docker"
        return "json"
    if NGINX_ACCESS.match(rec) or NGINX_ERROR.match(rec):
        return "nginx"
    return "linux"


def normalize(rec: dict | str, host_hint: str = "unknown", source_hint: str | None = None) -> dict:
    """Normalise one record. Raises ParseError with a diagnostic on failure."""
    raw = rec if isinstance(rec, str) else json.dumps(rec, default=str, sort_keys=True)
    if isinstance(rec, dict) and not source_hint and isinstance(rec.get("source_type"), str):
        source_hint = rec["source_type"]
    st = detect_type(rec, source_hint)
    try:
        if st == "windows":
            if not isinstance(rec, dict):
                rec = json.loads(rec)
            return parse_windows(rec, host_hint, raw)
        if st == "docker":
            if isinstance(rec, str):
                rec = json.loads(rec)
            return parse_docker(rec, host_hint, raw)
        if st == "nginx":
            line = rec if isinstance(rec, str) else str(rec.get("log") or rec.get("message") or "")
            return parse_nginx(line, host_hint)
        if st == "linux":
            line = rec if isinstance(rec, str) else str(rec.get("log") or rec.get("message") or "")
            if not line.strip():
                raise ParseError("empty log line")
            ts_hint = parse_ts(rec.get("date")) if isinstance(rec, dict) and rec.get("date") else None
            return parse_syslog(line, host_hint, ts_hint)
        if st in ("json", "synthetic"):
            if isinstance(rec, str):
                rec = json.loads(rec)
            return parse_generic(rec, host_hint, raw, "json")
    except ParseError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as e:
        raise ParseError(f"{type(e).__name__}: {e}"[:200]) from e
    raise ParseError(f"unsupported source_type {st!r}")
