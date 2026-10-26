"""Deterministic synthetic event generator (safe: only produces log records, executes nothing).

CLI:  python -m app.demo --url http://localhost:8000 --key <ingest key> [--scenario all]
All records carry synthetic=true so the UI labels them. Addresses use RFC 5737 documentation ranges.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat()


def _ssh(t: datetime, host: str, ok: bool, user: str, ip: str, pid: int) -> dict:
    verb = "Accepted password" if ok else "Failed password"
    return {
        "source_type": "linux",
        "synthetic": True,
        "log": f"{_iso(t)} {host} sshd[{pid}]: {verb} for {user} from {ip} port {40000 + pid % 1000} ssh2",
    }


def _win(t: datetime, host: str, code: int, **data) -> dict:
    return {
        "source_type": "windows",
        "synthetic": True,
        "EventID": code,
        "Channel": "Security",
        "Computer": host,
        "TimeCreated": _iso(t),
        "EventData": data,
    }


def _fw(t: datetime, host: str, src: str, dst: str, port: int) -> dict:
    return {
        "source_type": "linux",
        "synthetic": True,
        "log": f"{_iso(t)} {host} kernel: IN=eth0 SRC={src} DST={dst} LEN=60 PROTO=TCP SPT=51515 DPT={port}",
    }


def scenarios(now: datetime | None = None) -> dict[str, list[dict]]:
    now = (now or datetime.now(UTC)).replace(microsecond=0)
    t0 = now - timedelta(minutes=6)
    out: dict[str, list[dict]] = {}
    out["normal_activity"] = [
        _ssh(t0 + timedelta(seconds=20 * i), "web-01", True, "deploy", "10.0.0.12", 100 + i) for i in range(3)
    ] + [
        _win(
            t0 + timedelta(seconds=30 * i),
            "WIN-DC01",
            4624,
            TargetUserName="alice",
            IpAddress="10.0.0.31",
            LogonType="3",
        )
        for i in range(3)
    ]
    out["bruteforce_ssh"] = [  # R1 positive: 8 failures from one IP in 35s (no single account reaches R2's threshold)
        _ssh(t0 + timedelta(seconds=5 * i), "web-01", False, "root" if i % 2 else "admin", "198.51.100.23", 200 + i)
        for i in range(8)
    ]
    out["failed_logins_windows"] = [  # R2 positive: 6 failures for one account over 150s
        _win(
            t0 + timedelta(seconds=30 * i),
            "WIN-DC01",
            4625,
            TargetUserName="jdoe",
            IpAddress="10.0.0.45",
            LogonType="3",
        )
        for i in range(6)
    ]
    out["port_scan"] = [
        _fw(t0 + timedelta(seconds=i * 0.5), "fw-01", "198.51.100.77", "10.0.0.5", 20 + i) for i in range(24)
    ]
    out["suspicious_command"] = [
        _win(
            t0,
            "WIN-WS07",
            4688,
            SubjectUserName="bob",
            NewProcessName=r"C:\Windows\System32\powershell.exe",
            CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
        ),
    ]
    out["malware_indicator"] = [
        _win(
            t0,
            "WIN-WS07",
            1,
            SubjectUserName="bob",
            Image=r"C:\Users\bob\Downloads\eicar.com",
            Hashes=f"SHA256={EICAR_SHA256}",
        )
        | {"Channel": "Microsoft-Windows-Sysmon/Operational"},
        {
            "source_type": "json",
            "synthetic": True,
            "host": "WIN-WS07",
            "timestamp": _iso(t0 + timedelta(seconds=3)),
            "category": "network",
            "action": "dns_query",
            "domain": "malware-test.example.invalid",
            "message": "DNS query for test indicator domain",
        },
    ]
    out["negative_cases"] = [  # none of these may alert
        *[_ssh(t0 + timedelta(seconds=10 * i), "web-02", False, "carol", "10.0.0.88", 300 + i) for i in range(3)],
        *[_fw(t0 + timedelta(seconds=i), "fw-01", "10.0.0.9", "10.0.0.5", 443) for i in range(30)],
        _win(
            t0,
            "WIN-WS09",
            4688,
            SubjectUserName="dave",
            NewProcessName=r"C:\Windows\notepad.exe",
            CommandLine=r"notepad.exe C:\notes\todo.txt",
        ),
        _win(t0, "WIN-WS09", 1, Image=r"C:\tools\app.exe", Hashes="SHA256=" + "ab" * 32)
        | {"Channel": "Microsoft-Windows-Sysmon/Operational"},
    ]
    return out


def flat(now: datetime | None = None, only: str = "all") -> list[dict]:
    sc = scenarios(now)
    if only != "all":
        if only not in sc:
            raise SystemExit(f"unknown scenario {only!r}; choose from: all, {', '.join(sc)}")
        return sc[only]
    return [r for recs in sc.values() for r in recs]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--key", required=True, help="ingest API key (SIEM_INGEST_API_KEYS)")
    ap.add_argument("--scenario", default="all")
    ap.add_argument("--print", action="store_true", help="print records instead of sending")
    a = ap.parse_args(argv)
    recs = flat(only=a.scenario)
    if a.print:
        print(json.dumps(recs, indent=2))
        return 0
    import httpx

    r = httpx.post(
        f"{a.url.rstrip('/')}/api/ingest",
        headers={"X-Ingest-Key": a.key, "X-Collector": "synthetic-generator"},
        json={"source_type": "auto", "host": "synthetic", "synthetic": True, "records": recs},
        timeout=30,
    )
    print(r.status_code, r.text)
    return 0 if r.is_success else 1


if __name__ == "__main__":
    sys.exit(main())
