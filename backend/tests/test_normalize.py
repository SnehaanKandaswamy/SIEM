import pytest

from app.ingest.normalize import ParseError, normalize, parse_ts


def test_ssh_failure():
    e = normalize(
        "Oct 22 10:00:01 web-01 sshd[12]: Failed password for invalid user bob from 203.0.113.9 port 4242 ssh2"
    )
    assert (e["category"], e["outcome"], e["user"], e["src_ip"], e["src_port"]) == (
        "authentication",
        "failure",
        "bob",
        "203.0.113.9",
        4242,
    )
    assert e["host"] == "web-01" and e["@timestamp"].endswith("+00:00")


def test_ssh_success_and_sudo():
    ok = normalize("2026-01-02T03:04:05+00:00 h1 sshd[1]: Accepted publickey for ana from 10.0.0.1 port 22 ssh2")
    assert ok["outcome"] == "success"
    s = normalize(
        "2026-01-02T03:04:05+00:00 h1 sudo[7]: ana : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    assert s["command_line"] == "/bin/cat /etc/shadow" and s["category"] == "process"


def test_windows_4625():
    e = normalize(
        {
            "EventID": 4625,
            "Channel": "Security",
            "Computer": "DC1",
            "TimeCreated": "2026-01-02T03:04:05Z",
            "EventData": {"TargetUserName": "jdoe", "IpAddress": "10.1.1.1", "LogonType": 3},
        }
    )
    assert e["source_type"] == "windows" and e["outcome"] == "failure" and e["user"] == "jdoe"
    assert e["fields"]["logon_type"] == "3"


def test_windows_missing_commandline_is_none():
    e = normalize({"EventID": 4688, "EventData": {"NewProcessName": "C:/x.exe"}})
    assert e["command_line"] is None  # no command-line auditing -> never invented


def test_sysmon_hash():
    e = normalize(
        {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventData": {"Image": "a.exe", "Hashes": "MD5=" + "a" * 32 + ",SHA256=" + "b" * 64},
        }
    )
    assert e["file_hash"] == "b" * 64 and e["category"] == "process"


def test_nginx_access_and_error():
    a = normalize('1.2.3.4 - - [22/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "curl/8"')
    assert a["source_type"] == "nginx" and a["fields"]["status"] == 401 and a["outcome"] == "failure"
    e = normalize("2026/10/22 10:00:00 [error] 29#29: *1 open() failed, client: 5.6.7.8, server: x")
    assert e["action"] == "http_error" and e["src_ip"] == "5.6.7.8"


def test_firewall_line():
    e = normalize("2026-01-02T03:04:05+00:00 fw kernel: IN=eth0 SRC=1.1.1.1 DST=10.0.0.5 PROTO=TCP SPT=1 DPT=22")
    assert e["category"] == "network" and e["dst_port"] == 22


def test_docker_and_json():
    d = normalize({"log": "panic: boom\n", "container_name": "api", "stream": "stderr", "date": 1767323045})
    assert d["source_type"] == "docker" and d["severity"] == "low"
    j = normalize({"timestamp": "2026-01-02T03:04:05+02:00", "host": "h", "severity": "HIGH", "src_ip": "bad"})
    assert j["@timestamp"] == "2026-01-02T01:04:05+00:00" and j["src_ip"] is None and j["severity"] == "high"


def test_errors_are_explicit():
    for bad in ({"EventID": "x"}, {"timestamp": "not a date", "host": "h"}, ""):
        with pytest.raises(ParseError):
            normalize(bad, source_hint="windows" if isinstance(bad, dict) and "EventID" in bad else None)


def test_ts_variants():
    assert parse_ts(1_700_000_000_000).year == 2023
    assert parse_ts("1700000000").tzinfo is not None


def test_event_id_deterministic():
    line = "2026-01-02T03:04:05+00:00 h sshd[1]: Failed password for a from 1.1.1.1 port 1 ssh2"
    assert normalize(line)["event_id"] == normalize(line)["event_id"]


def test_windows_string_inserts_layout():
    inserts = [
        "S-1",
        "-",
        "WORKGROUP",
        "0x0",
        "S-1-0",
        "mallory",
        "DOM",
        "0xc000006d",
        "%%2313",
        "0xc000006a",
        "3",
        "NtLmSsp",
        "NTLM",
        "WS1",
        "-",
        "-",
        "0",
        "0x0",
        "-",
        "203.0.113.5",
        "5555",
    ]
    e = normalize(
        {
            "EventId": 4625,
            "Channel": "Security",
            "ComputerName": "WS1",
            "TimeGenerated": 1767323045,
            "StringInserts": inserts,
        }
    )
    assert (e["user"], e["src_ip"], e["host"], e["outcome"]) == ("mallory", "203.0.113.5", "WS1", "failure")
    p = normalize(
        {
            "EventId": 4688,
            "Channel": "Security",
            "StringInserts": ["s", "bob", "d", "0x1", "0x2", "C:/a.exe", "%%1936", "0x3", "a.exe -x"],
        }
    )
    assert p["command_line"] == "a.exe -x" and p["user"] == "bob"
