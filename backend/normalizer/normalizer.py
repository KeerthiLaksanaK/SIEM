"""
normalizer.py - Converts raw log lines into a common normalized event schema.

WHY normalization matters:
  Different systems produce logs in completely different formats.
  A SIEM must translate all of them into one unified structure so that
  detection rules can work across all sources without knowing the original format.

Each parser function handles one log source format.
If a line cannot be parsed, it is returned as a low-severity 'parse_error' event
rather than crashing the pipeline.
"""

import re
from datetime import datetime
from typing import Optional


def _base_event(source: str, raw_log: str) -> dict:
    """Returns a skeleton event dict with all fields set to None/defaults."""
    return {
        "timestamp": None,
        "source": source,
        "event_type": "unknown",
        "username": None,
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "http_method": None,
        "endpoint": None,
        "status_code": None,
        "status": None,
        "severity": "low",
        "raw_log": raw_log,
    }


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.utcnow()


# ── Authentication log parser ──────────────────────────────────────────────────
# Format: 2026-08-24 10:01:15 LOGIN_FAILED user=admin ip=192.168.1.50
AUTH_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>LOGIN_SUCCESS|LOGIN_FAILED|LOGOUT)\s+"
    r"user=(?P<user>\S+)\s+ip=(?P<ip>\S+)"
)


def parse_auth_log(raw: str) -> dict:
    event = _base_event("authentication", raw)
    m = AUTH_PATTERN.match(raw)
    if not m:
        event["event_type"] = "parse_error"
        return event

    action = m.group("action")
    event["timestamp"] = _parse_timestamp(m.group("ts"))
    event["username"] = m.group("user")
    event["source_ip"] = m.group("ip")

    if action == "LOGIN_SUCCESS":
        event["event_type"] = "login_success"
        event["status"] = "success"
        event["severity"] = "low"
    elif action == "LOGIN_FAILED":
        event["event_type"] = "login_failed"
        event["status"] = "failure"
        event["severity"] = "medium"
    elif action == "LOGOUT":
        event["event_type"] = "logout"
        event["status"] = "success"
        event["severity"] = "low"

    return event


# ── Web log parser ─────────────────────────────────────────────────────────────
# Format: 2026-08-24 10:05:30 POST /login 401 192.168.1.50
WEB_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"(?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+"
    r"(?P<endpoint>\S+)\s+"
    r"(?P<code>\d{3})\s+"
    r"(?P<ip>\S+)"
)


def parse_web_log(raw: str) -> dict:
    event = _base_event("web", raw)
    m = WEB_PATTERN.match(raw)
    if not m:
        event["event_type"] = "parse_error"
        return event

    code = int(m.group("code"))
    endpoint = m.group("endpoint")
    event["timestamp"] = _parse_timestamp(m.group("ts"))
    event["http_method"] = m.group("method")
    event["endpoint"] = endpoint
    event["status_code"] = code
    event["source_ip"] = m.group("ip")
    event["event_type"] = "http_request"

    # Assign severity based on HTTP status code - standard SOC practice
    if code < 400:
        event["status"] = "success"
        event["severity"] = "low"
    elif code == 401:
        event["status"] = "unauthorized"
        event["severity"] = "medium"
    elif code == 403:
        event["status"] = "forbidden"
        event["severity"] = "high"
        # Accessing /admin and getting 403 is a specific high-interest event
        if "/admin" in endpoint:
            event["event_type"] = "admin_access_denied"
    else:
        event["status"] = "error"
        event["severity"] = "low"

    return event


# ── Network log parser ─────────────────────────────────────────────────────────
# Format: 2026-08-24 10:10:01 CONNECTION src=192.168.1.50 dst=192.168.1.10 port=21
NET_PATTERN = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"CONNECTION\s+"
    r"src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+port=(?P<port>\d+)"
)


def parse_network_log(raw: str) -> dict:
    event = _base_event("network", raw)
    m = NET_PATTERN.match(raw)
    if not m:
        event["event_type"] = "parse_error"
        return event

    port = int(m.group("port"))
    event["timestamp"] = _parse_timestamp(m.group("ts"))
    event["source_ip"] = m.group("src")
    event["destination_ip"] = m.group("dst")
    event["destination_port"] = port
    event["event_type"] = "network_connection"
    event["status"] = "connection"

    # Flag connections to sensitive/well-known ports
    sensitive_ports = {21, 22, 23, 25, 3389, 445, 139}
    event["severity"] = "medium" if port in sensitive_ports else "low"

    return event


# ── Dispatcher ─────────────────────────────────────────────────────────────────
PARSERS = {
    "authentication": parse_auth_log,
    "web": parse_web_log,
    "network": parse_network_log,
}


def normalize(source: str, raw_line: str) -> dict:
    """
    Entry point: given a source name and raw log line, return a normalized event dict.
    Falls back to a parse_error event if the source is unknown or parsing fails.
    """
    parser = PARSERS.get(source)
    if parser is None:
        event = _base_event(source, raw_line)
        event["event_type"] = "parse_error"
        return event
    try:
        return parser(raw_line)
    except Exception as exc:
        # Never let a single bad log line crash the entire pipeline
        event = _base_event(source, raw_line)
        event["event_type"] = "parse_error"
        event["status"] = str(exc)
        return event
