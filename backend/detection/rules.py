"""
rules.py - Detection rule definitions.

Each rule is a pure function that receives a list of normalized Event ORM objects
and returns a list of alert dictionaries (or empty list if no alert triggered).

WHY separate rules from the engine:
  In real SIEMs (Splunk, QRadar, Elastic SIEM), rules are stored separately
  from the execution engine so analysts can add/modify rules without touching
  core infrastructure. We mirror that pattern here.
"""

from datetime import timedelta
from collections import defaultdict
from typing import List


# ── RULE AUTH-001: Brute Force Attack ─────────────────────────────────────────
def rule_brute_force(events: List) -> List[dict]:
    """
    Detects brute force: 5+ failed logins from the same IP within 5 minutes.
    This is the most common authentication attack pattern.
    """
    THRESHOLD = 5
    WINDOW_MINUTES = 5
    alerts = []

    failures_by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "login_failed" and e.source_ip:
            failures_by_ip[e.source_ip].append(e.timestamp)

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            window = [
                t for t in timestamps[i:]
                if t <= timestamps[i] + timedelta(minutes=WINDOW_MINUTES)
            ]
            if len(window) >= THRESHOLD:
                alerts.append({
                    "alert_type": "BRUTE_FORCE_ATTACK",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "description": (
                        f"{len(window)} failed login attempts detected from {ip} "
                        f"within {WINDOW_MINUTES} minutes. Possible brute force attack."
                    ),
                    "event_count": len(window),
                    "first_seen": timestamps[i],
                    "last_seen": window[-1],
                    "rule_id": "AUTH-001",
                })
                break  # One alert per IP per rule run

    return alerts


# ── RULE NET-001: Port Scan ────────────────────────────────────────────────────
def rule_port_scan(events: List) -> List[dict]:
    """
    Detects port scanning: same source IP connecting to 5+ unique ports within 2 minutes.
    Port scanning is a reconnaissance technique used before an attack.
    """
    THRESHOLD = 5
    WINDOW_MINUTES = 2
    alerts = []

    connections_by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "network_connection" and e.source_ip and e.destination_port:
            connections_by_ip[e.source_ip].append((e.timestamp, e.destination_port))

    for ip, conn_list in connections_by_ip.items():
        conn_list.sort(key=lambda x: x[0])
        for i in range(len(conn_list)):
            window = [
                (t, p) for t, p in conn_list[i:]
                if t <= conn_list[i][0] + timedelta(minutes=WINDOW_MINUTES)
            ]
            unique_ports = set(p for _, p in window)
            if len(unique_ports) >= THRESHOLD:
                timestamps = [t for t, _ in window]
                alerts.append({
                    "alert_type": "PORT_SCAN_DETECTED",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "description": (
                        f"Port scan detected from {ip}: {len(unique_ports)} unique ports "
                        f"({sorted(unique_ports)}) probed within {WINDOW_MINUTES} minutes."
                    ),
                    "event_count": len(window),
                    "first_seen": min(timestamps),
                    "last_seen": max(timestamps),
                    "rule_id": "NET-001",
                })
                break

    return alerts


# ── RULE WEB-001: Repeated HTTP 401 ───────────────────────────────────────────
def rule_repeated_401(events: List) -> List[dict]:
    """
    Detects repeated HTTP 401 (Unauthorized) responses from the same IP.
    Multiple 401s suggest credential stuffing or web application brute force.
    """
    THRESHOLD = 3
    alerts = []

    failures_by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "http_request" and e.status_code == 401 and e.source_ip:
            failures_by_ip[e.source_ip].append(e.timestamp)

    for ip, timestamps in failures_by_ip.items():
        if len(timestamps) >= THRESHOLD:
            alerts.append({
                "alert_type": "REPEATED_AUTH_FAILURE",
                "severity": "MEDIUM",
                "source_ip": ip,
                "description": (
                    f"{len(timestamps)} HTTP 401 Unauthorized responses from {ip}. "
                    f"Possible web application credential attack."
                ),
                "event_count": len(timestamps),
                "first_seen": min(timestamps),
                "last_seen": max(timestamps),
                "rule_id": "WEB-001",
            })

    return alerts


# ── RULE WEB-002: Unauthorized Admin Access ───────────────────────────────────
def rule_admin_access(events: List) -> List[dict]:
    """
    Detects attempts to access /admin that result in HTTP 403 (Forbidden).
    Unauthorized admin access attempts indicate privilege escalation attempts.
    """
    alerts = []

    by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "admin_access_denied" and e.source_ip:
            by_ip[e.source_ip].append(e.timestamp)

    for ip, timestamps in by_ip.items():
        alerts.append({
            "alert_type": "UNAUTHORIZED_ADMIN_ACCESS",
            "severity": "HIGH",
            "source_ip": ip,
            "description": (
                f"Unauthorized access attempt to /admin from {ip} "
                f"({len(timestamps)} attempt(s)). HTTP 403 Forbidden returned."
            ),
            "event_count": len(timestamps),
            "first_seen": min(timestamps),
            "last_seen": max(timestamps),
            "rule_id": "WEB-002",
        })

    return alerts


# ── RULE AUTH-002: Possible Account Compromise (Correlation Rule) ─────────────
def rule_account_compromise(events: List) -> List[dict]:
    """
    Correlation rule: 5+ failed logins followed by a successful login from the same IP.
    This pattern strongly suggests a successful brute force - the attacker eventually
    guessed the correct password. This is more dangerous than failed attempts alone.

    WHY correlation matters:
      Simple rules look at single events. Correlation rules look at sequences of events
      across time. This is what separates a SIEM from a simple log monitor.
    """
    FAIL_THRESHOLD = 5
    WINDOW_HOURS = 1
    alerts = []

    failures_by_ip = defaultdict(list)
    successes_by_ip = defaultdict(list)

    for e in events:
        if e.source == "authentication":
            if e.event_type == "login_failed" and e.source_ip:
                failures_by_ip[e.source_ip].append(e.timestamp)
            elif e.event_type == "login_success" and e.source_ip:
                successes_by_ip[e.source_ip].append(e.timestamp)

    for ip, fail_times in failures_by_ip.items():
        if len(fail_times) < FAIL_THRESHOLD:
            continue
        success_times = successes_by_ip.get(ip, [])
        if not success_times:
            continue

        fail_times.sort()
        for success_time in success_times:
            prior_failures = [t for t in fail_times if t < success_time]
            if len(prior_failures) >= FAIL_THRESHOLD:
                window_start = success_time - timedelta(hours=WINDOW_HOURS)
                recent_failures = [t for t in prior_failures if t >= window_start]
                if len(recent_failures) >= FAIL_THRESHOLD:
                    alerts.append({
                        "alert_type": "POSSIBLE_ACCOUNT_COMPROMISE",
                        "severity": "CRITICAL",
                        "source_ip": ip,
                        "description": (
                            f"CRITICAL: {len(recent_failures)} failed login attempts from {ip} "
                            f"followed by a successful login at {success_time.strftime('%H:%M:%S')}. "
                            f"Account may be compromised."
                        ),
                        "event_count": len(recent_failures) + 1,
                        "first_seen": min(recent_failures),
                        "last_seen": success_time,
                        "rule_id": "AUTH-002",
                    })
                    break

    return alerts


# Registry of all rules - add new rules here to include them in detection
ALL_RULES = [
    rule_brute_force,
    rule_port_scan,
    rule_repeated_401,
    rule_admin_access,
    rule_account_compromise,
]
