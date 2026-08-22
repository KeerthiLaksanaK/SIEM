# SIEM Mini Platform

## Security Information and Event Management Prototype

This project is a lightweight SIEM web application developed for an **authorized local academic laboratory**. It collects application, authentication and authorized Nmap events, normalizes them, applies rule-based detections, generates alerts, and provides a web interface for monitoring and investigation.

## Main Features

- User authentication with **Admin** and **Analyst** roles
- Centralized event collection and normalization
- SQLite-based event, alert and audit storage
- Rule-based security detection
- Alert severity and lifecycle management
- Investigation notes
- Dashboard with event and alert summaries
- Authorized localhost Nmap port-scan lab
- Controlled HTTP traffic-generation lab
- Audit logging for supported actions
- Analyst access to Dashboard, Alerts and Logs
- Admin access to Audit Logs

## Detection Rules

| Detection | Condition | Severity |
|---|---|---|
| Brute Force Attack | 5 or more failed logins from the same source IP within 2 minutes | HIGH |
| Port Scan Detected | 6 or more distinct authorized Nmap ports in one scan correlation within 2 minutes | MEDIUM |
| Excessive HTTP Requests | 20 or more `/lab/status` HTTP requests from the same source IP within 1 minute | HIGH |

The Nmap detector is restricted to the authorized local lab source and localhost testing.

## Technology Stack

- Python
- Flask
- SQLite
- Werkzeug password hashing
- Requests
- Nmap
- HTML / CSS / JavaScript

## Project Structure

```text
SIEM-Mini-Platform-Finalv3/
├── app.py
├── app_base.py
├── requirements.txt
├── README.md
├── siem.db
├── lab/
│   ├── collect_nmap.py
│   ├── generate_http_traffic.py
│   ├── open_test_ports.py
│   └── run_port_scan_test.py
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── alerts.html
│   ├── alert_detail.html
│   ├── logs.html
│   └── audit.html
└── static/
    └── style.css
```

`app.py` is the application entry point used for the demonstration.

## Requirements

- Python 3.x
- Packages listed in `requirements.txt`
- Nmap installed and available in PATH
- Windows PowerShell or another terminal

## Setup

Open PowerShell in the project directory.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Start the SIEM:

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000/login
```

If the demo credentials in `app.py` have not been changed, the supplied application defines:

```text
Admin:
Username: admin
Password: Admin@123

Analyst:
Username: analyst
Password: Analyst@123
```

For a submitted/production package, change default credentials before deployment.

## Authorized Security Labs

### 1. Automated Nmap Port-Scan Test

Keep Flask running and execute:

```powershell
python lab\run_port_scan_test.py
```

The lab opens temporary TCP listeners on `127.0.0.1`, performs the authorized local scan, and sends detected open-port events to the SIEM.

The current predefined scenarios use local test ports. The detection logic is based on the number of distinct ports and scan correlation rather than a particular service port.

### 2. Controlled HTTP Traffic Test

Run:

```powershell
python lab\generate_http_traffic.py
```

The generator sends controlled requests to:

```text
http://127.0.0.1:5000/lab/status
```

A qualifying burst produces an **Excessive HTTP Requests** alert.

## Demonstration Flow

1. Start the Flask application.
2. Log in as Admin and show the dashboard.
3. Show normalized events and current alerts.
4. Demonstrate five failed logins to trigger Brute Force detection.
5. Run the authorized Nmap test.
6. Show the Port Scan alert and its evidence.
7. Run the controlled HTTP traffic test.
8. Open Logs and show `/lab/status` events.
9. Open the corresponding alert and demonstrate investigation/status management.
10. Move an alert to `Investigating`, `Resolved` or `False Positive` as appropriate.
11. Show that `Resolved` and `False Positive` are terminal states.
12. Log in as Analyst and demonstrate Dashboard, Alerts and Logs access.
13. Confirm that Audit Logs is not available in the Analyst navigation.
14. Log in as Admin and show Audit Logs when demonstrating the audit trail.

## Alert Lifecycle

```text
New
  ├── Investigating
  ├── Resolved
  └── False Positive

Investigating
  ├── Resolved
  └── False Positive
```

`Resolved` and `False Positive` are terminal states and cannot be moved back to another state.

## Evidence Included in the Final Report

The updated report includes:

- Dashboard evidence
- Security Alerts evidence
- All Events / normalized logs evidence
- Analyst-role access evidence
- Brute Force alert evidence
- Port Scan alert evidence
- Excessive HTTP Requests alert evidence
- Alert investigation evidence
- Resolved terminal-state evidence
- False Positive terminal-state evidence
- Automated HTTP lab terminal output
- Automated Nmap lab terminal output
- Audit-log evidence
- Database/test summary and project architecture

## Current Review Statistics

At the reviewed database state documented in the final report:

- Total normalized events: **321**
- Total alerts: **12**
- Brute Force alerts: **2**
- Port Scan alerts: **6**
- Excessive HTTP alerts: **4**
- New alerts: **9**
- Resolved alerts: **2**
- False Positive alerts: **1**
- Audit records: **44**

These are review-time values from the supplied project database and screenshots; they can change when new tests are executed.

## Security / Scope Note

This project is an academic SIEM prototype. The security labs are intended only for the authorized localhost environment.

Do not use the Nmap or traffic-generation scripts against systems you do not own or do not have explicit authorization to test.

The project is not intended to represent a production enterprise SIEM. Known limitations include rule/threshold-based detection, SQLite storage, localhost-only Nmap ingestion, and the absence of enterprise-scale telemetry and cloud connectors.

## Documentation

The complete documentation is provided in:

```text
SIEM_Mini_Platform_Updated_Final_Report.docx
```

The report combines the original implementation review with the latest Analyst-role and alert-lifecycle evidence.
