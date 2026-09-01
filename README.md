# SIEM Mini Platform
### Security Information and Event Management — Academic Cybersecurity Project

---

## 1. Problem Statement

Organizations generate thousands of security log entries every day from different systems — web servers, authentication systems, firewalls, and network devices. Without a centralized platform, security analysts cannot detect attack patterns that span multiple systems. This project implements a miniature SIEM that collects, normalizes, correlates, and alerts on security events from multiple log sources.

---

## 2. Objectives

- Collect raw logs from multiple heterogeneous sources
- Normalize different log formats into a common event schema
- Store normalized events in a centralized database
- Apply rule-based detection to identify attack patterns
- Generate and deduplicate security alerts
- Provide a SOC-style dashboard for investigation

---

## 3. Features

| Feature | Description |
|---|---|
| Log Collection | Reads auth, web, and network logs |
| Normalization | Converts 3 different formats into one schema |
| Detection Engine | 5 detection rules including a correlation rule |
| Alert Deduplication | Prevents duplicate alerts on repeated runs |
| SOC Dashboard | Dark-theme professional security dashboard |
| Alert Workflow | OPEN → INVESTIGATING → RESOLVED / FALSE_POSITIVE |
| Raw Log Viewer | View original log line for any event |
| Charts | Severity, source, alert type, and timeline charts |
| REST API | Full FastAPI backend with documented endpoints |
| Reset | One-click database reset for demonstrations |

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SAMPLE LOG SOURCES                    │
│         auth.log    web.log    network.log               │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                   LOG COLLECTOR                          │
│         collector/log_collector.py                       │
│   Reads raw lines, yields (source, raw_line) tuples     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  LOG NORMALIZER                          │
│         normalizer/normalizer.py                         │
│   Parses each format → common event dictionary          │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                 SQLITE DATABASE                          │
│         data/siem.db  (SQLAlchemy ORM)                  │
│         Tables: events, alerts                          │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│               DETECTION ENGINE                           │
│         detection/detection_engine.py                    │
│         detection/rules.py                              │
│   Applies 5 rules to all stored events                  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                ALERT MANAGER                             │
│         alerts/alert_manager.py                          │
│   Creates alerts, deduplicates, manages status          │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  REST API                                │
│         backend/main.py  (FastAPI)                      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│               SIEM DASHBOARD                             │
│         frontend/index.html + dashboard.js              │
│   Charts, alert tables, event tables, investigation     │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Technologies

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI |
| ORM | SQLAlchemy |
| Database | SQLite |
| Validation | Pydantic v2 |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4 |
| Server | Uvicorn |

---

## 6. Folder Structure

```
SIEM/
├── backend/
│   ├── main.py                  # FastAPI app, all API endpoints
│   ├── database.py              # SQLAlchemy engine and session
│   ├── models.py                # Event and Alert ORM models
│   ├── schemas.py               # Pydantic request/response schemas
│   ├── requirements.txt
│   ├── collector/
│   │   └── log_collector.py     # Reads raw log files
│   ├── normalizer/
│   │   └── normalizer.py        # Parses logs into common schema
│   ├── detection/
│   │   ├── rules.py             # 5 detection rules
│   │   └── detection_engine.py  # Executes rules, calls alert manager
│   ├── alerts/
│   │   └── alert_manager.py     # Creates/deduplicates/updates alerts
│   └── sample_logs/
│       ├── auth.log
│       ├── web.log
│       └── network.log
├── frontend/
│   ├── index.html               # Dashboard HTML
│   ├── style.css                # SOC dark theme
│   └── dashboard.js             # All frontend logic
├── data/
│   └── siem.db                  # Created automatically on first run
└── README.md
```

---

## 7. Installation

```bash
# 1. Navigate to project folder
cd c:\Users\dell\Desktop\SIEM

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment (Windows)
venv\Scripts\activate

# 4. Install dependencies
cd backend
pip install -r requirements.txt
```

---

## 8. How to Run

```bash
# From the backend/ directory with venv activated:
python -m uvicorn main:app --reload
```

Open browser: **http://127.0.0.1:8000**

---

## 9. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/health | System health check |
| GET | /api/events | List all events (with filters) |
| GET | /api/events/{id} | Get single event |
| GET | /api/alerts | List all alerts (with filters) |
| GET | /api/alerts/{id} | Get single alert |
| GET | /api/alerts/{id}/events | Get events related to an alert |
| GET | /api/stats | Dashboard statistics |
| POST | /api/collect | Collect and normalize logs |
| POST | /api/detect | Run detection rules |
| PATCH | /api/alerts/{id}/status | Update alert status |
| POST | /api/reset | Clear all data |
| POST | /api/seed | Collect + detect in one call |

---

## 10. Detection Rules

| Rule ID | Name | Condition | Severity |
|---|---|---|---|
| AUTH-001 | Brute Force Attack | 5+ failed logins from same IP in 5 min | HIGH |
| NET-001 | Port Scan Detected | 5+ unique ports from same IP in 2 min | HIGH |
| WEB-001 | Repeated Auth Failure | 3+ HTTP 401 from same IP | MEDIUM |
| WEB-002 | Unauthorized Admin Access | HTTP 403 on /admin endpoint | HIGH |
| AUTH-002 | Possible Account Compromise | 5+ failures then success from same IP | CRITICAL |

---

## 11. Database Schema

**events table**
```
id, timestamp, source, event_type, username, source_ip,
destination_ip, destination_port, http_method, endpoint,
status_code, status, severity, raw_log, created_at
```

**alerts table**
```
id, alert_type, severity, source_ip, description,
event_count, first_seen, last_seen, status, rule_id, created_at
```

---

## 12. Demo Procedure

1. Start the application: `python -m uvicorn main:app --reload`
2. Open http://127.0.0.1:8000 — dashboard shows 0 events, 0 alerts
3. Click **Collect Logs** — events appear in the Events table
4. Click **Run Detection** — alerts appear in the Alerts table
5. Click **View** on the Brute Force alert — see source IP and related events
6. Click **Raw Log** on any event — see the original log line
7. Change status to **INVESTIGATING** — dashboard updates
8. Change status to **RESOLVED** — alert moves out of open count
9. Click **Reset Database** to start over

---

## 13. Limitations

- Sample logs are static files (not real-time streaming)
- No user authentication on the dashboard
- Detection runs on full event history (not sliding time windows in production sense)
- Single-user, single-machine deployment only

---

## 14. Future Enhancements

- Real-time log ingestion via WebSockets
- Machine learning anomaly detection
- Email/SMS alert notifications
- Multi-user authentication with role-based access
- Log source agents for Windows Event Log, syslog
- MITRE ATT&CK technique mapping
- Threat intelligence IP feed integration
