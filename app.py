from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = os.path.join(os.path.dirname(__file__), "siem.db")
TERMINAL_STATUSES = {"Resolved", "False Positive"}
VALID_STATUSES = {"New", "Investigating", "Resolved", "False Positive"}


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst'
    );
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        event_type TEXT NOT NULL,
        username TEXT,
        details TEXT,
        source TEXT DEFAULT 'application',
        action TEXT,
        status TEXT,
        severity TEXT DEFAULT 'INFO',
        normalized_event TEXT,
        correlation_id TEXT
    );
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        source_ip TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'New',
        evidence TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT
    );
    """)

    existing = {r["name"] for r in conn.execute("PRAGMA table_info(logs)").fetchall()}
    migrations = {
        "source": "ALTER TABLE logs ADD COLUMN source TEXT DEFAULT 'application'",
        "action": "ALTER TABLE logs ADD COLUMN action TEXT",
        "status": "ALTER TABLE logs ADD COLUMN status TEXT",
        "severity": "ALTER TABLE logs ADD COLUMN severity TEXT DEFAULT 'INFO'",
        "normalized_event": "ALTER TABLE logs ADD COLUMN normalized_event TEXT",
        "correlation_id": "ALTER TABLE logs ADD COLUMN correlation_id TEXT",
    }
    for col, sql in migrations.items():
        if col not in existing:
            conn.execute(sql)

    if not conn.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
        conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                     ("admin", generate_password_hash("Admin@123"), "admin"))
    if not conn.execute("SELECT 1 FROM users WHERE username='analyst'").fetchone():
        conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                     ("analyst", generate_password_hash("Analyst@123"), "analyst"))
    conn.commit()
    conn.close()


def add_log(source_ip, event_type, username=None, details="", source="application",
            action=None, status=None, severity="INFO", correlation_id=None):
    timestamp = datetime.now().isoformat(timespec="seconds")
    normalized = {
        "timestamp": timestamp, "source": source, "source_ip": source_ip,
        "event_type": event_type, "username": username, "action": action,
        "status": status, "severity": severity, "details": details,
        "correlation_id": correlation_id
    }
    conn = db()
    conn.execute("""
        INSERT INTO logs(timestamp,source_ip,event_type,username,details,
                         source,action,status,severity,normalized_event,correlation_id)
        VALUES(?,?,?,?,?,?,?,?,?,?,?)
    """, (timestamp, source_ip, event_type, username, details, source,
          action, status, severity, str(normalized), correlation_id))
    conn.commit()
    conn.close()


def audit(action, details=""):
    conn = db()
    conn.execute("INSERT INTO audit_logs(timestamp,username,action,details) VALUES(?,?,?,?)",
                 (datetime.now().isoformat(timespec="seconds"),
                  session.get("username"), action, details))
    conn.commit()
    conn.close()


def logged_in():
    return "user_id" in session


def require_login():
    if not logged_in():
        return redirect(url_for("login"))
    return None


def require_admin():
    if not logged_in():
        return redirect(url_for("login"))
    if session.get("role") != "admin":
        flash("Administrator access required.", "error")
        return redirect(url_for("dashboard"))
    return None


def create_alert_if_missing(alert_type, ip, severity, description, evidence,
                            dedupe_seconds=0, dedupe_text=None):
    """Create a qualifying alert without suppressing later attack windows.

    Existing New/Investigating alerts do NOT block a new attack. Dedupe only
    prevents repeated creation from the same detection window/correlation.
    """
    conn = db()
    exists = None
    if dedupe_seconds > 0:
        cutoff = (datetime.now() - timedelta(seconds=dedupe_seconds)).isoformat(timespec="seconds")
        if dedupe_text:
            exists = conn.execute("""
                SELECT 1 FROM alerts
                WHERE alert_type=? AND source_ip=? AND created_at>=?
                  AND evidence LIKE '%' || ? || '%'
                LIMIT 1
            """, (alert_type, ip, cutoff, dedupe_text)).fetchone()
        else:
            exists = conn.execute("""
                SELECT 1 FROM alerts
                WHERE alert_type=? AND source_ip=? AND created_at>=?
                LIMIT 1
            """, (alert_type, ip, cutoff)).fetchone()
    elif dedupe_text:
        exists = conn.execute("""
            SELECT 1 FROM alerts
            WHERE alert_type=? AND source_ip=? AND evidence LIKE '%' || ? || '%'
            LIMIT 1
        """, (alert_type, ip, dedupe_text)).fetchone()

    if not exists:
        conn.execute("""
            INSERT INTO alerts(created_at,alert_type,source_ip,severity,description,status,evidence)
            VALUES(?,?,?,?,?,?,?)
        """, (datetime.now().isoformat(timespec="seconds"), alert_type, ip,
              severity, description, "New", evidence))
        conn.commit()
    conn.close()


def detect_rules():
    conn = db()
    now = datetime.now()

    rows = conn.execute("""
        SELECT source_ip, COUNT(*) AS c
        FROM logs
        WHERE event_type='LOGIN_FAILED' AND timestamp >= ?
        GROUP BY source_ip HAVING c >= 5
    """, ((now - timedelta(minutes=2)).isoformat(timespec="seconds"),)).fetchall()
    for r in rows:
        create_alert_if_missing(
            "Brute Force Attack", r["source_ip"], "HIGH",
            "Possible brute-force authentication activity.",
            f"{r['c']} failed login attempts from {r['source_ip']} in 2 minutes.",
            dedupe_seconds=120
        )

    rows = conn.execute("""
        SELECT source_ip, correlation_id, COUNT(DISTINCT details) AS c,
               GROUP_CONCAT(DISTINCT details) AS ports
        FROM logs
        WHERE event_type='PORT_ACCESS'
          AND source='nmap_authorized_lab'
          AND correlation_id IS NOT NULL
          AND timestamp >= ?
        GROUP BY source_ip, correlation_id HAVING c >= 6
    """, ((now - timedelta(minutes=2)).isoformat(timespec="seconds"),)).fetchall()
    for r in rows:
        create_alert_if_missing(
            "Port Scan Detected", r["source_ip"], "MEDIUM",
            "Possible port-scanning activity in the authorized lab.",
            f"{r['c']} unique ports in scan {r['correlation_id']} from {r['source_ip']} in 2 minutes. "
            f"Ports: {r['ports']}",
            dedupe_text=f"scan {r['correlation_id']}"
        )

    rows = conn.execute("""
        SELECT source_ip, COUNT(*) AS c
        FROM logs
        WHERE event_type='HTTP_REQUEST'
          AND source='flask_http'
          AND details LIKE '%/lab/status%'
          AND timestamp >= ?
        GROUP BY source_ip HAVING c >= 20
    """, ((now - timedelta(minutes=1)).isoformat(timespec="seconds"),)).fetchall()
    for r in rows:
        create_alert_if_missing(
            "Excessive HTTP Requests", r["source_ip"], "HIGH",
            "Possible request flood against the authorized local application.",
            f"{r['c']} HTTP requests from {r['source_ip']} in 1 minute.",
            dedupe_seconds=60
        )
    conn.close()


@app.before_request
def collect_http_event():
    ignored_prefixes = (
        "/static/", "/dashboard", "/alerts", "/alert/", "/audit",
        "/login", "/logout", "/lab/ingest-port", "/api/", "/logs"
    )
    if request.path.startswith(ignored_prefixes):
        return
    if request.method in {"GET", "POST"}:
        add_log(
            request.remote_addr or "unknown", "HTTP_REQUEST",
            username=session.get("username"),
            details=f"{request.method} {request.path}",
            source="flask_http", action=request.method,
            status="REQUEST", severity="INFO"
        )
        detect_rules()


def dashboard_payload():
    detect_rules()
    conn = db()
    stats = {
        "events": conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"],
        "alerts": conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"],
        "active": conn.execute("SELECT COUNT(*) c FROM alerts WHERE status NOT IN ('Resolved','False Positive')").fetchone()["c"],
        "high": conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='HIGH' AND status NOT IN ('Resolved','False Positive')").fetchone()["c"],
        "critical": conn.execute("SELECT COUNT(*) c FROM alerts WHERE severity='CRITICAL' AND status NOT IN ('Resolved','False Positive')").fetchone()["c"],
        "resolved": conn.execute("SELECT COUNT(*) c FROM alerts WHERE status='Resolved'").fetchone()["c"],
        "false_positive": conn.execute("SELECT COUNT(*) c FROM alerts WHERE status='False Positive'").fetchone()["c"],
    }
    by_source = [dict(x) for x in conn.execute("""
        SELECT COALESCE(source,'unknown') AS name, COUNT(*) AS value
        FROM logs GROUP BY COALESCE(source,'unknown') ORDER BY value DESC
    """).fetchall()]
    by_alert_type = [dict(x) for x in conn.execute("""
        SELECT alert_type AS name, COUNT(*) AS value
        FROM alerts GROUP BY alert_type ORDER BY value DESC
    """).fetchall()]
    by_status = [dict(x) for x in conn.execute("""
        SELECT status AS name, COUNT(*) AS value
        FROM alerts GROUP BY status ORDER BY value DESC
    """).fetchall()]
    alerts = [dict(x) for x in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 8").fetchall()]
    logs = [dict(x) for x in conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 12").fetchall()]
    conn.close()
    return {"stats": stats, "by_source": by_source, "by_alert_type": by_alert_type,
            "by_status": by_status, "alerts": alerts, "logs": logs}


@app.route("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            add_log(request.remote_addr or "unknown", "LOGIN_SUCCESS",
                    username=username, details="Successful user authentication",
                    source="flask_auth", action="LOGIN", status="SUCCESS", severity="INFO")
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            audit("LOGIN", "Successful login")
            return redirect(url_for("dashboard"))
        add_log(request.remote_addr or "unknown", "LOGIN_FAILED",
                 username=username, details="Invalid username or password",
                 source="flask_auth", action="LOGIN", status="FAILED", severity="MEDIUM")
        audit("LOGIN_FAILED", f"Failed login attempt for username: {username}")
        detect_rules()
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    if logged_in():
        add_log(request.remote_addr or "unknown", "LOGOUT",
                username=session.get("username"), details="User logged out",
                source="flask_auth", action="LOGOUT", status="SUCCESS", severity="INFO")
        audit("LOGOUT", "User logged out")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    r = require_login()
    if r: return r
    payload = dashboard_payload()
    return render_template("dashboard.html", **payload)


@app.route("/api/dashboard-data")
def dashboard_data():
    r = require_login()
    if r: return r
    return jsonify(dashboard_payload())


@app.route("/alerts")
def alerts():
    r = require_login()
    if r: return r
    detect_rules()
    conn = db()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("alerts.html", alerts=rows)


@app.route("/alert/<int:alert_id>", methods=["GET", "POST"])
def alert_detail(alert_id):
    r = require_login()
    if r: return r
    conn = db()
    alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        flash("Alert not found.", "error")
        return redirect(url_for("alerts"))

    if request.method == "POST":
        current = alert["status"]
        requested = request.form.get("status", "").strip()
        note = request.form.get("note", "").strip()

        if current in TERMINAL_STATUSES:
            flash(f"Alert #{alert_id} is {current} and is locked.", "error")
            conn.close()
            return redirect(url_for("alert_detail", alert_id=alert_id))

        allowed_next = {
            "New": {"New", "Investigating", "Resolved", "False Positive"},
            "Investigating": {"Investigating", "Resolved", "False Positive"},
        }.get(current, {current})

        if requested not in VALID_STATUSES or requested not in allowed_next:
            flash("Invalid status transition.", "error")
        else:
            evidence = alert["evidence"] or ""
            if note:
                evidence += f"\n[{datetime.now().isoformat(timespec='seconds')}] {session['username']}: {note}"
            conn.execute("UPDATE alerts SET status=?, evidence=? WHERE id=?",
                         (requested, evidence, alert_id))
            conn.commit()
            audit("UPDATE_ALERT", f"Alert #{alert_id}: {current} -> {requested}")
            flash("Alert updated.", "success")
        conn.close()
        return redirect(url_for("alert_detail", alert_id=alert_id))

    conn.close()
    allowed_options = {
        "New": ["New", "Investigating", "Resolved", "False Positive"],
        "Investigating": ["Investigating", "Resolved", "False Positive"],
        "Resolved": ["Resolved"],
        "False Positive": ["False Positive"],
    }[alert["status"]]
    return render_template("alert_detail.html", alert=alert, allowed_options=allowed_options,
                           terminal=alert["status"] in TERMINAL_STATUSES)


@app.route("/logs")
def logs_page():
    r = require_login()
    if r: return r
    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1
    per_page = 50
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM logs").fetchone()["c"]
    pages = max((total + per_page - 1) // per_page, 1)
    page = min(page, pages)
    offset = (page - 1) * per_page
    rows = conn.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ? OFFSET ?", (per_page, offset)).fetchall()
    conn.close()
    return render_template("logs.html", logs=rows, page=page, pages=pages, total=total)


@app.route("/audit")
def audit_page():
    r = require_admin()
    if r: return r
    conn = db()
    rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("audit.html", rows=rows)


@app.route("/lab/ingest-port", methods=["POST"])
def ingest_port():
    data = request.get_json(silent=True) or {}
    if data.get("source") != "nmap_authorized_lab":
        return {"error": "Only authorized local Nmap lab events are accepted."}, 403
    port = str(data.get("port", "")).strip()
    protocol = str(data.get("protocol", "tcp")).strip()
    state = str(data.get("state", "unknown")).strip()
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return {"error": "Invalid port."}, 400
    correlation_id = str(data.get("scan_id", "")).strip() or None
    add_log(data.get("source_ip", "127.0.0.1"), "PORT_ACCESS",
            details=port, source="nmap_authorized_lab",
            action=f"SCAN_{protocol.upper()}", status=state.upper(), severity="INFO",
            correlation_id=correlation_id)
    detect_rules()
    return {"status": "accepted", "port": port, "protocol": protocol, "state": state}


@app.route("/lab/status")
def lab_status():
    return {"status": "ok", "message": "Authorized local SIEM lab endpoint"}


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
