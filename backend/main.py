"""
main.py - FastAPI application entry point.

Wires together all SIEM components and exposes the REST API.
Also serves the frontend HTML/CSS/JS as static files so no separate
web server is needed - the student only needs to run one process.
"""

import os
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import engine, get_db, Base
from models import Event, Alert
from schemas import EventOut, AlertOut, AlertStatusUpdate, StatsOut
from collector.log_collector import collect_raw_logs
from normalizer.normalizer import normalize
from detection.detection_engine import run_detection
from alerts.alert_manager import update_alert_status, VALID_STATUSES

# Create all database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SIEM Mini Platform",
    description="Security Information and Event Management - Academic Project",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static file serving ────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend")
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/", include_in_schema=False)
def serve_dashboard():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


# ── Health check ───────────────────────────────────────────────────────────────
@app.get("/api/health")
def health_check():
    return {"status": "online", "service": "SIEM Mini Platform"}


# ── Events ─────────────────────────────────────────────────────────────────────
@app.get("/api/events", response_model=List[EventOut])
def get_events(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 500,
    db: Session = Depends(get_db),
):
    query = db.query(Event)
    if source:
        query = query.filter(Event.source == source)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if severity:
        query = query.filter(Event.severity == severity)
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    if status:
        query = query.filter(Event.status == status)
    return query.order_by(Event.timestamp.desc()).limit(limit).all()


@app.get("/api/events/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(Event).filter(Event.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


# ── Alerts ─────────────────────────────────────────────────────────────────────
@app.get("/api/alerts", response_model=List[AlertOut])
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    return query.order_by(Alert.created_at.desc()).all()


@app.get("/api/alerts/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.get("/api/alerts/{alert_id}/events", response_model=List[EventOut])
def get_alert_events(alert_id: int, db: Session = Depends(get_db)):
    """Returns events related to an alert based on source IP and time window."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    query = db.query(Event)
    if alert.source_ip:
        query = query.filter(Event.source_ip == alert.source_ip)
    # Return events within the alert's time window
    query = query.filter(
        Event.timestamp >= alert.first_seen,
        Event.timestamp <= alert.last_seen,
    )
    return query.order_by(Event.timestamp.asc()).all()


@app.patch("/api/alerts/{alert_id}/status", response_model=AlertOut)
def update_status(
    alert_id: int,
    body: AlertStatusUpdate,
    db: Session = Depends(get_db),
):
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(VALID_STATUSES)}",
        )
    alert = update_alert_status(db, alert_id, body.status)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


# ── Statistics ─────────────────────────────────────────────────────────────────
@app.get("/api/stats", response_model=StatsOut)
def get_stats(db: Session = Depends(get_db)):
    total_events = db.query(func.count(Event.id)).scalar()
    total_alerts = db.query(func.count(Alert.id)).scalar()

    # Alert counts by severity
    def alert_count(sev):
        return db.query(func.count(Alert.id)).filter(Alert.severity == sev).scalar()

    # Alert counts by status
    def status_count(st):
        return db.query(func.count(Alert.id)).filter(Alert.status == st).scalar()

    # Events grouped by source
    source_rows = db.query(Event.source, func.count(Event.id)).group_by(Event.source).all()
    event_count_by_source = {row[0]: row[1] for row in source_rows}

    # Alerts grouped by type
    type_rows = db.query(Alert.alert_type, func.count(Alert.id)).group_by(Alert.alert_type).all()
    alert_count_by_type = {row[0]: row[1] for row in type_rows}

    return StatsOut(
        total_events=total_events,
        total_alerts=total_alerts,
        critical_alerts=alert_count("CRITICAL"),
        high_alerts=alert_count("HIGH"),
        medium_alerts=alert_count("MEDIUM"),
        low_alerts=alert_count("LOW"),
        open_alerts=status_count("OPEN"),
        resolved_alerts=status_count("RESOLVED"),
        event_count_by_source=event_count_by_source,
        alert_count_by_type=alert_count_by_type,
    )


# ── Pipeline endpoints ─────────────────────────────────────────────────────────
@app.post("/api/collect")
def collect_logs(db: Session = Depends(get_db)):
    """
    Reads all sample log files, normalizes each line, and stores events in the DB.
    This is the entry point of the SIEM pipeline.
    """
    events_added = 0
    files_seen = set()
    errors = 0

    for source, raw_line in collect_raw_logs():
        files_seen.add(source)
        normalized = normalize(source, raw_line)

        # Skip lines that failed to parse entirely (no timestamp)
        if normalized.get("timestamp") is None:
            normalized["timestamp"] = datetime.utcnow()

        try:
            event = Event(**normalized)
            db.add(event)
            events_added += 1
        except Exception:
            errors += 1
            db.rollback()
            continue

    db.commit()

    return {
        "status": "success",
        "files_processed": len(files_seen),
        "events_collected": events_added,
        "parse_errors": errors,
    }


@app.post("/api/detect")
def detect(db: Session = Depends(get_db)):
    """
    Runs all detection rules against stored events and generates alerts.
    Must be called after /api/collect.
    """
    event_count = db.query(func.count(Event.id)).scalar()
    if event_count == 0:
        raise HTTPException(
            status_code=400,
            detail="No events in database. Run /api/collect first.",
        )
    return run_detection(db)


@app.post("/api/reset")
def reset_database(db: Session = Depends(get_db)):
    """
    Clears all events and alerts from the database.
    Useful for demonstration resets without restarting the server.
    """
    db.query(Alert).delete()
    db.query(Event).delete()
    db.commit()
    return {"status": "success", "message": "Database cleared. Ready for fresh demonstration."}


@app.post("/api/seed")
def seed(db: Session = Depends(get_db)):
    """Convenience endpoint: collect + detect in one call."""
    collect_result = collect_logs(db)
    detect_result = detect(db)
    return {
        "status": "success",
        "collect": collect_result,
        "detect": detect_result,
    }
