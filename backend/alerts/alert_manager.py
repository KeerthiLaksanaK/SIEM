"""
alert_manager.py - Creates and deduplicates alerts.

WHY deduplication is critical:
  Without deduplication, running detection twice would create duplicate alerts.
  In a real SOC, duplicate alerts cause alert fatigue - analysts start ignoring
  alerts because there are too many. Deduplication keeps the alert queue clean.

Deduplication logic:
  If an OPEN alert already exists for the same rule_id + source_ip combination,
  update its event_count and last_seen instead of creating a new alert.
"""

from sqlalchemy.orm import Session
from models import Alert

VALID_STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}


def create_or_update_alert(db: Session, alert_data: dict) -> bool:
    """
    Creates a new alert or updates an existing open one.
    Returns True if a new alert was created, False if an existing one was updated.
    """
    existing = (
        db.query(Alert)
        .filter(
            Alert.rule_id == alert_data["rule_id"],
            Alert.source_ip == alert_data.get("source_ip"),
            Alert.status == "OPEN",
        )
        .first()
    )

    if existing:
        # Update existing alert - do not create a duplicate
        existing.event_count = max(existing.event_count, alert_data["event_count"])
        existing.last_seen = alert_data["last_seen"]
        existing.description = alert_data["description"]
        db.commit()
        return False  # Updated, not created
    else:
        new_alert = Alert(
            alert_type=alert_data["alert_type"],
            severity=alert_data["severity"],
            source_ip=alert_data.get("source_ip"),
            description=alert_data["description"],
            event_count=alert_data["event_count"],
            first_seen=alert_data["first_seen"],
            last_seen=alert_data["last_seen"],
            status="OPEN",
            rule_id=alert_data["rule_id"],
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        return True  # Created


def update_alert_status(db: Session, alert_id: int, new_status: str):
    """
    Updates the investigation status of an alert.
    Implements the SOC incident lifecycle: OPEN -> INVESTIGATING -> RESOLVED.
    """
    if new_status not in VALID_STATUSES:
        return None

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert:
        alert.status = new_status
        db.commit()
        db.refresh(alert)
    return alert
