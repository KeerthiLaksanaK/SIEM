"""
detection_engine.py - Executes all detection rules against stored events.

The engine is the brain of the SIEM. It:
  1. Loads all normalized events from the database
  2. Passes them to each detection rule
  3. Sends results to the alert manager for storage/deduplication
"""

from sqlalchemy.orm import Session
from models import Event
from detection.rules import ALL_RULES
from alerts.alert_manager import create_or_update_alert


def run_detection(db: Session) -> dict:
    """
    Runs all detection rules and returns a summary of what was found.
    Called by POST /api/detect endpoint.
    """
    # Load all events once - rules operate on this in-memory list
    # In a production SIEM this would be time-windowed to avoid loading millions of events
    events = db.query(Event).all()

    total_created = 0
    total_updated = 0

    for rule_fn in ALL_RULES:
        rule_alerts = rule_fn(events)
        for alert_data in rule_alerts:
            created = create_or_update_alert(db, alert_data)
            if created:
                total_created += 1
            else:
                total_updated += 1

    return {
        "status": "success",
        "rules_executed": len(ALL_RULES),
        "alerts_created": total_created,
        "alerts_updated": total_updated,
    }
