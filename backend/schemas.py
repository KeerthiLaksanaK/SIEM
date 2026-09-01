"""
schemas.py - Pydantic models for API request/response validation.
Pydantic ensures that data entering and leaving the API is correctly typed and structured.
"""

from datetime import datetime
from typing import Optional, Dict
from pydantic import BaseModel


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    source: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    http_method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    status: Optional[str] = None
    severity: str
    raw_log: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: int
    alert_type: str
    severity: str
    source_ip: Optional[str] = None
    description: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    status: str
    rule_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    status: str


class StatsOut(BaseModel):
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    open_alerts: int
    resolved_alerts: int
    event_count_by_source: Dict[str, int]
    alert_count_by_type: Dict[str, int]
