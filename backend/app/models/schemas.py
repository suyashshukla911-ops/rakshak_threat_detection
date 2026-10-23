from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field, ConfigDict

Severity = Literal["low", "medium", "high", "critical", "info"]
EventType = Literal[
    "ssh_failed_login",
    "ssh_success_login",
    "privilege_escalation",
    "file_access",
    "outbound_transfer",
    "other",
]

class EventIn(BaseModel):
    id: str | None = None
    timestamp: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    host: str
    event_type: EventType
    severity: Severity = "low"
    message: str = ""
    bytes: int = Field(default=0, ge=0)
    process: str | None = None
    path: str | None = None
    batch_id: str | None = None

    source_file: str | None = None
    line_offset: int | None = None


class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    event_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    mitre_ids: list[str]
    explanation: dict[str, Any]
    anomaly_score: float | None = None
    link_reason: str | None = None

class TimelineStage(BaseModel):
    ts: datetime
    stage: str
    event_ids: list[str]
    description: str
    mitre_id: str
    link_reason: str
    severity: str | None = None
    anomaly_score: float | None = None

class AIOutput(BaseModel):
    executive_summary: str = Field(..., max_length=1000)
    attack_narrative: str = Field(..., max_length=4000)
    why_detected: list[str] = Field(..., max_length=20)
    potential_impact: str = Field(..., max_length=2000)
    investigation_steps: list[str] = Field(..., max_length=20)
    evidence_refs: list[str] = Field(..., max_length=100)

class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    severity: Severity
    score: int
    status: str
    source_ip: str
    affected_hosts: list[str]
    users: list[str]
    alert_ids: list[str]
    stages: list[str]
    timeline: list[TimelineStage]
    mitre_techniques: list[dict[str, Any]]
    enrichment: dict[str, Any]
    ai_summary: dict[str, Any]

class StatsOut(BaseModel):
    critical_incidents: int
    high_alerts: int
    events_processed: int
    anomalies: int
    top_attacker_ip: str | None
    most_targeted_user: str | None
    most_common_detection: str | None
    event_volume: list[dict[str, Any]]

class HealthOut(BaseModel):
    db: str
    rules: str
    ml: str
    threat_intel: str
    ai: str

class SimulationStartOut(BaseModel):
    run_id: str
