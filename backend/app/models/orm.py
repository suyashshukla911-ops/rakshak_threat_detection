from datetime import datetime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import JSON, Integer, String, DateTime, Text, Float

class Base(DeclarativeBase):
    pass

class EventORM(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    user: Mapped[str | None] = mapped_column(String, nullable=True, index=True)
    host: Mapped[str] = mapped_column(String, index=True)
    event_type: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String, default="low")
    message: Mapped[str] = mapped_column(Text, default="")
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    process: Mapped[str | None] = mapped_column(String, nullable=True)
    path: Mapped[str | None] = mapped_column(String, nullable=True)
    raw_hash: Mapped[str] = mapped_column(String, unique=True, index=True)

    batch_id: Mapped[str] = mapped_column(String, index=True)
    source_file: Mapped[str | None] = mapped_column(String, nullable=True)
    line_offset: Mapped[int | None] = mapped_column(Integer, nullable=True)


class AlertORM(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    rule_id: Mapped[str] = mapped_column(String, index=True)
    title: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(Float)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    mitre_ids: Mapped[list] = mapped_column(JSON, default=list)
    explanation: Mapped[dict] = mapped_column(JSON, default=dict)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    link_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    batch_id: Mapped[str] = mapped_column(String, default="demo", index=True)

class IncidentORM(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String, primary_key=True)
    severity: Mapped[str] = mapped_column(String)
    score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String, default="open")
    source_ip: Mapped[str] = mapped_column(String)
    affected_hosts: Mapped[list] = mapped_column(JSON, default=list)
    users: Mapped[list] = mapped_column(JSON, default=list)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    stages: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    enrichment: Mapped[dict] = mapped_column(JSON, default=dict)
    ai_summary: Mapped[dict] = mapped_column(JSON, default=dict)
    batch_id: Mapped[str] = mapped_column(String, default="demo", index=True)
