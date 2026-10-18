import asyncio
from datetime import datetime, timezone
import pathlib
import time
from uuid import uuid4
from collections import Counter
from sqlalchemy import select, func
from app.models.orm import EventORM, AlertORM, IncidentORM
from app.ingest.normalizer import normalize_event
from app.ingest.validation import validate_event
from app.ingest.parsers import parse_content
from app.detection.rules import detect_alerts
from app.detection.anomaly import AnomalyEngine
from app.correlation.correlator import build_incidents
from app.ai.explainer import ai_explainer
from app.enrichment.demo_mock import DemoMockProvider
from app.enrichment.abuseipdb import AbuseIPDBProvider
from app.core.config import settings

ROOT = settings.model_config.get("env_file") and pathlib.Path(settings.model_config['env_file']).parent or pathlib.Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "data/fixtures/enrichment_demo.json"

_ANOMALY_COUNT_CACHE = 0

class IncidentService:
    def __init__(self, db):
        self.db = db
        self.anomaly = AnomalyEngine()
        self.explainer = ai_explainer

    def clear_demo(self, clear_uploads: bool = False):
        """Resets the demo data while preserving any user-uploaded logs, alerts, and incidents."""
        global _ANOMALY_COUNT_CACHE
        _ANOMALY_COUNT_CACHE = 0
        if clear_uploads:
            self.db.query(IncidentORM).delete()
            self.db.query(AlertORM).delete()
            self.db.query(EventORM).delete()
        else:
            self.db.query(IncidentORM).filter(IncidentORM.batch_id.notlike("upload-%")).delete()
            self.db.query(AlertORM).filter(AlertORM.batch_id.notlike("upload-%")).delete()
            self.db.query(EventORM).filter(EventORM.batch_id.notlike("upload-%")).delete()
        self.db.commit()

    def ingest_records(self, records: list[dict], batch_id: str, source_file: str | None = None) -> tuple[int, list[str]]:
        accepted = 0
        rejected = []
        existing_hashes = set(self.db.scalars(select(EventORM.raw_hash)).all())
        batch_to_add = []
        for idx, raw in enumerate(records, start=1):
            event, error = validate_event(raw)
            if error:
                rejected.append(f"record {idx}: {error}")
                continue
            sf = raw.get("source_file", source_file)
            lo = raw.get("line_offset", idx)
            payload = normalize_event(event, batch_id, source_file=sf, line_offset=lo)
            raw_hash = payload["raw_hash"]
            if raw_hash in existing_hashes:
                continue
            existing_hashes.add(raw_hash)
            # Filter to known fields on EventORM
            orm_kwargs = {k: v for k, v in payload.items() if hasattr(EventORM, k)}
            batch_to_add.append(EventORM(**orm_kwargs))
            accepted += 1
            if len(batch_to_add) >= 1000:
                self.db.add_all(batch_to_add)
                batch_to_add = []
        if batch_to_add:
            self.db.add_all(batch_to_add)
        self.db.commit()
        return accepted, rejected

    async def run_detection(self, progress_callback=None, is_simulation: bool = False, batch_id: str | None = None, simulate_bad_ai: bool = False) -> tuple[list[AlertORM], list[IncidentORM], int]:
        if is_simulation or batch_id == "demo":
            effective_batch_id = "demo"
            id_prefix = "INC-"
            alert_prefix = "alert-"
            events_stmt = select(EventORM).where(EventORM.batch_id.notlike("upload-%")).order_by(EventORM.timestamp)
            self.db.query(IncidentORM).filter(IncidentORM.batch_id.notlike("upload-%")).delete()
            self.db.query(AlertORM).filter(AlertORM.batch_id.notlike("upload-%")).delete()
            self.db.commit()
        elif batch_id and batch_id.startswith("upload-"):
            effective_batch_id = batch_id
            id_prefix = "INC-UP-"
            alert_prefix = f"alert-{batch_id[:12]}-"
            events_stmt = select(EventORM).where(EventORM.batch_id == batch_id).order_by(EventORM.timestamp)
            self.db.query(IncidentORM).filter(IncidentORM.batch_id == batch_id).delete()
            self.db.query(AlertORM).filter(AlertORM.batch_id == batch_id).delete()
            self.db.commit()
        else:
            effective_batch_id = "demo"
            id_prefix = "INC-"
            alert_prefix = "alert-"
            events_stmt = select(EventORM).order_by(EventORM.timestamp)
            self.db.query(IncidentORM).delete()
            self.db.query(AlertORM).delete()
            self.db.commit()

        events_orm = list(self.db.scalars(events_stmt).all())
        events_count = len(events_orm)
        
        def notify(stage: str, details: str = ""):
            if progress_callback:
                try:
                    progress_callback(stage, details)
                except TypeError:
                    progress_callback(stage)

        t0 = time.time()
        notify("Detecting", f"{events_count} events")
        
        events = [self.orm_event_to_dict(e) for e in events_orm]
        for event in events:
            if event["timestamp"].tzinfo is None:
                event["timestamp"] = event["timestamp"].replace(tzinfo=timezone.utc)
        
        detection = detect_alerts(events)
        detect_time = round(time.time() - t0, 3)

        event_by_id = {e["id"]: e for e in events}
        anomaly_map = {}
        anomaly_count = 0
        try:
            if self.anomaly.status == "ready":
                anomaly_map = self.anomaly.score(events)
                anomaly_count = sum(1 for v in anomaly_map.values() if v >= 0.70)
        except Exception:
            anomaly_map = {}

        alerts_orm = []
        alert_key_to_orm_id = {}
        for idx, a in enumerate(detection, start=1):
            score = None
            if a.event_ids and a.event_ids[0] in event_by_id:
                first = event_by_id[a.event_ids[0]]
                src_ip = first.get("source_ip")
                if src_ip:
                    for key, val in anomaly_map.items():
                        if key.startswith(f"{src_ip}|"):
                            try:
                                window_ts = __import__('pandas').Timestamp(key.split('|', 1)[1]).to_pydatetime().replace(tzinfo=timezone.utc)
                                if abs((window_ts - first['timestamp']).total_seconds()) <= 60:
                                    score = val
                                    break
                            except Exception:
                                continue

            orm_id = f"{alert_prefix}{idx:03d}"
            orm = AlertORM(
                id=orm_id,
                rule_id=a.rule_id,
                title=a.title,
                severity=a.severity,
                confidence=a.confidence,
                event_ids=a.event_ids,
                first_seen=a.first_seen,
                last_seen=a.last_seen,
                mitre_ids=a.mitre_ids,
                explanation=a.explanation,
                anomaly_score=score,
                link_reason=a.link_reason,
                batch_id=effective_batch_id,
            )
            self.db.add(orm)
            alerts_orm.append(orm)
            alert_key_to_orm_id[(a.rule_id, tuple(a.event_ids))] = orm_id

        self.db.commit()

        t_corr = time.time()
        notify("Correlating", f"{len(detection)} alerts ({detect_time}s)")
        incidents = build_incidents(detection, event_by_id, id_prefix=id_prefix)

        notify("Building timeline", f"{len(incidents)} candidate incidents")
        incident_orms = []
        for inc in incidents:
            rel_alerts = inc.get("_alerts", [])
            inc_alert_ids = [
                alert_key_to_orm_id.get((a.rule_id, tuple(a.event_ids)))
                for a in rel_alerts
                if (a.rule_id, tuple(a.event_ids)) in alert_key_to_orm_id
            ]
            inc["alert_ids"] = [aid for aid in inc_alert_ids if aid]

            incident_orm = IncidentORM(**{k: v for k, v in inc.items() if not k.startswith('_')})
            incident_orm.enrichment = {}
            incident_orm.ai_summary = {}
            incident_orm.batch_id = effective_batch_id
            self.db.add(incident_orm)
            incident_orms.append(incident_orm)

        self.db.commit()

        notify("Mapping MITRE", "Validating techniques")
        notify("Enriching", "Threat intelligence lookup")

        if is_simulation or effective_batch_id == "demo":
            provider = DemoMockProvider(str(FIXTURE))
        else:
            provider = AbuseIPDBProvider()

        for incorm in incident_orms:
            notify("Generating report", f"{incorm.id}")
            incdict = self.incident_to_dict(incorm)
            incorm.enrichment = provider.lookup(incorm.source_ip)
            status, report, metadata = await self.explainer.generate(incdict, simulate_bad_ai=simulate_bad_ai)
            incorm.ai_summary = {
                "status": status,
                "content": report,
                "model": metadata.get("model", "unavailable"),
                "input_hash": metadata.get("input_hash", ""),
            }

        self.db.commit()
        global _ANOMALY_COUNT_CACHE
        _ANOMALY_COUNT_CACHE = anomaly_count
        return alerts_orm, incident_orms, anomaly_count

    def run_detection_sync(self, progress_callback=None, is_simulation: bool = False, batch_id: str | None = None, simulate_bad_ai: bool = False) -> tuple[list[AlertORM], list[IncidentORM], int]:
        return asyncio.run(self.run_detection(progress_callback=progress_callback, is_simulation=is_simulation, batch_id=batch_id, simulate_bad_ai=simulate_bad_ai))

    @staticmethod
    def orm_event_to_dict(e: EventORM) -> dict:
        return {c: getattr(e, c) for c in ["id", "timestamp", "source_ip", "destination_ip", "user", "host", "event_type", "severity", "message", "bytes", "process", "path", "raw_hash", "batch_id", "source_file", "line_offset"]}

    @staticmethod
    def alert_to_dict(a: AlertORM) -> dict:
        return {"id": a.id, "rule_id": a.rule_id, "title": a.title, "severity": a.severity, "confidence": a.confidence, "event_ids": a.event_ids, "first_seen": a.first_seen, "last_seen": a.last_seen, "mitre_ids": a.mitre_ids, "explanation": a.explanation, "anomaly_score": a.anomaly_score, "link_reason": a.link_reason, "batch_id": a.batch_id}

    @staticmethod
    def incident_to_dict(i: IncidentORM) -> dict:
        return {"id": i.id, "severity": i.severity, "score": i.score, "status": i.status, "source_ip": i.source_ip, "affected_hosts": i.affected_hosts, "users": i.users, "alert_ids": i.alert_ids, "stages": i.stages, "timeline": i.timeline, "mitre_techniques": i.mitre_techniques, "enrichment": i.enrichment, "ai_summary": i.ai_summary, "batch_id": i.batch_id}

    def get_incident(self, incident_id: str) -> dict | None:
        obj = self.db.get(IncidentORM, incident_id)
        if not obj:
            return None
        data = self.incident_to_dict(obj)
        all_event_ids = set()
        for t in data.get("timeline", []):
            all_event_ids.update(t.get("event_ids", []))
        if all_event_ids:
            events = self.db.scalars(select(EventORM).where(EventORM.id.in_(list(all_event_ids)))).all()
            # Sort events by timestamp
            events_sorted = sorted(events, key=lambda e: e.timestamp)
            data["events"] = [self.orm_event_to_dict(e) for e in events_sorted]
        else:
            data["events"] = []
        return data

    def get_alerts(self) -> list[dict]:
        return [self.alert_to_dict(x) for x in self.db.scalars(select(AlertORM).order_by(AlertORM.first_seen.desc())).all()]

    def get_incidents(self) -> list[dict]:
        return [self.incident_to_dict(x) for x in self.db.scalars(select(IncidentORM).order_by(IncidentORM.id)).all()]

    def stats(self) -> dict:
        events = list(self.db.scalars(select(EventORM)).all())
        alerts = list(self.db.scalars(select(AlertORM)).all())
        incidents = list(self.db.scalars(select(IncidentORM)).all())
        top_ip = Counter([a.explanation.get("entities", {}).get("source_ip") for a in alerts if a.explanation.get("entities", {}).get("source_ip")]).most_common(1)
        targeted_users = [e.user for e in events if e.user and e.event_type in {"ssh_failed_login", "ssh_success_login"}]
        top_user = Counter(targeted_users).most_common(1)
        top_rule = Counter([a.rule_id for a in alerts]).most_common(1)
        volumes = []
        if events:
            by_day = Counter([e.timestamp.strftime("%Y-%m-%dT%H:%M") for e in events])
            volumes = [{"ts": k, "count": v} for k, v in sorted(by_day.items())[-30:]]

        # Count anomalous 1-minute feature windows
        global _ANOMALY_COUNT_CACHE
        anomaly_count = _ANOMALY_COUNT_CACHE


        return {
            "critical_incidents": sum(i.severity == "critical" for i in incidents),
            "high_alerts": sum(a.severity == "high" for a in alerts),
            "events_processed": len(events),
            "anomalies": anomaly_count,
            "top_attacker_ip": top_ip[0][0] if top_ip else None,
            "most_targeted_user": top_user[0][0] if top_user else None,
            "most_common_detection": top_rule[0][0] if top_rule else None,
            "event_volume": volumes
        }

