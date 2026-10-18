from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.api.routes.common import get_db
from app.models.orm import Base, EventORM, AlertORM, IncidentORM
from app.services.incident_service import IncidentService
from app.core.config import settings

ROOT = Path(__file__).resolve().parents[2]


def get_test_client_and_session():
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(test_engine)
    TestingSession = sessionmaker(bind=test_engine)

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), TestingSession


def test_multi_upload_collisions_distinct_ids():
    """Two different files uploaded back to back produce two incidents with distinct IDs and distinct alert IDs."""
    client, TestingSession = get_test_client_and_session()
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

    # File 1: Attack on server-01 from 198.51.100.99
    events_1 = [
        *[
            {
                "timestamp": (base + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z"),
                "source_ip": "198.51.100.99",
                "destination_ip": None,
                "user": "victim1",
                "host": "server-upload-1",
                "event_type": "ssh_failed_login",
                "severity": "low",
                "message": "Failed password for victim1",
                "bytes": 0,
                "process": "sshd",
                "path": None,
            }
            for i in range(5)
        ],
        {
            "timestamp": (base + timedelta(seconds=70)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.99",
            "destination_ip": None,
            "user": "victim1",
            "host": "server-upload-1",
            "event_type": "ssh_success_login",
            "severity": "medium",
            "message": "Accepted password for victim1",
            "bytes": 0,
            "process": "sshd",
            "path": None,
        },
    ]

    # File 2: Attack on server-02 from 198.51.100.88
    events_2 = [
        *[
            {
                "timestamp": (base + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z"),
                "source_ip": "198.51.100.88",
                "destination_ip": None,
                "user": "victim2",
                "host": "server-upload-2",
                "event_type": "ssh_failed_login",
                "severity": "low",
                "message": "Failed password for victim2",
                "bytes": 0,
                "process": "sshd",
                "path": None,
            }
            for i in range(5)
        ],
        {
            "timestamp": (base + timedelta(seconds=70)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.88",
            "destination_ip": None,
            "user": "victim2",
            "host": "server-upload-2",
            "event_type": "ssh_success_login",
            "severity": "medium",
            "message": "Accepted password for victim2",
            "bytes": 0,
            "process": "sshd",
            "path": None,
        },
    ]

    resp1 = client.post(
        "/api/logs/upload",
        files={"file": ("upload_1.json", json.dumps(events_1).encode("utf-8"), "application/json")},
    )
    assert resp1.status_code == 200
    assert resp1.json()["accepted"] == 6

    resp2 = client.post(
        "/api/logs/upload",
        files={"file": ("upload_2.json", json.dumps(events_2).encode("utf-8"), "application/json")},
    )
    assert resp2.status_code == 200
    assert resp2.json()["accepted"] == 6

    db = TestingSession()
    incidents = db.query(IncidentORM).filter(IncidentORM.batch_id.like("upload-%")).all()
    assert len(incidents) == 2, f"Expected 2 incidents, got {len(incidents)}"

    inc1, inc2 = incidents[0], incidents[1]
    # Distinct Incident IDs
    assert inc1.id != inc2.id
    assert inc1.id.startswith("INC-UP-")
    assert inc2.id.startswith("INC-UP-")

    # Distinct Alert IDs
    assert len(inc1.alert_ids) >= 2
    assert len(inc2.alert_ids) >= 2
    assert set(inc1.alert_ids).isdisjoint(set(inc2.alert_ids))

    alerts = db.query(AlertORM).filter(AlertORM.batch_id.like("upload-%")).all()
    alert_ids = [a.id for a in alerts]
    assert len(alert_ids) == len(set(alert_ids)), "Alert IDs must all be unique"
    app.dependency_overrides.clear()


def test_appended_file_dedupe_accepts_only_new_events():
    """Upload a file, then upload the same file with one extra line. Only the new event should be accepted."""
    client, TestingSession = get_test_client_and_session()
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

    initial_events = [
        {
            "timestamp": (base + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.77",
            "destination_ip": None,
            "user": "appended_test",
            "host": "server-append",
            "event_type": "ssh_failed_login",
            "severity": "low",
            "message": f"Failed password attempt {i}",
            "bytes": 0,
            "process": "sshd",
            "path": None,
        }
        for i in range(4)
    ]

    # First upload: 4 events
    resp1 = client.post(
        "/api/logs/upload",
        files={"file": ("server.log", json.dumps(initial_events).encode("utf-8"), "application/json")},
    )
    assert resp1.status_code == 200
    assert resp1.json()["accepted"] == 4
    assert resp1.json()["rejected"] == 0

    # Second upload: Same 4 events + exactly 1 new event appended
    one_extra_event = {
        "timestamp": (base + timedelta(seconds=50)).isoformat().replace("+00:00", "Z"),
        "source_ip": "198.51.100.77",
        "destination_ip": None,
        "user": "appended_test",
        "host": "server-append",
        "event_type": "ssh_failed_login",
        "severity": "low",
        "message": "Failed password attempt 5 - the extra line",
        "bytes": 0,
        "process": "sshd",
        "path": None,
    }
    appended_events = initial_events + [one_extra_event]

    resp2 = client.post(
        "/api/logs/upload",
        files={"file": ("server.log", json.dumps(appended_events).encode("utf-8"), "application/json")},
    )
    assert resp2.status_code == 200
    # Exactly 1 new event accepted!
    assert resp2.json()["accepted"] == 1
    assert resp2.json()["rejected"] == 0

    db = TestingSession()
    total_events = db.query(EventORM).filter(EventORM.user == "appended_test").count()
    assert total_events == 5, f"Expected exactly 5 events in database, found {total_events}"
    app.dependency_overrides.clear()


def test_duplicate_survival_in_seed_stores_all_13904_events():
    """The 3 identical same-second pairs in the seed should all be stored, with 13,904 events after simulation."""
    client, TestingSession = get_test_client_and_session()
    db = TestingSession()
    service = IncidentService(db)

    seed_path = ROOT / "data/sample_logs/ssh_attack.json"
    seed_data = json.loads(seed_path.read_text(encoding="utf-8"))
    assert len(seed_data) == 13904

    accepted, rejected = service.ingest_records(seed_data, "demo", source_file="ssh_attack.json")
    assert accepted == 13904
    assert len(rejected) == 0

    # Assert exactly 13,904 events stored in EventORM
    db_count = db.query(EventORM).filter(EventORM.batch_id == "demo").count()
    assert db_count == 13904

    # Verify specific identical same-second duplicate pairs all survived in the database:
    # 1. 2026-10-18T09:40:18Z ssh_success_login from 198.51.100.50
    target_ts = datetime(2026, 10, 18, 9, 40, 18, tzinfo=timezone.utc)
    evts_target = db.query(EventORM).filter(
        EventORM.timestamp == target_ts,
        EventORM.source_ip == "198.51.100.50",
        EventORM.event_type == "ssh_success_login"
    ).all()
    assert len(evts_target) == 2, f"Expected identical pair to survive (count 2), found {len(evts_target)}"
    # Hashes are distinct due to occurrence counter
    assert evts_target[0].raw_hash != evts_target[1].raw_hash
    assert evts_target[0].id != evts_target[1].id

    # 2. 2026-10-18T09:15:40Z file_access
    ts_file = datetime(2026, 10, 18, 9, 15, 40, tzinfo=timezone.utc)
    evts_file = db.query(EventORM).filter(
        EventORM.timestamp == ts_file,
        EventORM.event_type == "file_access"
    ).all()
    assert len(evts_file) == 2
    assert evts_file[0].raw_hash != evts_file[1].raw_hash

    # Run detection on demo data
    alerts, incidents, anomaly_count = service.run_detection_sync(is_simulation=True, batch_id="demo")
    assert len(incidents) == 1
    assert incidents[0].id == "INC-001"
    assert incidents[0].score == 100
    app.dependency_overrides.clear()


def test_rename_content_adds_zero_events():
    """The same content under a new filename should add 0 events."""
    client, TestingSession = get_test_client_and_session()
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

    sample_events = [
        {
            "timestamp": (base + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.66",
            "destination_ip": None,
            "user": "rename_victim",
            "host": "server-rename",
            "event_type": "ssh_failed_login",
            "severity": "low",
            "message": f"Auth failure {i}",
            "bytes": 0,
            "process": "sshd",
            "path": None,
        }
        for i in range(5)
    ]
    raw_bytes = json.dumps(sample_events).encode("utf-8")

    # Ingest under first filename
    resp1 = client.post(
        "/api/logs/upload",
        files={"file": ("original_audit.json", raw_bytes, "application/json")},
    )
    assert resp1.status_code == 200
    assert resp1.json()["accepted"] == 5

    # Re-upload the exact same content under a different filename
    resp2 = client.post(
        "/api/logs/upload",
        files={"file": ("renamed_copy_audit.json", raw_bytes, "application/json")},
    )
    assert resp2.status_code == 200
    # Must accept 0 new events because semantic content is identical
    assert resp2.json()["accepted"] == 0

    db = TestingSession()
    total_events = db.query(EventORM).filter(EventORM.user == "rename_victim").count()
    assert total_events == 5
    app.dependency_overrides.clear()


def test_demo_mode_default_and_gate():
    """With DEMO_MODE unset (default False in config.py), inject_bad=true should return 403."""
    client, TestingSession = get_test_client_and_session()
    db = TestingSession()

    # Confirm default in settings is False
    assert settings.demo_mode is False, "demo_mode must default to False"

    # Seed an incident for testing the endpoint
    inc = IncidentORM(
        id="INC-DEMO-GATE",
        severity="high",
        score=80,
        status="open",
        source_ip="203.0.113.10",
        affected_hosts=["server-01"],
        users=["admin"],
        alert_ids=[],
        stages=["ssh_brute_force"],
        timeline=[{
            "ts": "2026-10-18T09:00:00Z",
            "stage": "ssh_brute_force",
            "event_ids": ["evt-1"],
            "description": "5 failed logins",
            "mitre_id": "T1110.001",
            "link_reason": "seed",
        }],
        mitre_techniques=[{"id": "T1110.001", "name": "Brute Force"}],
        enrichment={},
        ai_summary={},
        batch_id="demo",
    )
    db.add(inc)
    db.commit()

    # 1. With demo_mode=False -> 403 Forbidden
    res_blocked = client.post(f"/api/incidents/{inc.id}/report?inject_bad=true")
    assert res_blocked.status_code == 403
    assert "disabled outside demo mode" in res_blocked.json()["detail"]

    # 2. When DEMO_MODE=true is enabled -> 200 OK with fallback
    try:
        settings.demo_mode = True
        res_allowed = client.post(f"/api/incidents/{inc.id}/report?inject_bad=true")
        assert res_allowed.status_code == 200
        data = res_allowed.json()
        assert data["status"] == "fallback"
        assert "rejected_reason" in data
    finally:
        settings.demo_mode = False

    app.dependency_overrides.clear()
