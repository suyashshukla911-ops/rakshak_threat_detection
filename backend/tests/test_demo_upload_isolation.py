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


def test_demo_and_upload_data_isolation():
    # Setup test in-memory database with StaticPool and check_same_thread=False
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
    client = TestClient(app)

    # 1. Upload a custom attack log file
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)
    upload_events = [
        # 5 failed logins within 60s -> triggers brute force
        *[
            {
                "timestamp": (base + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z"),
                "source_ip": "198.51.100.99",
                "destination_ip": None,
                "user": "victim",
                "host": "server-upload",
                "event_type": "ssh_failed_login",
                "severity": "low",
                "message": "Failed password for victim",
                "bytes": 0,
                "process": "sshd",
                "path": None,
            }
            for i in range(5)
        ],
        # Login after brute force
        {
            "timestamp": (base + timedelta(seconds=70)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.99",
            "destination_ip": None,
            "user": "victim",
            "host": "server-upload",
            "event_type": "ssh_success_login",
            "severity": "medium",
            "message": "Accepted password for victim",
            "bytes": 0,
            "process": "sshd",
            "path": None,
        },
    ]

    upload_bytes = json.dumps(upload_events).encode("utf-8")
    resp_upload = client.post(
        "/api/logs/upload",
        files={"file": ("original_attack.json", upload_bytes, "application/json")},
    )
    assert resp_upload.status_code == 200
    assert resp_upload.json()["accepted"] == 6

    # Verify upload incident was created with INC-UP- prefix
    db = TestingSession()
    upload_incidents = db.query(IncidentORM).filter(IncidentORM.batch_id.like("upload-%")).all()
    assert len(upload_incidents) == 1
    upload_inc = upload_incidents[0]
    assert upload_inc.id.startswith("INC-UP-")
    assert upload_inc.source_ip == "198.51.100.99"
    upload_inc_id_1 = upload_inc.id

    # 2. Test Coexistence of Multiple Different Uploads (No Primary Key Collision)
    # Upload a second different attack file
    upload_events_2 = [
        *[
            {
                "timestamp": (base + timedelta(seconds=i * 10)).isoformat().replace("+00:00", "Z"),
                "source_ip": "198.51.100.88",
                "destination_ip": None,
                "user": "alice",
                "host": "server-upload-2",
                "event_type": "ssh_failed_login",
                "severity": "low",
                "message": "Failed password for alice",
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
            "user": "alice",
            "host": "server-upload-2",
            "event_type": "ssh_success_login",
            "severity": "medium",
            "message": "Accepted password for alice",
            "bytes": 0,
            "process": "sshd",
            "path": None,
        },
    ]
    resp_upload_2 = client.post(
        "/api/logs/upload",
        files={"file": ("second_attack.json", json.dumps(upload_events_2).encode("utf-8"), "application/json")},
    )
    assert resp_upload_2.status_code == 200
    assert resp_upload_2.json()["accepted"] == 6

    # Both upload incidents must coexist without ID collision
    upload_incidents = db.query(IncidentORM).filter(IncidentORM.batch_id.like("upload-%")).all()
    assert len(upload_incidents) == 2
    upload_ids = {u.id for u in upload_incidents}
    assert upload_inc_id_1 in upload_ids
    upload_inc_id_2 = [uid for uid in upload_ids if uid != upload_inc_id_1][0]
    assert upload_inc_id_2.startswith("INC-UP-")
    assert upload_inc_id_1 != upload_inc_id_2

    # Verify alerts coexist
    upload_alerts = db.query(AlertORM).filter(AlertORM.batch_id.like("upload-%")).all()
    assert len(upload_alerts) >= 4  # At least 2 alerts per incident (brute force + login)

    # 3. Test Appended Log Deduplication
    # Append 2 new events to upload_events_2 and re-upload:
    appended_events_2 = upload_events_2 + [
        {
            "timestamp": (base + timedelta(seconds=80)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.88",
            "destination_ip": None,
            "user": "alice",
            "host": "server-upload-2",
            "event_type": "privilege_escalation",
            "severity": "high",
            "message": "sudo su executed by alice",
            "bytes": 0,
            "process": "sudo",
            "path": None,
        },
        {
            "timestamp": (base + timedelta(seconds=90)).isoformat().replace("+00:00", "Z"),
            "source_ip": "198.51.100.88",
            "destination_ip": None,
            "user": "alice",
            "host": "server-upload-2",
            "event_type": "file_access",
            "severity": "high",
            "message": "cat /etc/shadow",
            "bytes": 0,
            "process": "cat",
            "path": "/etc/shadow",
        },
    ]
    resp_appended = client.post(
        "/api/logs/upload",
        files={"file": ("second_attack_appended.json", json.dumps(appended_events_2).encode("utf-8"), "application/json")},
    )
    assert resp_appended.status_code == 200
    # Exactly 2 new events accepted, all 6 earlier events deduped!
    assert resp_appended.json()["accepted"] == 2

    # 4. Test Deduplication with a Different Filename
    # Re-upload the exact same content under a different filename "renamed_attack.json"
    resp_reupload = client.post(
        "/api/logs/upload",
        files={"file": ("renamed_attack.json", upload_bytes, "application/json")},
    )
    assert resp_reupload.status_code == 200
    # All duplicate events are deduplicated despite different filename
    assert resp_reupload.json()["accepted"] == 0

    # 5. Run Demo Simulation
    service = IncidentService(db)
    # Ingest the standard demo attack dataset
    root = Path(__file__).resolve().parents[2]
    demo_raw = json.loads((root / "data/sample_logs/ssh_attack.json").read_text(encoding="utf-8"))
    accepted, rejected = service.ingest_records(demo_raw, "demo", source_file="ssh_attack.json")
    assert accepted == len(demo_raw)

    # Run detection in demo/simulation mode
    alerts_orm, incident_orms, anomaly_count = service.run_detection_sync(is_simulation=True, batch_id="demo")
    assert len(incident_orms) == 1
    demo_inc = incident_orms[0]
    assert demo_inc.id == "INC-001"
    assert demo_inc.source_ip == "203.0.113.45"

    # 6. Assert Complete Data Isolation:
    # A. Demo incident is INC-001 from 203.0.113.45
    # B. Upload incidents still exist and were not overwritten or merged!
    all_incidents = service.get_incidents()
    inc_ids = {i["id"] for i in all_incidents}
    assert "INC-001" in inc_ids
    assert upload_inc_id_1 in inc_ids
    assert upload_inc_id_2 in inc_ids
    assert len(all_incidents) >= 3

    # 7. Test Demo Reset with Upload Preservation
    service.clear_demo(clear_uploads=False)

    # Demo events, alerts, and incidents are wiped:
    demo_inc_check = db.query(IncidentORM).filter(IncidentORM.batch_id == "demo").all()
    assert len(demo_inc_check) == 0
    demo_evt_check = db.query(EventORM).filter(EventORM.batch_id.notlike("upload-%")).all()
    assert len(demo_evt_check) == 0

    # Upload events, alerts, and incidents remain intact:
    upload_inc_after_reset = db.query(IncidentORM).filter(IncidentORM.batch_id.like("upload-%")).all()
    assert len(upload_inc_after_reset) >= 2

    app.dependency_overrides.clear()
