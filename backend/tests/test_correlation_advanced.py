from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.rules import detect_alerts
from app.correlation.correlator import build_incidents
from app.ingest.normalizer import normalize_event
from app.models.schemas import EventIn

base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

def test_user_and_host_pivot_attachment():
    # Attack setup on server-01 with admin
    events = [
        *[
            {
                "id": f"evt-bf-{i}",
                "timestamp": base + timedelta(seconds=i * 10),
                "source_ip": "203.0.113.50",
                "host": "server-01",
                "event_type": "ssh_failed_login",
                "user": "admin",
                "bytes": 0,
            }
            for i in range(5)
        ],
        {
            "id": "evt-login",
            "timestamp": base + timedelta(minutes=2),
            "source_ip": "203.0.113.50",
            "host": "server-01",
            "event_type": "ssh_success_login",
            "user": "admin",
            "bytes": 0,
        },
        # 1. Matching sudo: admin on server-01 (should attach)
        {
            "id": "evt-sudo-match",
            "timestamp": base + timedelta(minutes=4),
            "source_ip": None,
            "host": "server-01",
            "event_type": "privilege_escalation",
            "user": "admin",
            "bytes": 0,
        },
        # 2. Non-matching user: bob on server-01 (should NOT attach)
        {
            "id": "evt-sudo-other-user",
            "timestamp": base + timedelta(minutes=5),
            "source_ip": None,
            "host": "server-01",
            "event_type": "privilege_escalation",
            "user": "bob",
            "bytes": 0,
        },
        # 3. Non-matching host: admin on server-02 (should NOT attach)
        {
            "id": "evt-sudo-other-host",
            "timestamp": base + timedelta(minutes=6),
            "source_ip": None,
            "host": "server-02",
            "event_type": "privilege_escalation",
            "user": "admin",
            "bytes": 0,
        },
    ]

    alerts = detect_alerts(events)
    events_by_id = {e["id"]: e for e in events}
    incidents = build_incidents(alerts, events_by_id)

    assert len(incidents) == 1
    inc = incidents[0]
    # Check attached timeline event IDs
    attached_eids = {eid for stage in inc["timeline"] for eid in stage["event_ids"]}
    assert "evt-sudo-match" in attached_eids
    assert "evt-sudo-other-user" not in attached_eids
    assert "evt-sudo-other-host" not in attached_eids
    assert inc["affected_hosts"] == ["server-01"]
    assert inc["users"] == ["admin"]


def test_timeline_chronological_ordering():
    events = [
        *[
            {
                "id": f"evt-bf-{i}",
                "timestamp": base + timedelta(seconds=i * 10),
                "source_ip": "203.0.113.55",
                "host": "server-01",
                "event_type": "ssh_failed_login",
                "user": "admin",
                "bytes": 0,
            }
            for i in range(5)
        ],
        {
            "id": "evt-login",
            "timestamp": base + timedelta(minutes=2),
            "source_ip": "203.0.113.55",
            "host": "server-01",
            "event_type": "ssh_success_login",
            "user": "admin",
            "bytes": 0,
        },
        {
            "id": "evt-sudo",
            "timestamp": base + timedelta(minutes=3),
            "source_ip": None,
            "host": "server-01",
            "event_type": "privilege_escalation",
            "user": "admin",
            "bytes": 0,
        },
        {
            "id": "evt-file",
            "timestamp": base + timedelta(minutes=5),
            "source_ip": None,
            "host": "server-01",
            "event_type": "file_access",
            "user": "admin",
            "path": "/etc/shadow",
            "bytes": 0,
        },
        {
            "id": "evt-exfil",
            "timestamp": base + timedelta(minutes=7),
            "source_ip": None,
            "destination_ip": "203.0.113.55",
            "host": "server-01",
            "event_type": "outbound_transfer",
            "user": "admin",
            "bytes": 100 * 1024 * 1024,
        },
    ]

    alerts = detect_alerts(events)
    events_by_id = {e["id"]: e for e in events}
    incidents = build_incidents(alerts, events_by_id)

    assert len(incidents) == 1
    timeline = incidents[0]["timeline"]
    assert len(timeline) == 5
    timestamps = [datetime.fromisoformat(t["ts"]) for t in timeline]
    assert timestamps == sorted(timestamps)


def test_deduplication_preserves_distinct_lines_same_second():
    # Two identical failed login events occurring at the exact same second
    same_time = datetime(2026, 10, 18, 9, 41, 20, tzinfo=timezone.utc)
    ev1 = EventIn(
        timestamp=same_time,
        source_ip="203.0.113.45",
        host="server-01",
        user="admin",
        event_type="ssh_failed_login",
        message="Failed password for admin",
        source_file="auth.log",
        line_offset=101,
    )
    ev2 = EventIn(
        timestamp=same_time,
        source_ip="203.0.113.45",
        host="server-01",
        user="admin",
        event_type="ssh_failed_login",
        message="Failed password for admin",
        source_file="auth.log",
        line_offset=102,
    )

    # Distinct occurrences within the same second have different raw_hashes and ids
    norm1 = normalize_event(ev1, "batch-1", occurrence=1)
    norm2 = normalize_event(ev2, "batch-1", occurrence=2)

    assert norm1["raw_hash"] != norm2["raw_hash"]
    assert norm1["id"] != norm2["id"]

    # Re-normalizing the identical occurrence yields exact same hash
    norm1_repeat = normalize_event(ev1, "batch-1", occurrence=1)
    assert norm1["raw_hash"] == norm1_repeat["raw_hash"]

    # Line offset change (e.g. rotated log) does NOT change hash (line_offset is excluded from hash)
    ev1_rotated = ev1.model_copy(update={"line_offset": 500, "source_file": "auth.log.1"})
    norm1_rotated = normalize_event(ev1_rotated, "batch-1", occurrence=1)
    assert norm1["raw_hash"] == norm1_rotated["raw_hash"]
