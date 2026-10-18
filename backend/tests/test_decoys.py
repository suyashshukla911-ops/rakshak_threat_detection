from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.rules import detect_alerts
from app.correlation.correlator import build_incidents

base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

def test_decoy_1_three_failures_no_incident():
    events = [
        {
            "id": f"d1-{i}",
            "timestamp": base + timedelta(seconds=i * 20),
            "source_ip": "198.51.100.10",
            "destination_ip": None,
            "user": "alice",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "bytes": 0,
        }
        for i in range(3)
    ]
    alerts = detect_alerts(events)
    incidents = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incidents) == 0


def test_decoy_2_four_mistypes_then_login_no_incident():
    events = [
        {
            "id": f"d2-{i}",
            "timestamp": base + timedelta(seconds=i * 20),
            "source_ip": "198.51.100.11",
            "destination_ip": None,
            "user": "bob",
            "host": "server-02",
            "event_type": "ssh_failed_login",
            "bytes": 0,
        }
        for i in range(4)
    ]
    events.append({
        "id": "d2-login",
        "timestamp": base + timedelta(seconds=90),
        "source_ip": "198.51.100.11",
        "destination_ip": None,
        "user": "bob",
        "host": "server-02",
        "event_type": "ssh_success_login",
        "bytes": 0,
    })
    alerts = detect_alerts(events)
    incidents = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incidents) == 0


def test_decoy_3_routine_admin_sudo_no_incident():
    events = [{
        "id": "d3-sudo",
        "timestamp": base + timedelta(minutes=20),
        "source_ip": "10.0.0.20",
        "destination_ip": None,
        "user": "admin",
        "host": "server-02",
        "event_type": "privilege_escalation",
        "bytes": 0,
        "process": "sudo",
    }]
    alerts = detect_alerts(events)
    incidents = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incidents) == 0


def test_decoy_4_nightly_backup_no_incident():
    events = [{
        "id": "d4-backup",
        "timestamp": base + timedelta(minutes=25),
        "source_ip": "10.0.0.30",
        "destination_ip": "10.0.0.10",
        "user": "backup",
        "host": "server-03",
        "event_type": "outbound_transfer",
        "bytes": 2 * 1024 * 1024 * 1024,
        "process": "backupd",
    }]
    alerts = detect_alerts(events)
    incidents = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incidents) == 0


def test_all_decoys_and_near_misses_together_produce_zero_incidents():
    decoy_events = []
    
    # Decoy 1: 3 failures
    for i in range(3):
        decoy_events.append({
            "id": f"d1-{i}",
            "timestamp": base + timedelta(minutes=10, seconds=i * 20),
            "source_ip": "198.51.100.10",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "user": "alice",
            "bytes": 0,
        })
        
    # Decoy 2: 4 mistypes + login
    for i in range(4):
        decoy_events.append({
            "id": f"d2-{i}",
            "timestamp": base + timedelta(minutes=15, seconds=i * 20),
            "source_ip": "198.51.100.11",
            "host": "server-02",
            "event_type": "ssh_failed_login",
            "user": "bob",
            "bytes": 0,
        })
    decoy_events.append({
        "id": "d2-login",
        "timestamp": base + timedelta(minutes=16, seconds=50),
        "source_ip": "198.51.100.11",
        "host": "server-02",
        "event_type": "ssh_success_login",
        "user": "bob",
        "bytes": 0,
    })
    
    # Decoy 3: routine admin sudo
    decoy_events.append({
        "id": "d3-sudo",
        "timestamp": base + timedelta(minutes=20),
        "source_ip": "10.0.0.20",
        "host": "server-02",
        "event_type": "privilege_escalation",
        "user": "admin",
        "bytes": 0,
    })
    
    # Decoy 4: nightly backup
    decoy_events.append({
        "id": "d4-backup",
        "timestamp": base + timedelta(minutes=25),
        "source_ip": "10.0.0.30",
        "destination_ip": "10.0.0.10",
        "host": "server-03",
        "event_type": "outbound_transfer",
        "user": "backup",
        "bytes": 2 * 1024 * 1024 * 1024,
    })
    
    # Near-miss 1: admin sudo before login
    decoy_events.append({
        "id": "nm1-sudo",
        "timestamp": base + timedelta(minutes=12),
        "source_ip": "10.0.0.25",
        "host": "server-01",
        "event_type": "privilege_escalation",
        "user": "admin",
        "bytes": 0,
    })
    
    # Near-miss 3a: 4 failures in 120s
    for i in range(4):
        decoy_events.append({
            "id": f"nm3a-{i}",
            "timestamp": base + timedelta(minutes=22, seconds=i * 25),
            "source_ip": "198.51.100.33",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "user": "dave",
            "bytes": 0,
        })
        
    # Near-miss 3b: 5 failures in 121s
    for sec in [0, 30, 60, 90, 121]:
        decoy_events.append({
            "id": f"nm3b-{sec}",
            "timestamp": base + timedelta(minutes=26, seconds=sec),
            "source_ip": "198.51.100.34",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "user": "dave",
            "bytes": 0,
        })
        
    # Near-miss 4: 49 MB transfer
    decoy_events.append({
        "id": "nm4-transfer",
        "timestamp": base + timedelta(minutes=30),
        "source_ip": "10.0.0.15",
        "destination_ip": "198.51.100.77",
        "host": "server-01",
        "event_type": "outbound_transfer",
        "user": "alice",
        "bytes": 49 * 1024 * 1024,
    })

    alerts = detect_alerts(decoy_events)
    events_by_id = {e["id"]: e for e in decoy_events}
    incidents = build_incidents(alerts, events_by_id)
    assert len(incidents) == 0, f"Expected 0 incidents from decoys, but got: {incidents}"
