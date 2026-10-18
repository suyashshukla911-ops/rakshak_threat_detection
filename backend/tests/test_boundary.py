from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection.rules import detect_alerts

def test_brute_force_failure_count_boundary():
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)
    
    # 4 failures within 120s (below threshold of 5)
    below_threshold = [
        {
            "id": f"evt-fail-{i}",
            "timestamp": base + timedelta(seconds=i * 20),
            "source_ip": "198.51.100.100",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "user": "alice",
            "bytes": 0,
        }
        for i in range(4)
    ]
    alerts_below = detect_alerts(below_threshold)
    assert not any(a.rule_id == "SSH_BRUTE_FORCE" for a in alerts_below)

    # Exactly 5 failures within 120s (meets threshold)
    at_threshold = below_threshold + [{
        "id": "evt-fail-4",
        "timestamp": base + timedelta(seconds=80),
        "source_ip": "198.51.100.100",
        "host": "server-01",
        "event_type": "ssh_failed_login",
        "user": "alice",
        "bytes": 0,
    }]
    alerts_at = detect_alerts(at_threshold)
    brute = [a for a in alerts_at if a.rule_id == "SSH_BRUTE_FORCE"]
    assert len(brute) == 1
    assert len(brute[0].event_ids) == 5


def test_brute_force_time_window_boundary():
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

    # 5 failures in 119 seconds (within 120s window -> fires)
    within_window = [
        {
            "id": f"evt-win-{i}",
            "timestamp": base + timedelta(seconds=sec),
            "source_ip": "198.51.100.101",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "user": "bob",
            "bytes": 0,
        }
        for i, sec in enumerate([0, 25, 50, 75, 119])
    ]
    alerts_within = detect_alerts(within_window)
    assert any(a.rule_id == "SSH_BRUTE_FORCE" for a in alerts_within)

    # 5 failures in 121 seconds (exceeds 120s window -> does not fire)
    outside_window = [
        {
            "id": f"evt-out-{i}",
            "timestamp": base + timedelta(seconds=sec),
            "source_ip": "198.51.100.102",
            "host": "server-01",
            "event_type": "ssh_failed_login",
            "user": "bob",
            "bytes": 0,
        }
        for i, sec in enumerate([0, 30, 60, 90, 121])
    ]
    alerts_outside = detect_alerts(outside_window)
    assert not any(a.rule_id == "SSH_BRUTE_FORCE" for a in alerts_outside)


def test_exfiltration_size_boundary():
    base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)
    
    # Prerequisite session to test exfiltration rule
    events_49mb = [
        # Brute force
        *[
            {
                "id": f"evt-bf-{i}",
                "timestamp": base + timedelta(seconds=i * 10),
                "source_ip": "203.0.113.88",
                "host": "server-01",
                "event_type": "ssh_failed_login",
                "user": "root",
                "bytes": 0,
            }
            for i in range(5)
        ],
        # Login
        {
            "id": "evt-login",
            "timestamp": base + timedelta(minutes=2),
            "source_ip": "203.0.113.88",
            "host": "server-01",
            "event_type": "ssh_success_login",
            "user": "root",
            "bytes": 0,
        },
        # 49 MB outbound transfer (below 50 MB threshold)
        {
            "id": "evt-transfer-49",
            "timestamp": base + timedelta(minutes=4),
            "source_ip": None,
            "destination_ip": "203.0.113.88",
            "host": "server-01",
            "event_type": "outbound_transfer",
            "user": "root",
            "bytes": 49 * 1024 * 1024,
            "process": "scp",
        }
    ]
    alerts_49 = detect_alerts(events_49mb)
    assert not any(a.rule_id == "EXFILTRATION" for a in alerts_49)

    # 51 MB outbound transfer (exceeds 50 MB threshold)
    events_51mb = list(events_49mb)
    events_51mb[-1] = {
        "id": "evt-transfer-51",
        "timestamp": base + timedelta(minutes=4),
        "source_ip": None,
        "destination_ip": "203.0.113.88",
        "host": "server-01",
        "event_type": "outbound_transfer",
        "user": "root",
        "bytes": 51 * 1024 * 1024,
        "process": "scp",
    }
    alerts_51 = detect_alerts(events_51mb)
    exfil = [a for a in alerts_51 if a.rule_id == "EXFILTRATION"]
    assert len(exfil) == 1
    assert "51.0 MB" in exfil[0].explanation["observed"] or "0.05 GB" in exfil[0].explanation["observed"]
