from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.detection.rules import detect_alerts
from app.correlation.correlator import build_incidents

T0 = datetime(2026, 10, 18, 9, 0, tzinfo=timezone.utc)
GB = 1024 ** 3

def _ev(sec, etype, **kw):
    d = dict(
        id=f"e_{sec}_{etype}_{kw.get('host', 's1')}",
        timestamp=T0 + timedelta(seconds=sec),
        source_ip=None,
        destination_ip=None,
        user="admin",
        host="server-01",
        event_type=etype,
        severity="low",
        message="",
        bytes=0,
        process=None,
        path=None,
    )
    d.update(kw)
    return d


def test_scenario_a_exfil_shadow_sudo_no_brute():
    events = [
        _ev(0, "privilege_escalation"),
        _ev(10, "file_access", path="/etc/shadow"),
        _ev(20, "outbound_transfer", destination_ip="8.8.8.8", bytes=5 * GB),
    ]
    alerts = detect_alerts(events)
    incs = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incs) == 1
    inc = incs[0]
    assert inc["score"] >= 50
    assert "privilege_escalation" in inc["stages"]
    assert "sensitive_data_access" in inc["stages"]
    assert "exfiltration" in inc["stages"]


def test_scenario_b_stolen_credentials_external_login():
    events = [
        _ev(0, "ssh_success_login", source_ip="203.0.113.45"),
        _ev(60, "privilege_escalation"),
        _ev(90, "file_access", path="/etc/shadow"),
        _ev(120, "outbound_transfer", destination_ip="45.33.32.156", bytes=2 * GB),
    ]
    alerts = detect_alerts(events)
    incs = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incs) == 1
    inc = incs[0]
    assert inc["score"] >= 50
    assert "external_login" in inc["stages"]
    assert inc["source_ip"] == "203.0.113.45"


def test_scenario_c_low_and_slow_brute_force():
    events = [
        _ev(w * 125 + i * 20, "ssh_failed_login", source_ip="203.0.113.45")
        for w in range(30)
        for i in range(4)
    ] + [_ev(30 * 125 + 5, "ssh_success_login", source_ip="203.0.113.45")]
    alerts = detect_alerts(events)
    incs = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incs) == 1
    inc = incs[0]
    assert inc["score"] >= 50
    assert "ssh_brute_force" in inc["stages"]
    assert "login_after_brute_force" in inc["stages"]


def test_scenario_d_password_spraying():
    events = [
        _ev(i * 40, "ssh_failed_login", source_ip="203.0.113.45", host=f"srv-{i}", user=f"u{i}")
        for i in range(60)
    ]
    alerts = detect_alerts(events)
    incs = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incs) == 1
    inc = incs[0]
    assert inc["score"] >= 50
    assert "password_spray" in inc["stages"]


def test_scenario_e_brute_then_multiple_accounts():
    fails = [_ev(i * 2, "ssh_failed_login", source_ip="203.0.113.45") for i in range(10)]
    events = fails + [
        _ev(30, "ssh_success_login", source_ip="203.0.113.45", user="svc_backup"),
        _ev(40, "ssh_success_login", source_ip="203.0.113.45", user="admin"),
        _ev(90, "privilege_escalation", user="admin"),
        _ev(100, "file_access", path="/etc/shadow", user="admin"),
    ]
    alerts = detect_alerts(events)
    incs = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incs) == 1
    inc = incs[0]
    assert inc["score"] >= 50
    assert set(inc["users"]) == {"admin", "svc_backup"}


def test_scenario_h_cross_host_hop():
    fails = [_ev(i * 2, "ssh_failed_login", source_ip="203.0.113.45", host="server-01") for i in range(10)]
    events = fails + [
        _ev(30, "ssh_success_login", source_ip="203.0.113.45", host="server-02"),
    ]
    alerts = detect_alerts(events)
    incs = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incs) == 1
    inc = incs[0]
    assert inc["score"] >= 50
    assert set(inc["affected_hosts"]) == {"server-01", "server-02"}
