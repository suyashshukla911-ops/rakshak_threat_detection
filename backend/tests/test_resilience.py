import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.ai.explainer import AIExplainer
from app.ai.validator import validate_ai_output
from app.enrichment.abuseipdb import AbuseIPDBProvider
from app.detection.anomaly import AnomalyEngine
from app.detection.rules import detect_alerts
from app.correlation.correlator import build_incidents

base = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)

def sample_incident():
    return {
        "id": "INC-001",
        "severity": "critical",
        "score": 100,
        "source_ip": "203.0.113.45",
        "affected_hosts": ["server-01"],
        "users": ["admin"],
        "stages": ["ssh_brute_force", "login_after_brute_force"],
        "timeline": [
            {
                "ts": "2026-10-18T09:41:00Z",
                "stage": "ssh_brute_force",
                "event_ids": ["evt-1"],
                "description": "5 failed logins",
                "mitre_id": "T1110.001",
                "link_reason": "seed",
            },
            {
                "ts": "2026-10-18T09:43:00Z",
                "stage": "login_after_brute_force",
                "event_ids": ["evt-2"],
                "description": "login as admin",
                "mitre_id": "T1078",
                "link_reason": "session pivot",
            }
        ],
        "mitre_techniques": [{"id": "T1110.001", "name": "Brute Force"}, {"id": "T1078", "name": "Valid Accounts"}],
    }


def test_ai_unavailable_returns_deterministic_report():
    explainer = AIExplainer()
    # No API key configured
    status, report, meta = asyncio.run(explainer.generate(sample_incident()))
    assert status == "unavailable"
    assert "executive_summary" in report
    assert "evidence_refs" in report
    assert meta["model"] == "deterministic-template"


def test_ai_fabricated_id_falls_back():
    inc = sample_incident()
    bad_payload = {
        "executive_summary": "Test summary",
        "attack_narrative": "Test narrative",
        "why_detected": ["Detection reason"],
        "potential_impact": "Impact",
        "investigation_steps": ["Check logs"],
        "evidence_refs": ["evt-nonexistent-999"],
    }
    ok, validated, reason = validate_ai_output(bad_payload, inc)
    assert not ok
    assert "fabricated" in reason


def test_threat_intel_failure_degrades_gracefully():
    # AbuseIPDB with no key on a public IP returns unavailable
    provider = AbuseIPDBProvider(api_key=None)
    result = provider.lookup("8.8.8.8")
    assert result["available"] is False
    assert result["provider"] == "abuseipdb"
    assert "Threat intel: unavailable" in result.get("reason", "")

    # Private or reserved IP returns private_or_reserved without network request
    priv_result = provider.lookup("10.0.0.1")
    assert priv_result["available"] is False
    assert priv_result["reason"] == "private_or_reserved"



def test_ml_failure_allows_rules_to_continue():
    engine = AnomalyEngine()
    # Simulate missing model
    engine.model = None
    engine.status = "unavailable"

    events = [
        *[
            {
                "id": f"evt-{i}",
                "timestamp": base + timedelta(seconds=i * 10),
                "source_ip": "203.0.113.45",
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
            "source_ip": "203.0.113.45",
            "host": "server-01",
            "event_type": "ssh_success_login",
            "user": "admin",
            "bytes": 0,
        }
    ]

    # Rule detection and correlation must succeed regardless of ML model failure
    alerts = detect_alerts(events)
    assert len(alerts) >= 2
    incidents = build_incidents(alerts, {e["id"]: e for e in events})
    assert len(incidents) == 1
    assert incidents[0]["severity"] == "medium"
