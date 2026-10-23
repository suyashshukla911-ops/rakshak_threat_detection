import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.ai.validator import validate_ai_output
from app.ai.template_report import deterministic_report

ROOT = Path(__file__).resolve().parents[2]

def _get_demo_incident_and_report():
    facts_report = json.loads((ROOT / "data/fixtures/test_facts.json").read_text(encoding="utf-8"))
    facts = facts_report["facts"]
    good_report = facts_report["report"]
    return facts, good_report


def test_template_report_passes_grounding():
    facts, good_report = _get_demo_incident_and_report()
    ok, res, reason = validate_ai_output(good_report, facts)
    assert ok, f"Template report should pass grounding, failed: {reason}"
    assert res is not None


def test_paraphrased_valid_report_passes_grounding():
    facts, good_report = _get_demo_incident_and_report()
    paraphrase = dict(good_report)
    paraphrase["executive_summary"] = (
        "Source 203.0.113.45 brute-forced server-01, logged in as admin, "
        "escalated with sudo, read /etc/shadow and sent a large transfer out."
    )
    ok, res, reason = validate_ai_output(paraphrase, facts)
    assert ok, f"Valid paraphrase should pass grounding, failed: {reason}"


def test_rejects_invented_counts():
    facts, good_report = _get_demo_incident_and_report()
    bad = dict(good_report)
    bad["executive_summary"] = "The attacker made 4,000 failed attempts then compromised root."
    ok, _, reason = validate_ai_output(bad, facts)
    assert not ok
    assert "ungrounded fact" in reason and "4000" in reason


def test_rejects_invented_hostname_and_storage():
    facts, good_report = _get_demo_incident_and_report()
    bad = dict(good_report)
    bad["executive_summary"] = "prod-db-09 lost 50 TB of customer data."
    ok, _, reason = validate_ai_output(bad, facts)
    assert not ok
    assert "ungrounded fact" in reason


def test_rejects_invented_domain():
    facts, good_report = _get_demo_incident_and_report()
    bad = dict(good_report)
    bad["executive_summary"] = "Payload fetched from evil-c2.example.com."
    ok, _, reason = validate_ai_output(bad, facts)
    assert not ok
    assert "ungrounded fact" in reason and "evil-c2.example.com" in reason


def test_rejects_invented_ipv6():
    facts, good_report = _get_demo_incident_and_report()
    bad = dict(good_report)
    bad["executive_summary"] = "Also seen from 2001:db8::bad:1."
    ok, _, reason = validate_ai_output(bad, facts)
    assert not ok
    assert "ungrounded fact" in reason


def test_rejects_invented_path():
    facts, good_report = _get_demo_incident_and_report()
    bad = dict(good_report)
    bad["executive_summary"] = "The attacker read /opt/secret/keys.pem."
    ok, _, reason = validate_ai_output(bad, facts)
    assert not ok
    assert "ungrounded fact" in reason and "keys.pem" in reason


def test_rejects_invented_account():
    facts, good_report = _get_demo_incident_and_report()
    bad = dict(good_report)
    bad["executive_summary"] = "Account svc_deploy2 was also used."
    ok, _, reason = validate_ai_output(bad, facts)
    assert not ok
    assert "ungrounded fact" in reason and "svc_deploy2" in reason
