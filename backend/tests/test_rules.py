import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.detection.rules import detect_alerts

ROOT=Path(__file__).resolve().parents[2]

def test_attack_rules_and_decoys():
    records=json.loads((ROOT/"data/sample_logs/ssh_attack.json").read_text())
    # timestamps from JSON are strings; normalize only the field needed for the rule function
    from datetime import datetime
    for r in records: r["timestamp"]=datetime.fromisoformat(r["timestamp"].replace("Z","+00:00")); r["id"]=str(id(r))
    alerts=detect_alerts(records)
    rules={a.rule_id for a in alerts}
    assert {"SSH_BRUTE_FORCE","LOGIN_AFTER_BRUTE_FORCE","PRIVILEGE_ESCALATION","SENSITIVE_DATA_ACCESS","EXFILTRATION"}.issubset(rules)
    brute=[a for a in alerts if a.rule_id=="SSH_BRUTE_FORCE"]
    assert len(brute)==1
    assert "203.0.113.45" == brute[0].explanation["entities"]["source_ip"]
