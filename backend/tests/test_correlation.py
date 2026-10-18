import json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.detection.rules import detect_alerts
from app.correlation.correlator import build_incidents
from datetime import datetime
ROOT=Path(__file__).resolve().parents[2]

def test_exactly_one_critical_incident():
    records=json.loads((ROOT/"data/sample_logs/ssh_attack.json").read_text())
    for i,r in enumerate(records): r["timestamp"]=datetime.fromisoformat(r["timestamp"].replace("Z","+00:00")); r["id"]=f"evt-{i}"
    alerts=detect_alerts(records); events={r["id"]:r for r in records}
    incidents=build_incidents(alerts,events)
    assert len(incidents)==1
    inc=incidents[0]
    assert inc["severity"]=="critical"
    assert inc["score"]==100
    assert inc["stages"]==["ssh_brute_force","login_after_brute_force","privilege_escalation","sensitive_data_access","exfiltration"]
    assert {m["id"] for m in inc["mitre_techniques"]}=={"T1110.001","T1078","T1548.003","T1005","T1048"}
