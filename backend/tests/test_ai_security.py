from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.ai.validator import validate_ai_output

def incident():
    return {"timeline":[{"event_ids":["evt-1"]}],"mitre_techniques":[{"id":"T1110.001"}]}

def test_rejects_fabricated_evidence():
    payload={"executive_summary":"x","attack_narrative":"x","why_detected":[],"potential_impact":"x","investigation_steps":[],"evidence_refs":["evt-999"]}
    ok,_,reason=validate_ai_output(payload,incident())
    assert not ok and "evidence" in reason

def test_rejects_command_pattern():
    payload={"executive_summary":"x","attack_narrative":"x","why_detected":[],"potential_impact":"x","investigation_steps":["sudo rm -rf /"],"evidence_refs":["evt-1"]}
    ok,_,reason=validate_ai_output(payload,incident())
    assert not ok
