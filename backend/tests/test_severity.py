import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.correlation.severity import calculate_score

def test_score_boundaries():
    assert calculate_score(["SSH_BRUTE_FORCE"])[0]==25
    assert calculate_score(["SSH_BRUTE_FORCE","LOGIN_AFTER_BRUTE_FORCE"])[1]=="medium"
    assert calculate_score(["SSH_BRUTE_FORCE","LOGIN_AFTER_BRUTE_FORCE","PRIVILEGE_ESCALATION","SENSITIVE_DATA_ACCESS","EXFILTRATION"])[1]=="critical"
