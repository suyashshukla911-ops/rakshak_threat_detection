WEIGHTS = {
    "SSH_BRUTE_FORCE": 25,
    "LOGIN_AFTER_BRUTE_FORCE": 25,
    "PRIVILEGE_ESCALATION": 20,
    "SENSITIVE_DATA_ACCESS": 15,
    "EXFILTRATION": 15,
}

def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"

def calculate_score(rule_ids: list[str]) -> tuple[int, str]:
    score = min(100, sum(WEIGHTS.get(r, 0) for r in set(rule_ids)))
    return score, severity_for(score)

