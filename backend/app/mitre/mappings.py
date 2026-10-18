DETECTION_TO_MITRE = {
    "SSH_BRUTE_FORCE": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1110/001/"},
    "LOGIN_AFTER_BRUTE_FORCE": {"id": "T1078", "name": "Valid Accounts", "tactic": "Stealth / Persistence / Privilege Escalation / Initial Access", "url": "https://attack.mitre.org/techniques/T1078/"},
    "PRIVILEGE_ESCALATION": {"id": "T1548.003", "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "tactic": "Privilege Escalation", "url": "https://attack.mitre.org/techniques/T1548/003/"},
    "SENSITIVE_DATA_ACCESS": {"id": "T1005", "name": "Data from Local System", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1005/"},
    "EXFILTRATION": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "url": "https://attack.mitre.org/techniques/T1048/"},
}


def get_mitre(rule_id: str) -> dict:
    return DETECTION_TO_MITRE[rule_id]
