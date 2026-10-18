# Detection Rules

- SSH_BRUTE_FORCE: >=5 failed SSH logins / 120s / same source IP + host. High if >=20.
- LOGIN_AFTER_BRUTE_FORCE: successful login from an IP with brute-force alert in prior 10 min.
- PRIVILEGE_ESCALATION: sudo/root shell by session user on same host within 15 min of suspicious login.
- SENSITIVE_DATA_ACCESS: sensitive path access by session user within 15 min of suspicious login.
- EXFILTRATION: >50 MB outbound transfer to non-private, non-allowlisted IP within 15 min of prior stage.
