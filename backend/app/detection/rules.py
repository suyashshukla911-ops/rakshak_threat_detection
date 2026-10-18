from dataclasses import dataclass
from datetime import datetime, timezone
from collections import defaultdict
import fnmatch
import ipaddress
import re
from app.mitre.mappings import get_mitre

ALLOWLISTED_DESTINATIONS = {"10.0.0.10", "192.168.1.50", "172.16.0.5"}

@dataclass
class DetectionAlert:
    rule_id: str
    title: str
    severity: str
    confidence: float
    event_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    mitre_ids: list[str]
    explanation: dict
    link_reason: str | None = None


def is_sensitive_path(path: str | None) -> bool:
    if not path:
        return False
    p = path.strip()
    if p == "/etc/shadow" or p.startswith("/etc/shadow/"):
        return True
    if p.startswith("/var/backups/"):
        return True
    if fnmatch.fnmatch(p, "*.sql") or p.endswith(".sql"):
        return True
    if p.startswith("~/.ssh/") or p.startswith("/root/.ssh/") or re.match(r"^/home/[^/]+/\.ssh/", p):
        return True
    return False


def is_non_private_ip(ip_str: str | None) -> bool:
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        # RFC 5737 / documentation range (203.0.113.0/24) is used in demo/testing
        # Treat as non-private external IP for testing
        doc_net = ipaddress.ip_network("203.0.113.0/24")
        if addr in doc_net:
            return True
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local)
    except ValueError:
        return False


def detect_alerts(events: list[dict]) -> list[DetectionAlert]:
    events = sorted(events, key=lambda e: e["timestamp"])
    alerts: list[DetectionAlert] = []
    by_source_host = defaultdict(list)
    successes = []
    privs = []
    accesses = []
    transfers = []

    for e in events:
        key = (e.get("source_ip"), e.get("host"))
        etype = e.get("event_type")
        if etype == "ssh_failed_login":
            if e.get("source_ip") and e.get("host"):
                by_source_host[key].append(e)
        elif etype == "ssh_success_login":
            successes.append(e)
        elif etype == "privilege_escalation":
            privs.append(e)
        elif etype == "file_access":
            accesses.append(e)
        elif etype == "outbound_transfer":
            transfers.append(e)

    # 1. SSH Brute Force: sliding 120s window, >= 5 failures per (source_ip, host)
    brute_alerts: list[DetectionAlert] = []
    for (src, host), faileds in by_source_host.items():
        n = len(faileds)
        left = 0
        while left < n:
            right = left
            while right < n and (faileds[right]["timestamp"] - faileds[left]["timestamp"]).total_seconds() <= 120:
                right += 1
            count = right - left
            if count >= 5:
                window = faileds[left:right]
                duration = int((window[-1]["timestamp"] - window[0]["timestamp"]).total_seconds())
                sev = "high" if count >= 20 else "medium"
                mitre = get_mitre("SSH_BRUTE_FORCE")
                alert = DetectionAlert(
                    rule_id="SSH_BRUTE_FORCE",
                    title="SSH brute force",
                    severity=sev,
                    confidence=0.9,
                    event_ids=[x["id"] for x in window],
                    first_seen=window[0]["timestamp"],
                    last_seen=window[-1]["timestamp"],
                    mitre_ids=[mitre["id"]],
                    explanation={
                        "threshold": ">=5 failed logins / 120s / same source_ip + host",
                        "observed": f"{count} failed logins in {duration}s",
                        "entities": {"source_ip": src, "host": host},
                    },
                )
                alerts.append(alert)
                brute_alerts.append(alert)
                # Advance past this burst to detect any subsequent bursts from same (src, host)
                left = right
            else:
                left += 1

    # 2. Login After Brute Force: successful login from same (source_ip, host) within 600s (10 min)
    sessions = []
    for brute in brute_alerts:
        src = brute.explanation["entities"]["source_ip"]
        host = brute.explanation["entities"]["host"]
        for s in successes:
            if s.get("source_ip") == src and s.get("host") == host and 0 <= (s["timestamp"] - brute.last_seen).total_seconds() <= 600:
                mitre = get_mitre("LOGIN_AFTER_BRUTE_FORCE")
                delta_s = int((s["timestamp"] - brute.last_seen).total_seconds())
                alert = DetectionAlert(
                    rule_id="LOGIN_AFTER_BRUTE_FORCE",
                    title="Successful login after brute force",
                    severity="high",
                    confidence=0.96,
                    event_ids=[s["id"]],
                    first_seen=s["timestamp"],
                    last_seen=s["timestamp"],
                    mitre_ids=[mitre["id"]],
                    explanation={
                        "threshold": "successful login within 600s of brute-force alert",
                        "observed": f"successful login {delta_s}s after brute-force activity",
                        "entities": {"source_ip": src, "host": host, "user": s.get("user")},
                    },
                    link_reason="seed: same source_ip + host within 10 min of brute-force alert",
                )
                alerts.append(alert)
                sessions.append((s, src, host, brute))

    # 3. Post-login stages: chain extends within 15 min of suspicious login OR previous stage
    for login, src, host, brute in sessions:
        user = login.get("user")
        chain_timestamps = [login["timestamp"]]

        # Privilege escalation: by session user on same host within 15 min of login or prior stage
        for e in privs:
            if e.get("host") == host and e.get("user") == user:
                min_diff = min(abs((e["timestamp"] - t).total_seconds()) for t in chain_timestamps)
                if min_diff <= 900 and e["timestamp"] >= login["timestamp"]:
                    mitre = get_mitre("PRIVILEGE_ESCALATION")
                    delta = int((e["timestamp"] - login["timestamp"]).total_seconds())
                    alerts.append(DetectionAlert(
                        rule_id="PRIVILEGE_ESCALATION",
                        title="Privilege escalation",
                        severity="high",
                        confidence=0.95,
                        event_ids=[e["id"]],
                        first_seen=e["timestamp"],
                        last_seen=e["timestamp"],
                        mitre_ids=[mitre["id"]],
                        explanation={
                            "threshold": "sudo/root shell by session user within 15 min of suspicious login or prior stage",
                            "observed": f"privilege escalation {delta}s after login",
                            "entities": {"host": host, "user": user},
                        },
                        link_reason="session pivot: same user + host after suspicious login",
                    ))
                    chain_timestamps.append(e["timestamp"])

        # Sensitive data access: sensitive paths by session user within 15 min
        matching_accesses = []
        for e in accesses:
            if e.get("host") == host and e.get("user") == user and is_sensitive_path(e.get("path")):
                min_diff = min(abs((e["timestamp"] - t).total_seconds()) for t in chain_timestamps)
                if min_diff <= 900 and e["timestamp"] >= login["timestamp"]:
                    matching_accesses.append(e)

        if matching_accesses:
            mitre = get_mitre("SENSITIVE_DATA_ACCESS")
            paths = [e.get("path") for e in matching_accesses]
            sev = "high" if any("/etc/shadow" in (p or "") for p in paths) else "medium"
            for acc in matching_accesses:
                chain_timestamps.append(acc["timestamp"])
            alerts.append(DetectionAlert(
                rule_id="SENSITIVE_DATA_ACCESS",
                title="Sensitive data access",
                severity=sev,
                confidence=0.92,
                event_ids=[e["id"] for e in matching_accesses],
                first_seen=matching_accesses[0]["timestamp"],
                last_seen=matching_accesses[-1]["timestamp"],
                mitre_ids=[mitre["id"]],
                explanation={
                    "threshold": "sensitive path access by session user within 15 min of suspicious login or prior stage",
                    "observed": f"accessed {len(paths)} sensitive paths: {', '.join(paths)}",
                    "entities": {"host": host, "user": user, "paths": paths},
                },
                link_reason="session pivot: same user + host after suspicious login",
            ))

        # Exfiltration: >50 MB outbound transfer from host to non-private non-allowlisted IP within 15 min of prior stage
        for e in transfers:
            if e.get("host") == host and (not e.get("user") or e.get("user") == user):
                dest = e.get("destination_ip")
                bytes_sent = e.get("bytes", 0)
                if bytes_sent > 50 * 1024 * 1024 and dest and dest not in ALLOWLISTED_DESTINATIONS and is_non_private_ip(dest):
                    min_diff = min(abs((e["timestamp"] - t).total_seconds()) for t in chain_timestamps)
                    if min_diff <= 900 and e["timestamp"] >= login["timestamp"]:
                        mitre = get_mitre("EXFILTRATION")
                        gb_val = bytes_sent / (1024 ** 3)
                        mb_val = bytes_sent / (1024 ** 2)
                        size_str = f"{gb_val:.2f} GB" if gb_val >= 0.1 else f"{mb_val:.1f} MB"
                        alerts.append(DetectionAlert(
                            rule_id="EXFILTRATION",
                            title="Possible data exfiltration",
                            severity="critical",
                            confidence=0.97,
                            event_ids=[e["id"]],
                            first_seen=e["timestamp"],
                            last_seen=e["timestamp"],
                            mitre_ids=[mitre["id"]],
                            explanation={
                                "threshold": ">50 MB to non-private, non-allowlisted IP within 15 min of prior stage",
                                "observed": f"{size_str} outbound to {dest}",
                                "entities": {"host": host, "destination_ip": dest, "bytes": bytes_sent},
                            },
                            link_reason="session stage chain: same host within 15 min of prior stage",
                        ))
                        chain_timestamps.append(e["timestamp"])

    # De-duplicate alerts by rule+event_ids
    unique = {}
    for a in alerts:
        key = (a.rule_id, tuple(a.event_ids))
        unique[key] = a
    return list(unique.values())

