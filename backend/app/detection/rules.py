from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
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
    entity_keys: list[str] = field(default_factory=list)


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


def _window_hits(times: list[datetime], span: int, need: int):
    """two-pointer: yield (start_idx, end_idx) of non-overlapping windows with >= need items inside span seconds"""
    i = 0
    n = len(times)
    while i < n:
        j = i
        while j < n and (times[j] - times[i]).total_seconds() <= span:
            j += 1
        if j - i >= need:
            yield i, j
            i = j
        else:
            i += 1


def detect_alerts(events: list[dict]) -> list[DetectionAlert]:
    events = sorted(events, key=lambda e: e["timestamp"])
    alerts: list[DetectionAlert] = []

    fails_ih = defaultdict(list)
    fails_by_ip = defaultdict(list)
    successes = []
    privs = []
    accesses = []
    transfers = []

    for e in events:
        etype = e.get("event_type")
        ip = e.get("source_ip")
        host = e.get("host")
        if etype == "ssh_failed_login":
            if ip and host:
                fails_ih[(ip, host)].append(e)
            if ip:
                fails_by_ip[ip].append(e)
        elif etype == "ssh_success_login":
            successes.append(e)
        elif etype == "privilege_escalation":
            privs.append(e)
        elif etype == "file_access":
            if is_sensitive_path(e.get("path")):
                accesses.append(e)
        elif etype == "outbound_transfer":
            dest = e.get("destination_ip")
            if (e.get("bytes") or 0) > 50 * 1024 * 1024 and dest and dest not in ALLOWLISTED_DESTINATIONS and is_non_private_ip(dest):
                transfers.append(e)

    # 1. SSH Brute Force (burst): sliding 120s window, >= 5 failures per (source_ip, host)
    burst_ts_by_ip = defaultdict(list)
    for (src, host), fl in fails_ih.items():
        ts = [x["timestamp"] for x in fl]
        for a, b in _window_hits(ts, 120, 5):
            window = fl[a:b]
            count = b - a
            duration = int((window[-1]["timestamp"] - window[0]["timestamp"]).total_seconds())
            sev = "high" if count >= 20 else "medium"
            mitre = get_mitre("SSH_BRUTE_FORCE")
            burst_ts_by_ip[src].append(window[-1]["timestamp"])
            alerts.append(DetectionAlert(
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
                link_reason=f"failed login burst: {count} failures in <=120s",
                entity_keys=[f"ip:{src}"],
            ))

    # 2. Low-and-Slow Brute Force: >= 20 failures in <= 3600s per source_ip (duration > 120s)
    slow_ts_by_ip = defaultdict(list)
    for src, fl in fails_by_ip.items():
        ts = [x["timestamp"] for x in fl]
        for a, b in _window_hits(ts, 3600, 20):
            window = fl[a:b]
            duration = int((window[-1]["timestamp"] - window[0]["timestamp"]).total_seconds())
            if duration > 120:
                count = b - a
                mitre = get_mitre("SSH_BRUTE_FORCE")
                slow_ts_by_ip[src].append(window[-1]["timestamp"])
                alerts.append(DetectionAlert(
                    rule_id="SSH_BRUTE_FORCE",
                    title="Low-and-slow SSH brute force",
                    severity="high",
                    confidence=0.9,
                    event_ids=[x["id"] for x in window],
                    first_seen=window[0]["timestamp"],
                    last_seen=window[-1]["timestamp"],
                    mitre_ids=[mitre["id"]],
                    explanation={
                        "threshold": ">=20 failed logins / 3600s / same source_ip",
                        "observed": f"{count} failed logins in {duration}s",
                        "entities": {"source_ip": src},
                    },
                    link_reason=f"low-and-slow brute force: {count} failures in <=1h",
                    entity_keys=[f"ip:{src}"],
                ))

    # 3. Password Spray: >= 15 distinct (host, user) targets in <= 600s per source_ip
    for src, fl in fails_by_ip.items():
        ts = [x["timestamp"] for x in fl]
        pairs = [(x.get("host"), x.get("user")) for x in fl]
        for a, b in _window_hits(ts, 600, 15):
            window = fl[a:b]
            targets = set(pairs[a:b])
            if len(targets) >= 15:
                duration = int((window[-1]["timestamp"] - window[0]["timestamp"]).total_seconds())
                mitre = get_mitre("PASSWORD_SPRAY")
                slow_ts_by_ip[src].append(window[-1]["timestamp"])
                alerts.append(DetectionAlert(
                    rule_id="PASSWORD_SPRAY",
                    title="Password spraying attempt",
                    severity="high",
                    confidence=0.92,
                    event_ids=[x["id"] for x in window],
                    first_seen=window[0]["timestamp"],
                    last_seen=window[-1]["timestamp"],
                    mitre_ids=[mitre["id"]],
                    explanation={
                        "threshold": ">=15 distinct (host, user) targets / 600s / same source_ip",
                        "observed": f"{len(targets)} distinct targets in {duration}s",
                        "entities": {"source_ip": src},
                    },
                    link_reason=f"password spraying: {len(targets)} distinct targets in <=10min",
                    entity_keys=[f"ip:{src}"],
                ))

    # 4. Successful Logins: Login After Brute Force or External Login
    logins = defaultdict(list)  # (host, user) -> [(login_ts, sess_key)]
    for s in successes:
        src = s.get("source_ip")
        host = s.get("host")
        user = s.get("user")
        if not src or not host:
            continue
        ts = s["timestamp"]
        sess = f"s:{host}|{user}@{ts.isoformat()}"

        burst_priors = [b for b in burst_ts_by_ip.get(src, []) if timedelta(0) <= ts - b <= timedelta(seconds=600)]
        slow_priors = [b for b in slow_ts_by_ip.get(src, []) if timedelta(0) <= ts - b <= timedelta(seconds=3600)]

        if burst_priors or slow_priors:
            last_prior = max(burst_priors + slow_priors)
            delta_s = int((ts - last_prior).total_seconds())
            logins[(host, user)].append((ts, sess))
            mitre = get_mitre("LOGIN_AFTER_BRUTE_FORCE")
            alerts.append(DetectionAlert(
                rule_id="LOGIN_AFTER_BRUTE_FORCE",
                title="Successful login after brute force",
                severity="high",
                confidence=0.96,
                event_ids=[s["id"]],
                first_seen=ts,
                last_seen=ts,
                mitre_ids=[mitre["id"]],
                explanation={
                    "threshold": "successful login within 600s of burst or 3600s of failure activity",
                    "observed": f"successful login {delta_s}s after failure activity",
                    "entities": {"source_ip": src, "host": host, "user": user},
                },
                link_reason="seed: same source_ip within failure window",
                entity_keys=[f"ip:{src}", sess],
            ))
        elif is_non_private_ip(src):
            had_old_burst = any(b < ts for b in burst_ts_by_ip.get(src, []))
            if not had_old_burst:
                logins[(host, user)].append((ts, sess))
                mitre = get_mitre("EXTERNAL_LOGIN")
                alerts.append(DetectionAlert(
                    rule_id="EXTERNAL_LOGIN",
                    title="SSH login from external IP",
                    severity="medium",
                    confidence=0.85,
                    event_ids=[s["id"]],
                    first_seen=ts,
                    last_seen=ts,
                    mitre_ids=[mitre["id"]],
                    explanation={
                        "threshold": "login from external/non-private IP",
                        "observed": f"successful login from external IP {src}",
                        "entities": {"source_ip": src, "host": host, "user": user},
                    },
                    link_reason="initial access: login from external IP",
                    entity_keys=[f"ip:{src}", sess],
                ))

    def session_for(host, user, ts):
        for lts, skey in reversed(logins.get((host, user), [])):
            if lts <= ts <= lts + timedelta(minutes=30):
                return skey
        return f"u:{host}|{user}"

    # 5. Privilege Escalation
    for e in privs:
        host = e.get("host")
        user = e.get("user")
        sess = session_for(host, user, e["timestamp"])
        mitre = get_mitre("PRIVILEGE_ESCALATION")
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
                "threshold": "sudo/root shell privilege escalation",
                "observed": "sudo/root shell detected",
                "entities": {"host": host, "user": user},
            },
            link_reason="session pivot: privilege escalation",
            entity_keys=[sess],
        ))

    # 6. Sensitive Data Access: Group by (sess, host, user) within 30 min
    accesses_by_sess = defaultdict(list)
    for e in accesses:
        host = e.get("host")
        user = e.get("user")
        sess = session_for(host, user, e["timestamp"])
        accesses_by_sess[(sess, host, user)].append(e)

    for (sess, host, user), grp in accesses_by_sess.items():
        paths = [x.get("path") for x in grp]
        mitre = get_mitre("SENSITIVE_DATA_ACCESS")
        sev = "high" if any("/etc/shadow" in (p or "") for p in paths) else "medium"
        alerts.append(DetectionAlert(
            rule_id="SENSITIVE_DATA_ACCESS",
            title="Sensitive data access",
            severity=sev,
            confidence=0.92,
            event_ids=[x["id"] for x in grp],
            first_seen=grp[0]["timestamp"],
            last_seen=grp[-1]["timestamp"],
            mitre_ids=[mitre["id"]],
            explanation={
                "threshold": "sensitive path access by user or session",
                "observed": f"accessed {len(paths)} sensitive paths: {', '.join(filter(None, paths))}",
                "entities": {"host": host, "user": user, "paths": paths},
            },
            link_reason="session pivot: sensitive data access",
            entity_keys=[sess],
        ))

    # 7. Exfiltration: >50 MB outbound transfer to non-private external IP
    for e in transfers:
        host = e.get("host")
        user = e.get("user")
        dest = e.get("destination_ip")
        bytes_sent = e.get("bytes", 0)
        sess = session_for(host, user, e["timestamp"]) if user else f"h:{host}"
        gb_val = bytes_sent / (1024 ** 3)
        mb_val = bytes_sent / (1024 ** 2)
        size_str = f"{gb_val:.2f} GB" if gb_val >= 0.1 else f"{mb_val:.1f} MB"
        mitre = get_mitre("EXFILTRATION")
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
                "threshold": ">50 MB to non-private, non-allowlisted external IP",
                "observed": f"{size_str} outbound to {dest}",
                "entities": {"host": host, "destination_ip": dest, "bytes": bytes_sent},
            },
            link_reason="exfiltration: large outbound transfer",
            entity_keys=[sess],
        ))

    # De-duplicate alerts by rule+event_ids
    unique = {}
    for a in alerts:
        key = (a.rule_id, tuple(a.event_ids))
        unique[key] = a
    return list(unique.values())

