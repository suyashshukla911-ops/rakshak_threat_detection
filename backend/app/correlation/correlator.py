from collections import defaultdict
from datetime import datetime, timezone
from app.mitre.mappings import DETECTION_TO_MITRE
from app.correlation.severity import calculate_score, severity_for

GAP = 1800  # 30-minute inactivity window
OPEN_AT = 50  # Entity-risk threshold

def _alert_desc(a, events_by_id: dict[str, dict], source_ip: str) -> str:
    rule = a.rule_id
    event_ids = list(a.event_ids)
    first_event = events_by_id.get(event_ids[0], {}) if event_ids else {}
    if rule == "SSH_BRUTE_FORCE":
        return f"{len(event_ids)} failed SSH logins from {source_ip}"
    elif rule == "PASSWORD_SPRAY":
        return f"Password spraying attempt from {source_ip}"
    elif rule == "LOGIN_AFTER_BRUTE_FORCE":
        u = first_event.get("user") or a.explanation.get("entities", {}).get("user", "user")
        return f"Successful SSH login as {u}"
    elif rule == "EXTERNAL_LOGIN":
        u = first_event.get("user") or a.explanation.get("entities", {}).get("user", "user")
        return f"Successful SSH login from external IP as {u}"
    elif rule == "PRIVILEGE_ESCALATION":
        return "sudo/root shell detected"
    elif rule == "SENSITIVE_DATA_ACCESS":
        paths = a.explanation.get("entities", {}).get("paths") or [first_event.get("path")]
        return f"Sensitive file access: {', '.join(filter(None, paths))}"
    elif rule == "EXFILTRATION":
        bytes_val = first_event.get("bytes", 0) or a.explanation.get("entities", {}).get("bytes", 0)
        gb = bytes_val / (1024 ** 3)
        mb = bytes_val / (1024 ** 2)
        sz = f"{gb:.2f} GB" if gb >= 0.1 else f"{mb:.1f} MB"
        dest = first_event.get("destination_ip") or a.explanation.get("entities", {}).get("destination_ip", "external IP")
        return f"Outbound transfer of {sz} to {dest}"
    return a.title


def build_incidents(alerts: list, events_by_id: dict[str, dict], id_prefix: str = "INC-") -> list[dict]:
    sorted_alerts = sorted(alerts, key=lambda a: a.first_seen)
    if not sorted_alerts:
        return []

    parent = {}
    key_last = {}
    members = defaultdict(list)

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    nid = 0
    for a in sorted_alerts:
        keys = getattr(a, "entity_keys", None) or []
        if not keys:
            ent = a.explanation.get("entities", {})
            if ent.get("source_ip"):
                keys.append(f"ip:{ent['source_ip']}")
            if ent.get("host") and ent.get("user"):
                keys.append(f"u:{ent['host']}|{ent['user']}")
            elif ent.get("host"):
                keys.append(f"h:{ent['host']}")

        roots = {
            find(key_last[k][0])
            for k in keys
            if k in key_last and (a.first_seen - key_last[k][1]).total_seconds() <= GAP
        }

        if roots:
            root = min(roots)
            for r in roots:
                parent[r] = root
        else:
            root = nid
            parent[root] = root
            nid += 1

        for k in keys:
            key_last[k] = (root, a.last_seen or a.first_seen)
        members[root].append(a)

    merged = defaultdict(list)
    for r, ms in members.items():
        merged[find(r)].extend(ms)

    clusters = []
    for ms in merged.values():
        rule_ids = [m.rule_id for m in ms]
        score, sev = calculate_score(rule_ids)
        if score >= OPEN_AT:
            clusters.append((score, sev, ms))

    # Sort clusters by score descending
    clusters.sort(key=lambda c: -c[0])

    incidents = []
    for idx, (score, sev, rel_alerts) in enumerate(clusters, start=1):
        rel_alerts = sorted(rel_alerts, key=lambda a: a.first_seen)

        # Primary source IP
        src_ip = None
        for a in rel_alerts:
            ent = a.explanation.get("entities", {})
            if ent.get("source_ip"):
                src_ip = ent["source_ip"]
                break
        if not src_ip:
            for a in rel_alerts:
                for eid in a.event_ids:
                    ev = events_by_id.get(eid, {})
                    if ev.get("source_ip"):
                        src_ip = ev["source_ip"]
                        break
                if src_ip:
                    break
        if not src_ip:
            for a in rel_alerts:
                ent = a.explanation.get("entities", {})
                if ent.get("destination_ip"):
                    src_ip = ent["destination_ip"]
                    break
        if not src_ip:
            src_ip = "internal"

        # Affected hosts
        hosts = set()
        for a in rel_alerts:
            ent = a.explanation.get("entities", {})
            if ent.get("host"):
                hosts.add(ent["host"])
            for eid in a.event_ids:
                ev = events_by_id.get(eid, {})
                if ev.get("host"):
                    hosts.add(ev["host"])
        affected_hosts = sorted(list(hosts))

        # Affected users
        users = set()
        for a in rel_alerts:
            ent = a.explanation.get("entities", {})
            if ent.get("user"):
                users.add(ent["user"])
        affected_users = sorted(list(users))

        # Timeline
        timeline = []
        for a in rel_alerts:
            desc = _alert_desc(a, events_by_id, src_ip)
            timeline.append({
                "ts": a.first_seen.isoformat(),
                "stage": a.rule_id.lower(),
                "event_ids": list(a.event_ids),
                "description": desc,
                "mitre_id": a.mitre_ids[0] if a.mitre_ids else "",
                "link_reason": a.link_reason or "correlated entity activity",
                "severity": a.severity,
                "anomaly_score": getattr(a, "anomaly_score", None),
            })

        timeline.sort(key=lambda x: x["ts"])
        stages = list(dict.fromkeys(t["stage"] for t in timeline))

        mitres = []
        seen_mitre = set()
        for s in stages:
            rule_key = s.upper()
            if rule_key in DETECTION_TO_MITRE:
                m = DETECTION_TO_MITRE[rule_key]
                if m["id"] not in seen_mitre:
                    mitres.append(m)
                    seen_mitre.add(m["id"])

        incidents.append({
            "id": f"{id_prefix}{idx:03d}",
            "severity": sev,
            "score": score,
            "status": "open",
            "source_ip": src_ip,
            "affected_hosts": affected_hosts,
            "users": affected_users,
            "alert_ids": [],  # Will be populated with AlertORM IDs in incident_service
            "stages": stages,
            "timeline": timeline,
            "mitre_techniques": mitres,
            "enrichment": {},
            "ai_summary": {},
            "_alerts": rel_alerts,
        })

    return incidents
