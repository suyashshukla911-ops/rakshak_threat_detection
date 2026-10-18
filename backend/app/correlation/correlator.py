from collections import defaultdict
from datetime import datetime, timezone
from app.mitre.mappings import DETECTION_TO_MITRE
from app.correlation.severity import calculate_score, severity_for

STAGES_ORDER = [
    "SSH_BRUTE_FORCE",
    "LOGIN_AFTER_BRUTE_FORCE",
    "PRIVILEGE_ESCALATION",
    "SENSITIVE_DATA_ACCESS",
    "EXFILTRATION",
]

def _alert_desc(a, events_by_id: dict[str, dict], source_ip: str) -> str:
    rule = a.rule_id
    event_ids = list(a.event_ids)
    first_event = events_by_id.get(event_ids[0], {}) if event_ids else {}
    if rule == "SSH_BRUTE_FORCE":
        return f"{len(event_ids)} failed SSH logins from {source_ip}"
    elif rule == "LOGIN_AFTER_BRUTE_FORCE":
        u = first_event.get("user") or a.explanation.get("entities", {}).get("user", "user")
        return f"Successful SSH login as {u}"
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


def build_candidate_incident(seed, alerts: list, events_by_id: dict[str, dict]) -> dict | None:
    source_ip = seed.explanation["entities"]["source_ip"]
    host = seed.explanation["entities"]["host"]
    
    # Candidate must have a successful login following brute force
    logins = [
        a for a in alerts
        if a.rule_id == "LOGIN_AFTER_BRUTE_FORCE"
        and a.explanation.get("entities", {}).get("source_ip") == source_ip
        and a.explanation.get("entities", {}).get("host") == host
        and a.first_seen >= seed.first_seen
    ]
    if not logins:
        return None

    # Sort alerts chronologically
    related_alerts = [seed]
    login = logins[0]
    related_alerts.append(login)
    user = login.explanation.get("entities", {}).get("user")

    # Track chain timestamps for 15-minute stage attachment and 30-minute close
    chain_timestamps = [seed.first_seen, seed.last_seen, login.first_seen]

    # Find matching subsequent alerts
    post_login_rules = {"PRIVILEGE_ESCALATION", "SENSITIVE_DATA_ACCESS", "EXFILTRATION"}
    candidate_post = [a for a in alerts if a.rule_id in post_login_rules and a.first_seen >= login.first_seen]
    candidate_post.sort(key=lambda x: x.first_seen)

    for a in candidate_post:
        # Check 30-minute inactivity close
        latest_chain_time = max(chain_timestamps)
        if (a.first_seen - latest_chain_time).total_seconds() > 1800:
            # Inactivity exceeds 30 minutes; incident closes
            break

        # Check match by host and user
        first_ev = events_by_id.get(a.event_ids[0], {})
        ev_user = first_ev.get("user") or a.explanation.get("entities", {}).get("user")
        ev_host = first_ev.get("host") or a.explanation.get("entities", {}).get("host")

        if ev_host != host:
            continue

        if a.rule_id == "EXFILTRATION":
            # For exfiltration, user may not be present in network log; if present, must match
            if ev_user and user and ev_user != user:
                continue
        else:
            if ev_user != user:
                continue

        # Attach if within 15 minutes (900s) of previous stage or login
        min_diff = min(abs((a.first_seen - t).total_seconds()) for t in chain_timestamps)
        if min_diff <= 900:
            related_alerts.append(a)
            chain_timestamps.append(a.first_seen)
            if a.last_seen:
                chain_timestamps.append(a.last_seen)

    # De-duplicate alerts preserving identity
    seen_alert_ids = set()
    deduped_alerts = []
    for a in related_alerts:
        alert_key = (a.rule_id, tuple(a.event_ids))
        if alert_key not in seen_alert_ids:
            seen_alert_ids.add(alert_key)
            deduped_alerts.append(a)

    return {
        "source_ip": source_ip,
        "affected_hosts": [host],
        "users": [user] if user else [],
        "alerts": deduped_alerts,
        "first_seen": min(chain_timestamps),
        "last_seen": max(chain_timestamps),
    }


def merge_overlapping_candidates(candidates: list[dict]) -> list[dict]:
    if not candidates:
        return []
    # Group candidates by source_ip
    by_src = defaultdict(list)
    for c in candidates:
        by_src[c["source_ip"]].append(c)

    merged_list = []
    for src, group in by_src.items():
        # Sort group by first_seen
        group.sort(key=lambda x: x["first_seen"])
        current = group[0]
        for next_c in group[1:]:
            # If windows overlap or are within 30 min (1800s)
            if (next_c["first_seen"] - current["last_seen"]).total_seconds() <= 1800:
                # Merge into current
                current["affected_hosts"] = sorted(list(set(current["affected_hosts"] + next_c["affected_hosts"])))
                current["users"] = sorted(list(set(current["users"] + next_c["users"])))
                current["last_seen"] = max(current["last_seen"], next_c["last_seen"])
                # Combine alerts deduped
                existing_keys = {(a.rule_id, tuple(a.event_ids)) for a in current["alerts"]}
                for a in next_c["alerts"]:
                    k = (a.rule_id, tuple(a.event_ids))
                    if k not in existing_keys:
                        existing_keys.add(k)
                        current["alerts"].append(a)
            else:
                merged_list.append(current)
                current = next_c
        merged_list.append(current)

    return merged_list


def build_incidents(alerts: list, events_by_id: dict[str, dict]) -> list[dict]:
    brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
    candidates = []
    for seed in brute:
        cand = build_candidate_incident(seed, alerts, events_by_id)
        if cand:
            candidates.append(cand)

    merged = merge_overlapping_candidates(candidates)
    incidents = []

    for idx, item in enumerate(merged, start=1):
        rel_alerts = sorted(item["alerts"], key=lambda a: a.first_seen)
        rule_ids = [a.rule_id for a in rel_alerts]
        score, sev = calculate_score(rule_ids)

        # Build timeline entries for each alert
        timeline = []
        for a in rel_alerts:
            desc = _alert_desc(a, events_by_id, item["source_ip"])
            timeline.append({
                "ts": a.first_seen.isoformat(),
                "stage": a.rule_id.lower(),
                "event_ids": list(a.event_ids),
                "description": desc,
                "mitre_id": a.mitre_ids[0] if a.mitre_ids else "",
                "link_reason": a.link_reason or "seed: same source_ip + host",
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
            "id": f"INC-{idx:03d}",
            "severity": sev,
            "score": score,
            "status": "open",
            "source_ip": item["source_ip"],
            "affected_hosts": item["affected_hosts"],
            "users": item["users"],
            "alert_ids": [],  # Will be populated with AlertORM IDs in incident_service
            "stages": stages,
            "timeline": timeline,
            "mitre_techniques": mitres,
            "enrichment": {},
            "ai_summary": {},
            "_alerts": rel_alerts,
        })

    return incidents

