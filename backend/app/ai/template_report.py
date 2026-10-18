from app.mitre.mappings import DETECTION_TO_MITRE

def deterministic_report(incident: dict) -> dict:
    evidence_refs = []
    for stage in incident.get("timeline", []):
        evidence_refs.extend(stage.get("event_ids", []))
    unique_refs = list(dict.fromkeys(evidence_refs))
    
    stages_raw = incident.get("stages", [])
    stage_set = set(stages_raw)
    stages_display = ", ".join(s.replace("_", " ") for s in stages_raw)
    mitre = ", ".join(f"{m['id']} ({m['name']})" for m in incident.get("mitre_techniques", []) if isinstance(m, dict) and "id" in m)
    
    # Dynamic potential impact based only on stages actually present
    impact_parts = []
    if "exfiltration" in stage_set:
        impact_parts.append("unauthorized outbound data transfer and potential data leakage")
    if "sensitive_data_access" in stage_set:
        impact_parts.append("unauthorized access to sensitive system or credential files")
    if "privilege_escalation" in stage_set:
        impact_parts.append("administrative privilege escalation via sudo")
    if "login_after_brute_force" in stage_set:
        impact_parts.append("unauthorized access via compromised credentials following brute force")
    elif "ssh_brute_force" in stage_set:
        impact_parts.append("credential guessing attempts against SSH authentication")

    if impact_parts:
        potential_impact = f"The observed activity is consistent with {', '.join(impact_parts)}. Validate scope and affected credentials before taking containment action."
    else:
        potential_impact = "Suspicious security signals observed. Review affected hosts and accounts."

    # Build why_detected with threshold vs observed
    why_detected = [
        "Deterministic detection rules verified each stage against explicit operational thresholds.",
    ]
    
    # Extract threshold vs observed from attached alerts or timeline
    alerts = incident.get("_alerts", [])
    if alerts:
        for a in alerts:
            exp = getattr(a, "explanation", None) or (a.get("explanation") if isinstance(a, dict) else {})
            th = exp.get("threshold")
            obs = exp.get("observed")
            rule = getattr(a, "rule_id", None) or (a.get("rule_id") if isinstance(a, dict) else "")
            if th and obs:
                why_detected.append(f"{rule}: Threshold: {th} vs Observed: {obs}")
    else:
        # Fallback to timeline link reasons if raw alerts are not present
        for t in incident.get("timeline", []):
            if t.get("link_reason"):
                why_detected.append(f"{t['stage'].upper()}: {t['description']} ({t['link_reason']})")

    why_detected.append(f"Incident reached deterministic severity score of {incident.get('score', 0)}/100 ({incident.get('severity', 'unknown')}).")
    if mitre:
        why_detected.append(f"Controlled MITRE ATT&CK mapping: {mitre}.")

    return {
        "executive_summary": f"A {incident.get('severity', 'high')} incident was reconstructed from source IP {incident.get('source_ip', 'unknown')} on {', '.join(incident.get('affected_hosts', []))}. Detected stages: {stages_display}.",
        "attack_narrative": " → ".join(stage.get("description", "") for stage in incident.get("timeline", [])),
        "why_detected": why_detected,
        "potential_impact": potential_impact,
        "investigation_steps": [
            "Verify the SSH source IP and affected account in authoritative authentication logs.",
            "Review privileged commands executed during the suspicious session.",
            "Validate accessed file paths and outbound transfer destinations against known business activity.",
            "Preserve relevant event logs and volatile memory before making containment changes.",
        ],
        "evidence_refs": unique_refs,
    }

