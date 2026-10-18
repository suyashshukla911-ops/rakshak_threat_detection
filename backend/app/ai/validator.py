import ipaddress
import re
from app.models.schemas import AIOutput

# Command-like syntax / code fences checked ONLY in investigation_steps
SHELL_COMMAND_PATTERNS = [
    r"```",
    r"^\s*(?:sudo|bash|sh|zsh|powershell|cmd|curl|wget|nc|netcat|ncat|iptables|rm\s+-rf|chmod|chown)\b",
    r"\b(?:sudo\s+[\w/]+|bash\s+-c|sh\s+-c|powershell\s+-[eE]|curl\s+-[a-zA-Z]|wget\s+-[a-zA-Z]|nc\s+-[a-zA-Z]|rm\s+-rf)\b",
    r"[|;&`]\s*(?:sudo|bash|sh|rm|curl|wget|nc)\b",
]

REPUTATION_CLAIM_PATTERNS = [
    r"\bknown\s+malicious\b",
    r"\bbotnet\b",
    r"\breputation\s+score\b",
    r"\babuse\s+score\b",
]

def validate_ai_output(payload: dict, incident: dict) -> tuple[bool, AIOutput | None, str | None]:
    try:
        result = AIOutput.model_validate(payload)
    except Exception as exc:
        return False, None, f"schema: {exc}"

    # Require non-empty evidence_refs
    if not result.evidence_refs:
        return False, None, "empty evidence references"

    # Every cited evidence ID must exist in the incident timeline
    allowed_evidence = {eid for stage in incident.get("timeline", []) for eid in stage.get("event_ids", [])}
    if any(ref not in allowed_evidence for ref in result.evidence_refs):
        return False, None, "fabricated evidence reference"

    # Check only investigation_steps for command-like syntax or code fences
    for step in result.investigation_steps:
        for pattern in SHELL_COMMAND_PATTERNS:
            if re.search(pattern, step, flags=re.I | re.MULTILINE):
                return False, None, "unsafe command/code pattern in investigation step"

    # Entire output text for semantic checks
    text = " ".join([
        result.executive_summary,
        result.attack_narrative,
        result.potential_impact,
        *result.why_detected,
        *result.investigation_steps,
    ])

    # MITRE check: any MITRE ID appearing in the text must be in the mapped set
    mitre_allowed = {m["id"] for m in incident.get("mitre_techniques", []) if isinstance(m, dict) and "id" in m}
    mentioned_mitre = set(re.findall(r"T\d{4}(?:\.\d{3})?", text))
    if not mentioned_mitre.issubset(mitre_allowed):
        return False, None, "unknown MITRE id"

    # Threat reputation claims check: LLM must not assert reputation as fact
    for pattern in REPUTATION_CLAIM_PATTERNS:
        if re.search(pattern, text, flags=re.I):
            return False, None, "unauthorized threat reputation claim"

    # IP address validation: any IPv4 in the text must be part of the incident entities
    allowed_ips = set()
    if incident.get("source_ip"):
        allowed_ips.add(str(incident["source_ip"]))
    for host in incident.get("affected_hosts", []):
        allowed_ips.add(str(host))
    for stage in incident.get("timeline", []):
        for candidate in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", stage.get("description", "") + " " + stage.get("link_reason", "")):
            allowed_ips.add(candidate)
    
    mentioned_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    for ip in mentioned_ips:
        try:
            ipaddress.ip_address(ip)
            if ip not in allowed_ips:
                return False, None, f"unverified IP address in output: {ip}"
        except ValueError:
            continue

    return True, result, None

