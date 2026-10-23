import json
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

MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
RATIO = re.compile(r"\b(\d+)/(\d+)\b")
NUM = re.compile(r"(?<![\w.])\d[\d,]*(?:\.\d+)?")
ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?")
IDENT = re.compile(r"[\w~.\-/]*[\d/_~][\w~.\-/]*|\b[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")
STRIP = ".,;:()[]\"'"


def norm_nums(text: str) -> set[str]:
    text = RATIO.sub(r" \1 \2 ", text)
    text = ISO_TS.sub(" ", MITRE.sub(" ", IPV4.sub(" ", IPV6.sub(" ", text))))
    return {n.replace(",", "") for n in NUM.findall(text)}


def idents(text: str) -> set[str]:
    text = RATIO.sub(" ", text)
    text = MITRE.sub(" ", ISO_TS.sub(" ", text))
    return {
        t.strip(STRIP).lower()
        for t in IDENT.findall(IPV4.sub(" ", text))
        if t.strip(STRIP) and not NUM.fullmatch(t.strip(STRIP))
    }


def ips(text: str) -> set[str]:
    return set(IPV4.findall(text)) | {m.lower() for m in IPV6.findall(text)}


def build_allowed_facts(facts: dict) -> tuple[set[str], set[str], set[str]]:
    blob = json.dumps(facts, default=str)
    return norm_nums(blob), idents(blob), ips(blob)


def check_grounding(text_fields: list[str], facts: dict) -> tuple[bool, list[str]]:
    a_nums, a_ids, a_ips = build_allowed_facts(facts)
    text = " ".join(text_fields)
    bad = []
    bad += [f"number {n}" for n in sorted(norm_nums(text) - a_nums)]
    bad += [f"identifier {i}" for i in sorted(idents(text) - a_ids)]
    bad += [f"ip {i}" for i in sorted(ips(text) - a_ips)]
    return (not bad), bad


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
    text_fields = [
        result.executive_summary,
        result.attack_narrative,
        result.potential_impact,
        *result.why_detected,
        *result.investigation_steps,
    ]
    text = " ".join(text_fields)

    # MITRE check: any MITRE ID appearing in the text must be in the mapped set
    mitre_allowed = {m["id"] for m in incident.get("mitre_techniques", []) if isinstance(m, dict) and "id" in m}
    mentioned_mitre = set(re.findall(r"T\d{4}(?:\.\d{3})?", text))
    if not mentioned_mitre.issubset(mitre_allowed):
        return False, None, "unknown MITRE id"

    # Threat reputation claims check: LLM must not assert reputation as fact
    for pattern in REPUTATION_CLAIM_PATTERNS:
        if re.search(pattern, text, flags=re.I):
            return False, None, "unauthorized threat reputation claim"

    # Fact grounding: all numbers, identifiers, and IPs must be grounded in incident facts
    ok, bad = check_grounding(text_fields, incident)
    if not ok:
        return False, None, f"ungrounded fact: {', '.join(bad[:3])}"

    return True, result, None
