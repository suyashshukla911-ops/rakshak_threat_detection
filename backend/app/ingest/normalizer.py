from datetime import timezone
import hashlib
import json
from app.models.schemas import EventIn

SEMANTIC_FIELDS = (
    "timestamp",
    "event_type",
    "host",
    "user",
    "source_ip",
    "destination_ip",
    "process",
    "path",
    "bytes",
    "severity",
    "message",
)


def get_semantic_key(event: EventIn) -> str:
    utc_ts = event.timestamp.astimezone(timezone.utc)
    # Truncate timestamp to 1-second precision in canonical UTC format
    ts_sec_str = utc_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    semantic_dict = {
        "timestamp": ts_sec_str,
        "event_type": event.event_type,
        "host": event.host,
        "user": event.user,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "process": event.process,
        "path": event.path,
        "bytes": event.bytes or 0,
        "severity": event.severity or "low",
        "message": event.message or "",
    }
    return json.dumps(semantic_dict, sort_keys=True, default=str)


def normalize_event(
    event: EventIn,
    batch_id: str,
    source_file: str | None = None,
    line_offset: int | None = None,
    occurrence: int = 1,
) -> dict:
    payload = event.model_dump(mode="json")
    payload["timestamp"] = event.timestamp.astimezone(timezone.utc)
    payload["batch_id"] = batch_id
    if source_file is not None and not payload.get("source_file"):
        payload["source_file"] = source_file
    if line_offset is not None and payload.get("line_offset") is None:
        payload["line_offset"] = line_offset

    sem_key = get_semantic_key(event)
    hash_input = f"{sem_key}#occ={occurrence}"
    raw_hash = hashlib.sha256(hash_input.encode()).hexdigest()

    payload["id"] = event.id or f"evt-{raw_hash[:12]}"
    payload["raw_hash"] = raw_hash
    return payload


