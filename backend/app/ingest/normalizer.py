from datetime import timezone
import hashlib
import json
from app.models.schemas import EventIn


def normalize_event(event: EventIn, batch_id: str, source_file: str | None = None, line_offset: int | None = None) -> dict:
    payload = event.model_dump(mode="json")
    payload["timestamp"] = event.timestamp.astimezone(timezone.utc)
    payload["batch_id"] = batch_id
    if source_file is not None and not payload.get("source_file"):
        payload["source_file"] = source_file
    if line_offset is not None and payload.get("line_offset") is None:
        payload["line_offset"] = line_offset
    canonical = json.dumps({k: payload[k] for k in sorted(payload) if k not in {"id", "batch_id"}}, sort_keys=True, default=str)
    payload["id"] = event.id or f"evt-{hashlib.sha256(canonical.encode()).hexdigest()[:12]}"
    payload["raw_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    return payload

