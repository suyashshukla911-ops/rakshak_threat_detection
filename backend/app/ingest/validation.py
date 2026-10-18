import ipaddress
from pydantic import ValidationError
from app.models.schemas import EventIn


def validate_event(raw: dict) -> tuple[EventIn | None, str | None]:
    try:
        event = EventIn.model_validate(raw)
        for field_name in ("source_ip", "destination_ip"):
            value = getattr(event, field_name)
            if value:
                ipaddress.ip_address(value)
        return event, None
    except (ValidationError, ValueError) as exc:
        return None, str(exc)
