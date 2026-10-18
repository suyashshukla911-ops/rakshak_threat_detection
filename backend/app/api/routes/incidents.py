from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from app.api.routes.common import get_db, check_rate_limit
from app.services.incident_service import IncidentService
from app.models.orm import IncidentORM
from app.ai.explainer import ai_explainer
from app.core.config import settings

router = APIRouter()

@router.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    return IncidentService(db).get_incidents()

@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    item = IncidentService(db).get_incident(incident_id)
    if not item:
        raise HTTPException(404, "Incident not found")
    return item

@router.post("/incidents/{incident_id}/report")
async def report(
    incident_id: str,
    request: Request,
    format: str = Query("json"),
    inject_bad: bool = Query(False, description="Demo toggle to inject fabricated AI output and verify validation rejection"),
    db: Session = Depends(get_db)
):
    check_rate_limit(request, limit=30, window_seconds=60)
    service = IncidentService(db)
    item = service.get_incident(incident_id)
    if not item:
        raise HTTPException(404, "Incident not found")
    if format != "json":
        raise HTTPException(400, "Only JSON export is implemented in P1")
    if inject_bad and not settings.demo_mode:
        raise HTTPException(403, "Bad AI injection toggle is disabled outside demo mode")

    # Re-run explain and validate
    status, content, metadata = await ai_explainer.generate(item, simulate_bad_ai=inject_bad)
    new_summary = {
        "status": status,
        "content": content,
        "model": metadata.get("model", "unavailable"),
        "input_hash": metadata.get("input_hash", ""),
    }
    if "rejected_reason" in metadata:
        new_summary["rejected_reason"] = metadata["rejected_reason"]

    # Persist updated summary to DB
    orm_obj = db.get(IncidentORM, incident_id)
    if orm_obj:
        orm_obj.ai_summary = new_summary
        db.commit()

    return new_summary

