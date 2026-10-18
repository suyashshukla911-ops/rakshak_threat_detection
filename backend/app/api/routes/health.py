from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.routes.common import get_db
from app.services.incident_service import IncidentService
from app.core.config import settings
router = APIRouter()
@router.get("/health")
def health(db: Session = Depends(get_db)):
    service = IncidentService(db)
    return {
        "db": "ready",
        "rules": "ready",
        "ml": service.anomaly.status,
        "threat_intel": "configured" if settings.abuseipdb_api_key else "demo-only",
        "ai": "configured" if service.explainer.available() else "fallback-only",
    }
