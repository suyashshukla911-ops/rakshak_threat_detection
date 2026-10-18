from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.routes.common import get_db
from app.services.incident_service import IncidentService
router = APIRouter()
@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    return IncidentService(db).get_alerts()
@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    service = IncidentService(db)
    alert = next((a for a in service.get_alerts() if a["id"] == alert_id), None)
    if not alert: raise HTTPException(404, "Alert not found")
    return alert
