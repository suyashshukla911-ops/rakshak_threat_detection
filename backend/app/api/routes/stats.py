from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.routes.common import get_db
from app.services.incident_service import IncidentService
router = APIRouter()
@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    return IncidentService(db).stats()
