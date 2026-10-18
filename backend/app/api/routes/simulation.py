from fastapi import APIRouter, Depends, HTTPException
from app.api.routes.common import get_db
from app.db.session import SessionLocal
from app.services.simulation_service import simulation_manager
router = APIRouter()
@router.post("/simulation/run")
def start_simulation():
    run_id = simulation_manager.start(SessionLocal)
    return {"run_id": run_id}
@router.get("/simulation/{run_id}/status")
def simulation_status(run_id: str):
    status = simulation_manager.status(run_id)
    if not status: raise HTTPException(404, "Run not found")
    return status
@router.post("/simulation/reset")
def reset():
    db = SessionLocal()
    try:
        from app.services.incident_service import IncidentService
        IncidentService(db).clear_demo(clear_uploads=False)
        return {"ok": True}

    finally:
        db.close()
