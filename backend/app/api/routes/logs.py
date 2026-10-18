from fastapi import APIRouter, Depends, File, UploadFile, HTTPException, Request
from sqlalchemy.orm import Session
from app.api.routes.common import get_db, check_rate_limit
from app.ingest.parsers import parse_content
from app.services.incident_service import IncidentService
from app.core.config import settings
import uuid

router = APIRouter()

@router.post("/logs/upload")
async def upload_logs(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db)):
    check_rate_limit(request, limit=20, window_seconds=60)
    content = await file.read()
    if len(content) > settings.upload_max_bytes:
        raise HTTPException(413, "File too large")
    try:
        records, parse_errors = parse_content(file.filename or "upload.json", content, settings.upload_max_lines)
    except Exception as exc:
        raise HTTPException(400, f"Invalid file: {exc}")
    service = IncidentService(db)
    batch_id = f"upload-{uuid.uuid4().hex[:8]}"
    accepted, rejected = service.ingest_records(records, batch_id, source_file=file.filename or "upload.json")
    await service.run_detection(is_simulation=False)
    return {"accepted": accepted, "rejected": len(rejected) + len(parse_errors), "errors": (parse_errors + rejected)[:25]}

