from collections import defaultdict
import time
from fastapi import Depends, Request, HTTPException
from sqlalchemy.orm import Session
from app.db.session import SessionLocal

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

_RATE_LIMITS = defaultdict(list)

def check_rate_limit(request: Request, limit: int = 30, window_seconds: int = 60):
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    _RATE_LIMITS[client_ip] = [t for t in _RATE_LIMITS[client_ip] if now - t < window_seconds]
    if len(_RATE_LIMITS[client_ip]) >= limit:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please retry shortly.")
    _RATE_LIMITS[client_ip].append(now)

