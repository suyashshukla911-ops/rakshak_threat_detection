from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import configure_logging
from app.db.session import init_db
from app.api.routes import logs, alerts, incidents, simulation, health, stats

configure_logging()
init_db()
app = FastAPI(title="Rakshak", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=[settings.frontend_origin], allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["*"])
app.include_router(logs.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(simulation.router, prefix="/api")
app.include_router(health.router, prefix="/api")
app.include_router(stats.router, prefix="/api")

@app.get("/")
def root():
    return {"name":"Rakshak","status":"ready"}
