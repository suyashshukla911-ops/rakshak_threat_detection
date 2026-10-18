import asyncio
import json
import threading
import time
from pathlib import Path
from sqlalchemy.orm import Session
from app.services.incident_service import IncidentService
from app.core.config import settings

class SimulationManager:
    def __init__(self):
        self.runs = {}

    def start(self, db_factory) -> str:
        run_id = f"run-{int(time.time()*1000)}"
        self.runs[run_id] = {
            "stage": "Queued",
            "detail": "Initializing simulation...",
            "done": False,
            "error": None,
            "incident_id": None,
            "start_time": time.time(),
        }
        threading.Thread(target=self._worker, args=(run_id, db_factory), daemon=True).start()
        return run_id

    def _worker(self, run_id, db_factory):
        db = db_factory()
        try:
            service = IncidentService(db)
            service.clear_demo(clear_uploads=False)

            t_start = time.time()
            root = Path(__file__).resolve().parents[3]
            data_file = root / "data/sample_logs/ssh_attack.json"
            raw_text = data_file.read_text(encoding="utf-8")
            data = json.loads(raw_text)

            self.runs[run_id]["stage"] = "Ingesting"
            self.runs[run_id]["detail"] = f"Ingesting {len(data)} events from {data_file.name}..."
            self.runs[run_id]["events_count"] = len(data)

            t_ingest = time.time()
            accepted, rejected = service.ingest_records(data, run_id, source_file=data_file.name)
            ingest_dur = round(time.time() - t_ingest, 3)
            self.runs[run_id]["detail"] = f"Ingested {accepted} events in {ingest_dur}s"

            def progress(stage: str, details: str = ""):
                self.runs[run_id]["stage"] = stage
                if details:
                    self.runs[run_id]["detail"] = details
                self.runs[run_id]["updated_at"] = time.time()

            alerts_orm, incident_orms, anomaly_count = asyncio.run(
                service.run_detection(progress_callback=progress, is_simulation=True, batch_id="demo")
            )

            demo_incidents = [i for i in service.get_incidents() if not i.get("batch_id", "").startswith("upload-")]
            total_dur = round(time.time() - t_start, 2)
            self.runs[run_id]["done"] = True
            self.runs[run_id]["stage"] = "CRITICAL INCIDENT DETECTED" if demo_incidents else "Complete"
            self.runs[run_id]["detail"] = f"Reconstructed {len(demo_incidents)} incident and {len(alerts_orm)} alerts in {total_dur}s"
            self.runs[run_id]["incident_id"] = demo_incidents[0]["id"] if demo_incidents else None
            self.runs[run_id]["alerts_count"] = len(alerts_orm)
            self.runs[run_id]["incidents_count"] = len(demo_incidents)
            self.runs[run_id]["anomaly_count"] = anomaly_count
        except Exception as exc:
            self.runs[run_id]["error"] = str(exc)
            self.runs[run_id]["stage"] = "Failed"
            self.runs[run_id]["detail"] = str(exc)
        finally:
            db.close()

    def status(self, run_id: str):
        return self.runs.get(run_id)

simulation_manager = SimulationManager()

