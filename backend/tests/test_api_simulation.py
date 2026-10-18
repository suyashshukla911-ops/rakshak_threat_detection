from pathlib import Path
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient
from app.main import app

def test_api_simulation_and_report_generation():
    client = TestClient(app)

    # 1. Start simulation
    res = client.post("/api/simulation/run")
    assert res.status_code == 200
    data = res.json()
    assert "run_id" in data
    run_id = data["run_id"]

    # 2. Poll until simulation completes
    max_wait = 20.0
    start = time.time()
    final_status = None
    while time.time() - start < max_wait:
        st_res = client.get(f"/api/simulation/{run_id}/status")
        assert st_res.status_code == 200
        st = st_res.json()
        if st.get("done") or st.get("error"):
            final_status = st
            break
        time.sleep(0.3)

    assert final_status is not None, "Simulation timed out"
    assert final_status.get("error") is None, f"Simulation errored: {final_status.get('error')}"
    assert final_status.get("done") is True
    assert final_status.get("incident_id") == "INC-001"

    # 3. Assert exactly one critical incident exists
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["id"] == "INC-001"
    assert inc["severity"] == "critical"
    assert inc["score"] == 100
    assert inc["source_ip"] == "203.0.113.45"
    assert inc["affected_hosts"] == ["server-01"]
    assert "admin" in inc["users"]
    assert len(inc["alert_ids"]) >= 5

    # 4. Generate report endpoint
    rep_res = client.post(f"/api/incidents/{inc['id']}/report")
    assert rep_res.status_code == 200
    rep = rep_res.json()
    assert "status" in rep
    assert "content" in rep
    assert len(rep["content"]["evidence_refs"]) > 0

    # 5. Inject bad AI answer demo toggle verifies validation fallback
    bad_res = client.post(f"/api/incidents/{inc['id']}/report?inject_bad=true")
    assert bad_res.status_code == 200
    bad_rep = bad_res.json()
    assert bad_rep["status"] == "fallback"
    assert "rejected_reason" in bad_rep
