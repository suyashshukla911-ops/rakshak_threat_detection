# SentinelAI (Rakshak Core)

**SentinelAI — Autonomous SOC Monitoring, Deterministic Correlation & Validated LLM Incident Reconstruction**

> Turn thousands of logs into one understandable, verifiable attack incident.

SentinelAI ingests heterogeneous security logs (JSON, JSONL, CSV), detects suspicious behavior with strict deterministic rules, correlates events across IP and host/user pivots into a single incident, reconstructs the attack timeline, maps each stage to MITRE ATT&CK, enriches indicators via AbuseIPDB (or demo mock) with a 24-hour SQLite cache, and uses an LLM **only** to explain facts the deterministic engine has already established—safeguarded by a multi-layer validator.

---

## What is Included

- **Realistic Scale**: ~14,000 events dataset with benign background SSH logins, routine sudo sessions, small curl transfers, file accesses, and scattered mistypes.
- **5-Stage Attack Chain**: Seeded SSH brute force (27 attempts), login after brute force, sudo root privilege escalation, sensitive credential file access (`/etc/shadow`, `/var/backups/db.sql`), and 1.8 GB outbound exfiltration.
- **4 Spec Decoys + 4 Near-Miss Decoys**:
  - 3 failed logins (< 5 threshold) -> 0 incidents
  - 4 mistypes + login (< 5 threshold) -> 0 incidents
  - Benign admin sudo on uncompromised host -> 0 incidents
  - Nightly 2 GB backup to internal allowlist -> 0 incidents
  - Admin sudo on target host *before* attack login -> 0 incidents
  - Attack IP login > 10 min after brute force -> 0 incidents
  - 4 failures in 120s vs 5 in 120s boundary check -> 0 incidents
  - 5 failures spread over 121s boundary check -> 0 incidents
  - 49 MB transfer vs 51 MB threshold boundary check -> 0 incidents
- **Deterministic Correlation Engine**:
  - Sliding-window $O(n)$ multi-burst brute force detection
  - IP to host/user pivot chaining within 15 minutes of previous stage
  - 30-minute inactivity session close & candidate merging
  - Sequential `INC-001` ID generation
- **Anomaly Detection (Isolation Forest)**:
  - 1-minute tumbling windows grouped by `source_ip`
  - 5-feature vector: `event_count`, `failed_login_count`, `distinct_users_attempted`, `distinct_hosts_touched`, `bytes_out`
  - Retrained baseline ranking attack windows at **#1 and #2** with anomaly scores up to 1.0
- **Threat Intelligence**:
  - Real mode via `AbuseIPDBProvider` with 5s timeout, 2 retries with exponential backoff, and 24-hour SQLite cache table (`threat_intel_cache`)
  - Demo mode via `DemoMockProvider` with realistic report count (142 reports) and honest `unknown` status for unlisted IPs
- **AI Validation & Safe Fallback**:
  - Untrusted data containment: raw messages stripped, log strings (paths/users) sanitized and quoted
  - Multi-layer validator: checks shell syntax **only** in `investigation_steps`, enforces non-empty `evidence_refs`, ensures cited IPs exist in evidence, blocks unverified reputation claims
  - Explicit status: `generated` (real LLM), `unavailable` (no API key configured), `fallback` (validator rejected output or API failure)
  - Live **"Inject Bad AI (Demo)"** toggle in the UI: simulates fabricated event IDs and demonstrates live validator rejection and safety fallback
  - Auditable status metadata: records model name and SHA-256 input hash on reports
- **Full-Stack Application**:
  - FastAPI backend with async endpoints, rate limiting, and real stage reporting (no artificial sleep delays)
  - React + Vite + Tailwind CSS frontend with attack timeline, raw evidence table, anomaly badges, severity badges, and interactive alert drawer

---

## Quick Start

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ..
copy .env.example .env   # DEMO_MODE=true is enabled by default in .env.example for live testing
python scripts/generate_attack.py
python scripts/train_anomaly.py
uvicorn app.main:app --reload --app-dir backend --port 8000
```

### Frontend

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

### Full Test Suite

```powershell
python -m pytest backend/tests -v
```

All 33 test cases cover:
- Multi-upload & dedupe (`test_upload_dedupe_collision.py`): multi-upload collision prevention with distinct incident/alert IDs, appended-file single-event acceptance, duplicate survival (all 13,904 seed events stored), rename dedupe, and `DEMO_MODE` gate.
- Boundary tests (`test_boundary.py`): 4 vs 5 failures, 119 vs 121s, 49 vs 51 MB.
- Decoy immunity (`test_decoys.py`): 4 standard decoys + near-miss decoys produce zero incidents.
- Advanced correlation (`test_correlation_advanced.py`): user+host pivot attachment, chronological timeline ordering, deduplication.
- Hardening & safety (`test_hardening.py`): invalid input rejection, timezone normalization, prompt injection safety.
- Resilience & degradation (`test_resilience.py`): LLM failure fallback, threat intel failure handling, ML failure fallback.
- Anomaly ranking (`test_anomaly_ranking.py`): Isolation Forest ranks attack windows in the top anomalous windows.
- Full API simulation (`test_api_simulation.py`): end-to-end ingestion, detection, and report generation.
- Detection rules (`test_rules.py`), Ingest parsers (`test_ingest.py`), and Severity score (`test_severity.py`).

---

## Live Demo Walkthrough

1. Open the Dashboard at `http://localhost:5173`.
2. Click **Run Attack Simulation**.
3. Observe real pipeline timings and counts reported live: Ingestion (13,904 events) -> Rules (5 alerts) -> Anomaly Detection -> Correlation -> Threat Intel -> AI Explanation.
4. Click **Open** on incident `INC-001` (Score: 100/100, Critical).
5. Inspect the **Attack Timeline**:
   - Distinct severity icons and badges for each stage (Critical, High, Medium).
   - Anomaly score badges on anomalous windows.
   - Event count badges per stage.
6. Inspect the **Raw Evidence Events** table:
   - Filter events dynamically by keyword or click to view details.
7. Inspect the **Threat Intelligence** card:
   - Shows report count (142 reports), confidence, and mode.
8. Click **Inject Bad AI (Demo)**:
   - Sends a payload with hallucinated event references (`evt-99999`).
   - The validator intercepts the hallucination live, rejects it, and displays an alert banner explaining that the output was safely degraded to the verified deterministic template report.
9. Click **Generate report** to re-run standard generation.
10. Click **Export JSON** to download the auditable report containing model and input hash metadata.

---

## Architecture

```text
Log Sources (.json, .jsonl, .csv)
  │
  ▼
Parser & Deduplication Engine (source_file + line_offset canonical hash)
  │
  ▼
SQLite Database (EventORM)
  │
  ├──────────────────────────────────┐
  ▼                                  ▼
Rule Engine (Sliding Window O(n))   Isolation Forest Anomaly Engine (1-min buckets)
  │                                  │
  └─────────────────┬────────────────┘
                    ▼
Correlator & Session Pivoting (15m window, 30m close, source_ip merge)
  │
  ▼
Incident Construction (INC-001, MITRE lookup, Threat Intel 24h SQLite Cache)
  │
  ▼
AI Explainer & Multi-Layer Schema Validator
  │
  ├─── Passed ───► Validated AI Summary (status: generated)
  └─── Failed ───► Deterministic Template Fallback (status: fallback)
  │
  ▼
FastAPI REST Endpoints & React/TypeScript SOC Dashboard
```

---

## Known Limitations

- **Single Attack Chain**: Focuses on reconstructing the targeted five-stage SSH-to-exfiltration attack chain.
- **Batch Processing**: Designed for batch log ingestion and demonstration, not real-time streaming sockets.
- **Uploads Scoped Per File**: Uploads are correlated per-file/batch, so a brute force in one uploaded file and a login in a separate file will not cross-correlate.
- **Thresholds**: Rule thresholds (e.g. 5 failures in 120s, 50 MB transfer) are calibrated for demonstration clarity rather than general production noise.
- **Authentication**: No authentication or multi-tenant RBAC is included in this build.
