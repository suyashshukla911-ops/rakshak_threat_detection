# Rakshak

**Rakshak — AI-Assisted Security Monitoring and Incident Reconstruction**

> Turn thousands of logs into one understandable attack.

Rakshak ingests security logs, detects suspicious behavior with deterministic rules, correlates events into a single incident, reconstructs the attack timeline, maps it to MITRE ATT&CK, optionally enriches attacker IPs, and uses an LLM only to explain facts the engine has already established.

## What is included

- Seeded attack simulation with the exact five-stage SSH attack chain
- Four decoy scenarios that must stay quiet
- Deterministic rules + explainable alerts
- Correlation via source-IP → user/host session pivot
- Deterministic severity score
- Controlled MITRE ATT&CK lookup
- Isolation Forest anomaly support with graceful fallback
- Demo threat-intel provider and optional AbuseIPDB provider
- AI report generation with strict validation + deterministic fallback
- FastAPI backend + React/TypeScript frontend
- SQLite storage
- Upload API/UI for JSON, JSONL and CSV
- Pytest coverage for detection, correlation, validation, prompt injection and graceful degradation

## Quick start

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cd ..
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

Open the Vite URL shown in the terminal, usually `http://localhost:5173`.

### Tests

```powershell
cd backend
pytest -q
```

### Optional AI

Copy `.env.example` to `.env` and set:

```text
LLM_API_KEY=...
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=<your compatible model>
```

The application works without these variables; the AI layer falls back to the deterministic report.

## Demo

1. Open Dashboard.
2. Click **RUN ATTACK SIMULATION**.
3. Watch the real pipeline stages.
4. Open `INC-001`.
5. Show the five-stage timeline, evidence, MITRE mapping and demo enrichment.
6. Open **Why did this fire?** on the alert drawer.
7. Generate the AI report.
8. Remove/disable the LLM configuration and demonstrate the deterministic fallback.

The simulation banner explicitly says **Simulated data**.

## Important safety / scope boundaries

- No authentication in this hackathon build.
- Never execute attacker input or AI-generated text.
- API keys remain backend-only.
- AI cannot create detections, invent evidence or MITRE IDs, or output commands.
- MITRE mappings come from a controlled lookup, not the LLM.
- Threat-intel reputation is never guessed by the LLM.
- Demo data uses `203.0.113.0/24` documentation addresses.

## Architecture

```text
Log sources
  -> ingestion/validation
  -> normalization
  -> SQLite
  -> rule engine + ML support
  -> correlation
  -> incident builder
  -> MITRE + threat intel + timeline
  -> structured incident facts
  -> AI explanation/report or deterministic fallback
  -> React dashboard
```

## Known limitations

This version is a focused demo, not a production SIEM. It uses synthetic data, one attack chain, batch processing and a single-host focus. ML is trained on synthetic normal activity. There is no authentication or multi-tenancy.
