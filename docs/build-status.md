# Rakshak Build Status

- Backend unit tests: **6 passed** with pytest.
- Seeded simulation: **verified** to produce exactly one `INC-001`, severity `critical`, score `100/100`, all five stages, five controlled MITRE IDs, demo enrichment and deterministic AI fallback.
- Simulation API: verified end-to-end through FastAPI on localhost.
- Frontend source: React/TypeScript/Vite/Tailwind/Recharts/Lucide implementation included.
- Frontend package installation was not executed to completion in the build container because the npm registry was not reachable from the container environment (`EAI_AGAIN`). The source is intended to install normally on the user's machine with `npm install`.
