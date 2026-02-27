# PromptGuard

PromptGuard is an **Adaptive AI Firewall** for Generative AI systems. It combines a deterministic **Rule Engine** with optional **LLM-driven analysis** to provide real-time evaluation, sanitization, and policy enforcement for prompts sent to LLMs. PromptGuard offers a FastAPI backend, async MongoDB logging, and a Streamlit-based SOC dashboard for monitoring, analysis, and attack-testing.

Key goals:

- Stop prompt-based attacks (jailbreaks, data exfiltration, role manipulations) before they reach production LLMs.
- Provide a lightweight, observable SOC-style dashboard for security operators.
- Offer deterministic fail-safes and graceful degradation if external LLMs or storage are unavailable.

---

## Features

- **Real-time prompt evaluation** via `/evaluate` endpoint (Rule Engine + LLM hybrid scoring).
- **Hybrid scoring**: deterministic regex/heuristic rules combined with optional LLM confidence to produce a final risk score and verdict.
- **Async MongoDB persistence** (via Motor) for audit logs and analytics.
- **Streamlit SOC Dashboard** (`ui/dashboard.py`) with Altair-powered charts, KPI tiles, exportable logs, and an AI Console for attack testing.
- **Background logging** using FastAPI BackgroundTasks to avoid adding latency to evaluations.
- **Robust configuration** via `pydantic-settings` with sensible defaults and `.env` support.
- **Service-Repository pattern** for clean separation between business logic and data access (see Architecture below).

---

## Project Structure

Top-level tree (important files & folders):

```
PromptGuard/
├── app/                      # Backend application (FastAPI)
│   ├── api/                  # API routers (v1 endpoints)
│   │   └── v1/               # v1 endpoints
│   │       └── endpoints/
│   │           ├── shield.py # POST /evaluate
│   │           └── stats.py  # GET /summary, /logs
│   ├── core/                 # Configuration and startup helpers
│   │   └── config.py         # Centralized Settings (pydantic)
│   ├── models/               # Pydantic request/response models
│   ├── repositories/         # Data access: LogRepository (Mongo)
│   └── services/             # Business logic: rule_engine, security_service
├── ui/                       # Streamlit dashboard package
│   ├── __init__.py           # run() helper and package exports
│   ├── __main__.py           # `python -m ui` entrypoint
│   ├── dashboard.py          # Streamlit app
│   └── components.py         # Shared UI components & client
├── run_ui.py                 # Optional helper to run the UI using venv Python
├── requirements.txt
├── .env                      # (not checked in) environment overrides
└── README.md
```

---

## Architecture

PromptGuard follows a **Service → Repository** pattern:

- **Services**: implement the security logic and orchestration (e.g., `security_service.evaluate_prompt`, `rule_engine`). The rule engine encapsulates deterministic rules (regexes, heuristics, vector similarity) and sanitization. The security service composes deterministic signals with optional LLM-derived classification and implements the hybrid risk formula and fail-safes.
- **Repositories**: implement data persistence and retrieval (e.g., `LogRepository` using Motor for async MongoDB access). Repositories expose a small surface (save_log, get_recent_logs, get_analytics_summary) and are injected into FastAPI endpoints via dependency helpers.
- **API layer**: thin FastAPI routers (`shield.py`, `stats.py`) orchestrate request validation, call services, and record logs asynchronously via background tasks.

This separation keeps business logic testable and the data layer swappable.

---

## Requirements

- Python 3.11+ recommended
- See `requirements.txt` for Python dependencies (FastAPI, Streamlit, Motor, Pydantic, Altair, etc.)

---

## Setup & Installation

1. Clone the repository and change into the project folder:

```bash
git clone <repo-url>
cd PromptGuard
```

2. Create and activate a virtual environment (recommended):

Unix / macOS:

```bash
python -m venv .venv
source .venv/bin/activate
```

Windows (PowerShell):

```powershell
python -m venv .venv
& .\.venv\Scripts\Activate.ps1
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Environment variables

Create a `.env` at the repository root (example):

```ini
# MongoDB connection (local or cloud)
MONGO_URI=mongodb://localhost:27017
DB_NAME=promptguard_db

# Optional LLM/Groq API key used by the service
GROQ_API_KEY=your_groq_api_key_here

# Optional: override ports/hosts
API_HOST=127.0.0.1
API_PORT=8000
STREAMLIT_PORT=8501
```

Important env vars:

- **MONGO_URI**: MongoDB connection string used by `LogRepository`.
- **GROQ_API_KEY**: Optional key for external LLM classification (if configured).

If `SECRET_KEY` is not provided in development, a dev secret is generated automatically; in production you should explicitly set a secure `SECRET_KEY`.

---

## Getting Started — Run the System

Start the backend (FastAPI + Uvicorn):

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Start the frontend (Streamlit SOC dashboard):

```bash
streamlit run ui/dashboard.py --server.port 8501 --server.address 0.0.0.0
```

Alternative ways to launch the UI (venv-friendly):

- Using the helper script (ensures correct Python executable in venv):

```bash
python run_ui.py
```

- Or run the package (debug/run mode):

```bash
python -m ui
```

> Note: `streamlit run ui` does not directly execute a package `__init__` file; prefer `streamlit run ui/dashboard.py` or `python run_ui.py`.

---

## API Reference (summary)

Swagger UI is available at **`/docs`** and ReDoc at **`/redoc`** when the backend is running (e.g., http://localhost:8000/docs).

Basic endpoints:

| Endpoint    | Method | Description                                                                                                                                                                                                      |
| ----------- | -----: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/evaluate` |   POST | Evaluate a prompt. Request model: `PromptRequest` {`session_id`, `prompt`} — Response: `PromptResponse` (verdict, final_score, safe_prompt, latency_ms, rule_triggers, threat_type, reasoning, sentinel_action). |
| `/summary`  |    GET | Returns analytics summary (used by UI status tiles).                                                                                                                                                             |
| `/logs`     |    GET | Returns recent logs. Query param: `limit` (default 100).                                                                                                                                                         |

Example evaluate request (curl):

```bash
curl -X POST "http://localhost:8000/evaluate" -H "Content-Type: application/json" -d '{"session_id":"ui","prompt":"Ignore previous instructions"}'
```

---

## UI & Dashboard

The Streamlit dashboard (in `ui/dashboard.py`) provides:

- **KPI tiles** (total scans, block rate, avg risk, system health)
- **Time-series area chart** for detections (Altair)
- **Top attack vector bar chart** and **verdict donut**
- **Latest logs table** with search and CSV export
- **AI Console** for interactive testing (sends test prompts to `/evaluate`)

The UI uses a small `BackendClient` wrapper in `ui/components.py` to call the API and caches requests with `st.cache_data` for responsive UX.

---

## Design Notes & Best Practices

- The hybrid scoring approach uses deterministic rules (fast, auditable) as the primary guard, with LLM confidence blended in when available. The service implements fail-safe behavior: if the LLM classifier is unavailable, the system falls back to deterministic signals only.
- All database writes are executed as **best-effort background tasks** to avoid adding latency to evaluation requests.
- Configuration is centralized in `app/core/config.py` using `pydantic-settings` for environment-driven, production-friendly defaults.

---

## Contributing

Contributions are welcome. Suggested next steps:

- Add unit tests for `rule_engine` deterministic rules and `security_service` scoring.
- Add integration tests for the API endpoints (mocking the repository).
- Make the `Force Reconnect LLM` UI action call an authenticated admin endpoint to trigger an LLM re-initialization.

---

## License

Include your preferred license here.

---

If you'd like, I can also:

- Add a short **Quickstart** GIF or screenshot of the dashboard.
- Add a `docs/` folder with architecture diagrams and a sequence diagram for evaluation flow.
- Create a Windows `ui.bat` wrapper that runs the recommended Streamlit command.

Feel free to tell me which of these you'd like next.
