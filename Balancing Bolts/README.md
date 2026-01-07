Apartment Inventory & Invoice Tracker

Overview
- FastAPI backend with SQLite (SQLModel)
- Basic frontend at `index.html`
- Invoice CSV import and item assignment
- Role-based users and property management
- AI assistant endpoint using OpenAI embeddings + completion (requires API key)
- Placeholder OAuth/OpenID Connect integration for ResMan (requires client credentials)

Quick start
1. Create a Python venv and activate it.

```bash
python -m venv .venv
# Windows
.\\.venv\\Scripts\\activate
# mac / linux
source .venv/bin/activate
pip install -r backend/requirements.txt
```

2. Set environment variables (example):

```bash
set OPENAI_API_KEY=sk-...
# optionally, set RESMAN_CLIENT_ID and RESMAN_CLIENT_SECRET and RESMAN_REDIRECT_URI
```

3. Run the backend:

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

4. Open `index.html` in a browser (or serve it).

Notes
- To connect to ResMan: obtain client id/secret and configure OAuth callback. The backend includes a placeholder route and storage for tokens.
- AI assistant uses OpenAI embeddings and completion; billing applies.
- This is a starting scaffold. Next steps: secure auth flows, background ingestion from ResMan, production deployment.

Logging & Environment
---------------------
- `OPENAI_API_KEY`: required for AI assistant features.
- `RESMAN_CLIENT_ID`, `RESMAN_CLIENT_SECRET`, `RESMAN_REDIRECT_URI`: for ResMan OAuth flow (optional).
- `RESMAN_INVOICES_URL`: if set, the background poller calls this endpoint using stored tokens to pull invoices (JSON or CSV expected).
- `RESMAN_POLL_INTERVAL`: seconds between automatic polls (default `3600`).
- `LOG_LEVEL`: logging level (e.g. `DEBUG`, `INFO`, `WARNING`).

Example: enable polling every 15 minutes and run backend

```bash
set RESMAN_INVOICES_URL=https://example.com/invoices
set RESMAN_POLL_INTERVAL=900
set LOG_LEVEL=DEBUG
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Admin endpoints
---------------
- `POST /api/resman/poller/enable` — start the background poller (manager-only)
- `POST /api/resman/poller/disable` — stop the poller (manager-only)
- `GET /api/resman/poller/status` — check poller status (manager-only)
- `POST /api/resman/pull` — trigger a manual pull and return detailed results (manager-only)

Reports
-------
- `GET /api/reports/monthly?year=YYYY&month=M[&property_id=N]` — returns total spend for that month.
- `GET /api/reports/yearly?year=YYYY[&property_id=N]` — returns total spend for that year.

Testing
-------
Run tests (requires `pytest`):

```bash
cd backend
pytest -q
```

Continuous integration
----------------------
There's a GitHub Actions workflow at `.github/workflows/ci.yml` that runs the tests on pushes and pull requests. To enable it, push this repository to GitHub and open a PR.

API Docs
--------
The FastAPI app exposes OpenAPI documentation at `/docs` (Swagger UI) and `/redoc` (ReDoc). When the backend is running locally, open `http://localhost:8000/docs` to explore and try endpoints.
