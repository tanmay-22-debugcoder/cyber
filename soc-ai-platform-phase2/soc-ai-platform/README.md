# AI-Based Cyber Threat Detection & SOC Dashboard

## Status (Phase 2 of 10)

| Feature | Status |
|---|---|
| JWT auth, bcrypt hashing, admin/analyst RBAC, login rate limit | Implemented, tested |
| Event ingestion (JSON API, JSON/CSV file import, Wazuh webhook) | Implemented, tested |
| Normalization, validation, sanitization, dedupe, pagination/filter search | Implemented, tested |
| MongoDB indexes, TTL retention, JSON-schema validators | Implemented (validators only applied on real MongoDB; not covered by tests) |
| Rules, simulator, correlation, attack chains, risk, intel, ML, dashboard, reports | **Pending** (Phases 3-10) |

Tests run against an in-memory MongoDB mock (`mongomock-motor`). They have **not** been run against a real MongoDB server
or a real Wazuh instance; the Wazuh endpoint is tested with a sample alert payload only.

## Run locally (without Docker)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example .env        # then set JWT_SECRET (and MONGO_URI=mongodb://localhost:27017)
python seed_admin.py admin 'ChangeThisPass123!'
uvicorn app.main:app --reload
```
Open http://localhost:8000/docs for the interactive OpenAPI docs. Requires a running MongoDB.

## Run with Docker
```bash
cp .env.example .env           # set JWT_SECRET
docker compose up --build
docker compose exec backend python seed_admin.py admin 'ChangeThisPass123!'
```

## Tests
```bash
cd backend && python -m pytest -q
```

## API (Phase 2)
| Method | Path | Auth |
|---|---|---|
| POST | /api/auth/login | none |
| POST | /api/auth/logout, GET /api/auth/me | any user |
| POST | /api/auth/users | admin |
| POST | /api/events (JSON array, max 1000) | analyst+ |
| POST | /api/events/import (.json/.csv upload) | analyst+ |
| POST | /api/ingest/wazuh (header `X-Webhook-Token`) | shared secret |
| GET | /api/events (filters: q, src_ip, dst_ip, username, event_type, severity, host, source, start, end, page, page_size) | analyst+ |
| GET | /api/events/{id} | analyst+ |
| GET | /api/health | none |

Errors always use `{"error": {"code", "message", "details"}}`.

### Wazuh setup (outline, untested against a live Wazuh)
Configure a Wazuh integration (custom `integratord` script or similar) to POST alerts to `/api/ingest/wazuh`
with the `X-Webhook-Token` header set to `WAZUH_WEBHOOK_TOKEN`.

## Security notes
Secrets only via environment; server refuses to start with the default JWT secret; user role is read from the DB on every
request; regex-escaped search; control characters stripped from event fields; request body and batch size limits.
