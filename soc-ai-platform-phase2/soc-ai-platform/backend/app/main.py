from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import auth as auth_api, events as events_api
from app.config import get_settings
from app.db import apply_validators, ensure_indexes, get_db
from app.errors import register_error_handlers


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    if s.jwt_secret == "CHANGE_ME_IN_ENV" and not s.use_mock_db:
        raise RuntimeError("Set JWT_SECRET in the environment before starting the server")
    db = get_db()
    await apply_validators(db)
    await ensure_indexes(db)
    yield


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title=s.app_name, version="0.2.0", lifespan=lifespan,
                  description="AI-assisted SOC platform API (Phase 2: auth + event ingestion).")
    app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in s.cors_origins.split(",")],
                       allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > s.max_body_bytes + 4096:
            return JSONResponse({"error": {"code": "payload_too_large", "message": "Request body too large",
                                           "details": None}}, status_code=413)
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    register_error_handlers(app)
    app.include_router(auth_api.router)
    app.include_router(events_api.router)

    @app.get("/api/health", tags=["System"])
    async def health():
        return {"status": "ok", "mock_db": s.use_mock_db}
    return app


app = create_app()
