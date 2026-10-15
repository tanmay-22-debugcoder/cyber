import hmac
import re
from datetime import datetime
from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, File, Header, Query, UploadFile
from app.auth.deps import require_analyst
from app.config import get_settings
from app.db import get_db
from app.errors import AppError
from app.ingestion.importers import parse_csv_bytes, parse_json_bytes
from app.ingestion.service import ingest_raw
from app.schemas.common import Page
from app.schemas.events import EventIn, EventOut, IngestResult

router = APIRouter(prefix="/api", tags=["Events"])


def _to_out(doc: dict) -> EventOut:
    ts = doc["timestamp"]
    doc = {**doc, "id": str(doc.pop("_id")), "timestamp": ts}
    return EventOut(**{k: doc.get(k) for k in EventOut.model_fields if k in doc})


@router.post("/events", response_model=IngestResult, status_code=201)
async def ingest_events(events: list[EventIn], _: dict = Depends(require_analyst)):
    """Ingest a batch of events (JSON array)."""
    s = get_settings()
    if not events:
        raise AppError(400, "empty_batch", "No events supplied")
    if len(events) > s.max_batch_events:
        raise AppError(413, "batch_too_large", f"Max {s.max_batch_events} events per request")
    return await ingest_raw([e.model_dump(mode="json") for e in events])


@router.post("/events/import", response_model=IngestResult, status_code=201)
async def import_events(file: UploadFile = File(...), _: dict = Depends(require_analyst)):
    """Import events from a .json or .csv file."""
    s = get_settings()
    data = await file.read(s.max_body_bytes + 1)
    if len(data) > s.max_body_bytes:
        raise AppError(413, "file_too_large", "File exceeds size limit")
    name = (file.filename or "").lower()
    if name.endswith(".json"):
        items = parse_json_bytes(data)
    elif name.endswith(".csv"):
        items = parse_csv_bytes(data)
    else:
        raise AppError(400, "unsupported_file", "Only .json and .csv files are supported")
    if len(items) > s.max_batch_events * 10:
        raise AppError(413, "batch_too_large", "Too many rows in file")
    return await ingest_raw(items, default_source="import")


@router.post("/ingest/wazuh", response_model=IngestResult, status_code=201, tags=["Wazuh"])
async def ingest_wazuh(payload: dict | list[dict], x_webhook_token: str | None = Header(default=None)):
    """Wazuh integration endpoint (shared-secret header `X-Webhook-Token`).

    Accepts one alert object or an array of alerts in Wazuh `alerts.json` format.
    Disabled unless WAZUH_WEBHOOK_TOKEN is set.
    """
    expected = get_settings().wazuh_webhook_token
    if not expected:
        raise AppError(503, "wazuh_disabled", "Wazuh webhook is not configured")
    if not x_webhook_token or not hmac.compare_digest(x_webhook_token, expected):
        raise AppError(401, "invalid_webhook_token", "Invalid webhook token")
    items = payload if isinstance(payload, list) else [payload]
    if len(items) > get_settings().max_batch_events:
        raise AppError(413, "batch_too_large", "Batch too large")
    return await ingest_raw(items, wazuh=True)


@router.get("/events", response_model=Page[EventOut])
async def search_events(
    q: str | None = Query(None, max_length=128, description="Substring match on event_type/user/host/IP"),
    src_ip: str | None = None, dst_ip: str | None = None, username: str | None = None,
    event_type: str | None = None, severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    host: str | None = None, source: str | None = None, is_synthetic: bool | None = None,
    start: datetime | None = None, end: datetime | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(25, ge=1, le=200),
    _: dict = Depends(require_analyst),
):
    flt: dict = {}
    for key, val in (("src_ip", src_ip), ("dst_ip", dst_ip), ("username", username),
                     ("event_type", event_type), ("severity", severity), ("host", host), ("source", source)):
        if val:
            flt[key] = val
    if is_synthetic is not None:
        flt["is_synthetic"] = is_synthetic
    if start or end:
        flt["timestamp"] = {}
        if start:
            flt["timestamp"]["$gte"] = start.replace(tzinfo=None) if start.tzinfo is None else start
        if end:
            flt["timestamp"]["$lte"] = end.replace(tzinfo=None) if end.tzinfo is None else end
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}  # escaped: no regex injection
        flt["$or"] = [{f: rx} for f in ("event_type", "username", "host", "src_ip", "dst_ip")]
    coll = get_db().security_events
    total = await coll.count_documents(flt)
    cursor = coll.find(flt).sort("timestamp", -1).skip((page - 1) * page_size).limit(page_size)
    items = [_to_out(d) async for d in cursor]
    return Page[EventOut](items=items, total=total, page=page, page_size=page_size)


@router.get("/events/{event_id}", response_model=EventOut)
async def get_event(event_id: str, _: dict = Depends(require_analyst)):
    try:
        oid = ObjectId(event_id)
    except (InvalidId, TypeError):
        raise AppError(400, "invalid_id", "Invalid event id")
    doc = await get_db().security_events.find_one({"_id": oid})
    if not doc:
        raise AppError(404, "not_found", "Event not found")
    return _to_out(doc)
