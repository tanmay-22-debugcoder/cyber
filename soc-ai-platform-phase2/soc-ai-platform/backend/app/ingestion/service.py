"""Shared ingestion pipeline: normalize -> validate -> dedupe -> insert."""
from datetime import datetime, timezone
from pymongo.errors import DuplicateKeyError
from app.db import get_db
from app.ingestion.dedupe import compute_dedupe_hash
from app.ingestion.normalizer import NormalizationError, normalize_event, normalize_wazuh_alert
from app.schemas.events import IngestResult


async def ingest_raw(items: list[dict], default_source: str | None = None, wazuh: bool = False,
                     force_synthetic: bool | None = None) -> IngestResult:
    coll = get_db().security_events
    res = IngestResult(received=len(items), inserted=0, duplicates=0, rejected=0)
    for idx, item in enumerate(items):
        try:
            if wazuh:
                ev = normalize_wazuh_alert(item)
            else:
                if default_source and not item.get("source"):
                    item = {**item, "source": default_source}
                ev = normalize_event(item)
            if force_synthetic is not None:
                ev["is_synthetic"] = force_synthetic
        except (NormalizationError, AttributeError, TypeError) as e:
            res.rejected += 1
            if len(res.errors) < 50:
                res.errors.append({"index": idx, "error": str(e)})
            continue
        ev["dedupe_hash"] = compute_dedupe_hash(ev)
        ev["ingested_at"] = datetime.now(timezone.utc)
        try:
            await coll.insert_one(ev)
            res.inserted += 1
        except DuplicateKeyError:
            res.duplicates += 1
    return res
