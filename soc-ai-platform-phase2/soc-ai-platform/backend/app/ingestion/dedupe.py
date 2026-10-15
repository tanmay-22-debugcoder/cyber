import hashlib
import json


def compute_dedupe_hash(ev: dict) -> str:
    """SHA-256 over identifying fields. Identical events (same time, entities, type, source, raw) collapse."""
    ts = ev["timestamp"].isoformat() if ev.get("timestamp") else ""
    parts = [ts, ev.get("src_ip") or "", ev.get("dst_ip") or "", ev.get("username") or "",
             ev.get("event_type") or "", ev.get("host") or "", ev.get("source") or "",
             json.dumps(ev.get("raw") or {}, sort_keys=True, default=str)]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
