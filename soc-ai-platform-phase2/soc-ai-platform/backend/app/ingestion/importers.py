"""JSON / CSV file parsing into raw event dicts."""
import csv
import io
import json
from app.errors import AppError

CSV_FIELDS = {"timestamp", "src_ip", "dst_ip", "username", "event_type", "severity", "host", "source"}


def parse_json_bytes(data: bytes) -> list[dict]:
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise AppError(400, "invalid_file", f"Invalid JSON file: {e}")
    if isinstance(obj, dict):
        obj = obj.get("events", [obj])
    if not isinstance(obj, list) or not all(isinstance(x, dict) for x in obj):
        raise AppError(400, "invalid_file", "JSON must be an object or an array of objects")
    return obj


def parse_csv_bytes(data: bytes) -> list[dict]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise AppError(400, "invalid_file", "CSV must be UTF-8 encoded")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "event_type" not in reader.fieldnames:
        raise AppError(400, "invalid_file", "CSV must have a header row including 'event_type'")
    return [{**{k: (v or None) for k, v in row.items() if k in CSV_FIELDS},
             "raw": {k: v for k, v in row.items() if k and k not in CSV_FIELDS}} for row in reader]
