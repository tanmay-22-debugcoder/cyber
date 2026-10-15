from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]


class EventIn(BaseModel):
    """Loose input shape; the normalizer converts it to the common schema."""
    timestamp: datetime | str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    event_type: str
    severity: str | int | None = "low"
    host: str | None = None
    source: str | None = "api"
    raw: dict[str, Any] = Field(default_factory=dict)
    is_synthetic: bool = False


class EventOut(BaseModel):
    id: str
    timestamp: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    event_type: str
    severity: Severity
    host: str | None = None
    source: str
    raw: dict[str, Any] = {}
    is_synthetic: bool = False


class IngestResult(BaseModel):
    received: int
    inserted: int
    duplicates: int
    rejected: int
    errors: list[dict] = []
