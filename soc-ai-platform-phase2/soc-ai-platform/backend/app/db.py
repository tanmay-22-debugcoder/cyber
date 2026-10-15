"""MongoDB connection, validators and indexes."""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import get_settings

_client = None
_db = None


def get_db() -> AsyncIOMotorDatabase:
    global _client, _db
    if _db is None:
        s = get_settings()
        if s.use_mock_db:
            from mongomock_motor import AsyncMongoMockClient
            _client = AsyncMongoMockClient()
        else:
            _client = AsyncIOMotorClient(s.mongo_uri, serverSelectionTimeoutMS=5000)
        _db = _client[s.mongo_db]
    return _db


def reset_db() -> None:
    """Drop the cached client (used by tests)."""
    global _client, _db
    _client = _db = None


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    s = get_settings()
    await db.users.create_index("username", unique=True)
    ev = db.security_events
    await ev.create_index("dedupe_hash", unique=True)
    await ev.create_index([("timestamp", -1)])
    await ev.create_index([("src_ip", 1), ("timestamp", -1)])
    await ev.create_index([("username", 1), ("timestamp", -1)])
    await ev.create_index([("event_type", 1), ("timestamp", -1)])
    await ev.create_index("ingested_at", expireAfterSeconds=s.event_retention_days * 86400)
    await db.analyst_actions.create_index([("incident_id", 1), ("timestamp", -1)])
    # Phase 4+ collections (incidents, correlations, ...) get their indexes when implemented.


USER_VALIDATOR = {"$jsonSchema": {
    "bsonType": "object", "required": ["username", "password_hash", "role"],
    "properties": {"role": {"enum": ["admin", "analyst"]}}}}

EVENT_VALIDATOR = {"$jsonSchema": {
    "bsonType": "object",
    "required": ["timestamp", "event_type", "severity", "source", "dedupe_hash"],
    "properties": {"severity": {"enum": ["low", "medium", "high", "critical"]}}}}


async def apply_validators(db: AsyncIOMotorDatabase) -> None:
    """Server-side JSON-schema validation (real MongoDB only; skipped for the mock)."""
    if get_settings().use_mock_db:
        return
    existing = await db.list_collection_names()
    for name, validator in (("users", USER_VALIDATOR), ("security_events", EVENT_VALIDATOR)):
        if name in existing:
            await db.command("collMod", name, validator=validator)
        else:
            await db.create_collection(name, validator=validator)
