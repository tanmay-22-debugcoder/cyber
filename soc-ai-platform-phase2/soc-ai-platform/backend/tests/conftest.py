import os
os.environ["USE_MOCK_DB"] = "true"
os.environ["JWT_SECRET"] = "test-secret-test-secret-test-secret"
os.environ["WAZUH_WEBHOOK_TOKEN"] = "hook-secret"

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from app.auth.security import hash_password
from app.config import get_settings
from app.db import ensure_indexes, get_db, reset_db


@pytest_asyncio.fixture
async def client():
    get_settings.cache_clear()
    reset_db()
    from app.api import auth as auth_api
    auth_api._attempts.clear()
    db = get_db()
    await ensure_indexes(db)
    for name, role in (("admin1", "admin"), ("analyst1", "analyst")):
        await db.users.insert_one({"username": name, "password_hash": hash_password("Password123!"),
                                   "role": role, "is_active": True})
    from app.main import create_app
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def login(client, username="analyst1", password="Password123!"):
    r = await client.post("/api/auth/login", json={"username": username, "password": password})
    return {"Authorization": f"Bearer {r.json()['access_token']}"} if r.status_code == 200 else None


@pytest_asyncio.fixture
async def analyst(client):
    return await login(client)


@pytest_asyncio.fixture
async def admin(client):
    return await login(client, "admin1")
