from tests.conftest import login


async def test_login_success_and_me(client):
    h = await login(client)
    r = await client.get("/api/auth/me", headers=h)
    assert r.status_code == 200 and r.json()["role"] == "analyst"


async def test_login_wrong_password(client):
    r = await client.post("/api/auth/login", json={"username": "analyst1", "password": "nope"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_credentials"


async def test_protected_requires_token(client):
    r = await client.get("/api/events")
    assert r.status_code == 401
    r = await client.get("/api/events", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401


async def test_rbac_only_admin_creates_users(client, analyst, admin):
    body = {"username": "newuser", "password": "LongPassword1!", "role": "analyst"}
    assert (await client.post("/api/auth/users", json=body, headers=analyst)).status_code == 403
    assert (await client.post("/api/auth/users", json=body, headers=admin)).status_code == 201
    assert (await client.post("/api/auth/users", json=body, headers=admin)).status_code == 409
    assert await login(client, "newuser", "LongPassword1!") is not None


async def test_login_rate_limit(client):
    for _ in range(5):
        await client.post("/api/auth/login", json={"username": "analyst1", "password": "bad"})
    r = await client.post("/api/auth/login", json={"username": "analyst1", "password": "Password123!"})
    assert r.status_code == 429


async def test_weak_password_rejected(client, admin):
    r = await client.post("/api/auth/users", json={"username": "x1y2z3", "password": "short"}, headers=admin)
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
