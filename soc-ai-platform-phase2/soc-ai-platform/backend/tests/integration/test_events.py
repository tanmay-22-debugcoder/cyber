import io

EV = {"timestamp": "2026-03-01T10:00:00Z", "src_ip": "203.0.113.5", "dst_ip": "10.0.0.8",
      "username": "alice", "event_type": "failed_login", "severity": "medium", "host": "web01"}


async def test_ingest_and_dedupe(client, analyst):
    r = await client.post("/api/events", json=[EV, EV], headers=analyst)
    assert r.status_code == 201
    assert r.json()["inserted"] == 1 and r.json()["duplicates"] == 1


async def test_ingest_reports_rejected(client, analyst):
    bad = {**EV, "src_ip": "not-an-ip"}
    r = await client.post("/api/events", json=[EV, bad], headers=analyst)
    assert r.json()["inserted"] == 1 and r.json()["rejected"] == 1
    assert r.json()["errors"][0]["index"] == 1


async def test_search_filters_and_pagination(client, analyst):
    evs = [{**EV, "timestamp": f"2026-03-01T10:{i:02d}:00Z", "src_ip": f"203.0.113.{i}",
            "severity": "high" if i % 2 else "low"} for i in range(1, 11)]
    await client.post("/api/events", json=evs, headers=analyst)
    r = await client.get("/api/events?severity=high", headers=analyst)
    assert r.json()["total"] == 5
    r = await client.get("/api/events?page=2&page_size=4", headers=analyst)
    body = r.json()
    assert body["total"] == 10 and len(body["items"]) == 4 and body["page"] == 2
    r = await client.get("/api/events?start=2026-03-01T10:05:00Z&end=2026-03-01T10:07:00Z", headers=analyst)
    assert r.json()["total"] == 3
    r = await client.get("/api/events?q=203.0.113.1", headers=analyst)
    assert r.json()["total"] >= 1
    assert (await client.get("/api/events?severity=bogus", headers=analyst)).status_code == 422


async def test_search_regex_is_escaped(client, analyst):
    await client.post("/api/events", json=[EV], headers=analyst)
    r = await client.get("/api/events?q=.*", headers=analyst)
    assert r.status_code == 200 and r.json()["total"] == 0


async def test_get_event_and_errors(client, analyst):
    await client.post("/api/events", json=[EV], headers=analyst)
    eid = (await client.get("/api/events", headers=analyst)).json()["items"][0]["id"]
    assert (await client.get(f"/api/events/{eid}", headers=analyst)).json()["username"] == "alice"
    assert (await client.get("/api/events/zzz", headers=analyst)).status_code == 400
    assert (await client.get("/api/events/" + "0" * 24, headers=analyst)).status_code == 404


async def test_import_csv_and_json(client, analyst):
    csv_data = ("timestamp,src_ip,event_type,severity,username,extra\n"
                "2026-03-02T10:00:00Z,198.51.100.7,failed_login,high,bob,abc\n"
                "2026-03-02T10:01:00Z,198.51.100.7,failed_login,high,bob,def\n")
    r = await client.post("/api/events/import", headers=analyst,
                          files={"file": ("e.csv", io.BytesIO(csv_data.encode()), "text/csv")})
    assert r.status_code == 201 and r.json()["inserted"] == 2
    js = b'{"events":[{"event_type":"port_scan","src_ip":"198.51.100.9","severity":"high"}]}'
    r = await client.post("/api/events/import", headers=analyst,
                          files={"file": ("e.json", io.BytesIO(js), "application/json")})
    assert r.json()["inserted"] == 1
    r = await client.post("/api/events/import", headers=analyst,
                          files={"file": ("e.txt", io.BytesIO(b"x"), "text/plain")})
    assert r.status_code == 400
    r = await client.post("/api/events/import", headers=analyst,
                          files={"file": ("e.json", io.BytesIO(b"{bad"), "application/json")})
    assert r.status_code == 400


async def test_wazuh_webhook(client, analyst):
    alert = {"timestamp": "2026-03-03T10:00:00.000+0000", "rule": {"level": 10, "groups": ["authentication_failed"]},
             "agent": {"name": "db01"}, "data": {"srcip": "192.0.2.44", "dstuser": "root"}}
    assert (await client.post("/api/ingest/wazuh", json=alert)).status_code == 401
    assert (await client.post("/api/ingest/wazuh", json=alert, headers={"X-Webhook-Token": "wrong"})).status_code == 401
    r = await client.post("/api/ingest/wazuh", json=[alert], headers={"X-Webhook-Token": "hook-secret"})
    assert r.status_code == 201 and r.json()["inserted"] == 1
    ev = (await client.get("/api/events?source=wazuh", headers=analyst)).json()["items"][0]
    assert ev["event_type"] == "failed_login" and ev["host"] == "db01"


async def test_batch_limit(client, analyst):
    evs = [{**EV, "src_ip": f"10.1.{i // 250}.{i % 250 + 1}"} for i in range(1001)]
    assert (await client.post("/api/events", json=evs, headers=analyst)).status_code == 413


async def test_health_and_docs(client):
    assert (await client.get("/api/health")).json()["status"] == "ok"
    assert (await client.get("/openapi.json")).status_code == 200
