import json

from fastapi.testclient import TestClient

from app.main import app, normalize_message

client = TestClient(app)


def _events(resp):
    out = []
    for block in resp.text.strip().split("\n\n"):
        data = [line[6:] for line in block.splitlines() if line.startswith("data: ")]
        if data:
            out.append(json.loads(data[0]))
    return out


def test_health():
    assert client.get("/health").json()["status"] == "ok"
    deep = client.get("/health/deep").json()
    assert deep["integrations"]["llm_providers"] == []
    assert "key" not in json.dumps(deep).lower().replace("api_key", "")  # no secrets exposed


def test_investigate_streams_result_and_caches():
    msg = {"message": "Your electricity will be disconnected tonight. Call officer 9876543210 immediately"}
    r = client.post("/api/investigate", json=msg)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
    events = _events(r)
    result = events[-1]
    assert result["type"] == "result" and result["report"]["verdict"] in ("scam", "suspicious")
    assert result["case_id"] is None  # anonymous: nothing stored
    again = _events(client.post("/api/investigate", json=msg))
    assert again[-1]["report"]["cached"] is True


def test_validation():
    assert client.post("/api/investigate", json={"message": "  "}).status_code == 422
    assert client.post("/api/investigate", json={"message": "x" * 2500}).status_code == 422


def test_anonymous_rate_limit():
    for i in range(5):
        assert client.post("/api/investigate", json={"message": f"hello number {i} test"}).status_code == 200
    r = client.post("/api/investigate", json={"message": "hello number 99 test"})
    assert r.status_code == 429 and "retry_after" in r.json() and r.json()["reason"] == "ip"


def test_history_requires_login():
    assert client.get("/api/cases").status_code == 401
    assert client.post("/api/cases/abc/followup", json={"question": "hi"}).status_code == 401


def test_cors_only_allows_configured_origin():
    ok = client.options("/api/investigate", headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "POST"})
    bad = client.options("/api/investigate", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-origin" not in bad.headers


def test_normalize_folds_lookalike_letters_and_zero_width():
    assert normalize_message("\U0001d412\U0001d401\U0001d408 K\u200bYC") == "SBI KYC"  # bold letters + zero-width space
    assert "\u200d" in normalize_message("\u0915\u094d\u200d\u0937")  # Hindi zero-width joiner is kept


def test_cached_repeats_do_not_use_up_the_allowance():
    msg = {"message": "Your parcel is held at customs, pay Rs 49 now"}
    for _ in range(8):  # same message: only the first one costs quota
        assert client.post("/api/investigate", json=msg).status_code == 200
    for i in range(4):  # 4 more new messages still fit in the 5/hour allowance
        assert client.post("/api/investigate", json={"message": f"new message {i} to check"}).status_code == 200
    assert client.post("/api/investigate", json={"message": "one too many"}).status_code == 429


def test_admin_email_skips_user_limit(settings_env, monkeypatch):
    settings_env(admin_emails="owner@example.com", user_checks_per_day=1)

    async def fake_user():
        return {"id": "u1", "email": "Owner@Example.com"}

    from app.main import current_user

    app.dependency_overrides[current_user] = fake_user
    try:
        for i in range(3):
            assert client.post("/api/investigate", json={"message": f"admin test message {i}"}).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_feedback_validation_and_masking(monkeypatch):
    saved = {}

    async def fake_save(row):
        saved.update(row)
        return True

    from app.services.store import store

    monkeypatch.setattr(store, "save_feedback", fake_save)
    r = client.post(
        "/api/feedback",
        json={
            "rating": "wrong",
            "verdict_shown": "likely_safe",
            "actual": "scam",
            "comment": "call me on 9876543210",
            "share_message": True,
            "message": "Pay challan for MH12AB1234 at http://echallan-pay.top",
        },
    )
    assert r.status_code == 200 and r.json()["saved"] is True
    assert "9876543210" not in saved["comment"] and "MH12AB1234" not in saved["masked_message"]
    assert "echallan-pay.top" in saved["masked_message"]
    bad = client.post("/api/feedback", json={"rating": "meh", "verdict_shown": "scam"})
    assert bad.status_code == 422


def test_supabase_rest_endpoint_is_accepted(settings_env):
    s = settings_env(supabase_url="https://abcd.supabase.co/rest/v1/")
    assert s.supabase_url == "https://abcd.supabase.co"
