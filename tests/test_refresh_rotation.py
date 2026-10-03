"""一次性刷新令牌：轮换、重放检测、过期与失效的区分。"""
import time

from app.config import Settings
from fastapi.testclient import TestClient
from main import create_app
from tests.conftest import bearer, login


def test_refresh_rotates_and_old_token_dies(client):
    tokens = login(client, "analyst", "analyst-pass")
    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 200
    rotated = resp.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]
    assert rotated["access_token"] != tokens["access_token"]
    # 新令牌可用
    assert client.get("/me", headers=bearer(rotated)).status_code == 200


def test_reused_refresh_token_is_replay_and_kills_session(client):
    tokens = login(client, "analyst", "analyst-pass")
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    # 同一个旧令牌再次使用 -> 重放
    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "refresh_reused"
    # 整个会话被熔断：连刚换出的新访问令牌也立即失效
    tokens2 = login(client, "analyst", "analyst-pass")
    r = client.post("/auth/refresh", json={"refresh_token": tokens2["refresh_token"]})
    assert r.status_code == 200
    client.post("/auth/refresh", json={"refresh_token": tokens2["refresh_token"]})  # replay
    resp = client.get("/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "session_revoked"


def test_replay_is_audited(client):
    tokens = login(client, "analyst", "analyst-pass")
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    audit = client.app.state.store.audit
    assert any(e.action == "refresh_reuse_detected" for e in audit)


def test_unknown_refresh_token_is_invalid(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "no-such-token"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "refresh_invalid"


def test_expired_refresh_token_is_distinct_from_replay():
    settings = Settings(secret_key="t", access_token_ttl=300, refresh_token_ttl=-1)
    client = TestClient(create_app(settings))
    from app.security import hash_password
    from app.models import User
    client.app.state.store.add_user(User(
        id="u1", username="a", password_hash=hash_password("p"), roles=frozenset({"viewer"})))
    tokens = login(client, "a", "p")
    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "refresh_expired"


def test_expired_access_token_is_distinct():
    settings = Settings(secret_key="t", access_token_ttl=-1, refresh_token_ttl=3600)
    client = TestClient(create_app(settings))
    from app.security import hash_password
    from app.models import User
    client.app.state.store.add_user(User(
        id="u1", username="a", password_hash=hash_password("p"), roles=frozenset({"viewer"})))
    tokens = login(client, "a", "p")
    time.sleep(0.01)
    resp = client.get("/me", headers=bearer(tokens))
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "token_expired"
