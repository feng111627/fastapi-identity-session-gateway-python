"""登录与认证失败原因的区分。"""
from tests.conftest import bearer, login


def test_login_success_returns_token_pair(client):
    tokens = login(client, "analyst", "analyst-pass")
    assert tokens["token_type"] == "bearer"
    assert tokens["access_token"] and tokens["refresh_token"]
    assert tokens["expires_in"] == 300


def test_login_wrong_password_is_bad_credentials(client):
    resp = client.post("/auth/login", json={"username": "analyst", "password": "nope"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "bad_credentials"


def test_login_unknown_user_is_bad_credentials(client):
    resp = client.post("/auth/login", json={"username": "ghost", "password": "x"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "bad_credentials"


def test_missing_token_is_not_authenticated(client):
    resp = client.get("/me")
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "not_authenticated"


def test_malformed_token_is_token_invalid(client):
    resp = client.get("/me", headers={"Authorization": "Bearer garbage.token"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "token_invalid"


def test_wrong_scheme_is_not_authenticated(client):
    tokens = login(client, "viewer", "viewer-pass")
    resp = client.get("/me", headers={"Authorization": f"Basic {tokens['access_token']}"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "not_authenticated"


def test_valid_token_reaches_me(client):
    tokens = login(client, "viewer", "viewer-pass")
    resp = client.get("/me", headers=bearer(tokens))
    assert resp.status_code == 200
    assert resp.json()["username"] == "viewer"
