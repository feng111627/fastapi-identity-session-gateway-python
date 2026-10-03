"""管理员撤销：立即生效、可审计。"""
from tests.conftest import bearer, login


def test_admin_revoke_session_invalidates_access_and_refresh(client):
    victim = login(client, "analyst", "analyst-pass")
    admin = login(client, "admin", "admin-pass")
    resp = client.post(f"/admin/sessions/{victim['session_id']}/revoke", headers=bearer(admin))
    assert resp.status_code == 200
    # 访问令牌立即失效
    resp = client.get("/me", headers=bearer(victim))
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "session_revoked"
    # 刷新令牌同样失效，且是 revoked 而不是 expired/reused
    resp = client.post("/auth/refresh", json={"refresh_token": victim["refresh_token"]})
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "session_revoked"


def test_admin_revoke_all_user_sessions(client):
    t1 = login(client, "analyst", "analyst-pass")
    t2 = login(client, "analyst", "analyst-pass")
    other = login(client, "viewer", "viewer-pass")
    admin = login(client, "admin", "admin-pass")
    resp = client.post("/admin/users/u-analyst/revoke-all", headers=bearer(admin))
    assert resp.status_code == 200
    assert resp.json()["revoked_sessions"] == 2
    for t in (t1, t2):
        assert client.get("/me", headers=bearer(t)).json()["detail"]["code"] == "session_revoked"
    # 其他用户不受影响
    assert client.get("/me", headers=bearer(other)).status_code == 200


def test_revocation_is_audited(client):
    victim = login(client, "viewer", "viewer-pass")
    admin = login(client, "admin", "admin-pass")
    client.post(f"/admin/sessions/{victim['session_id']}/revoke", headers=bearer(admin))
    client.post("/admin/users/u-viewer/revoke-all", headers=bearer(admin))
    audit = client.app.state.store.audit
    assert any(e.action == "session_revoked" and e.actor == "u-admin" for e in audit)
    assert any(e.action == "user_sessions_revoked" and e.detail.get("user_id") == "u-viewer" for e in audit)


def test_revoke_unknown_session_is_clear_error(client):
    admin = login(client, "admin", "admin-pass")
    resp = client.post("/admin/sessions/nope/revoke", headers=bearer(admin))
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "refresh_invalid"
