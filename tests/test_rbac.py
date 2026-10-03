"""越权场景：权限不足必须 403 forbidden，且与未登录/凭据问题区分开。"""
from tests.conftest import bearer, login


def test_viewer_cannot_read_reports(client):
    tokens = login(client, "viewer", "viewer-pass")
    resp = client.get("/reports", headers=bearer(tokens))
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "forbidden"


def test_analyst_can_read_reports(client):
    tokens = login(client, "analyst", "analyst-pass")
    assert client.get("/reports", headers=bearer(tokens)).status_code == 200


def test_multi_role_user_gets_union_of_permissions(client):
    tokens = login(client, "multi", "multi-pass")
    assert client.get("/me", headers=bearer(tokens)).status_code == 200
    assert client.get("/reports", headers=bearer(tokens)).status_code == 200


def test_non_admin_cannot_revoke_session(client):
    victim = login(client, "viewer", "viewer-pass")
    attacker = login(client, "analyst", "analyst-pass")
    resp = client.post(f"/admin/sessions/{victim['session_id']}/revoke", headers=bearer(attacker))
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "forbidden"
    # 越权尝试不影响受害者会话
    assert client.get("/me", headers=bearer(victim)).status_code == 200


def test_anonymous_cannot_call_admin_api(client):
    resp = client.post("/admin/users/u-viewer/revoke-all")
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "not_authenticated"


def test_forbidden_attempt_is_audited(client):
    tokens = login(client, "viewer", "viewer-pass")
    client.get("/reports", headers=bearer(tokens))
    audit = client.app.state.store.audit
    assert any(e.action == "forbidden" and e.detail.get("permission") == "reports:read" for e in audit)
