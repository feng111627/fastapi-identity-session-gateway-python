"""业务场景测试：登录、越权、过期、重放、撤销、审计。

错误码约定：
  not_authenticated / invalid_credentials / token_expired /
  refresh_token_replayed / session_revoked / user_sessions_revoked /
  permission_denied
"""

from tests.support import GatewayTestCase


class LoginTests(GatewayTestCase):
    business = "登录认证"

    def test_login_success_returns_token_pair(self):
        """正确凭据应返回访问令牌+一次性刷新令牌及会话标识"""
        data = self.login("alice")
        self.assertEqual(data["token_type"], "Bearer")
        self.assertTrue(data["access_token"])
        self.assertTrue(data["refresh_token"])
        self.assertEqual(data["expires_in"], 900)
        self.assertTrue(data["session_id"])

    def test_login_bad_password_is_invalid_credentials(self):
        """密码错误必须是 invalid_credentials，而不是含糊的 401"""
        r = self.client.post("/auth/login",
                             json={"username": "alice", "password": "wrong"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "invalid_credentials")

    def test_login_unknown_user_is_invalid_credentials(self):
        """未知用户同样给出 invalid_credentials（不暴露用户是否存在）"""
        r = self.client.post("/auth/login",
                             json={"username": "ghost", "password": "x"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "invalid_credentials")


class AccessControlTests(GatewayTestCase):
    business = "角色与权限"

    def test_missing_token_is_not_authenticated(self):
        """不带令牌访问受保护接口必须是 not_authenticated"""
        r = self.client.get("/me")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "not_authenticated")

    def test_viewer_can_read_cannot_write(self):
        """viewer 可读不可写：同一用户对不同权限接口结论不同"""
        tok = self.login("alice")["access_token"]
        ok = self.client.get("/viewer-area", headers=self.auth(tok))
        no = self.client.post("/editor-area", headers=self.auth(tok))
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(no.status_code, 403)
        self.assertEqual(no.json()["error"]["code"], "permission_denied")

    def test_multi_role_user_gets_union_of_permissions(self):
        """多角色用户 bob(viewer,editor) 应同时拥有读和写权限"""
        tok = self.login("bob")["access_token"]
        self.assertEqual(self.client.get("/viewer-area",
                                         headers=self.auth(tok)).status_code, 200)
        self.assertEqual(self.client.post("/editor-area",
                                          headers=self.auth(tok)).status_code, 200)

    def test_auditor_cannot_reach_editor_area(self):
        """auditor 没有 content:write，必须 permission_denied"""
        tok = self.login("carol")["access_token"]
        r = self.client.post("/editor-area", headers=self.auth(tok))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.json()["error"]["code"], "permission_denied")

    def test_non_admin_cannot_revoke_or_read_audit(self):
        """普通用户访问管理接口必须 permission_denied（403 而非 401）"""
        tok = self.login("bob")["access_token"]
        h = self.auth(tok)
        self.assertEqual(self.client.post(
            "/admin/sessions/x/revoke", headers=h).status_code, 403)
        self.assertEqual(self.client.get("/admin/audit", headers=h).status_code, 403)
        self.assertEqual(self.client.get(
            "/admin/audit", headers=h).json()["error"]["code"],
            "permission_denied")

    def test_admin_can_read_audit(self):
        """admin 隐含全部权限，可查看审计"""
        tok = self.login("admin")["access_token"]
        r = self.client.get("/admin/audit", headers=self.auth(tok))
        self.assertEqual(r.status_code, 200)


class TokenValidityTests(GatewayTestCase):
    business = "凭据有效性"

    def test_malformed_and_forged_tokens_are_invalid(self):
        """格式错误/篡改/随机字符串一律 invalid_credentials"""
        for token in ("garbage", "aaa.bbb", "x" * 40):
            r = self.client.get("/me", headers=self.auth(token))
            self.assertEqual(r.status_code, 401, token)
            self.assertEqual(r.json()["error"]["code"],
                             "invalid_credentials", token)

    def test_tampered_signature_is_invalid(self):
        """改签名必须被判 invalid_credentials，不能误认为过期或越权"""
        tok = self.login("alice")["access_token"]
        head, sig = tok.split(".")
        flipped = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        r = self.client.get("/me", headers=self.auth(f"{head}.{flipped}"))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "invalid_credentials")

    def test_expired_access_token_is_token_expired(self):
        """过期访问令牌必须明确是 token_expired，区别于未登录/无效"""
        data = self.login("alice")
        self.advance(901)  # 访问令牌 TTL=900
        r = self.client.get("/me", headers=self.auth(data["access_token"]))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "token_expired")

    def test_expired_refresh_token_is_token_expired(self):
        """过期刷新令牌必须明确是 token_expired（而非重放）"""
        data = self.login("alice")
        self.advance(60 * 60 * 24 * 7 + 1)
        r = self.client.post("/auth/refresh",
                             json={"refresh_token": data["refresh_token"]})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "token_expired")

    def test_refresh_changes_both_tokens_and_invalidates_old(self):
        """刷新换发新对凭据：返回新令牌且与旧的不同"""
        data = self.login("alice")
        r = self.client.post("/auth/refresh",
                             json={"refresh_token": data["refresh_token"]})
        self.assertEqual(r.status_code, 200)
        new = r.json()
        self.assertNotEqual(new["access_token"], data["access_token"])
        self.assertNotEqual(new["refresh_token"], data["refresh_token"])
        self.assertEqual(new["session_id"], data["session_id"])


class RefreshReplayTests(GatewayTestCase):
    business = "刷新重放"

    def test_reuse_old_refresh_token_is_replay_not_expiry(self):
        """同一刷新令牌用第二次必须判定为 refresh_token_replayed"""
        data = self.login("alice")
        self.client.post("/auth/refresh",
                         json={"refresh_token": data["refresh_token"]})
        r = self.client.post("/auth/refresh",
                             json={"refresh_token": data["refresh_token"]})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"],
                         "refresh_token_replayed")
        self.assertNotEqual(r.json()["error"]["code"], "token_expired")

    def test_chain_rotation_only_last_token_valid(self):
        """连续轮转：只有最新一枚刷新令牌可用，历史全部作废"""
        data = self.login("bob")
        rt = data["refresh_token"]
        older = []
        for _ in range(3):
            r = self.client.post("/auth/refresh", json={"refresh_token": rt})
            self.assertEqual(r.status_code, 200)
            older.append(rt)
            rt = r.json()["refresh_token"]
        for old in older:
            r = self.client.post("/auth/refresh", json={"refresh_token": old})
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json()["error"]["code"],
                             "refresh_token_replayed")
        # 最新一枚仍可正常使用
        self.assertEqual(self.client.post(
            "/auth/refresh", json={"refresh_token": rt}).status_code, 200)

    def test_sessions_are_independent_per_user(self):
        """不同用户的会话与刷新令牌彼此独立，互不影响"""
        alice = self.login("alice")
        bob = self.login("bob")
        # 双方各自轮转自己的刷新令牌均应成功，不能互相作废
        self.assertEqual(self.client.post(
            "/auth/refresh",
            json={"refresh_token": alice["refresh_token"]}).status_code, 200)
        self.assertEqual(self.client.post(
            "/auth/refresh",
            json={"refresh_token": bob["refresh_token"]}).status_code, 200)
        # 随后两枚旧令牌都只能被判重放
        for old in (alice["refresh_token"], bob["refresh_token"]):
            r = self.client.post("/auth/refresh",
                                 json={"refresh_token": old})
            self.assertEqual(r.status_code, 401)
            self.assertEqual(r.json()["error"]["code"],
                             "refresh_token_replayed")


class RevocationTests(GatewayTestCase):
    business = "会话撤销"

    def test_admin_revoke_session_kills_access_immediately(self):
        """撤销单会话后，其未过期访问令牌必须立即 session_revoked"""
        victim = self.login("alice")
        admin = self.login("admin")
        h = self.auth(admin["access_token"])
        r = self.client.post(
            f"/admin/sessions/{victim['session_id']}/revoke", headers=h)
        self.assertEqual(r.status_code, 204)
        r = self.client.get("/me", headers=self.auth(victim["access_token"]))
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "session_revoked")

    def test_revoked_session_refresh_also_rejected(self):
        """撤销后刷新凭据同样不能换新，结论为 session_revoked"""
        victim = self.login("alice")
        admin = self.login("admin")
        self.client.post(
            f"/admin/sessions/{victim['session_id']}/revoke",
            headers=self.auth(admin["access_token"]))
        r = self.client.post("/auth/refresh",
                             json={"refresh_token": victim["refresh_token"]})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"]["code"], "session_revoked")

    def test_revoke_all_user_sessions(self):
        """用户级撤销：该用户所有会话立刻失效，其他用户不受影响"""
        a1 = self.login("alice")
        a2 = self.login("alice")
        bob = self.login("bob")
        admin = self.login("admin")
        r = self.client.post(
            "/admin/users/alice/revoke-sessions",
            headers=self.auth(admin["access_token"]))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["revoked"], 2)
        for tok in (a1["access_token"], a2["access_token"]):
            rr = self.client.get("/me", headers=self.auth(tok))
            self.assertEqual(rr.status_code, 401)
            self.assertEqual(rr.json()["error"]["code"],
                             "user_sessions_revoked")
        # bob 仍然有效
        self.assertEqual(self.client.get(
            "/me", headers=self.auth(bob["access_token"])).status_code, 200)

    def test_new_login_after_user_wide_revoke_is_clean(self):
        """用户级撤销之后新登录的会话不受旧 epoch 影响"""
        old = self.login("alice")
        admin = self.login("admin")
        self.client.post("/admin/users/alice/revoke-sessions",
                         headers=self.auth(admin["access_token"]))
        fresh = self.login("alice")
        r = self.client.get("/me", headers=self.auth(fresh["access_token"]))
        self.assertEqual(r.status_code, 200)
        # 旧会话仍是撤销状态
        self.assertEqual(self.client.get(
            "/me", headers=self.auth(old["access_token"])).status_code, 401)

    def test_logout_revokes_current_session(self):
        """登出即撤销当前会话，旧令牌立即失效"""
        data = self.login("carol")
        h = self.auth(data["access_token"])
        self.assertEqual(self.client.post("/auth/logout", headers=h).status_code,
                         204)
        self.assertEqual(self.client.get("/me", headers=h).status_code, 401)
        r = self.client.post("/auth/refresh",
                             json={"refresh_token": data["refresh_token"]})
        self.assertEqual(r.json()["error"]["code"], "session_revoked")


class AuditTests(GatewayTestCase):
    business = "审计追溯"

    def test_audit_records_key_actions_and_denials(self):
        """登录失败、成功、重放、撤销都要有可追溯记录与结果标记"""
        self.client.post("/auth/login",
                         json={"username": "alice", "password": "bad"})
        data = self.login("alice")
        self.client.post("/auth/refresh",
                         json={"refresh_token": data["refresh_token"]})
        self.client.post("/auth/refresh",
                         json={"refresh_token": data["refresh_token"]})
        admin = self.login("admin")
        self.client.post(
            f"/admin/sessions/{data['session_id']}/revoke",
            headers=self.auth(admin["access_token"]))
        audit = self.client.get(
            "/admin/audit", headers=self.auth(admin["access_token"])).json()
        actions = [(a["action"], a["result"]) for a in audit]
        self.assertIn(("login_failed", "denied"), actions)
        self.assertIn(("login", "success"), actions)
        self.assertIn(("refresh", "success"), actions)
        self.assertIn(("refresh_denied", "denied"), actions)
        self.assertIn(("admin_revoke_session", "success"), actions)
        # 序号严格递增，无遗漏
        self.assertEqual([a["seq"] for a in audit],
                         list(range(1, len(audit) + 1)))
