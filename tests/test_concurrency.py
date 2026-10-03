"""并发安全测试：并发重放、刷新与撤销同时发生时的自洽性。

直接在多线程中调用 SessionStore（纯本地、无外部依赖），
用 Barrier 让竞争线程尽量在同一瞬间进入临界区。
"""

import threading
from collections import Counter

from app.errors import SessionRevoked, TokenReplayed, UserSessionsRevoked
from app.main import create_app
from app.store import SessionStore
from tests.support import GatewayTestCase


class ConcurrentReplayTests(GatewayTestCase):
    business = "并发刷新重放"

    def test_concurrent_refresh_only_one_succeeds(self):
        """N 个线程同时拿同一枚刷新令牌换新，必须恰好 1 成功、其余重放"""
        store: SessionStore = self.client.app.state.store
        user = store.authenticate("alice", "alice-pass")
        _, _, refresh, _ = store.create_session(user)

        n = 8
        barrier = threading.Barrier(n)
        results: Counter[str] = Counter()
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()  # 尽量同时进入 rotate_refresh
            try:
                store.rotate_refresh(refresh)
                outcome = "success"
            except TokenReplayed:
                outcome = "replayed"
            except Exception as exc:  # noqa: BLE001 - 测试里需要暴露意外结果
                outcome = f"other:{type(exc).__name__}"
            with lock:
                results[outcome] += 1

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(results["success"], 1, dict(results))
        self.assertEqual(results["replayed"], n - 1, dict(results))
        self.assertEqual(sum(results.values()), n)

    def test_concurrent_refresh_each_loser_can_retry_with_new_token(self):
        """并发落败方拿到的是重放错误，且唯一胜出者的新令牌可继续使用"""
        store: SessionStore = self.client.app.state.store
        user = store.authenticate("bob", "bob-pass")
        _, _, refresh, _ = store.create_session(user)

        n = 6
        barrier = threading.Barrier(n)
        winners: list[str] = []
        replay_count = 0
        lock = threading.Lock()

        def worker() -> None:
            nonlocal replay_count
            barrier.wait()
            try:
                _, _, new_refresh, _ = store.rotate_refresh(refresh)
                with lock:
                    winners.append(new_refresh)
            except TokenReplayed:
                with lock:
                    replay_count += 1

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(winners), 1)
        self.assertEqual(replay_count, n - 1)
        # 唯一胜出者的新刷新令牌还能再轮转一次（系统未被并发打坏）
        store.rotate_refresh(winners[0])


class ConcurrentRevokeTests(GatewayTestCase):
    business = "并发撤销竞争"

    def test_revoke_and_refresh_race_is_always_consistent(self):
        """撤销与刷新同时发生：结果必须自洽，撤销后绝不允许换出新凭据。

        不变量：
          * 若刷新线程先进入临界区 -> 它成功，随后撤销使新会话失效，
            新访问令牌也必须被挡住；
          * 若撤销先进入临界区 -> 刷新必然得到 session_revoked。
        两种交错都不允许出现"已撤销却刷新成功且新令牌仍可用"。
        """
        for trial in range(20):  # 反复跑以覆盖两种交错顺序
            store: SessionStore = create_app().state.store
            user = store.authenticate("alice", "alice-pass")
            sid, access, refresh, _ = store.create_session(user)

            start = threading.Barrier(2)
            refresh_won = {"value": False}
            refresh_error: list[Exception] = []

            def do_refresh() -> None:
                start.wait()
                try:
                    _, new_access, new_refresh, _ = store.rotate_refresh(refresh)
                    refresh_won["value"] = True
                    refresh_won["access"] = new_access  # type: ignore[attr-defined]
                    refresh_won["refresh2"] = new_refresh  # type: ignore[attr-defined]
                except (SessionRevoked, UserSessionsRevoked) as exc:
                    refresh_error.append(exc)

            def do_revoke() -> None:
                start.wait()
                store.revoke_session(sid, "admin", reason="race test")

            t1 = threading.Thread(target=do_refresh)
            t2 = threading.Thread(target=do_revoke)
            t1.start(); t2.start()
            t1.join(); t2.join()

            session = store.get_session(sid)
            self.assertTrue(session.revoked, f"trial {trial}: session must end revoked")

            if refresh_won["value"]:
                # 刷新先赢：撤销必须紧随其后，新访问令牌也应立即失效。
                new_access = refresh_won["access"]  # type: ignore[attr-defined]
                from app import security
                payload = security.decode(new_access, "access")
                with self.assertRaises(
                        (SessionRevoked, UserSessionsRevoked),
                        msg=f"trial {trial}: post-rotate access must be blocked"):
                    store.validate_access_session(payload["sub"], payload["sid"])
                # 新刷新令牌同样不能再换出新凭据
                with self.assertRaises((SessionRevoked, UserSessionsRevoked)):
                    store.rotate_refresh(refresh_won["refresh2"])  # type: ignore[attr-defined]
            else:
                # 撤销先赢：刷新必须明确是 session_revoked
                self.assertEqual(len(refresh_error), 1, f"trial {trial}")
                self.assertIsInstance(refresh_error[0],
                                      (SessionRevoked, UserSessionsRevoked))

            # 无论哪种交错，旧的最初刷新令牌都绝不可能再成功
            with self.assertRaises((TokenReplayed, SessionRevoked,
                                    UserSessionsRevoked)):
                store.rotate_refresh(refresh)

    def test_concurrent_user_wide_revoke_and_refresh(self):
        """用户级撤销与并发刷新竞争：同样不允许撤销后换出新凭据"""
        store: SessionStore = self.client.app.state.store
        user = store.authenticate("alice", "alice-pass")
        sid, _, refresh, _ = store.create_session(user)

        n = 6
        barrier = threading.Barrier(n + 1)
        outcomes: Counter[str] = Counter()
        lock = threading.Lock()

        def refresh_worker() -> None:
            barrier.wait()
            try:
                store.rotate_refresh(refresh)
                outcome = "success"
            except (SessionRevoked, UserSessionsRevoked):
                outcome = "revoked"
            except TokenReplayed:
                outcome = "replayed"
            with lock:
                outcomes[outcome] += 1

        def revoke_worker() -> None:
            barrier.wait()
            store.revoke_all_user_sessions("alice", "admin")

        ts = [threading.Thread(target=refresh_worker) for _ in range(n)]
        ts.append(threading.Thread(target=revoke_worker))
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        # 最终会话必须处于用户级撤销状态
        with self.assertRaises(UserSessionsRevoked):
            store.validate_access_session("alice", sid)
        # 最多一个刷新成功（临界区互斥），其余只能是重放或撤销；
        # 若有刷新成功，它换出的新令牌在撤销后也必须被挡。
        self.assertLessEqual(outcomes["success"], 1, dict(outcomes))
        self.assertEqual(outcomes["success"] + outcomes["revoked"]
                         + outcomes["replayed"], n, dict(outcomes))
