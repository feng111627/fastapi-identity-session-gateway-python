"""并发场景：同一旧刷新令牌的并发重放、撤销与刷新的竞争自洽性。"""
from concurrent.futures import ThreadPoolExecutor

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.security import hash_password
from app.models import User
from app.service import AuthService
from app.store import Store


def make_service() -> AuthService:
    store = Store()
    store.add_user(User(id="u1", username="a",
                        password_hash=hash_password("p"), roles=frozenset({"viewer"})))
    store.add_user(User(id="admin", username="root",
                        password_hash=hash_password("p"), roles=frozenset({"admin"})))
    return AuthService(store, Settings(secret_key="t", access_token_ttl=300, refresh_token_ttl=3600))


def test_concurrent_refresh_same_token_only_one_wins():
    service = make_service()
    tokens = service.login("a", "p")
    old = tokens["refresh_token"]

    def attempt(_):
        try:
            service.refresh(old)
            return "ok"
        except AuthError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(16)))

    assert results.count("ok") == 1, results
    assert results.count(ErrorCode.REFRESH_REUSED) == 15, results
    # 重放检测已熔断会话：胜者的刷新令牌也必须失效
    session = service.store.get_session(tokens["session_id"])
    assert session.revoked


def test_refresh_and_revoke_race_is_self_consistent():
    for _ in range(30):
        service = make_service()
        tokens = service.login("a", "p")
        sid = tokens["session_id"]
        outcomes = {}

        def do_refresh():
            try:
                outcomes["refresh"] = ("ok", service.refresh(tokens["refresh_token"]))
            except AuthError as e:
                outcomes["refresh"] = (e.code, None)

        def do_revoke():
            service.revoke_session(sid, actor="admin")
            outcomes["revoke"] = "done"

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1, f2 = pool.submit(do_refresh), pool.submit(do_revoke)
            f1.result(); f2.result()

        session = service.store.get_session(sid)
        status, new_tokens = outcomes["refresh"]
        if status == "ok":
            # 刷新成功 => 撤销必在其后；会话已撤销时新令牌绝不可用
            assert session.revoked
            try:
                service.refresh(new_tokens["refresh_token"])
                raise AssertionError("revoked session must not mint tokens")
            except AuthError as e:
                assert e.code == ErrorCode.SESSION_REVOKED
        else:
            # 刷新失败 => 只能因为会话已被撤销
            assert status == ErrorCode.SESSION_REVOKED
            assert session.revoked


def test_concurrent_revoke_all_and_refresh_never_mints_after_revoke():
    service = make_service()
    tokens = service.login("a", "p")

    def do_refresh():
        try:
            return ("ok", service.refresh(tokens["refresh_token"]))
        except AuthError as e:
            return (e.code, None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_refresh = pool.submit(do_refresh)
        f_revoke = pool.submit(service.revoke_user_sessions, "u1", actor="admin")
        status, new_tokens = f_refresh.result()
        f_revoke.result()

    if status == "ok":
        try:
            service.refresh(new_tokens["refresh_token"])
            raise AssertionError("revoked user must not mint tokens")
        except AuthError as e:
            assert e.code == ErrorCode.SESSION_REVOKED
    else:
        assert status == ErrorCode.SESSION_REVOKED
