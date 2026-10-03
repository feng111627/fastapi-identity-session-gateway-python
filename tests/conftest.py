"""Shared fixtures + per-case result logging for the auth test suite."""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.security import hash_password
from app.models import User
from main import create_app

log = logging.getLogger("tests")

COVERAGE_AREAS = [
    "login 登录（成功/失败）",
    "rbac 越权访问（未登录/权限不足/多角色放行）",
    "token 凭据过期与无效（access/refresh）",
    "replay 一次性刷新令牌重放（含并发）",
    "revoke 管理员撤销会话（单会话/全用户/与刷新并发竞争）",
]


def pytest_sessionstart(session):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    log.info("=== 测试覆盖业务范围 ===")
    for area in COVERAGE_AREAS:
        log.info("覆盖: %s", area)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call":
        log.info("用例 %-55s %s", item.nodeid, report.outcome.upper())


@pytest.fixture()
def settings() -> Settings:
    return Settings(secret_key="test-secret", access_token_ttl=300, refresh_token_ttl=3600)


@pytest.fixture()
def client(settings):
    app = create_app(settings)
    store = app.state.store
    store.add_user(User(id="u-admin", username="admin",
                        password_hash=hash_password("admin-pass"), roles=frozenset({"admin"})))
    store.add_user(User(id="u-analyst", username="analyst",
                        password_hash=hash_password("analyst-pass"), roles=frozenset({"analyst"})))
    store.add_user(User(id="u-viewer", username="viewer",
                        password_hash=hash_password("viewer-pass"), roles=frozenset({"viewer"})))
    store.add_user(User(id="u-multi", username="multi",
                        password_hash=hash_password("multi-pass"), roles=frozenset({"analyst", "viewer"})))
    return TestClient(app)


def login(client, username, password) -> dict:
    resp = client.post("/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()


def bearer(tokens: dict) -> dict:
    return {"Authorization": f"Bearer {tokens['access_token']}"}
