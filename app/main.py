"""FastAPI 应用装配。

* 创建全局 :class:`~app.store.SessionStore` 并预置演示用户；
* 把 store 注入 ``SessionStoreDep``；
* 为 :class:`~app.errors.AuthError` 注册统一处理器，保证
  "未登录 / 凭据无效 / 过期 / 重放 / 撤销 / 权限不足" 返回
  各不相同且稳定的 ``error.code``。
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.errors import AuthError
from app.routes_admin import router as admin_router
from app.routes_auth import router as auth_router
from app.routes_demo import router as demo_router
from app.store import SessionStore


def build_store() -> SessionStore:
    """预置演示账号：多角色 + 单角色，覆盖越权测试。"""
    store = SessionStore()
    store.add_user("admin", "admin-pass", ("admin",))
    store.add_user("alice", "alice-pass", ("viewer",))
    store.add_user("bob", "bob-pass", ("viewer", "editor"))
    store.add_user("carol", "carol-pass", ("auditor",))
    return store


def create_app(store: SessionStore | None = None) -> FastAPI:
    app = FastAPI(title="identity-session-gateway", version="0.1.0")
    store = store or build_store()

    # 注入存储（测试也可直接传自定义 store）。
    from app.deps import _default_store
    app.dependency_overrides[_default_store] = lambda: store

    @app.exception_handler(AuthError)
    async def _on_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(demo_router)
    app.state.store = store
    return app
