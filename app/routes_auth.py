"""认证路由：登录、一次性刷新轮转、登出（撤销当前会话）。"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from app.deps import CurrentUser, SessionStoreDep
from app.errors import InvalidCredentials
from app.models import LoginRequest, RefreshRequest, TokenPair
from app.store import AUDIT_LOGIN, AUDIT_LOGIN_FAILED, AUDIT_LOGOUT

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
def login(body: LoginRequest, store: SessionStoreDep) -> TokenPair:
    """用户名/密码换一对凭据。密码错误给出明确的 invalid_credentials。"""
    try:
        user = store.authenticate(body.username, body.password)
    except InvalidCredentials:
        store.audit(AUDIT_LOGIN_FAILED, body.username, target="login",
                    detail="bad username or password", result="denied")
        raise
    session_id, access, refresh, ttl = store.create_session(user)
    store.audit(AUDIT_LOGIN, user.username, target="login",
                session_id=session_id, detail="login success")
    return TokenPair(access_token=access, refresh_token=refresh,
                     expires_in=ttl, session_id=session_id)


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, store: SessionStoreDep) -> TokenPair:
    """用一次性刷新令牌换新凭据。

    过期 -> token_expired；重复/并发使用 -> refresh_token_replayed；
    已撤销 -> session_revoked / user_sessions_revoked。
    这些区分由 :meth:`SessionStore.rotate_refresh` 与 security 保证。
    """
    session_id, access, new_refresh, ttl = store.rotate_refresh(body.refresh_token)
    return TokenPair(access_token=access, refresh_token=new_refresh,
                     expires_in=ttl, session_id=session_id)


@router.post("/logout", status_code=204)
def logout(principal: CurrentUser, store: SessionStoreDep) -> None:
    """登出即撤销当前会话；撤销后该会话的访问/刷新凭据立刻失效。"""
    store.revoke_session(principal.session_id, principal.username,
                         reason="user logout")
    store.audit(AUDIT_LOGOUT, principal.username, target="session",
                session_id=principal.session_id, detail="logout")
