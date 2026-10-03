"""管理员路由：撤销会话、撤销某用户全部会话、查看会话与审计记录。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.deps import CurrentUser, SessionStoreDep, require_admin
from app.models import AuditRecord, SessionInfo

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[])


def _session_info(s) -> SessionInfo:
    return SessionInfo(
        session_id=s.session_id, username=s.username,
        created_at=s.created_at, last_refreshed_at=s.last_refreshed_at,
        access_expires_at=s.access_expires_at,
        refresh_expires_at=s.refresh_expires_at, revoked=s.revoked,
    )


@router.post("/sessions/{session_id}/revoke", status_code=204)
def revoke_session(session_id: str, admin: CurrentUser,
                   store: SessionStoreDep) -> None:
    require_admin(admin)
    found = store.revoke_session(session_id, admin.username,
                                 reason="revoked by admin")
    if not found:
        raise HTTPException(status_code=404, detail="session not found or already revoked")


@router.post("/users/{username}/revoke-sessions", status_code=200)
def revoke_user_sessions(username: str, admin: CurrentUser,
                         store: SessionStoreDep) -> dict[str, str | int]:
    require_admin(admin)
    count = store.revoke_all_user_sessions(username, admin.username,
                                           reason="user-wide revoke by admin")
    return {"username": username, "revoked": count}


@router.get("/sessions", response_model=list[SessionInfo])
def list_sessions(admin: CurrentUser, store: SessionStoreDep) -> list[SessionInfo]:
    require_admin(admin)
    return [_session_info(s) for s in store.list_sessions()]


@router.get("/audit", response_model=list[AuditRecord])
def list_audit(admin: CurrentUser, store: SessionStoreDep) -> list[AuditRecord]:
    """关键动作审计：登录/刷新/撤销/越权访问等，全程可追溯。"""
    require_admin(admin)
    return store.list_audit()
