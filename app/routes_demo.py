"""演示用业务路由：公开接口 + 三档权限接口，覆盖越权判定。"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.deps import CurrentUser, require_permission

router = APIRouter(tags=["demo"])


@router.get("/")
def root() -> dict[str, str]:
    return {"service": "identity-session-gateway", "status": "ok"}


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/me")
def me(principal: CurrentUser) -> dict[str, object]:
    """任何已登录用户可访问；未登录 -> not_authenticated。"""
    return {"username": principal.username,
            "session_id": principal.session_id,
            "roles": list(principal.roles)}


@router.get("/viewer-area", dependencies=[Depends(require_permission("content:read"))])
def viewer_area(principal: CurrentUser) -> dict[str, str]:
    return {"message": f"hello {principal.username}", "area": "viewer"}


@router.post("/editor-area", dependencies=[Depends(require_permission("content:write"))])
def editor_area(principal: CurrentUser) -> dict[str, str]:
    return {"message": f"{principal.username} may write content", "area": "editor"}


@router.get("/audit-area", dependencies=[Depends(require_permission("audit:read"))])
def audit_area(principal: CurrentUser) -> dict[str, str]:
    return {"message": f"{principal.username} may read audit", "area": "audit"}
