"""HTTP routes: auth endpoints, protected resources, admin session control."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.deps import get_service, require_permission
from app.models import User
from app.service import AuthService

auth_router = APIRouter(tags=["auth"])
resource_router = APIRouter(tags=["resources"])
admin_router = APIRouter(tags=["admin"])


class LoginIn(BaseModel):
    username: str
    password: str


class RefreshIn(BaseModel):
    refresh_token: str


@auth_router.post("/auth/login")
def login(body: LoginIn, service: AuthService = Depends(get_service)):
    return service.login(body.username, body.password)


@auth_router.post("/auth/refresh")
def refresh(body: RefreshIn, service: AuthService = Depends(get_service)):
    return service.refresh(body.refresh_token)


@resource_router.get("/me")
def me(user: User = Depends(require_permission("profile:read"))):
    return {"id": user.id, "username": user.username, "roles": sorted(user.roles)}


@resource_router.get("/reports")
def reports(user: User = Depends(require_permission("reports:read"))):
    return {"reports": ["q1", "q2"], "by": user.username}


@admin_router.post("/admin/sessions/{session_id}/revoke")
def revoke_session(
    session_id: str,
    user: User = Depends(require_permission("admin:sessions")),
    service: AuthService = Depends(get_service),
):
    service.revoke_session(session_id, actor=user.id)
    return {"revoked": session_id}


@admin_router.post("/admin/users/{user_id}/revoke-all")
def revoke_user_sessions(
    user_id: str,
    user: User = Depends(require_permission("admin:sessions")),
    service: AuthService = Depends(get_service),
):
    count = service.revoke_user_sessions(user_id, actor=user.id)
    return {"user_id": user_id, "revoked_sessions": count}
