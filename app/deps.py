"""FastAPI dependencies wiring service into routes."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request

from app.errors import AuthError, ErrorCode
from app.models import User
from app.service import AuthService


def get_service(request: Request) -> AuthService:
    return request.app.state.service


def get_current_user(
    request: Request,
    service: AuthService = Depends(get_service),
) -> User:
    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthError(ErrorCode.NOT_AUTHENTICATED, "missing bearer token")
    user, _session_id = service.authenticate_access_token(token)
    return user


def require_permission(permission: str) -> Callable:
    """Dependency factory enforcing a permission."""

    def checker(
        user: User = Depends(get_current_user),
        service: AuthService = Depends(get_service),
    ) -> User:
        service.require_permission(user, permission)
        return user

    return checker
