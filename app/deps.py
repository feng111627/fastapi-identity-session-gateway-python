"""FastAPI 依赖：解析当前主体、按角色/权限放行。

权限模型（详见 docs/）：

* 角色 ``admin`` 隐含拥有全部权限；
* 其余角色到权限的映射集中在 :data:`ROLE_PERMISSIONS`；
* 接口用 ``require_permission("xxx")`` 声明所需权限，
  或用 :func:`require_admin` 限定管理员。
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Annotated

from app import security
from app.errors import (
    AuthError,
    InvalidCredentials,
    NotAuthenticated,
    PermissionDenied,
)
from app.store import SessionStore

# 角色 -> 权限集合。admin 单独按"拥有一切"处理。
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"profile:read", "content:read"}),
    "editor": frozenset({"profile:read", "content:read", "content:write"}),
    "auditor": frozenset({"profile:read", "audit:read", "session:read"}),
}
ADMIN_ROLE = "admin"

_bearer = HTTPBearer(auto_error=False)

CredentialsDep = Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]


@dataclass(frozen=True)
class Principal:
    username: str
    session_id: str
    roles: tuple[str, ...]

    def has_permission(self, permission: str) -> bool:
        if ADMIN_ROLE in self.roles:
            return True
        granted = set()
        for role in self.roles:
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        return permission in granted


def current_principal(
    credentials: CredentialsDep,
    store: SessionStoreDep,
) -> Principal:
    """解析 Authorization: Bearer <access_token>。

    * 无头/无凭据      -> NotAuthenticated
    * 格式/签名/类型错 -> InvalidCredentials
    * 过期             -> TokenExpired（由 security.decode 抛出）
    * 会话撤销         -> SessionRevoked / UserSessionsRevoked
    """
    if credentials is None or not credentials.credentials:
        raise NotAuthenticated("missing bearer token")
    token = credentials.credentials
    payload = security.decode(token, "access")  # 验签 + 过期
    username = payload.get("sub")
    session_id = payload.get("sid")
    roles = payload.get("roles", [])
    if not isinstance(username, str) or not isinstance(session_id, str) \
            or not isinstance(roles, list):
        raise InvalidCredentials("malformed access token claims")
    # 会话可能在令牌签发后被撤销；撤销判定与刷新/撤销动作共用一把锁。
    store.validate_access_session(username, session_id)
    return Principal(username=username, session_id=session_id,
                     roles=tuple(roles))


# 前向类型：store 由应用装配时通过依赖覆盖提供默认实例。
def _default_store() -> SessionStore:  # pragma: no cover - 被 app.main 覆盖
    raise RuntimeError("SessionStore dependency not configured")


SessionStoreDep = Annotated[SessionStore, Depends(_default_store)]
CurrentUser = Annotated[Principal, Depends(current_principal)]


def require_permission(permission: str):
    """生成一个"要求具体权限"的依赖。"""

    def _dep(principal: CurrentUser) -> Principal:
        if not principal.has_permission(permission):
            raise PermissionDenied(
                f"role(s) {list(principal.roles)} lack permission {permission!r}")
        return principal

    return _dep


def require_admin(principal: CurrentUser) -> Principal:
    if ADMIN_ROLE not in principal.roles:
        raise PermissionDenied("administrator role required")
    return principal
