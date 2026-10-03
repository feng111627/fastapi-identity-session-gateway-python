"""内存态的用户库、会话存储、刷新令牌轮转与审计日志。

并发安全策略：所有涉及"读取-判定-变更"的关键区都在同一把
``threading.RLock`` 内完成，因此：

* 刷新：旧 jti 标记为 used 与新 jti 落库是原子的，并发拿同一枚
  旧刷新令牌来换新时，只有一个能成功，其余得到 refresh_token_replayed；
* 撤销：会话置 revoked 与后续刷新判定在同一把锁下串行化，
  不可能出现"会话已撤销却又成功换出新凭据"。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Iterable

from app import clock, security
from app.errors import (
    InvalidCredentials,
    SessionRevoked,
    TokenReplayed,
    UserSessionsRevoked,
)
from app.models import AuditRecord


@dataclass(frozen=True)
class User:
    username: str
    password: str
    roles: tuple[str, ...]


@dataclass
class Session:
    session_id: str
    username: str
    created_at: float
    last_refreshed_at: float
    access_expires_at: float
    refresh_expires_at: float
    refresh_jti: str = ""
    used_jtis: set[str] = field(default_factory=set)
    revoked: bool = False
    revoke_reason: str = ""


# 审计动作常量，保证测试与文档里引用的名称稳定。
AUDIT_LOGIN = "login"
AUDIT_LOGIN_FAILED = "login_failed"
AUDIT_REFRESH = "refresh"
AUDIT_REFRESH_DENIED = "refresh_denied"
AUDIT_LOGOUT = "logout"
AUDIT_REVOKE_SESSION = "admin_revoke_session"
AUDIT_REVOKE_USER = "admin_revoke_user_sessions"
AUDIT_ACCESS_REVOKED = "access_revoked"


class SessionStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._sessions: dict[str, Session] = {}
        self._jti_index: dict[str, str] = {}   # jti -> session_id
        self._user_max_epoch: dict[str, int] = {}  # 用户级"全部会话撤销"代号
        self._session_epoch: dict[str, int] = {}   # 每会话创建时的用户 epoch
        self._audit: list[AuditRecord] = []
        self._lock = threading.RLock()

    # ---------- 用户库（演示用：进程内预置） ----------
    def add_user(self, username: str, password: str, roles: Iterable[str]) -> None:
        with self._lock:
            self._users[username] = User(username, password, tuple(roles))

    def authenticate(self, username: str, password: str) -> User:
        with self._lock:
            user = self._users.get(username)
            if user is None or user.password != password:
                raise InvalidCredentials("username or password is incorrect")
            return user

    def get_roles(self, username: str) -> tuple[str, ...]:
        with self._lock:
            user = self._users.get(username)
            return user.roles if user else ()

    # ---------- 审计 ----------
    def audit(self, action: str, actor: str, *, target: str = "",
              session_id: str = "", detail: str = "",
              result: str = "success") -> AuditRecord:
        with self._lock:
            record = AuditRecord(
                seq=len(self._audit) + 1, timestamp=clock.now(),
                action=action, actor=actor, target=target,
                session_id=session_id, detail=detail, result=result,
            )
            self._audit.append(record)
            return record

    def list_audit(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._audit)

    # ---------- 会话生命周期 ----------
    def create_session(self, user: User) -> tuple[str, str, str, int]:
        """创建会话并签发首对令牌。

        返回 (session_id, access_token, refresh_token, access_expires_in)。
        """
        import secrets
        with self._lock:
            session_id = secrets.token_hex(16)
            epoch = self._user_max_epoch.get(user.username, 0)
            self._session_epoch[session_id] = epoch
            now = clock.now()
            session = Session(
                session_id=session_id, username=user.username,
                created_at=now, last_refreshed_at=now,
                access_expires_at=now + security.access_ttl(),
                refresh_expires_at=now + security.refresh_ttl(),
            )
            self._sessions[session_id] = session
            access, _ = security.issue_access_token(
                user.username, session_id, list(user.roles))
            jti = secrets.token_hex(16)
            refresh, _ = security.issue_refresh_token(
                user.username, session_id, jti)
            session.refresh_jti = jti
            session.access_expires_at = now + security.access_ttl()
            session.refresh_expires_at = now + security.refresh_ttl()
            self._jti_index[jti] = session_id
            return session_id, access, refresh, security.access_ttl()

    def rotate_refresh(self, old_token: str) -> tuple[str, str, str, int]:
        """用一次性刷新令牌换新一对凭据。

        在单把锁内顺序完成：验签 -> 定位会话 -> 撤销判定 ->
        旧 jti 一次性校验 -> 作废旧 jti / 落新 jti -> 发新令牌。
        返回与 create_session 相同的四元组。
        """
        # 验签在锁外也安全（无共享状态），但为保证"撤销与刷新同时
        # 发生时结论自洽"，判定与变更必须在同一临界区。
        with self._lock:
            try:
                payload = security.decode(old_token, "refresh")
            except Exception:
                raise
            username = payload.get("sub")
            session_id = payload.get("sid")
            jti = payload.get("jti")
            session = self._sessions.get(session_id) if isinstance(session_id, str) else None

            def deny(detail: str) -> None:
                self.audit(AUDIT_REFRESH_DENIED, str(username), target="refresh",
                           session_id=session_id or "", detail=detail, result="denied")

            if session is None or session.username != username:
                deny("unknown session")
                raise InvalidCredentials("session not found")

            if self._session_epoch.get(session_id, 0) < self._user_max_epoch.get(username, 0):
                deny("user sessions revoked")
                raise UserSessionsRevoked("all sessions of this user have been revoked")
            if session.revoked:
                deny("session revoked")
                raise SessionRevoked("session has been revoked")

            if jti in session.used_jtis:
                # 旧刷新令牌被再次（含并发）使用：明确判定为重放。
                deny("refresh token replayed")
                raise TokenReplayed("refresh token has already been used")
            if jti != session.refresh_jti:
                # 既不是当前 jti 也没用过：伪造或来自更早世代。
                deny("unknown refresh token jti")
                raise InvalidCredentials("refresh token is not recognized")

            import secrets
            now = clock.now()
            new_jti = secrets.token_hex(16)
            access, _ = security.issue_access_token(
                username, session_id, list(self.get_roles(username)))
            refresh, _ = security.issue_refresh_token(username, session_id, new_jti)

            # 关键的原子轮转：旧 jti 立即作废，新 jti 立即生效。
            session.used_jtis.add(jti)
            self._jti_index.pop(jti, None)
            session.refresh_jti = new_jti
            self._jti_index[new_jti] = session_id
            session.last_refreshed_at = now
            session.access_expires_at = now + security.access_ttl()
            session.refresh_expires_at = now + security.refresh_ttl()

            self.audit(AUDIT_REFRESH, username, target="refresh",
                       session_id=session_id, detail="refresh token rotated")
            return session_id, access, refresh, security.access_ttl()

    # ---------- 访问令牌的会话/撤销校验 ----------
    def validate_access_session(self, username: str, session_id: str) -> None:
        """访问令牌验签通过后，确认其会话仍有效、未被撤销。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.username != username:
                self.audit(AUDIT_ACCESS_REVOKED, username, target="access",
                           session_id=session_id, detail="unknown session",
                           result="denied")
                raise InvalidCredentials("session not found")
            if self._session_epoch.get(session_id, 0) < self._user_max_epoch.get(username, 0):
                self.audit(AUDIT_ACCESS_REVOKED, username, target="access",
                           session_id=session_id,
                           detail="user sessions revoked", result="denied")
                raise UserSessionsRevoked("all sessions of this user have been revoked")
            if session.revoked:
                self.audit(AUDIT_ACCESS_REVOKED, username, target="access",
                           session_id=session_id,
                           detail="session revoked", result="denied")
                raise SessionRevoked("session has been revoked")

    # ---------- 管理员撤销 ----------
    def revoke_session(self, session_id: str, actor: str, reason: str = "") -> bool:
        """撤销单个会话；返回是否找到并撤销。与刷新互斥。"""
        with self._lock:
            session = self._sessions.get(session_id)
            found = session is not None and not session.revoked
            if session is not None and not session.revoked:
                session.revoked = True
                session.revoke_reason = reason or "revoked by admin"
            self.audit(AUDIT_REVOKE_SESSION, actor,
                       target=session_id, session_id=session_id,
                       detail=reason or "revoked by admin",
                       result="success" if found else "failure")
            return found

    def revoke_all_user_sessions(self, username: str, actor: str,
                                 reason: str = "") -> int:
        """撤销某用户的全部会话（用户级吊销），返回受影响会话数。"""
        with self._lock:
            count = 0
            for session in self._sessions.values():
                if session.username == username and not session.revoked:
                    session.revoked = True
                    session.revoke_reason = reason or "all sessions revoked by admin"
                    count += 1
            self._user_max_epoch[username] = self._user_max_epoch.get(username, 0) + 1
            self.audit(AUDIT_REVOKE_USER, actor, target=username,
                       detail=f"{count} session(s) revoked; {reason or 'user-wide revoke'}")
            return count

    # ---------- 查询 ----------
    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list_sessions(self, username: str | None = None) -> list[Session]:
        with self._lock:
            out = [s for s in self._sessions.values()
                   if username is None or s.username == username]
            return sorted(out, key=lambda s: s.created_at)

    def list_users(self) -> list[str]:
        with self._lock:
            return sorted(self._users)
