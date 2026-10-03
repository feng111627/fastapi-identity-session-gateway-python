"""Auth business logic: login, refresh rotation, revocation, authorization."""
from __future__ import annotations

import logging
import uuid

from app.config import Settings
from app.errors import AuthError, ErrorCode
from app.models import AuditEvent, RefreshTokenRecord, Session, User, now
from app.security import (
    hash_token,
    new_opaque_token,
    sign_access_token,
    verify_access_token,
    verify_password,
)
from app.store import Store

log = logging.getLogger("app.audit")


class AuthService:
    def __init__(self, store: Store, settings: Settings) -> None:
        self.store = store
        self.settings = settings

    # --- helpers ---
    def _audit(self, action: str, actor: str, **detail) -> None:
        event = AuditEvent(ts=now(), action=action, actor=actor, detail=detail)
        self.store.add_audit(event)
        log.info("audit action=%s actor=%s detail=%s", action, actor, detail)

    def _issue_tokens(self, user: User, session: Session) -> dict:
        refresh_token = new_opaque_token()
        self.store.add_refresh(RefreshTokenRecord(
            token_hash=hash_token(refresh_token),
            session_id=session.id,
            user_id=user.id,
            expires_at=now() + self.settings.refresh_token_ttl,
        ))
        access_token = sign_access_token({
            "sub": user.id,
            "sid": session.id,
            "roles": sorted(user.roles),
            "iat": now(),
            "exp": now() + self.settings.access_token_ttl,
        }, self.settings.secret_key)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_ttl,
        }

    # --- login ---
    def login(self, username: str, password: str) -> dict:
        """Return {access_token, refresh_token, token_type, expires_in}."""
        user = self.store.get_user_by_name(username)
        if user is None or user.disabled or not verify_password(password, user.password_hash):
            self._audit("login_failed", username)
            raise AuthError(ErrorCode.BAD_CREDENTIALS, "invalid username or password")
        session = Session(id=uuid.uuid4().hex, user_id=user.id, created_at=now())
        self.store.add_session(session)
        self._audit("login", user.id, session_id=session.id, roles=sorted(user.roles))
        tokens = self._issue_tokens(user, session)
        tokens["session_id"] = session.id
        return tokens

    # --- refresh (one-time rotation with replay detection) ---
    def refresh(self, refresh_token: str) -> dict:
        token_hash = hash_token(refresh_token)
        with self.store.locked():  # atomic check-and-rotate vs concurrent refresh/revoke
            rec = self.store.get_refresh(token_hash)
            if rec is None:
                raise AuthError(ErrorCode.REFRESH_INVALID, "unknown refresh token")
            session = self.store.get_session(rec.session_id)
            if rec.used:
                # one-time token presented again -> replay: kill the whole session
                if session is not None and not session.revoked:
                    session.revoked = True
                    session.revoked_reason = "refresh_token_reuse"
                    self._revoke_session_refresh_tokens(session.id)
                self._audit("refresh_reuse_detected", rec.user_id, session_id=rec.session_id)
                raise AuthError(ErrorCode.REFRESH_REUSED, "refresh token already used; session revoked")
            if rec.revoked or session is None or session.revoked:
                raise AuthError(ErrorCode.SESSION_REVOKED, "session has been revoked")
            if now() >= rec.expires_at:
                raise AuthError(ErrorCode.REFRESH_EXPIRED, "refresh token expired")
            user = self.store.get_user(rec.user_id)
            if user is None or user.disabled:
                raise AuthError(ErrorCode.SESSION_REVOKED, "account disabled")
            rec.used = True  # old token is dead from this moment
            self._audit("refresh", user.id, session_id=session.id)
            return self._issue_tokens(user, session)

    # --- access token authentication ---
    def authenticate_access_token(self, token: str) -> tuple[User, str]:
        """Return (user, session_id) or raise typed AuthError."""
        claims = verify_access_token(token, self.settings.secret_key)  # TOKEN_INVALID / TOKEN_EXPIRED
        session_id = claims.get("sid", "")
        session = self.store.get_session(session_id)
        if session is None or session.revoked:
            raise AuthError(ErrorCode.SESSION_REVOKED, "session has been revoked")
        user = self.store.get_user(claims.get("sub", ""))
        if user is None or user.disabled:
            raise AuthError(ErrorCode.SESSION_REVOKED, "account disabled")
        return user, session_id

    # --- authorization ---
    def permissions_for(self, user: User) -> frozenset[str]:
        perms: set[str] = set()
        for role in user.roles:
            perms |= self.settings.role_permissions.get(role, frozenset())
        return frozenset(perms)

    def require_permission(self, user: User, permission: str) -> None:
        if permission not in self.permissions_for(user):
            self._audit("forbidden", user.id, permission=permission)
            raise AuthError(ErrorCode.FORBIDDEN, f"missing permission: {permission}")

    # --- admin revocation ---
    def _revoke_session_refresh_tokens(self, session_id: str) -> None:
        for rec in self.store.refresh_by_hash.values():
            if rec.session_id == session_id:
                rec.revoked = True

    def revoke_session(self, session_id: str, *, actor: str) -> None:
        with self.store.locked():
            session = self.store.get_session(session_id)
            if session is None:
                raise AuthError(ErrorCode.REFRESH_INVALID, "unknown session")
            session.revoked = True
            session.revoked_reason = "admin_revoked"
            self._revoke_session_refresh_tokens(session_id)
            self._audit("session_revoked", actor, session_id=session_id, user_id=session.user_id)

    def revoke_user_sessions(self, user_id: str, *, actor: str) -> int:
        with self.store.locked():
            count = 0
            for session in self.store.sessions.values():
                if session.user_id == user_id and not session.revoked:
                    session.revoked = True
                    session.revoked_reason = "admin_revoked_user"
                    self._revoke_session_refresh_tokens(session.id)
                    count += 1
            self._audit("user_sessions_revoked", actor, user_id=user_id, count=count)
            return count
