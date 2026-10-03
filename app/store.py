"""Thread-safe in-memory repositories (single-process, local-only)."""
from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from app.models import AuditEvent, RefreshTokenRecord, Session, User


class Store:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.users_by_name: dict[str, User] = {}
        self.users_by_id: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}
        self.refresh_by_hash: dict[str, RefreshTokenRecord] = {}
        self.audit: list[AuditEvent] = []

    @contextmanager
    def locked(self) -> Iterator[None]:
        """Hold the store lock across a check-and-mutate sequence.

        Refresh rotation and revocation both take this so a session can
        never be revoked yet still mint new tokens (and vice versa).
        """
        with self._lock:
            yield

    # --- users ---
    def add_user(self, user: User) -> None:
        with self._lock:
            self.users_by_name[user.username] = user
            self.users_by_id[user.id] = user

    def get_user_by_name(self, username: str) -> User | None:
        with self._lock:
            return self.users_by_name.get(username)

    def get_user(self, user_id: str) -> User | None:
        with self._lock:
            return self.users_by_id.get(user_id)

    # --- sessions ---
    def add_session(self, session: Session) -> None:
        with self._lock:
            self.sessions[session.id] = session

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            return self.sessions.get(session_id)

    # --- refresh tokens ---
    def add_refresh(self, rec: RefreshTokenRecord) -> None:
        with self._lock:
            self.refresh_by_hash[rec.token_hash] = rec

    def get_refresh(self, token_hash: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self.refresh_by_hash.get(token_hash)

    # --- audit ---
    def add_audit(self, event: AuditEvent) -> None:
        with self._lock:
            self.audit.append(event)
