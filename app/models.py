"""In-memory domain models."""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    roles: frozenset[str]
    disabled: bool = False


@dataclass
class Session:
    id: str
    user_id: str
    created_at: float
    revoked: bool = False
    revoked_reason: str | None = None


@dataclass
class RefreshTokenRecord:
    token_hash: str
    session_id: str
    user_id: str
    expires_at: float
    used: bool = False          # rotated away (one-time use)
    revoked: bool = False


@dataclass
class AuditEvent:
    ts: float
    action: str
    actor: str
    detail: dict = field(default_factory=dict)


def now() -> float:
    return time.time()
