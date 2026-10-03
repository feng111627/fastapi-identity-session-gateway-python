"""Typed error codes so clients can distinguish auth failure causes."""
from __future__ import annotations

from enum import StrEnum


class ErrorCode(StrEnum):
    NOT_AUTHENTICATED = "not_authenticated"          # missing credentials
    TOKEN_INVALID = "token_invalid"                  # malformed / bad signature
    TOKEN_EXPIRED = "token_expired"                  # access token past expiry
    SESSION_REVOKED = "session_revoked"              # session was revoked
    REFRESH_INVALID = "refresh_invalid"              # unknown refresh token
    REFRESH_EXPIRED = "refresh_expired"              # refresh token past expiry
    REFRESH_REUSED = "refresh_reused"                # one-time token replayed
    FORBIDDEN = "forbidden"                          # authenticated but lacks permission
    BAD_CREDENTIALS = "bad_credentials"              # login failed


class AuthError(Exception):
    """Domain error carrying a stable machine-readable code."""

    def __init__(self, code: ErrorCode, message: str = "") -> None:
        self.code = code
        self.message = message or code.value
        super().__init__(self.message)
