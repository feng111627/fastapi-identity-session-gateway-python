"""Password hashing and HMAC-signed access tokens (stdlib only)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from app.errors import AuthError, ErrorCode

_PBKDF2_ITERATIONS = 120_000


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hash_password(password: str, *, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt, expected = stored.split("$")
        if scheme != "pbkdf2":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), expected)
    except (ValueError, TypeError):
        return False


def new_opaque_token() -> str:
    """Random one-time refresh token (returned to client, stored hashed)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def sign_access_token(payload: dict, secret: str) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64e(sig)}"


def verify_access_token(token: str, secret: str) -> dict:
    """Return claims; raise AuthError(TOKEN_INVALID/TOKEN_EXPIRED)."""
    try:
        body, sig = token.split(".")
        expected = hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64d(sig), expected):
            raise AuthError(ErrorCode.TOKEN_INVALID, "bad token signature")
        claims = json.loads(_b64d(body))
    except AuthError:
        raise
    except Exception:
        raise AuthError(ErrorCode.TOKEN_INVALID, "malformed token") from None
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or time.time() >= exp:
        raise AuthError(ErrorCode.TOKEN_EXPIRED, "access token expired")
    return claims
