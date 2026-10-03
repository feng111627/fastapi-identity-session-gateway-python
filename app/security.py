"""自包含的令牌签发与校验。

不引入额外依赖，直接使用标准库 HMAC-SHA256：

    token = base64url(payload_json) + "." + base64url(hmac)

访问令牌（access）携带身份、会话与角色，短期有效；
刷新令牌（refresh）携带一次性 jti，轮转/重放/撤销由 store 负责，
本模块只负责签名、防篡改与过期判定。

密钥取自环境变量 ``IDENTITY_SECRET_KEY``；未设置时为进程启动时
随机生成（不落盘、重启后所有旧令牌自然失效）。
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from typing import Any

from app import clock
from app.errors import InvalidCredentials, TokenExpired

_ACCESS_TTL = 60 * 15          # 访问令牌：15 分钟
_REFRESH_TTL = 60 * 60 * 24 * 7  # 刷新令牌：7 天


def access_ttl() -> int:
    return _ACCESS_TTL


def refresh_ttl() -> int:
    return _REFRESH_TTL


def _secret() -> bytes:
    key = os.environ.get("IDENTITY_SECRET_KEY")
    if key:
        return key.encode("utf-8")
    # 进程内固定，重启即换；惰性生成避免导入期不确定性。
    global _RUNTIME_SECRET
    if _RUNTIME_SECRET is None:
        _RUNTIME_SECRET = secrets.token_bytes(32)
    return _RUNTIME_SECRET


_RUNTIME_SECRET: bytes | None = None


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload_b64: str) -> str:
    mac = hmac.new(_secret(), payload_b64.encode("ascii"), hashlib.sha256)
    return _b64encode(mac.digest())


def encode(payload: dict[str, Any]) -> str:
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":"),
                                        sort_keys=True).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64)}"


def decode(token: str, expected_type: str) -> dict[str, Any]:
    """校验签名并返回载荷；类型不符/格式错/签名错 -> InvalidCredentials。

    过期 -> TokenExpired（先验签名再判过期，避免伪造令牌探测过期）。
    """
    parts = token.split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise InvalidCredentials("malformed token")
    payload_b64, signature = parts
    expected = _sign(payload_b64)
    if not hmac.compare_digest(signature, expected):
        raise InvalidCredentials("bad signature")
    try:
        payload = json.loads(_b64decode(payload_b64))
    except Exception:
        raise InvalidCredentials("malformed payload")
    if not isinstance(payload, dict) or payload.get("typ") != expected_type:
        raise InvalidCredentials("unexpected token type")
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or clock.now() >= exp:
        raise TokenExpired(f"{expected_type} token expired")
    return payload


def issue_access_token(username: str, session_id: str, roles: list[str]) -> tuple[str, int]:
    iat = clock.now()
    exp = iat + _ACCESS_TTL
    token = encode({
        "v": 1, "typ": "access", "sub": username,
        "sid": session_id, "roles": list(roles),
        "iat": iat, "exp": exp,
    })
    return token, int(exp)


def issue_refresh_token(username: str, session_id: str, jti: str) -> tuple[str, int]:
    iat = clock.now()
    exp = iat + _REFRESH_TTL
    token = encode({
        "v": 1, "typ": "refresh", "sub": username,
        "sid": session_id, "jti": jti,
        "iat": iat, "exp": exp,
    })
    return token, int(exp)
