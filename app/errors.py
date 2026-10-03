"""统一的认证/授权错误类型。

错误必须能区分：未登录、凭据缺失/格式错误、签名无效、过期、
重放（一次性刷新凭据被重复/并发使用）、已撤销（会话或用户级）、
权限不足。每类错误都有稳定的机器可读 ``code``，便于客户端与测试
断言，也保证整个网关返回结论一致。
"""


class AuthError(Exception):
    """所有可预期的认证/授权失败基类。"""

    code: str = "auth_error"
    status_code: int = 401

    def __init__(self, message: str = ""):
        super().__init__(message or self.code)
        self.message = message or self.code


class NotAuthenticated(AuthError):
    """请求未携带任何凭据（未登录）。"""

    code = "not_authenticated"
    status_code = 401


class InvalidCredentials(AuthError):
    """凭据缺失、格式错误或签名无效（无法证明身份）。"""

    code = "invalid_credentials"
    status_code = 401


class TokenExpired(AuthError):
    """凭据已过有效期，属于正常过期而非攻击。"""

    code = "token_expired"
    status_code = 401


class TokenReplayed(AuthError):
    """一次性刷新凭据已被使用过，再次出现即重放。

    包括旧刷新令牌被重复提交，以及并发情况下两个请求同时拿同一枚
    刷新令牌来换新——只允许第一个成功，其余一律判定为重放。
    """

    code = "refresh_token_replayed"
    status_code = 401


class SessionRevoked(AuthError):
    """凭据本身有效，但其所属会话已被管理员撤销。"""

    code = "session_revoked"
    status_code = 401


class UserSessionsRevoked(AuthError):
    """该用户的全部会话已被管理员撤销（用户级吊销）。"""

    code = "user_sessions_revoked"
    status_code = 401


class PermissionDenied(AuthError):
    """已认证，但角色不具备接口所需权限。"""

    code = "permission_denied"
    status_code = 403
