"""登录、刷新、会话与审计相关的请求/响应模型。"""

from typing import Literal

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class TokenPair(BaseModel):
    """登录或刷新成功后下发的一对凭据。

    access_token: 短期访问令牌，放 Authorization 头即可访问接口。
    refresh_token: 一次性刷新令牌，仅用于 /auth/refresh。
    """

    access_token: str
    refresh_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int = Field(description="access_token 有效期（秒）")
    session_id: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class SessionInfo(BaseModel):
    session_id: str
    username: str
    created_at: float
    last_refreshed_at: float
    access_expires_at: float
    refresh_expires_at: float
    revoked: bool


class AuditRecord(BaseModel):
    """一条可追溯的关键动作记录。"""

    seq: int
    timestamp: float
    action: str
    actor: str
    target: str = ""
    session_id: str = ""
    detail: str = ""
    result: Literal["success", "denied", "failure"] = "success"
