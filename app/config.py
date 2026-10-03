"""Runtime settings (local-only defaults, overridable via env)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    secret_key: str = "dev-only-secret"
    access_token_ttl: int = 300          # seconds
    refresh_token_ttl: int = 7 * 24 * 3600
    # role -> permissions granted
    role_permissions: dict[str, frozenset[str]] = field(default_factory=lambda: {
        "admin": frozenset({"profile:read", "reports:read", "admin:sessions"}),
        "analyst": frozenset({"profile:read", "reports:read"}),
        "viewer": frozenset({"profile:read"}),
    })


def load_settings() -> Settings:
    return Settings(
        secret_key=os.environ.get("APP_SECRET_KEY", "dev-only-secret"),
        access_token_ttl=int(os.environ.get("APP_ACCESS_TTL", "300")),
        refresh_token_ttl=int(os.environ.get("APP_REFRESH_TTL", str(7 * 24 * 3600))),
    )
