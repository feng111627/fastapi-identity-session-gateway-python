"""Seed demo users so a locally-run app is immediately usable."""
from __future__ import annotations

from app.security import hash_password
from app.models import User
from app.store import Store

DEMO_USERS = [
    ("u-admin", "admin", "admin-pass", {"admin"}),
    ("u-analyst", "analyst", "analyst-pass", {"analyst"}),
    ("u-viewer", "viewer", "viewer-pass", {"viewer"}),
    ("u-multi", "multi", "multi-pass", {"analyst", "viewer"}),
]


def seed_demo_users(store: Store) -> None:
    for uid, name, password, roles in DEMO_USERS:
        store.add_user(User(
            id=uid,
            username=name,
            password_hash=hash_password(password),
            roles=frozenset(roles),
        ))
