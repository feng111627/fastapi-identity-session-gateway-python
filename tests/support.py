"""测试公共工具：客户端、登录助手、业务化结果输出。

仅依赖标准库 unittest 与已随 FastAPI 安装的 httpx/TestClient，
不需要外部服务或真实凭据。
"""

from __future__ import annotations

import time
import unittest

from fastapi.testclient import TestClient

from app import clock
from app.main import create_app

USERS = {
    "admin": ("admin-pass", ["admin"]),
    "alice": ("alice-pass", ["viewer"]),
    "bob": ("bob-pass", ["viewer", "editor"]),
    "carol": ("carol-pass", ["auditor"]),
}


class GatewayTestCase(unittest.TestCase):
    """每个用例拿到全新的应用与内存存储，互不干扰。"""

    business: str = "未分类"

    def setUp(self) -> None:
        self.client = TestClient(create_app())

    def login(self, username: str, password: str | None = None) -> dict:
        pw = password or USERS[username][0]
        resp = self.client.post("/auth/login",
                                json={"username": username, "password": pw})
        assert resp.status_code == 200, resp.text
        return resp.json()

    def auth(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def advance(self, seconds: float) -> None:
        """把全局时钟向前拨（测试过期用）。"""
        base = clock.now()
        clock.now = lambda: base + seconds  # type: ignore[assignment]

    def tearDown(self) -> None:
        clock.now = time.time  # 还原，避免污染其他用例


class BusinessResult(unittest.TextTestResult):
    """打印每条用例覆盖的业务点与明确结论。"""

    def _line(self, test, tag: str) -> str:
        doc = (test.shortDescription() or "").splitlines()[0]
        return f"{tag} [{test.business}] {test._testMethodName} — {doc}"

    def addSuccess(self, test) -> None:
        super().addSuccess(test)
        if isinstance(test, GatewayTestCase):
            self.stream.write("  PASS " + self._line(test, "✅") + "\n")

    def addFailure(self, test, err) -> None:
        super().addFailure(test, err)
        if isinstance(test, GatewayTestCase):
            self.stream.write("  FAIL " + self._line(test, "❌") + "\n")

    def addError(self, test, err) -> None:
        super().addError(test, err)
        if isinstance(test, GatewayTestCase):
            self.stream.write(" ERROR " + self._line(test, "💥") + "\n")
