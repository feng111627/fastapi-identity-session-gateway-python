"""可替换的时钟，便于测试过期场景。"""

import time


def now() -> float:
    """当前 Unix 时间戳（秒）。测试中可 monkeypatch。"""
    return time.time()
