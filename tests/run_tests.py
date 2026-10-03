"""本地一键测试入口：按业务分组展示每条用例结果与覆盖汇总。

用法：
    uv run python -m tests.run_tests
仅使用本地能力（unittest + TestClient），不依赖外部服务或真实凭据。
"""

from __future__ import annotations

import io
import sys
import unittest
from collections import defaultdict

from tests.support import BusinessResult, GatewayTestCase


def _flatten(suite: unittest.TestSuite) -> list[unittest.TestCase]:
    tests: list[unittest.TestCase] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            tests.extend(_flatten(item))
        else:
            tests.append(item)
    return tests


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")
    all_tests = _flatten(suite)
    businesses = sorted({getattr(t, "business", "未分类")
                         for t in all_tests
                         if isinstance(t, GatewayTestCase)})

    by_biz: dict[str, list[unittest.TestCase]] = defaultdict(list)
    for t in all_tests:
        by_biz[getattr(t, "business", "未分类")].append(t)

    print("=" * 72)
    print("身份会话网关 · 业务覆盖测试")
    print("覆盖业务：" + " / ".join(businesses))
    print("用例总数：%d" % len(all_tests))
    for biz in sorted(by_biz):
        print(f"  - {biz}: {len(by_biz[biz])} 条")
    print("=" * 72)

    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=0,
                                     resultclass=BusinessResult)
    result = runner.run(suite)
    print(stream.getvalue(), end="")

    print("-" * 72)
    print("执行 %d · 成功 %d · 失败 %d · 错误 %d · 跳过 %d" % (
        result.testsRun,
        result.testsRun - len(result.failures) - len(result.errors)
        - len(result.skipped),
        len(result.failures), len(result.errors), len(result.skipped)))
    print("结论：%s" % ("全部通过 ✅" if result.wasSuccessful()
                       else "存在失败 ❌"))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
