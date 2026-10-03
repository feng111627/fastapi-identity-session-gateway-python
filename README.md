# fastapi-identity-session-gateway

基于 FastAPI 的本地身份与会话网关：登录、一次性刷新令牌轮换、基于角色/权限的接口鉴权、管理员会话撤销与审计。全部使用 Python 标准库 + FastAPI，无外部服务依赖。

## 运行

```bash
uv sync
uv run python main.py        # 或 uv run uvicorn main:app --reload
```

内置演示账号（见 `app/seed.py`）：`admin/admin-pass`、`analyst/analyst-pass`、`viewer/viewer-pass`、`multi/multi-pass`（多角色）。

## 角色与权限模型

- 一个账号可拥有**多个角色**；接口按**权限点**放行，用户权限 = 其所有角色权限的并集。
- 角色 → 权限映射在 `app/config.py` 的 `Settings.role_permissions`：

| 角色     | 权限点                                       |
| -------- | -------------------------------------------- |
| admin    | profile:read, reports:read, admin:sessions   |
| analyst  | profile:read, reports:read                   |
| viewer   | profile:read                                 |

- 路由用 `require_permission("reports:read")` 这类依赖声明所需权限（`app/deps.py`）。

### 错误码（区分失败原因，不混为一谈）

响应体统一为 `{"detail": {"code": ..., "message": ...}}`：

| code                | HTTP | 含义                                   |
| ------------------- | ---- | -------------------------------------- |
| not_authenticated   | 401  | 未携带/未正确使用 Bearer 凭据          |
| token_invalid       | 401  | 访问令牌格式或签名非法                 |
| token_expired       | 401  | 访问令牌已过期                         |
| session_revoked     | 401  | 会话已被撤销（或账号被禁用）           |
| refresh_invalid     | 401  | 刷新令牌不存在                         |
| refresh_expired     | 401  | 刷新令牌已过期                         |
| refresh_reused      | 401  | 刷新令牌被**重放**（一次性令牌再用）   |
| bad_credentials     | 401  | 登录用户名/密码错误                    |
| forbidden           | 403  | 已登录但权限不足                       |

## 凭据生命周期

1. **登录** `POST /auth/login` → 创建会话，签发访问令牌（HMAC 签名，默认 300s）+ 刷新令牌（不透明随机串，服务端只存 SHA-256 散列，默认 7 天）。
2. **刷新** `POST /auth/refresh` → **一次性轮换**：旧刷新令牌立即作废，换发新对。检查-轮换在 `Store.locked()` 临界区内原子完成。
   - 旧令牌被再次使用（含并发）→ 判定为**重放**：返回 `refresh_reused`，并**熔断整个会话**（新换出的令牌也一并失效），写审计 `refresh_reuse_detected`。
   - 过期 → `refresh_expired`；不存在 → `refresh_invalid`；会话已撤销 → `session_revoked`。
3. **访问** 受保护接口带 `Authorization: Bearer <access_token>`；校验签名、过期、会话撤销状态。
4. **撤销**（需 `admin:sessions` 权限）：
   - `POST /admin/sessions/{session_id}/revoke` 撤销单个会话；
   - `POST /admin/users/{user_id}/revoke-all` 撤销某用户全部会话。
   - 撤销与刷新共享同一把锁，二者竞争时结果自洽：会话已撤销就绝不会再换出新凭据。
5. **审计**：登录成功/失败、刷新、重放检测、越权尝试、撤销均写入内存审计日志（`Store.audit`）并输出到 `app.audit` 日志器。

## 接口一览

| 方法 | 路径                          | 所需权限       |
| ---- | ----------------------------- | -------------- |
| POST | /auth/login                   | 无             |
| POST | /auth/refresh                 | 无             |
| GET  | /me                           | profile:read   |
| GET  | /reports                      | reports:read   |
| POST | /admin/sessions/{sid}/revoke  | admin:sessions |
| POST | /admin/users/{uid}/revoke-all | admin:sessions |

## 验证方法

```bash
uv run pytest        # 全部 26 条用例，纯本地、无外部服务/真实凭据
```

测试日志会打印覆盖的业务范围（登录、越权、过期、重放、并发撤销）与每条用例结果。覆盖场景：

- `tests/test_login_and_authn.py`：登录成败、缺失/伪造凭据的区分；
- `tests/test_rbac.py`：越权 403、多角色权限并集、越权审计；
- `tests/test_refresh_rotation.py`：轮换、重放熔断、过期/无效/重放三者的区分；
- `tests/test_revocation.py`：撤销立即生效、全用户撤销、审计记录；
- `tests/test_concurrency.py`：16 线程并发刷新仅 1 个成功其余判重放；撤销与刷新竞争 30 轮结果自洽。

配置可用环境变量覆盖：`APP_SECRET_KEY`、`APP_ACCESS_TTL`、`APP_REFRESH_TTL`。
