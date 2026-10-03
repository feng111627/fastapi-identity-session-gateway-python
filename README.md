# FastAPI 身份认证与会话网关

在最小 FastAPI 骨架之上实现的一套**可实际使用**的登录、会话续期与接口鉴权能力：

- 账号可拥有**多个角色**，接口按**权限**放行；
- 未登录 / 凭据无效 / 凭据过期 / 重放 / 会话撤销 / 权限不足，返回**各不相同、稳定可读的错误码**；
- 刷新凭据**一次性**使用，每次刷新换发新对凭据，旧凭据立即作废；重复或并发使用旧凭据一律判为**重放**（与普通过期区分）；
- 管理员可撤销**单个会话**或某用户的**全部会话**，撤销立即生效；刷新与撤销并发时结论自洽，不会出现"已撤销却成功换新凭据"；
- 关键动作（登录、刷新、拒绝、撤销、登出）全部写入**审计记录**；
- 仅使用本地能力（标准库 + 已安装的 FastAPI/httpx），**不依赖外部服务或真实凭据**。

## 运行

```bash
uv sync                       # 安装锁定依赖
uv run python main.py         # 启动服务（127.0.0.1，随机端口）
# 或
uv run uvicorn main:app --reload
```

## 角色与权限模型

角色到权限的映射集中在 `app/deps.py` 的 `ROLE_PERMISSIONS`：

| 角色 | 权限 |
| --- | --- |
| `admin` | 拥有**全部**权限（隐含，不在表中展开） |
| `viewer` | `profile:read`, `content:read` |
| `editor` | `profile:read`, `content:read`, `content:write` |
| `auditor` | `profile:read`, `audit:read`, `session:read` |

- 一个账号可有多个角色，权限取各角色权限的**并集**（演示用户 `bob` 同时是 `viewer` 与 `editor`）。
- 接口通过依赖声明所需权限，例如：

```python
from app.deps import require_permission, require_admin, CurrentUser

@router.post("/editor-area",
             dependencies=[Depends(require_permission("content:write"))])
def editor_area(principal: CurrentUser): ...

@router.post("/admin/...", ...)
def admin_only(principal: CurrentUser):
    require_admin(principal)   # 仅 admin 角色
```

鉴权分两步：`current_principal` 先验访问令牌（签名 + 过期 + 会话状态），
`require_permission(...)` 再判权限；因此"没登录"和"登录了但越权"结论天然可区分。

### 预置演示账号（仅本地演示，进程内存储）

| 用户名 | 密码 | 角色 |
| --- | --- | --- |
| `admin` | `admin-pass` | admin |
| `alice` | `alice-pass` | viewer |
| `bob` | `bob-pass` | viewer, editor |
| `carol` | `carol-pass` | auditor |

## 凭据生命周期

```
  POST /auth/login  ──────────────►  access_token (15 分钟)  +  refresh_token (7 天, 一次性)
        │                                  │                        │
        │                                  ▼                        ▼
        │                       Authorization: Bearer      POST /auth/refresh
        │                       访问业务接口                ├─ 验签/过期
        │                                                   ├─ 会话是否被撤销
        │                                                   ├─ 旧 jti 是否用过（重放判定）
        │                                                   └─ 原子轮转：旧 jti 作废 + 发新对凭据
        ▼
  POST /auth/logout / 管理员撤销 ──► 会话 revoked，新旧访问/刷新凭据立即失效
```

- **令牌格式**：`base64url(payload).base64url(HMAC-SHA256)`，仅用标准库实现（`app/security.py`）。
  密钥取环境变量 `IDENTITY_SECRET_KEY`；未设置时进程启动随机生成，重启后旧令牌全部失效。
- **访问令牌**：自包含（sub/sid/roles/exp），短期 15 分钟。每次请求除验签外，
  还会向会话存储确认其会话未被撤销，因此撤销无需等待令牌自然过期。
- **刷新令牌（一次性 + 轮转）**：携带唯一 `jti`。刷新成功的**同一临界区**内完成
  "旧 jti 加入 used 集合 → 新 jti 生效 → 换发新 access/refresh"，
  保证：
  - 旧刷新令牌再用一次 → `refresh_token_replayed`（重放，不是过期）；
  - 并发拿同一枚刷新令牌刷新 → **恰好一个成功**，其余全部 `refresh_token_replayed`；
  - 连续多次刷新形成链，只有**最新一枚**刷新令牌有效，历史全部作废。
- **撤销**：
  - 单会话：`POST /admin/sessions/{id}/revoke`；
  - 用户级：`POST /admin/users/{username}/revoke-sessions`，
    通过单调递增的用户 epoch 使该用户所有旧会话立即失效，但撤销之后的新登录不受影响；
  - 登出等价于撤销当前会话。
  撤销与刷新共用同一把 `RLock`，二者的"判定 + 变更"互斥，
  任何交错顺序下都不可能出现"会话已撤销却成功换出新凭据"。

## 统一错误结论

所有认证/授权错误统一返回：

```json
{ "error": { "code": "<code>", "message": "<可读说明>" } }
```

| code | HTTP | 含义 |
| --- | --- | --- |
| `not_authenticated` | 401 | 未携带凭据（未登录） |
| `invalid_credentials` | 401 | 登录密码错误，或令牌缺失/格式错/签名错/类型错 |
| `token_expired` | 401 | 凭据正常过期（访问或刷新令牌） |
| `refresh_token_replayed` | 401 | 一次性刷新凭据被重复或并发使用（重放） |
| `session_revoked` | 401 | 所属会话已被管理员撤销（或登出） |
| `user_sessions_revoked` | 401 | 该用户全部会话已被撤销 |
| `permission_denied` | 403 | 已认证，但角色不具备所需权限 |

注意过期与重放的区分：`token_expired` 表示凭据到了有效期；
`refresh_token_replayed` 表示凭据本身可能没过期，但已被消费过。

## 接口一览

| 方法/路径 | 权限 | 说明 |
| --- | --- | --- |
| `POST /auth/login` | 公开 | 用户名密码换令牌对 |
| `POST /auth/refresh` | 持刷新令牌 | 一次性轮转，换新对凭据 |
| `POST /auth/logout` | 已登录 | 撤销当前会话 |
| `GET /me` | 已登录 | 当前主体与角色 |
| `GET /viewer-area` | `content:read` | 读权限演示 |
| `POST /editor-area` | `content:write` | 写权限演示（越权高发） |
| `GET /audit-area` | `audit:read` | 审计读权限演示 |
| `POST /admin/sessions/{id}/revoke` | admin | 撤销单会话 |
| `POST /admin/users/{username}/revoke-sessions` | admin | 撤销某用户全部会话 |
| `GET /admin/sessions` | admin | 查看会话 |
| `GET /admin/audit` | admin | 查看审计记录 |

审计动作包括：`login`、`login_failed`、`refresh`、`refresh_denied`、
`logout`、`admin_revoke_session`、`admin_revoke_user_sessions`、
`access_revoked`，每条记录带序号、时间、操作者、目标、会话、结果
（`success`/`denied`/`failure`）与说明。

## 验证方法（本地、无外部依赖）

```bash
# 一键：按业务分组打印每条用例及其结果，并汇总覆盖了哪些业务
uv run python -m tests.run_tests

# 或使用标准 unittest（同样只依赖本地）
uv run python -m unittest discover -s tests -v
```

覆盖 8 类业务、27 条用例：

- **登录认证**：成功、密码错误、未知用户；
- **角色与权限**：未登录、单角色可读不可写、多角色权限并集、越权 403、非管理员访问管理接口；
- **凭据有效性**：格式/伪造/篡改签名、访问令牌过期、刷新令牌过期（与重放区分）、刷新换发新令牌；
- **刷新重放**：旧刷新令牌二次使用判重放、连续轮转只有最新令牌有效、跨用户会话独立；
- **会话撤销**：撤单会话后访问/刷新立即失效、用户级撤销、撤销后新登录干净、登出即撤销；
- **并发刷新重放**：8 线程并发刷新同一令牌恰好 1 成功，其余全部重放；
- **并发撤销竞争**：刷新与撤销在 20 轮随机交错下始终自洽；用户级撤销与 6 路并发刷新竞争；
- **审计追溯**：成功/拒绝动作均有记录且序号连续。

## 代码结构

```
app/
  clock.py          # 可替换时钟（测试过期）
  errors.py         # 7 种可区分的认证/授权错误
  models.py         # 请求/响应/审计模型
  security.py       # HMAC 令牌签发、验签、过期判定
  store.py          # 用户库、会话、一次性轮转、撤销、审计（并发临界区）
  deps.py           # 当前主体解析与权限依赖（角色->权限）
  routes_auth.py    # 登录 / 刷新 / 登出
  routes_admin.py   # 撤销 / 会话与审计查询
  routes_demo.py    # 公开与分级权限演示接口
  main.py           # 应用组装、依赖注入、统一错误处理、演示账号
tests/              # 27 条用例 + 业务化结果输出
```
