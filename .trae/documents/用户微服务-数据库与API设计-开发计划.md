# 用户微服务：数据库设计、API 设计与开发计划（Plan）

## 1. 目标与成功标准

**目标**
- 为当前用户微服务仓库补齐：数据库（PostgreSQL）表结构设计、对外 REST API 设计、以及可直接落地的开发实施计划。

**成功标准**
- 数据库设计包含：核心表、字段、约束、索引、关系、软删除/审计/并发控制方案、刷新令牌存储方案。
- API 设计包含：路由清单、请求/响应结构、鉴权方式、RBAC 权限边界、错误模型、分页与幂等约定。
- 开发计划可执行：明确要改/新增哪些文件、依赖、目录结构、迁移与测试策略；避免依赖当前仓库不可见的外部实现细节。

## 2. 现状分析（基于仓库勘查）

- 技术栈：Rust 2021 + Tokio + Axum 0.8；通过 `gz_core::App` 启动；仅有 `GET /health` 路由（见 [main.rs](file:///c:/Development/users/src/main.rs)）。
- 配置：`config/default.toml` 与 `config/dev.toml` 仅包含 `server/shutdown`（见 [default.toml](file:///c:/Development/users/config/default.toml)、[dev.toml](file:///c:/Development/users/config/dev.toml)）。
- 数据库：无任何 DB/ORM 依赖与迁移目录；无数据模型与存储实现。
- 外部依赖约束：核心启动、`AppConfig/AppState`、中间件等在 `gz-core/gz-web/gz-observe` Git 依赖中，本仓库无法直接推断其扩展点与边界。

## 3. 已确认的关键需求与决策

- 登录标识：邮箱 + 手机号（两者可选其一登录，均可绑定）。
- 鉴权范围：密码登录 + RBAC。
- 数据库：PostgreSQL。
- 关键能力：软删除、审计字段、幂等与版本（并发控制）。
- Rust DB 访问层：SQLx。
- 令牌策略：JWT + 刷新令牌（Refresh Token）轮换、可撤销。
- 密码哈希：Argon2id。

## 4. 数据库设计（PostgreSQL）

### 4.1 通用约定

- 主键：`uuid`（服务端生成）。
- 时间：`timestamptz`（UTC）。
- 软删除：`deleted_at timestamptz null`，业务查询默认 `deleted_at is null`。
- 审计：`created_at/updated_at` + `created_by/updated_by uuid null`（操作者未知时允许 null）。
- 并发控制：`row_version bigint not null default 0`，更新时 `where row_version = ?`，成功后 `row_version = row_version + 1`。
- 幂等：对关键写入接口支持 `Idempotency-Key`，落库保存“请求指纹 + 响应快照”。

### 4.2 表结构（建议 v1）

#### 4.2.1 `users`

用途：用户档案（Profile）与登录标识信息。

字段（建议）
- `id uuid pk`
- `email text null`
- `email_normalized text null`（用于不区分大小写唯一性，例如存储 `lower(email)`）
- `email_verified_at timestamptz null`
- `phone text null`
- `phone_verified_at timestamptz null`
- `display_name text not null`
- `avatar_url text null`
- `status text not null`（如：`active|disabled`）
- `last_login_at timestamptz null`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `deleted_at timestamptz null`
- `created_by uuid null`
- `updated_by uuid null`
- `row_version bigint not null default 0`

约束与索引（建议）
- 约束：
  - 至少有一个标识：`(email is not null) or (phone is not null)`
- 唯一性（软删除场景的“活跃唯一”）：
  - `unique (email_normalized) where deleted_at is null and email_normalized is not null`
  - `unique (phone) where deleted_at is null and phone is not null`
- 查询索引：
  - `index (status) where deleted_at is null`
  - `index (created_at) where deleted_at is null`

#### 4.2.2 `user_credentials`

用途：与用户主体分离保存认证数据（便于合规与最小化暴露）。

字段（建议）
- `user_id uuid pk fk -> users(id)`
- `password_hash text not null`（仅存 Argon2id 哈希）
- `password_updated_at timestamptz not null`
- `failed_login_count int not null default 0`
- `locked_until timestamptz null`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `row_version bigint not null default 0`

索引（建议）
- `index (locked_until)`

#### 4.2.3 `roles`

字段（建议）
- `id uuid pk`
- `name text not null`
- `description text null`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `deleted_at timestamptz null`
- `created_by uuid null`
- `updated_by uuid null`
- `row_version bigint not null default 0`

约束与索引（建议）
- `unique (name) where deleted_at is null`

#### 4.2.4 `permissions`

字段（建议）
- `id uuid pk`
- `code text not null`（例如 `users.read`, `users.write`, `roles.manage`）
- `description text null`
- `created_at timestamptz not null`
- `updated_at timestamptz not null`
- `deleted_at timestamptz null`
- `row_version bigint not null default 0`

约束与索引（建议）
- `unique (code) where deleted_at is null`

#### 4.2.5 `user_roles`

字段（建议）
- `user_id uuid not null fk -> users(id)`
- `role_id uuid not null fk -> roles(id)`
- `created_at timestamptz not null`
- `created_by uuid null`

约束与索引（建议）
- `primary key (user_id, role_id)`
- `index (role_id)`

#### 4.2.6 `role_permissions`

字段（建议）
- `role_id uuid not null fk -> roles(id)`
- `permission_id uuid not null fk -> permissions(id)`
- `created_at timestamptz not null`
- `created_by uuid null`

约束与索引（建议）
- `primary key (role_id, permission_id)`
- `index (permission_id)`

#### 4.2.7 `refresh_tokens`

用途：支持刷新令牌轮换、撤销、审计；仅存 token 的哈希（不可逆）。

字段（建议）
- `id uuid pk`（token 记录 id）
- `user_id uuid not null fk -> users(id)`
- `token_hash text not null`（例如对 refresh token 做 `sha256` 后 base64）
- `issued_at timestamptz not null`
- `expires_at timestamptz not null`
- `revoked_at timestamptz null`
- `replaced_by uuid null`（轮换后指向新 token 记录 id）
- `ip text null`
- `user_agent text null`
- `created_at timestamptz not null`

约束与索引（建议）
- `unique (token_hash)`
- `index (user_id, expires_at)`
- `index (revoked_at)`

#### 4.2.8 `idempotency_records`

用途：对写接口实现幂等（客户端重试不重复创建/扣减）。

字段（建议）
- `key text not null`
- `scope text not null`（例如 `auth.register`、`users.create`）
- `request_hash text not null`（方法+路径+body 的 hash）
- `status_code int not null`
- `response_body jsonb not null`
- `created_at timestamptz not null`
- `expires_at timestamptz not null`

约束与索引（建议）
- `primary key (scope, key)`
- `index (expires_at)`

### 4.3 迁移与种子数据（建议）

- 迁移：使用 SQLx migrations（`migrations/` 目录，按时间戳命名）。
- 种子数据：
  - 内置权限码集合（`permissions`）；
  - 内置管理员角色（`roles`）及其权限绑定（`role_permissions`）；
  - 可选：初始化 admin 用户（通过一次性环境变量/启动参数触发，避免硬编码默认密码）。

## 5. API 设计（REST / JSON）

### 5.1 通用约定

- Base path：`/v1`
- Content-Type：`application/json`
- 认证：`Authorization: Bearer <access_token>`
- 幂等：对 `POST /v1/auth/register`、`POST /v1/users` 等写接口支持 `Idempotency-Key: <uuid/随机串>`
- 分页：
  - `GET` 列表使用 `page[size]`、`page[after]`（游标）或 `page[number]`（页码）二选一；v1 推荐游标分页（稳定且高性能）。
- 错误模型：
  - 统一返回结构沿用 `gz_web::ApiResponse` 现有约定（执行阶段先确认其字段形态，再对齐实现）。

### 5.2 Auth

#### 5.2.1 注册

- `POST /v1/auth/register`
  - Headers：可选 `Idempotency-Key`
  - Body（建议）
    - `email?`、`phone?`（至少一个）
    - `password`
    - `display_name`
  - Response（建议）
    - `user`（基础档案）
    - `tokens`：`access_token`, `expires_in`, `refresh_token`
  - 规则
    - email/phone 活跃唯一
    - password 用 Argon2id 哈希

#### 5.2.2 登录

- `POST /v1/auth/login`
  - Body（建议）
    - `identifier`（email 或 phone）
    - `password`
  - Response（建议）
    - `access_token`, `expires_in`, `refresh_token`
  - 安全策略（建议）
    - 失败计数与临时锁定（`user_credentials`）
    - 不泄露“用户是否存在”的差异化错误信息

#### 5.2.3 刷新令牌

- `POST /v1/auth/refresh`
  - Body：`refresh_token`
  - Response：新的 `access_token` + 新的 `refresh_token`（轮换），并将旧 refresh 标记为 revoked/replaced

#### 5.2.4 登出/撤销

- `POST /v1/auth/logout`
  - Body：`refresh_token`（或可扩展为“撤销当前会话/全部会话”）
  - Response：ok

#### 5.2.5 当前用户

- `GET /v1/auth/me`
  - Auth：必需
  - Response：`user` + `roles` + `permissions`（按实现需要返回其一或两者）

### 5.3 Users（RBAC 保护）

权限建议
- `users.read`：读取用户
- `users.write`：创建/更新/禁用用户

接口（建议）
- `GET /v1/users`（`users.read`）
  - Query：`email?`、`phone?`、`status?`、分页参数
- `POST /v1/users`（`users.write`，支持 `Idempotency-Key`）
  - 用于管理员创建用户（可选是否立即设置密码）
- `GET /v1/users/{id}`（`users.read`）
- `PATCH /v1/users/{id}`（`users.write`）
  - 支持乐观锁：`If-Match`（携带 `row_version`）或 body 中显式 `row_version`
- `DELETE /v1/users/{id}`（`users.write`）
  - 软删除

### 5.4 Roles & Permissions（RBAC 管理）

权限建议
- `roles.manage`
- `permissions.read`

接口（建议）
- `GET /v1/permissions`（`permissions.read`）
- `GET /v1/roles`（`roles.manage` 或 `roles.read`）
- `POST /v1/roles`（`roles.manage`）
- `GET /v1/roles/{id}`（`roles.manage`）
- `PATCH /v1/roles/{id}`（`roles.manage`，支持 `row_version`）
- `DELETE /v1/roles/{id}`（`roles.manage`，软删除）
- `PUT /v1/roles/{id}/permissions`（`roles.manage`）
  - Body：`permission_codes` 或 `permission_ids`
- `PUT /v1/users/{id}/roles`（`roles.manage`）
  - Body：`role_ids` 或 `role_names`

## 6. 代码落地方案（与现有框架的兼容策略）

### 6.1 State 组装策略（避免强依赖外部 `gz-core` 细节）

当前路由状态类型为 `AppState`（来自 `gz_core`）。由于 `AppState` 扩展点未知，执行阶段采用“最小侵入”策略：
- 继续使用 `AppState` 作为 Axum `State`。
- 通过 Axum `Extension` 注入：
  - `sqlx::PgPool`
  - JWT/加密相关配置（例如 `JwtKeys`、token TTL）
  - RBAC 计算所需的缓存/查询组件（可选）

这样无需假设 `gz_core::AppState` 必须包含 DB 连接池，也不要求改动 `gz_core::App` 的泛型边界。

### 6.2 目录与分层（建议）

新增模块（建议路径）
- `src/api/`：路由注册与 handler
- `src/domain/`：领域类型（User/Role/Permission）
- `src/repo/`：SQLx 查询与事务封装
- `src/service/`：业务用例（注册/登录/刷新/角色绑定等）
- `src/auth/`：JWT、密码哈希、鉴权 guard
- `migrations/`：SQLx migrations

## 7. 开发计划（实施步骤）

### 7.1 基础设施阶段

1) 引入依赖与基础配置
- 修改 [Cargo.toml](file:///c:/Development/users/Cargo.toml)
  - 增加：`sqlx`（postgres + runtime-tokio + uuid + chrono + json）、`uuid`、`chrono`、`argon2`、`sha2`、`base64`、`jsonwebtoken`（或同类 JWT 库）、`thiserror`（如现有错误体系不足）
- 新增环境变量约定（避免改动 `AppConfig` 结构）
  - `DATABASE_URL`
  - `JWT_SECRET`（或 `JWT_PRIVATE_KEY/JWT_PUBLIC_KEY`，视选型）
  - `ACCESS_TOKEN_TTL_SECONDS`、`REFRESH_TOKEN_TTL_SECONDS`（可选）

2) 初始化 DB 连接池并挂载到 Router
- 在 [main.rs](file:///c:/Development/users/src/main.rs) 中：
  - 创建 `PgPool`（从 `DATABASE_URL`）
  - `router.layer(Extension(pg_pool))` 注入

### 7.2 数据库阶段

3) 创建 migrations
- 新增 `migrations/`，按 4.2 表结构创建 SQL
- 添加必要索引与部分唯一索引（软删除活跃唯一）

4) 实现 repo 层（SQLx）
- 为每个聚合提供最小查询集：
  - users：按 id、按 email/phone、列表、创建、更新（含 row_version）、软删除
  - credentials：创建/更新、读取（用于登录校验）、失败计数与锁定更新
  - roles/permissions：CRUD 与绑定关系维护
  - refresh_tokens：插入、轮换、撤销、按 hash 查询
  - idempotency：插入/读取/过期清理（可先不做后台清理，优先在查询路径过滤 expires）

### 7.3 业务与 API 阶段

5) auth service
- 注册：事务内创建 `users + user_credentials`，返回 tokens；支持幂等
- 登录：校验密码、更新失败计数/锁定、更新 last_login_at，签发 tokens
- 刷新：校验 refresh token、轮换、撤销旧 token
- 登出：撤销 refresh token

6) JWT & RBAC
- JWT claim：`sub`（user_id）、`roles` 或 `permissions`（二选一；v1 建议 `roles` + 请求时从 DB 展开权限，或直接携带权限减少 DB 查询）
- RBAC 检查：提供 handler 级 guard（例如 `require_permission("users.read")`）

7) 路由与 handler
- 增加 `/v1/auth/*`、`/v1/users/*`、`/v1/roles/*`、`/v1/permissions`
- 统一响应：对齐 `ApiResponse` 规范（执行阶段先确认 `gz_web::ApiResponse` 的字段与错误映射方式）

### 7.4 测试与验收阶段

8) 测试
- repo 层：集成测试（需要 Postgres；优先使用 testcontainers 或本地 `DATABASE_URL`）
- service 层：关键路径测试（注册幂等、登录锁定、刷新轮换、乐观锁冲突）
- handler：最小 e2e（启动服务对关键路由发请求）

9) 验收清单（最小）
- migrations 可在干净库上执行成功
- 注册/登录/刷新/登出链路可跑通
- RBAC：无权限返回 403；有权限可访问
- 软删除后同 email/phone 可再次注册（活跃唯一）
- 并发更新可触发版本冲突（409）

## 8. 假设与边界

- 不修改 `gz_core::AppConfig` 结构；DB/JWT 等配置通过环境变量注入。
- `gz_web::ApiResponse` 为项目统一响应封装，执行阶段以其现有结构为准实现（不引入不兼容的自定义响应格式）。
- 初版不强制实现邮箱/短信验证流程，仅预留字段；如需验证/找回密码，将在后续扩展 token 表与外部消息通道。

