# gz-users（用户微服务）

基于 Rust + Axum 的用户微服务，提供用户注册/登录/刷新令牌、用户管理、RBAC（角色/权限）等能力。统一响应结构由 `gz-web` 提供（`ApiResponse` / `AppError`），运行框架由 `gz-core` 提供（配置加载、AppState、生命周期管理）。

## 功能概览

- 健康检查：`GET /health`
- Auth（JWT + Refresh Token）
  - `POST /v1/auth/register`（支持 `Idempotency-Key` 幂等）
  - `POST /v1/auth/login`
  - `POST /v1/auth/refresh`
  - `POST /v1/auth/logout`
  - `GET /v1/auth/me`
- Users（RBAC 保护）
  - `GET /v1/users`
  - `POST /v1/users`
  - `GET /v1/users/{id}`
  - `PATCH /v1/users/{id}`
  - `DELETE /v1/users/{id}`
- RBAC 管理（RBAC 保护）
  - `GET /v1/permissions`
  - `GET /v1/roles`
  - `POST /v1/roles`
  - `GET /v1/roles/{id}`
  - `PATCH /v1/roles/{id}`
  - `DELETE /v1/roles/{id}`
  - `PUT /v1/roles/{id}/permissions`
  - `PUT /v1/users/{id}/roles`
- OpenAPI 文档
  - `GET /v1/swagger-ui/`（Swagger UI）
  - `GET /api-docs/openapi.json`（OpenAPI JSON）

## 技术栈

- Rust 2021 / Tokio
- Axum
- PostgreSQL + SQLx
- Argon2（密码哈希）
- JWT（Access Token）+ Refresh Token（落库、可撤销/轮换）

## 数据库

迁移文件位于 `migrations/`：

- `20260414120000_init.sql`：初始化表结构
- `20260414121000_seed_rbac.sql`：写入基础权限与 `admin` 角色

主要表：

- `users`：用户主体与基础资料（含软删除、审计字段、row\_version）
- `user_credentials`：密码哈希/登录锁定等敏感认证信息
- `roles` / `permissions` / `user_roles` / `role_permissions`：RBAC
- `refresh_tokens`：刷新令牌（仅存哈希）
- `idempotency_records`：幂等记录（用于注册等写接口）

## 配置与环境变量

运行环境通过 `APP_ENV` 选择配置文件（例如 `config/dev.toml`），框架默认支持 `APP__SERVER__ADDR` 形式的环境变量覆盖。

服务数据库配置建议放在 `config/<env>.toml` 的 `[db]`（例如 `config/dev.toml`），也可以用环境变量覆盖：

- `APP__DB__URL`：PostgreSQL 连接串
- `APP__DB__MAX_CONNECTIONS`：连接池最大连接数

JWT 密钥建议放在 `config/<env>.toml` 的 `jwt_secret`，也可以用环境变量覆盖：

- `APP__JWT_SECRET`：JWT 签名密钥（推荐覆盖方式）
- `JWT_SECRET`：JWT 签名密钥（兼容兜底）

示例（`config/dev.toml`）：

```toml
jwt_secret = "change-me"

[server]
addr = "127.0.0.1:8080"

[db]
url = "postgres://postgres:postgres@127.0.0.1:5432/gz_users"
max_connections = 10
```

服务额外依赖以下环境变量：

- `ACCESS_TOKEN_TTL_SECONDS`：Access Token TTL（可选，默认 900）
- `REFRESH_TOKEN_TTL_SECONDS`：Refresh Token TTL（可选，默认 2592000）

## 本地开发

1. 启动 Postgres（Docker Compose）：

```powershell
docker compose up -d
docker compose ps
```

常用命令：

```powershell
docker compose logs -f postgres
docker compose stop
docker compose start
docker compose down
docker compose down -v
```

1. 配置 JWT 密钥：

- 方式 A：在 `config/<env>.toml` 设置 `jwt_secret`（推荐）
- 方式 B：用环境变量覆盖（仅对当前 PowerShell 会话生效）：

```powershell
$env:APP__JWT_SECRET = "change-me"
```

1. 执行迁移（任选其一）：

- 使用你熟悉的迁移工具执行 `migrations/*.sql`
- 或通过 SQLx CLI 执行迁移（推荐）

### 使用 SQLx CLI 执行迁移

1. 安装（仅需一次）：

```powershell
cargo install sqlx-cli --no-default-features --features postgres,rustls
```

1. 设置 `DATABASE_URL`（SQLx CLI 读取该环境变量）：

```powershell
$env:DATABASE_URL = "postgres://postgres:postgres@127.0.0.1:5432/gz_users"
```

1. 创建数据库并执行迁移：

```powershell
sqlx database create
sqlx migrate run
```

常用命令：

```powershell
sqlx migrate info
sqlx migrate revert
```

1. 启动：

```powershell
cargo run
```

1. 停止：

```powershell
Get-NetTCPConnection -LocalPort 8080 | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force }
```

默认监听地址来自 `config/default.toml` / `config/<env>.toml` 的 `server.addr`。

## Observability（Grafana + Tempo + Loki + Prometheus + OTel Collector）

本地观测栈复用 `deploy/observability` 目录。

1. 启动观测栈（在仓库根目录）：

```powershell
Set-Location .\deploy\observability
docker compose up -d
docker compose ps
```

1. 常用命令：

```powershell
docker compose logs -f otel-collector
docker compose logs -f grafana
docker compose stop
docker compose start
docker compose down
```

1. 关键端口：

- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9090`
- Loki: `http://localhost:3100`
- Tempo: `http://localhost:3200`
- OTel Collector: `4317` (gRPC), `4318` (HTTP), `9464` (Prometheus exporter)

1. 启动服务并开启 OTEL（PowerShell）：

```powershell
cargo run
```

1. 验证链路：

- 请求 `GET /health`、`GET /v1/auth/me` 或其他 API 产生 traces/logs/metrics。
- 在 Grafana Explore 中选择 Tempo 查看 `service.name=gz-users` 链路。
- 在 Grafana Explore 中选择 Loki 检索 `gz-users` 日志。
- 在 Prometheus 查看 `up` 与 OTel Collector 导出的指标。

## 权限与引导

- `seed_rbac` 会创建 `admin` 角色并绑定基础权限。
- 首个注册用户会被自动赋予 `admin` 角色（用于系统自举）。
