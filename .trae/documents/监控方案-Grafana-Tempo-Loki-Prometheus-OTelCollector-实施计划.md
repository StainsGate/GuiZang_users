# 监控方案（Grafana + Tempo + Loki + Prometheus + OpenTelemetry Collector）实施计划

## 1. Summary

目标是在当前 `gz-users` 微服务上落地一套“指标 + 链路 + 日志”的可观测性方案：

* **Traces**：服务以 **OTLP** 上报 → **OpenTelemetry Collector** → **Tempo** → Grafana Explore

* **Metrics**：服务以 **OTLP metrics** 上报 → Collector 暴露 **Prometheus /metrics** → **Prometheus** 抓取 → Grafana Dashboard

* **Logs**：服务以 **OTLP logs** 上报 → Collector → **Loki** → Grafana Explore

* **可运行环境**：复用已生成的本地部署目录 [`deploy/observability/`](file:///c:/Development/users/deploy/observability)，用 **docker compose** 一键启动

## 2. Current State Analysis（基于仓库与依赖勘查）

### 2.1 服务现状

* 服务入口：[`src/main.rs`](file:///c:/Development/users/src/main.rs)

  * 当前仅初始化 `gz_observe::init_tracing(TracingConfig::from_env())`（stdout 日志）

  * 未启用 OpenTelemetry（`gz-observe` 的 `otel` feature 未开启）

* 中间件：`gz-web` middleware 内使用 `tower_http::trace::TraceLayer` 生成 `http.request` span（见私有依赖源码 `crates/web/src/middleware.rs`）

### 2.2 观测库能力

* `gz-observe`（tag **0.1.2**）在 feature `otel` 下支持：

  * `init_otel()`：OTLP **traces + metrics + logs**（统一资源属性与全局 propagator）

  * `init_tracing_with_otel()`：tracing-subscriber + OTLP **traces + logs**（并注册 OTLP metrics provider）

  * 默认 OTLP endpoint：`OTEL_EXPORTER_OTLP_ENDPOINT`（默认 `http://localhost:4317`）

  * 默认 service.name：`OTEL_SERVICE_NAME`（默认 `gz-service`）

### 2.3 当前基础设施

* 根目录已有 `docker-compose.yml`（当前仅 Postgres）：[docker-compose.yml](file:///c:/Development/users/docker-compose.yml)

* 配置目录：`config/default.toml` 与 `config/dev.toml`（已包含 db 配置、jwt\_secret、server.addr）

* 本地观测栈部署目录（已生成）：[`deploy/observability/`](file:///c:/Development/users/deploy/observability)

  * compose：[`deploy/observability/docker-compose.yml`](file:///c:/Development/users/deploy/observability/docker-compose.yml)

  * Collector：[`deploy/observability/otel-collector-config.yaml`](file:///c:/Development/users/deploy/observability/otel-collector-config.yaml)

  * Prometheus：[`deploy/observability/prometheus.yml`](file:///c:/Development/users/deploy/observability/prometheus.yml)

  * Tempo：[`deploy/observability/tempo.yaml`](file:///c:/Development/users/deploy/observability/tempo.yaml)

  * Grafana 数据源预置：[`deploy/observability/grafana/provisioning/datasources/datasources.yaml`](file:///c:/Development/users/deploy/observability/grafana/provisioning/datasources/datasources.yaml)

## 3. Decisions & Assumptions（已确认/默认）

已由你确认：

* OTLP 接收/转发层：**OpenTelemetry Collector**

* 日志进 Loki：**OTEL Logs via Collector**

* 指标采集：**Prometheus pull scrape**

* 运行环境：**本地 docker compose**

默认假设（如需调整可在执行阶段替换）：

* OTLP 协议：优先 gRPC `4317`（服务 → collector）

* Tempo 启用 OTLP receiver（collector → tempo 也用 OTLP gRPC）

* Grafana 仅做本地开发默认账号密码（后续生产再加鉴权/HTTPS）

## 4. Proposed Changes（具体改动点）

### 4.1 代码侧：启用 traces + metrics + logs（基于 gz-observe 0.1.2 的 OTEL）

**文件：** [Cargo.toml](file:///c:/Development/users/Cargo.toml)

* 为 `gz-observe` 打开 feature：`features = ["otel"]`

**文件：** [src/main.rs](file:///c:/Development/users/src/main.rs)

* 将 `init_tracing(...)` 改为“按环境选择”：

  * 若设置 `OTEL_EXPORTER_OTLP_ENDPOINT`（或 `APP_OTEL_ENABLED=true`）则调用 `gz_observe::init_tracing_with_otel(TracingConfig::from_env())`

  * 否则保持现有 `init_tracing(...)`（本地不启用 collector 时也能运行）

* 需要把返回的 guard 保持到进程结束（避免 provider 提前 shutdown）

* 设置 `OTEL_SERVICE_NAME=gz-users`（推荐放在运行环境变量中）

* 推荐设置 `APP_ENV=dev`（让资源属性里包含 `deployment.environment=dev`）

**注意：分布式链路上下文传播**

* 当前 `gz-web` 的 `TraceLayer` span 未显式从 HTTP headers 提取 `traceparent` 作为 parent，可能导致链路“看得到 span，但不串起来”。

* 两条路径（执行时二选一）：

  1. 在本仓库追加一个 axum middleware：从 headers 提取 `traceparent` 并将其设为当前 span parent（需要评估与 `gz-web` TraceLayer 的配合）。
  2. 在 `gz-web` 上游调整 `make_span_with`：用 `opentelemetry_http::HeaderExtractor` + `OpenTelemetrySpanExt::set_parent` 把请求 parent 关联起来。

### 4.2 代码侧：OTLP Logs（满足“OTEL Logs via Collector”）

`gz-observe 0.1.2` 在 `otel` feature 下已内置 logs pipeline：

* `init_otel()` 会初始化 OTLP log exporter + logger provider

* `init_tracing_with_otel()` 会把 `tracing` events 桥接为 OTEL logs 并发往 `OTEL_EXPORTER_OTLP_ENDPOINT`

因此代码侧只需要：

* 打开 `gz-observe` 的 `otel` feature

* 在启用 OTEL 时调用 `init_tracing_with_otel(...)`

* 确保业务日志使用 `tracing::{info,warn,error,debug}`（当前项目已在使用）

### 4.3 docker compose：复用 deploy/observability（观测栈服务）

当前已存在可用的观测栈 compose 与配置文件（不影响现有 Postgres compose），直接复用：

* compose：[`deploy/observability/docker-compose.yml`](file:///c:/Development/users/deploy/observability/docker-compose.yml)

  * services：`otel-collector`、`tempo`、`loki`、`prometheus`、`grafana`

* 端口（localhost）：

  * Grafana：`3000`

  * Prometheus：`9090`

  * Loki：`3100`

  * Tempo：`3200`

  * OTel Collector（OTLP gRPC/HTTP）：`4317` / `4318`

  * OTel Collector（Prometheus exporter endpoint）：`9464`

Collector 配置要点（当前文件已满足）：

* OTLP receiver：`0.0.0.0:4317`（gRPC）与 `0.0.0.0:4318`（HTTP）

* traces → tempo：`otlp/tempo endpoint=tempo:4317`

* metrics → prometheus exporter：`endpoint=0.0.0.0:9464`（Prometheus 抓 `otel-collector:9464`）

* logs → loki exporter：`endpoint=http://loki:3100/loki/api/v1/push`

* processors：包含 `attributes/redact`（删掉 `password/secret/token/authorization` 等敏感字段）

* resource：从 `APP_ENV` 注入 `deployment.environment`

**运行方式（PowerShell）：**

* 启动 Postgres（在仓库根目录）：

  * `docker compose up -d`

* 启动观测栈（在仓库根目录任选其一）：

  * `Set-Location .\deploy\observability; docker compose up -d`

  * 或 `docker compose -f .\deploy\observability\docker-compose.yml --project-directory .\deploy\observability up -d`

### 4.4 README 文档

更新 [README.md](file:///c:/Development/users/README.md)：

* 新增“Observability / 监控栈”章节：

  * 启动命令（分别启动 Postgres 与 deploy/observability）

  * 关键端口：

    * Grafana `3000`

    * Prometheus `9090`

    * Loki `3100`

    * Tempo `3200`

    * OTel Collector `4317/4318`、Prometheus exporter `9464`

  * 常用排障命令（查看容器日志、验证 endpoints）

* 增加如何验证数据链路：

  * 访问 `/health` 与 `/v1/ping` 产生 trace/log

  * Grafana Explore：Tempo 查 trace、Loki 查日志、Prometheus 查指标

## 5. Verification（验收与排障步骤）

### 5.1 基础连通性

* 启动 Postgres + 观测栈后确认容器均 running（尤其 tempo/loki/collector）

* 用浏览器或 `Invoke-WebRequest` 验证：

  * `http://localhost:3000`（Grafana）

  * `http://localhost:9090`（Prometheus）

### 5.2 服务上报验证

* 启动 `gz-users`（本地）并设置（PowerShell）：

  * `$env:OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4317"`

  * `$env:OTEL_SERVICE_NAME="gz-users"`

  * `$env:APP_ENV="dev"`

* 请求几个接口（/health、/v1/ping、/v1/auth/\*）

### 5.3 Grafana 验证

* Tempo：能看到 `service.name=gz-users` 的 traces

* Loki：能检索到 `gz-users` 的日志（先用 label 浏览器确认 `service.name` 对应的实际 label key）

* Prometheus：能看到来自 collector exporter 的指标（以及 `up`、scrape 正常）

### 5.4 常见问题

* Swagger UI 空白：确认访问 `/v1/swagger-ui/`（带尾斜杠）

* 无 traces/logs：确认启用了 `gz-observe` 的 `otel` feature 且设置了 `OTEL_EXPORTER_OTLP_ENDPOINT`，并确保 `init_tracing_with_otel(...)` 的 guard 未提前 drop

* traces 不串联：需要做 header context 提取（见 4.1 的“注意”）

* Grafana 没有数据源：确认 `deploy/observability/grafana/provisioning` 目录已正确挂载（见 compose volumes）

