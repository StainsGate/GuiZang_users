use axum::{routing::get, Router};
use gz_core::AppState;
use gz_web::ApiResponse;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{openapi, Modify, OpenApi};

mod auth;
mod extractors;
mod permissions;
mod roles;
mod users;

#[derive(OpenApi)]
#[openapi(
    info(
        title = "gz-users 用户微服务 API",
        description = "用户注册/登录/刷新令牌、用户管理、RBAC（角色/权限）接口文档",
        version = "0.1.0"
    ),
    modifiers(&ApiDocSecurity),
    security(
        ("bearerAuth" = [])
    ),
    tags(
        (name = "System", description = "系统接口"),
        (name = "Auth", description = "认证与会话"),
        (name = "Users", description = "用户管理"),
        (name = "Roles", description = "角色管理"),
        (name = "Permissions", description = "权限查询")
    ),
    paths(
    ping,
    auth::register,
    auth::login,
    auth::refresh,
    auth::logout,
    auth::me,
    users::list_users,
    users::create_user,
    users::get_user,
    users::update_user,
    users::delete_user,
    roles::list_roles,
    roles::create_role,
    roles::get_role,
    roles::update_role,
    roles::delete_role,
    roles::replace_role_permissions,
    roles::replace_user_roles,
    permissions::list_permissions
))]
pub struct ApiDoc;

struct ApiDocSecurity;

impl Modify for ApiDocSecurity {
    fn modify(&self, openapi: &mut openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ping", get(ping))
        .merge(auth::router())
        .merge(users::router())
        .merge(roles::router())
        .merge(permissions::router())
}

#[utoipa::path(
    get,
    path = "/v1/ping",
    tag = "System",
    security(()),
    responses(
        (status = 200, description = "连通性检查（pong）")
    )
)]
async fn ping() -> ApiResponse<&'static str> {
    ApiResponse::ok("pong")
}
