use gz_web::AppError;
use serde_json::Value;

/// 构造 401 Unauthorized 错误（认证失败或缺失凭证）。
pub fn unauthorized(message: impl Into<String>) -> AppError {
    AppError::Unauthorized {
        code: 40_001,
        message: message.into(),
        context: None,
    }
}

/// 构造 403 Forbidden 错误（已认证但无权限）。
pub fn forbidden(message: impl Into<String>) -> AppError {
    AppError::Forbidden {
        code: 40_003,
        message: message.into(),
        context: None,
    }
}

/// 构造 404 Not Found 错误（资源不存在）。
pub fn not_found(message: impl Into<String>) -> AppError {
    AppError::NotFound {
        code: 40_404,
        message: message.into(),
        context: None,
    }
}

/// 构造 409 Conflict 错误（乐观锁冲突或幂等冲突）。
pub fn conflict(message: impl Into<String>) -> AppError {
    AppError::BadRequest {
        code: 40_409,
        message: message.into(),
        context: None,
    }
}

/// 构造 500 Internal 错误（服务端内部错误）。
pub fn internal(message: impl Into<String>) -> AppError {
    AppError::Internal {
        code: 50_000,
        message: message.into(),
        context: None,
    }
}

/// 构造 400 Bad Request 错误（输入不合法）。
pub fn bad_request(message: impl Into<String>) -> AppError {
    AppError::BadRequest {
        code: 40_000,
        message: message.into(),
        context: None,
    }
}

/// 为 AppError 附加结构化上下文（用于排障，不应包含敏感信息）。
pub fn with_context(err: AppError, context: Value) -> AppError {
    match err {
        AppError::BadRequest { code, message, .. } => AppError::BadRequest {
            code,
            message,
            context: Some(context),
        },
        AppError::Unauthorized { code, message, .. } => AppError::Unauthorized {
            code,
            message,
            context: Some(context),
        },
        AppError::Forbidden { code, message, .. } => AppError::Forbidden {
            code,
            message,
            context: Some(context),
        },
        AppError::NotFound { code, message, .. } => AppError::NotFound {
            code,
            message,
            context: Some(context),
        },
        AppError::TooManyRequests { code, message, .. } => AppError::TooManyRequests {
            code,
            message,
            context: Some(context),
        },
        AppError::Timeout { code, message, .. } => AppError::Timeout {
            code,
            message,
            context: Some(context),
        },
        AppError::Internal { code, message, .. } => AppError::Internal {
            code,
            message,
            context: Some(context),
        },
    }
}
