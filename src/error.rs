use gz_web::AppError;
use serde_json::Value;

pub fn unauthorized(message: impl Into<String>) -> AppError {
    AppError::Unauthorized {
        code: 40_001,
        message: message.into(),
        context: None,
    }
}

pub fn forbidden(message: impl Into<String>) -> AppError {
    AppError::Forbidden {
        code: 40_003,
        message: message.into(),
        context: None,
    }
}

pub fn not_found(message: impl Into<String>) -> AppError {
    AppError::NotFound {
        code: 40_404,
        message: message.into(),
        context: None,
    }
}

pub fn conflict(message: impl Into<String>) -> AppError {
    AppError::BadRequest {
        code: 40_409,
        message: message.into(),
        context: None,
    }
}

pub fn internal(message: impl Into<String>) -> AppError {
    AppError::Internal {
        code: 50_000,
        message: message.into(),
        context: None,
    }
}

pub fn bad_request(message: impl Into<String>) -> AppError {
    AppError::BadRequest {
        code: 40_000,
        message: message.into(),
        context: None,
    }
}

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
