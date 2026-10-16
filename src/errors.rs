use std::fmt::{self, Display, Formatter};

use axum::{
    Json,
    http::{
        StatusCode,
        header::{CONTENT_TYPE, HeaderValue},
    },
    response::{IntoResponse, Response},
};

use crate::transports::jsonapi::{ErrorDocument, ErrorObject};

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    UsernameIsTaken,
    UnknownDatabaseError,
    WeakPassword,
    UnknownError,
    LoginError,
    TempLocked,
    LoginRequired,
    NotFound,
    InvalidInput(String),
    Validation(Vec<ErrorObject>),
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AppError::UsernameIsTaken => write!(f, "Username is taken"),
            AppError::UnknownDatabaseError => write!(f, "Unknown database error"),
            AppError::UnknownError => write!(f, "Unknown system error"),
            AppError::WeakPassword => write!(f, "Weak password"),
            AppError::LoginError => write!(f, "Incorrect login or password"),
            AppError::TempLocked => write!(f, "Temporarily locked"),
            AppError::LoginRequired => write!(f, "Login required"),
            AppError::NotFound => write!(f, "Not Found"),
            AppError::InvalidInput(msg) => write!(f, "{}", msg),
            AppError::Validation(errors) => {
                write!(f, "Validation failed: {} error(s)", errors.len())
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Особый случай: Validation несёт уже готовый список ошибок.
        if let AppError::Validation(errors) = self {
            let doc = ErrorDocument { errors };
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                [(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/vnd.api+json"),
                )],
                Json(doc),
            )
                .into_response();
        }

        let (status, detail) = match &self {
            AppError::UsernameIsTaken => (StatusCode::CONFLICT, "Username is taken".to_string()),
            AppError::UnknownDatabaseError | AppError::UnknownError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
            AppError::WeakPassword => (StatusCode::BAD_REQUEST, "Weak password".to_string()),
            AppError::LoginError => (
                StatusCode::UNAUTHORIZED,
                "Incorrect login or password".to_string(),
            ),
            AppError::TempLocked => (
                StatusCode::TOO_MANY_REQUESTS,
                "Temporarily locked".to_string(),
            ),
            AppError::LoginRequired => (StatusCode::UNAUTHORIZED, "Login required".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found".to_string()),
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Validation(_) => unreachable!("handled above"),
        };

        let doc = ErrorDocument {
            errors: vec![ErrorObject::new(status.as_str(), detail)],
        };

        (
            status,
            [(
                CONTENT_TYPE,
                HeaderValue::from_static("application/vnd.api+json"),
            )],
            Json(doc),
        )
            .into_response()
    }
}
