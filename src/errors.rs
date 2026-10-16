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
            AppError::UsernameIsTaken => write!(f, "{}", t!("errors.username_taken")),
            AppError::UnknownDatabaseError => write!(f, "{}", t!("errors.unknown_database_error")),
            AppError::UnknownError => write!(f, "{}", t!("errors.unknown_error")),
            AppError::WeakPassword => write!(f, "{}", t!("errors.weak_password")),
            AppError::LoginError => write!(f, "{}", t!("errors.login_error")),
            AppError::TempLocked => write!(f, "{}", t!("errors.temp_locked")),
            AppError::LoginRequired => write!(f, "{}", t!("errors.login_required")),
            AppError::NotFound => write!(f, "{}", t!("errors.not_found")),
            AppError::InvalidInput(msg) => write!(f, "{}", msg),
            AppError::Validation(errors) => {
                write!(
                    f,
                    "{}: {} error(s)",
                    t!("errors.validation_failed"),
                    errors.len()
                )
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
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
            AppError::UsernameIsTaken => (
                StatusCode::CONFLICT,
                t!("errors.username_taken").to_string(),
            ),
            AppError::UnknownDatabaseError | AppError::UnknownError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                t!("errors.unknown_error").to_string(),
            ),
            AppError::WeakPassword => (
                StatusCode::BAD_REQUEST,
                t!("errors.weak_password").to_string(),
            ),
            AppError::LoginError => (
                StatusCode::UNAUTHORIZED,
                t!("errors.login_error").to_string(),
            ),
            AppError::TempLocked => (
                StatusCode::TOO_MANY_REQUESTS,
                t!("errors.temp_locked").to_string(),
            ),
            AppError::LoginRequired => (
                StatusCode::UNAUTHORIZED,
                t!("errors.login_required").to_string(),
            ),
            AppError::NotFound => (StatusCode::NOT_FOUND, t!("errors.not_found").to_string()),
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
