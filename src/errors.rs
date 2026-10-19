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
    UnsupportedMediaType,
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
            AppError::UnsupportedMediaType => {
                write!(f, "{}", t!("errors.unsupported_media_type"))
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Validation — уже готовый список ошибок с 422.
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

        let (status, error) = match &self {
            AppError::UsernameIsTaken => (
                StatusCode::CONFLICT,
                ErrorObject::new("409", t!("errors.username_taken")),
            ),
            AppError::UnknownDatabaseError | AppError::UnknownError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorObject::new("500", t!("errors.unknown_error")),
            ),
            AppError::WeakPassword => (
                StatusCode::BAD_REQUEST,
                ErrorObject::new("400", t!("errors.weak_password")),
            ),
            AppError::LoginError => (
                StatusCode::UNAUTHORIZED,
                ErrorObject::new("401", t!("errors.login_error")),
            ),
            AppError::TempLocked => (
                StatusCode::TOO_MANY_REQUESTS,
                ErrorObject::new("429", t!("errors.temp_locked")),
            ),
            AppError::LoginRequired => (
                StatusCode::UNAUTHORIZED,
                ErrorObject::new("401", t!("errors.login_required")),
            ),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                ErrorObject::new("404", t!("errors.not_found")),
            ),
            AppError::InvalidInput(msg) => (
                StatusCode::BAD_REQUEST,
                ErrorObject::new("400", msg.clone()),
            ),
            AppError::Validation(_) => unreachable!("handled above"),
            AppError::UnsupportedMediaType => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                ErrorObject::new("415", t!("errors.unsupported_media_type"))
                    .with_header("Content-Type"),
            ),
        };

        let doc = ErrorDocument {
            errors: vec![error],
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
