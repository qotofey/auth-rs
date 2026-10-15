use std::fmt::{self, Display, Formatter};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

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
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::UsernameIsTaken => StatusCode::CONFLICT,
            AppError::LoginError => StatusCode::UNAUTHORIZED,
            AppError::TempLocked => StatusCode::TOO_MANY_REQUESTS,
            AppError::LoginRequired => StatusCode::UNAUTHORIZED,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::WeakPassword => StatusCode::BAD_REQUEST,
            AppError::UnknownDatabaseError | AppError::UnknownError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        (status, self.to_string()).into_response()
    }
}
