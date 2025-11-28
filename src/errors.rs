use std::fmt::{self, Display, Formatter};

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    UsernameIsTaken,
    UnknownDatabaseError,
    WeakPassword,
    UnknownError, 
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AppError::UsernameIsTaken => write!(f, "Username is taken"),
            AppError::UnknownDatabaseError => write!(f, "Unknown database error"),
            AppError::UnknownError => write!(f, "Unknown system error"),
            AppError::WeakPassword => write!(f, "Weak password"),
        }
    }
}
