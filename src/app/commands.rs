use crate::app::NewUserProfile;
use crate::app::UserCredential;
use crate::errors::AppError;

pub mod authenticate_user;
pub mod change_password;
pub mod delete_user;
pub mod destroy_session;
pub mod refresh_session;
pub mod register_user;
pub mod restore_user;

pub const LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING: u16 = 5;
pub const LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING: u16 = 3;
pub const LOCKING_IN_MINUTES: i64 = 3;

pub struct Session {
    pub user_id: uuid::Uuid,
    pub access_token: String,
    pub refresh_token: String,
}

pub trait RegisterUserDao {
    fn register_user(
        &self,
        login_type: String,
        login: String,
        password_digest: String,
        profile: NewUserProfile,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}

pub trait AuthenticateUserDao {
    fn update_failure_login(
        &self,
        id: uuid::Uuid,
        actual_failure_login_attempts: u16,
        locked_until: Option<chrono::NaiveDateTime>,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
    fn create_session(
        &self,
        user_credential_id: uuid::Uuid,
        refresh_token: String,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}

pub trait RefreshSessionDao {
    fn refresh_session(
        &self,
        old_refresh_token: String,
        new_refresh_token: String,
    ) -> impl std::future::Future<Output = Result<Option<UserCredential>, AppError>> + Send;
}

pub trait DestroySessionDao {
    fn destroy_session(
        &self,
        refresh_token: String,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}

pub trait ChangePasswordDao {
    fn upgrade_password_digest(
        &self,
        user_secret_id: uuid::Uuid,
        new_password_digest: String,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}

pub trait DeleteUserDao {
    fn delete_user_by_id(
        &self,
        user_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}

pub trait RestoreUserDao {
    fn restore_user_by_id(
        &self,
        user_id: uuid::Uuid,
    ) -> impl std::future::Future<Output = Result<(), AppError>> + Send;
}
