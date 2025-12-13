pub mod register_user;
pub mod authenticate_user;
pub mod refresh_session;
pub mod change_password;
pub mod delete_user;

pub const LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING: u16 = 5;
pub const LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING: u16 = 3;
pub const LOCKING_IN_MINUTES: i64 = 3;

pub struct Session {
    pub user_id: uuid::Uuid,
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(sqlx::FromRow)]
pub struct UserSecret {
    pub id: uuid::Uuid,
    #[sqlx(try_from = "uuid::Uuid")]
    pub user_id: String,
    pub password_digest: String,
}

#[derive(sqlx::FromRow)]
pub struct UserCredential {
    pub id: uuid::Uuid,
    pub kind: Option<String>,
    pub login: String,
    pub confirmed_at: Option<chrono::NaiveDateTime>,
    pub user_id: uuid::Uuid,
    #[sqlx(rename = "login_attempts")]
    pub failure_login_attempts: i16,
    pub locked_until: Option<chrono::NaiveDateTime>,
}

pub trait AuthenticateUserDao {
    async fn find_user_credential_by_login(&self, login: String) -> Result<Option<UserCredential>, sqlx::Error>;
    async fn update_failure_login(&self, id: uuid::Uuid, actual_failure_login_attempts: u16, locked_until: Option<chrono::NaiveDateTime>) -> Result<(), sqlx::Error>;
    async fn create_session(&self, user_credential_id: uuid::Uuid, refresh_token: String) -> Result<(), sqlx::Error>;
}

pub trait ChangePasswordDao {
    // TODO: если не найдена запись - паникаовать
    async fn find_user_secret_by_user_id(&self, id: uuid::Uuid) -> Result<Option<UserSecret>, sqlx::Error>; 
    async fn upgrade_password_digest(&self, user_secret_id: uuid::Uuid, new_password_digest: String) -> Result<(), sqlx::Error>;
}

