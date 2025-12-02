use sqlx::types::uuid;
use crate::{
    errors::AppError,
    providers::{
        HashVerifierProvider, 
        IdProvider, 
        TokenProvider,
    }
};

const LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING: u16 = 5;
const LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING: u16 = 3;
const LOCKING_IN_MINUTES: i64 = 3;

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

#[derive(sqlx::FromRow)]
pub struct UserSecret {
    #[sqlx(try_from = "uuid::Uuid")]
    pub user_id: String,
    pub password_digest: String,
}

pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
}

pub trait AuthenticateUserDao {
    async fn find_user_credential_by_login(&self, login: String) -> Result<Option<UserCredential>, sqlx::Error>;
    // TODO: если не найдена запись - паникаовать
    async fn find_user_secret_by_user_id(&self, id: uuid::Uuid) -> Result<Option<UserSecret>, sqlx::Error>; 
    async fn update_failure_login(&self, id: uuid::Uuid, actual_failure_login_attempts: u16, locked_until: Option<chrono::NaiveDateTime>) -> Result<(), sqlx::Error>;
    async fn create_session(&self, user_credential_id: uuid::Uuid, refresh_token: String) -> Result<(), sqlx::Error>;
}

pub struct AuthenticateUser<V, I, T, A>
where
    V: HashVerifierProvider,
    I: IdProvider,
    T: TokenProvider,
    A: AuthenticateUserDao,
{
    hash_verifier_provider: V,
    refresh_token_generator: I,
    access_token_provider: T,
    repo: A,
}

impl<V, I, T, A> AuthenticateUser<V, I, T, A>
where
    V: HashVerifierProvider,
    I: IdProvider,
    T: TokenProvider,
    A: AuthenticateUserDao,
{
    pub fn new(hash_verifier_provider: V, refresh_token_generator: I, access_token_provider: T, repo: A) -> Self {
        Self {
            hash_verifier_provider,
            refresh_token_generator,
            access_token_provider,
            repo,
        }
    }

    pub async fn call(&self, login: String, password: String) -> Result<Session, AppError> {
        let credentail = match self.repo.find_user_credential_by_login(login.trim().to_lowercase()).await {
            Ok(some_or_none) => match some_or_none {
                Some(credentail) => credentail,
                None => return Err(AppError::LoginError),
            },
            Err(_) => {
                return Err(AppError::UnknownDatabaseError);
            },
        };

        let is_locked = match credentail.locked_until {
            Some(locked_until) => locked_until > chrono::Utc::now().naive_local(),
            None => false,
        };

        if is_locked { return Err(AppError::TempLocked) };

        let secret = match self.repo.find_user_secret_by_user_id(credentail.user_id).await {
            Ok(some_or_none) => match some_or_none {
                Some(secret) => secret,
                None => return Err(AppError::LoginError),
            },
            Err(_) => return Err(AppError::UnknownDatabaseError),
        };

        let is_password_correct = !self.hash_verifier_provider.provide(password.trim().to_string(), secret.password_digest);
        if is_password_correct {
            let actual_failure_login_attempts = credentail.failure_login_attempts as u16 + 1;
            let is_subject_locking = 
                actual_failure_login_attempts >= LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING && 
                (actual_failure_login_attempts - LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING) % LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING == 0;

            // TODO: eсли тут вернётся None блокировка не будет инкрементирована
            let locked_until = if is_subject_locking { 
                // TODO: обдумать алгоритм распределения времени блокировки
                chrono::Utc::now().naive_local().checked_add_signed(chrono::Duration::minutes(LOCKING_IN_MINUTES)) 
            } else { 
                None 
            };
            match self.repo.update_failure_login(credentail.id, actual_failure_login_attempts, locked_until).await {
                Ok(_) => if is_locked { return Err(AppError::TempLocked); },
                Err(_) => return Err(AppError::UnknownDatabaseError),
            };

            return Err(AppError::LoginError);
        }
        let refresh_token = match self.refresh_token_generator.provide() {
            Some(token) => token,
            None => return Err(AppError::UnknownError),
        };
        
        let access_token = match self.access_token_provider.provide(secret.user_id) {
            Some(token) => token,
            None => return Err(AppError::UnknownError),
        };
        match self.repo.create_session(credentail.id, refresh_token.clone()).await {
            Ok(_) => Ok(Session { refresh_token, access_token }),
            Err(_) => Err(AppError::UnknownDatabaseError),
        }         
    }
}
