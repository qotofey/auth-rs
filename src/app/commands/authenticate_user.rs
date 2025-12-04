use sqlx::types::uuid;
use crate::{
    errors::AppError,
    providers::{
        HashFuncProvider,
        HashVerifierProvider, 
        IdProvider, 
        TokenProvider,
    },
    app::commands::Session,
    adapters::postgres::UserCredential,
};

const LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING: u16 = 5;
const LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING: u16 = 3;
const LOCKING_IN_MINUTES: i64 = 3;

#[derive(sqlx::FromRow)]
pub struct UserSecret {
    pub id: uuid::Uuid,
    #[sqlx(try_from = "uuid::Uuid")]
    pub user_id: String,
    pub password_digest: String,
}

pub trait AuthenticateUserDao {
    async fn find_user_credential_by_login(&self, login: String) -> Result<Option<UserCredential>, sqlx::Error>;
    // TODO: если не найдена запись - паникаовать
    async fn find_user_secret_by_user_id(&self, id: uuid::Uuid) -> Result<Option<UserSecret>, sqlx::Error>; 
    async fn update_failure_login(&self, id: uuid::Uuid, actual_failure_login_attempts: u16, locked_until: Option<chrono::NaiveDateTime>) -> Result<(), sqlx::Error>;
    async fn create_session(&self, user_credential_id: uuid::Uuid, refresh_token: String) -> Result<(), sqlx::Error>;
    async fn upgrade_password_digest(&self, user_secret_id: uuid::Uuid, new_password_digest: String) -> Result<(), sqlx::Error>;
}

pub struct AuthenticateUser<H, V, I, T, A>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    I: IdProvider,
    T: TokenProvider,
    A: AuthenticateUserDao,
{
    hash_func_provider: H,
    hash_verifier_provider: V,
    refresh_token_generator: I,
    access_token_provider: T,
    repo: A,
}

impl<H, V, I, T, A> AuthenticateUser<H, V, I, T, A>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    I: IdProvider,
    T: TokenProvider,
    A: AuthenticateUserDao,
{
    pub fn new(hash_func_provider: H, hash_verifier_provider: V, refresh_token_generator: I, access_token_provider: T, repo: A) -> Self {
        Self {
            hash_func_provider,
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

        let password_confirmation = self.hash_verifier_provider.provide(password.clone(), secret.password_digest);
        let is_password_correct = password_confirmation.is_confirmed;

        if !is_password_correct {
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

        if password_confirmation.need_upgrade {
            let password_digest = match self.hash_func_provider.provide(password) {
                Some(hash) => hash,
                None => {
                    return Err(AppError::UnknownError);
                },
            };

            match self.repo.upgrade_password_digest(secret.id, password_digest).await {
                Ok(_) => {},
                Err(_) => return Err(AppError::UnknownDatabaseError),
            }
        }
        println!("! before refresh_token_generator()");

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
