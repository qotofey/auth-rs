use crate::{
    errors::AppError,
    providers::{
        HashFuncProvider,
        HashVerifierProvider, 
        IdProvider, 
        TokenEncoderProvider,
    },
    app::{
        queries::{
            FindUserCredentialDao,
            FindUserSecretDao,
        },
        commands::{
            LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING,
            LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING,
            LOCKING_IN_MINUTES,
            Session,
            AuthenticateUserDao,
            ChangePasswordDao,
        },
    },
};

pub struct AuthenticateUserCommand<H, V, I, T, A>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    I: IdProvider,
    T: TokenEncoderProvider,
    A: FindUserCredentialDao + FindUserSecretDao + AuthenticateUserDao + ChangePasswordDao,
{
    hash_func_provider: H,
    hash_verifier_provider: V,
    refresh_token_generator: I,
    access_token_provider: T,
    repo: A,
}

impl<H, V, I, T, A> AuthenticateUserCommand<H, V, I, T, A>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    I: IdProvider,
    T: TokenEncoderProvider,
    A: FindUserCredentialDao + FindUserSecretDao + AuthenticateUserDao + ChangePasswordDao,
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
            self.repo.update_failure_login(credentail.id, actual_failure_login_attempts, locked_until).await?;
            if is_locked { return Err(AppError::TempLocked); }

            return Err(AppError::LoginError);
        }

        if password_confirmation.need_upgrade {
            let password_digest = match self.hash_func_provider.provide(password) {
                Some(hash) => hash,
                None => {
                    return Err(AppError::UnknownError);
                },
            };

            self.repo.upgrade_password_digest(secret.id, password_digest).await?;
        }

        let refresh_token = match self.refresh_token_generator.provide() {
            Some(token) => token,
            None => return Err(AppError::UnknownError),
        };

        let access_token = match self.access_token_provider.provide(secret.user_id) {
            Some(token) => token,
            None => return Err(AppError::UnknownError),
        };

        let user_id = credentail.user_id;
        match self.repo.create_session(credentail.id, refresh_token.clone()).await {
            Ok(_) => Ok(Session { user_id, refresh_token, access_token }),
            Err(_) => Err(AppError::UnknownDatabaseError),
        }
    }
}
