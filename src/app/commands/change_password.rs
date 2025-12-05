use crate::{
    errors::AppError,
    providers::{
        HashFuncProvider,
        HashVerifierProvider, 
    },
    app::commands::{
        LOGIN_ATTEMPTS_BEFORE_FIRST_LOCKING,
        LOGIN_ATTEMPTS_AFTER_FIRST_LOCKING,
        LOCKING_IN_MINUTES,
        UserCredential,
        ChangePasswordDao,
    }
};

pub struct ChangePassword<H, V, C>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    C: ChangePasswordDao,
{
    hash_func_provider: H,
    hash_verifier_provider: V,
    repo: C,
}

impl<H, V, C> ChangePassword<H, V, C>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    C: ChangePasswordDao,
{
    pub fn new(hash_func_provider: H, hash_verifier_provider: V, repo: C) -> Self {
        Self {
            hash_func_provider,
            hash_verifier_provider,
            repo,
        }
    }

    pub async fn call(&self, user_id: uuid::Uuid, old_password: String, new_password: String) -> Result<(), AppError> {
        let secret = match self.repo.find_user_secret_by_user_id(user_id).await {
            Ok(some_or_none) => match some_or_none {
                Some(secret) => secret,
                None => return Err(AppError::LoginError),
            },
            Err(_) => return Err(AppError::UnknownDatabaseError),
        };
        let password_confirmation = self.hash_verifier_provider.provide(old_password, secret.password_digest);
        let is_password_correct = password_confirmation.is_confirmed;

        if !is_password_correct {
            // TODO: при 7 неудачных попытках - выкинуть пользователя
        }

        let new_password_digest = match self.hash_func_provider.provide(new_password) {
            Some(hash) => hash,
            None => {
                return Err(AppError::UnknownError);
            },
        };

        match self.repo.upgrade_password_digest(secret.id, new_password_digest).await {
            Ok(_) => Ok(()),
            Err(_) => return Err(AppError::UnknownDatabaseError),
        }
    }
}
