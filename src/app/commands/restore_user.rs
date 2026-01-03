use crate::{
    errors::AppError,
    providers::HashVerifierProvider,
    app::commands::RestoreUserDao,
};

pub struct RestoreUserCommand<V, C>
where
    V: HashVerifierProvider,
    C: RestoreUserDao,
{
    hash_verifier_provider: V,
    repo: C,
}

impl<V, C> RestoreUserCommand<V, C>
where
    V: HashVerifierProvider,
    C: RestoreUserDao,
{
    pub fn new(hash_verifier_provider: V, repo: C) -> Self {
        Self { hash_verifier_provider, repo }
    }

    pub async fn call(&self, user_id: uuid::Uuid, _password: String) -> Result<(), AppError> {
        // запросить user secrets по user_id, чтобы disabled_at IS NULL
        // верифицировать password_digest

        match self.repo.restore_user_by_id(user_id).await {
            Ok(_) => Ok(()),
            Err(_) => Err(AppError::UnknownDatabaseError),
        }
    }
}
