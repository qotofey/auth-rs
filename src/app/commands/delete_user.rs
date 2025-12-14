use crate::{
    errors::AppError,
    providers::HashVerifierProvider,
    app::commands::DeleteUserDao,
};

pub struct SoftDeleteUserCommand<V, D>
where
    V: HashVerifierProvider,
    D: DeleteUserDao,
{
    hash_verifier_provider: V,
    repo: D,
}

impl<V, D> SoftDeleteUserCommand<V, D>
where
    V: HashVerifierProvider,
    D: DeleteUserDao,
{
    pub fn new(hash_verifier_provider: V, repo: D) -> Self {
        Self { hash_verifier_provider, repo }
    }

    pub async fn call(&self, user_id: uuid::Uuid, password: String) -> Result<(), AppError> {
        // запросить user secrets по user_id, чтобы disabled_at IS NULL
        // верифицировать password_digest

        match self.repo.delete_user_by_id(user_id).await {
            Ok(_) => Ok(()),
            Err(_) => Err(AppError::UnknownDatabaseError), 
        }
    }
}
