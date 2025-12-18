use crate::{
    errors::AppError,
    app::{
        User,
        queries::FindUserDao,
    },
};

pub struct FindUserQuery<R>
where
    R: FindUserDao,
{
    repo: R,
}

impl<R> FindUserQuery<R>
where
    R: FindUserDao,
{
    pub fn new(repo: R) -> Self {
        Self { repo }
    }

    pub async fn call(&self, user_id: uuid::Uuid) -> Result<Option<User>, AppError> {
        self.repo.find_user_by_id(user_id).await
    }
}
