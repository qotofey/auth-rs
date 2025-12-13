use sqlx::FromRow;
use crate::{
    errors::AppError,
    app::commands::{
        AuthenticateUserDao,
        ChangePasswordDao, 
        UserSecret,
        UserCredential,
        register_user::RegisterUserDao,
        refresh_session::{RefreshSessionDao, UserSession},
        delete_user::DeleteUserDao,
    },
};

#[derive(Clone)]
pub struct UserRepository {
    pool: sqlx::PgPool,
}

impl UserRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
pub struct User {
    pub id: sqlx::types::uuid::Uuid,
}

impl RegisterUserDao for UserRepository {
    async fn register_user(&self, login_type: String, login: String, password_digest: String) -> Result<(), AppError> {
        let mut transaction = self.pool.begin().await.unwrap();

        let user = sqlx::query_as::<_, User>("INSERT INTO users DEFAULT VALUES RETURNING id;").fetch_one(&mut *transaction).await.unwrap();

        let result = sqlx::query("INSERT INTO user_credentials (login, user_id, kind) VALUES ($1, $2, $3);")
                    .bind(login)
                    .bind(user.id)
                    .bind(login_type)
                    .execute(&mut *transaction)
                    .await;
        match result {
            Err(sqlx::Error::Database(db_err)) => {
                if let Some(pg_err) = db_err.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
                    match pg_err.code() {
                        "23505" => Err(AppError::UsernameIsTaken),
                        _ => Err(AppError::UnknownDatabaseError),
                    }
                } else {
                    Err(AppError::UnknownDatabaseError)
                }
            },
            Err(_) => {
                Err(AppError::UnknownDatabaseError)
            },
            Ok(_) => {
                sqlx::query("INSERT INTO user_passwords (password_digest, user_id) VALUES ($1, $2);")
                    .bind(password_digest)
                    .bind(user.id)
                    .execute(&mut *transaction)
                    .await
                    .unwrap();
                transaction.commit().await.unwrap();
                Ok(())
            }
        }
    }
}

impl AuthenticateUserDao for UserRepository {
    async fn find_user_credential_by_login(&self, login: String) -> Result<Option<UserCredential>, sqlx::Error> {
        sqlx::query_as::<_, UserCredential>("SELECT id, kind, login, confirmed_at, user_id, login_attempts, locked_until FROM user_credentials WHERE login = $1")
            .bind(login)
            .fetch_optional(&self.pool)
            .await
    }

    async fn update_failure_login(&self, id: uuid::Uuid, actual_failure_login_attempts: u16, locked_until: Option<chrono::NaiveDateTime>) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE user_credentials SET login_attempts = $1, locked_until = $2 WHERE id = $3")
            .bind(actual_failure_login_attempts as i16)
            .bind(locked_until)
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn create_session(&self, user_credential_id: uuid::Uuid, refresh_token: String) -> Result<(), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(r#"
                UPDATE user_credentials 
                SET 
                    login_attempts = 0, 
                    locked_until = NULL,
                    confirmed_at = COALESCE(confirmed_at, CURRENT_TIMESTAMP) 
                WHERE id = $1
            "#)
            .bind(user_credential_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("UPDATE user_sessions SET deleted_at = CURRENT_TIMESTAMP WHERE user_credential_id = $1 AND deleted_at IS NULL")
            .bind(user_credential_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO user_sessions (refresh_token, user_credential_id) VALUES ($1, $2)")
            .bind(refresh_token)
            .bind(user_credential_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(())
    }
}

impl RefreshSessionDao for UserRepository {
    async fn refresh_session(&self, old_refresh_token: String, new_refresh_token: String) -> Result<Option<UserCredential>, sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let some_session_or_none = sqlx::query_as::<_, UserSession>(r#"
                UPDATE user_sessions 
                SET 
                    deleted_at = CURRENT_TIMESTAMP 
                WHERE 
                    refresh_token = $1 AND deleted_at IS NULL
                RETURNING user_credential_id
            "#)
            .bind(old_refresh_token)
            .fetch_optional(&mut *transaction)
            .await?;
        let session = match some_session_or_none {
            Some(session) => session,
            None => return Ok(None), 
        };
        // TODO: по сессии определить credential ( + user, если понадобится больше полей в jwt)
        let some_credential_or_none = sqlx::query_as::<_, UserCredential>("SELECT id, kind, login, confirmed_at, user_id, login_attempts, locked_until FROM user_credentials WHERE confirmed_at IS NOT NULL AND (locked_until IS NULL OR locked_until < CURRENT_TIMESTAMP) AND id = $1")
            .bind(session.user_credential_id)
            .fetch_optional(&mut *transaction)
            .await?;
        let credential = match some_credential_or_none {
            Some(credential) => credential,
            None => return Ok(None),
        };

        sqlx::query("INSERT INTO user_sessions (refresh_token, user_credential_id) VALUES ($1, $2)")
            .bind(new_refresh_token)
            .bind(session.user_credential_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;

        Ok(Some(credential))
    }
}

impl ChangePasswordDao for UserRepository {
    async fn find_user_secret_by_user_id(&self, id: uuid::Uuid) -> Result<Option<UserSecret>, sqlx::Error> {
        sqlx::query_as::<_, UserSecret>("SELECT * FROM user_passwords WHERE user_id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    async fn upgrade_password_digest(&self, user_secret_id: uuid::Uuid, new_password_digest: String) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE user_passwords SET password_digest = $1 WHERE id = $2")
            .bind(new_password_digest)
            .bind(user_secret_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl DeleteUserDao for UserRepository {
    async fn delete_user_by_id(&self, user_id: uuid::Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET deleted_at = CURRENT_TIMESTAMP WHERE id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
