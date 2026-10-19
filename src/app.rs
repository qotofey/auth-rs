pub mod commands;
pub mod queries;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(type_name = "genders", rename_all = "lowercase")]
pub enum Gender {
    Female,
    Male,
}

impl Gender {
    pub fn as_str(&self) -> &'static str {
        match self {
            Gender::Female => "female",
            Gender::Male => "male",
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct NewUserProfile {
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub birthdate: Option<chrono::NaiveDate>,
    pub gender: Option<Gender>,
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

#[derive(sqlx::FromRow)]
pub struct UserSecret {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub password_digest: String,
}

#[derive(sqlx::FromRow)]
pub struct User {
    pub id: uuid::Uuid,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub birthdate: Option<chrono::NaiveDate>,
    pub gender: Option<Gender>,
    pub blocked_at: Option<chrono::NaiveDateTime>,
    pub deleted_at: Option<chrono::NaiveDateTime>,
}
