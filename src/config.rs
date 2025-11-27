use std::env;

pub struct Config {
    pub database_url: String,
    pub is_login_by_username_available: bool,
}

impl Config {
    #[must_use]
    pub fn init() -> Self {
        let database_url = env::var("DATABASE_URL").expect("DATABASE_URL должен быть заполнен");

        let is_login_by_username_available = match env::var("IS_LOGIN_BY_USERNAME_AVAILABLE") {
            Ok(value) => {
                match value.to_lowercase().as_str() {
                    "true" | "t" | "1" | "yes" | "y" => true,
                    "false" | "f" | "0" | "no" | "n" => false,
                    _ => false,
                }
            },
            _ => true,
        };

        Self {
            database_url,
            is_login_by_username_available,
        }
    }
}

