// TODO: add validation
#[derive(Debug, validator::Validate, serde::Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    // #[validate(required)]
    pub database_url: String,
    #[validate(range(min = 1))]
    pub database_max_connections: u8,
    // #[validate(range(min = 0, max = 5))]
    // pub max_user_emails: u8,
    // #[validate(range(min = 0, max = 5))]
    // pub max_user_phones: u8,
    // pub is_login_by_username_available: bool,
}

#[derive(Debug, serde::Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn init() -> Self {
        dotenvy::dotenv().ok();
        let config = config::Config::builder()
            .set_default("database_url", "").unwrap()
            .set_default("database_max_connections", 5).unwrap()
            .set_default("server.host", "0.0.0.0").unwrap()
            .set_default("server.port", 5000).unwrap()
            .add_source(
                config::Environment::default()
            )
            .build()
            .unwrap();

        config.try_deserialize().unwrap()
    }
}

