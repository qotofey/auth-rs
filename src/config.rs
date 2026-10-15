// TODO: add validation
#[derive(Debug, validator::Validate, serde::Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database_url: String,
    #[validate(range(min = 1))]
    pub database_max_connections: u8,
    pub jwt_secret: String,
    #[validate(range(min = 1))]
    pub jwt_access_token_ttl_minutes: u64,
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
            .set_default("database_url", "")
            .unwrap()
            .set_default("database_max_connections", 5)
            .unwrap()
            .set_default("server.host", "0.0.0.0")
            .unwrap()
            .set_default("server.port", 5000)
            .unwrap()
            .set_default("jwt_secret", "")
            .unwrap()
            .set_default("jwt_access_token_ttl_minutes", 15)
            .unwrap()
            .add_source(config::Environment::default().separator("__"))
            .build()
            .unwrap();

        config.try_deserialize().unwrap()
    }
}
