#![warn(clippy::all, clippy::pedantic)]

pub mod config;
pub mod di;
pub mod providers;
pub mod app;
pub mod adapters;
pub mod errors;

#[tokio::main]
async fn main() {
    let conf = config::Config::init();
    println!("DATABASE_URL={}", &conf.database_url);
    println!("SERVER_URL={}:{}", conf.server.host, conf.server.port);
    let db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(5).connect(&conf.database_url).await.unwrap();

    let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider;
    let argon2_verifier = providers::argon2_verifier::Argon2VerifierProvider;
    let refresh_token_generator = providers::refresh_token_generator::RefreshTokenGeneratorProvider;
    let jwt_encoder = providers::jwt_encoder::JwtEncoderProvider;

    let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
    let container = di::Container::new(
        argon2_hasher,
        argon2_verifier,
        refresh_token_generator,
        jwt_encoder,
        user_repo.clone(),
        user_repo,
    );
    // container.register_user_command.call("\tqotofey    \r\n".to_string(), "\t Qwerty123!    \n".to_string()).await.unwrap();
    let res = container.authenticate_user_command.call("qotofey".to_string(), "   Qwerty123!".to_string()).await.unwrap();
    println!("Refresh Token = {} \nAccess Token = {}", res.refresh_token, res.access_token);
}

