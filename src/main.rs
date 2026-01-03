#![warn(clippy::all, clippy::pedantic)]

pub mod config;
pub mod di;
pub mod providers;
pub mod app;
pub mod adapters;
pub mod errors;

const DATABASE_MAX_CONNECTIONS: u32 = 5;
const ARGON2_MEMORY_COST: u32 = 8;//32768;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

#[tokio::main]
async fn main() {
    let conf = config::Config::init();
    println!("DATABASE_URL={}", &conf.database_url);
    println!("SERVER_URL={}:{}", conf.server.host, conf.server.port);
    let db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(DATABASE_MAX_CONNECTIONS).connect(&conf.database_url).await.unwrap();

    let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM);
    let argon2_verifier = providers::argon2_verifier::Argon2VerifierProvider::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM);

    let refresh_token_generator = providers::refresh_token_generator::RefreshTokenGeneratorProvider;
    let jwt_encoder = providers::jwt_encoder::JwtEncoderProvider;

    let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
    let container = di::Container::new(
        argon2_hasher,
        argon2_verifier,
        refresh_token_generator,
        jwt_encoder,
        user_repo.clone(),
        user_repo.clone(),
        user_repo.clone(),
        user_repo.clone(),
        user_repo,
    );
    // let res = container.register_user_command.call("qotofey".to_string(), "Qwerty123!".to_string()).await.unwrap();
    let res = container.authenticate_user_command.call("qotofey  ".to_string(), "Qwerty123!".to_string()).await.unwrap();
    let res = container.refresh_session_command.call(res.refresh_token).await.unwrap();
    let res = container.refresh_session_command.call(res.refresh_token).await.unwrap();
    let res = container.refresh_session_command.call(res.refresh_token).await.unwrap();
    let _ = container.change_password_command.call(res.user_id, "Qwerty123!".to_string(), "123123".to_string()).await.unwrap();
    let res = container.authenticate_user_command.call("qotofey".to_string(), "123123".to_string()).await.unwrap();
    let res = container.refresh_session_command.call(res.refresh_token).await.unwrap();
    let res = container.refresh_session_command.call(res.refresh_token).await.unwrap();
    let _ = container.change_password_command.call(res.user_id, "123123".to_string(), "Qwerty123!".to_string()).await.unwrap();
    let res = container.refresh_session_command.call(res.refresh_token).await.unwrap();

    println!("Refresh Token = {} \nAccess Token = {}", res.refresh_token, res.access_token);
    let _ = container.delete_user_command.call(res.user_id, "123123".to_string()).await.unwrap();
    let _ = container.restore_user_command.call(res.user_id, "123123".to_string()).await.unwrap();
}

