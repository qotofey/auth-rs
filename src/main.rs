#![warn(clippy::all, clippy::pedantic)]

pub mod config;
pub mod di;
pub mod providers;
pub mod app;
pub mod adapters;
pub mod errors;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let conf = config::Config::init();
    println!("DATABASE_URL={}", conf.database_url);
    let db_pool = sqlx::postgres::PgPoolOptions::new().max_connections(5).connect(&conf.database_url).await.unwrap();

    let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider;
    let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
    let container = di::Container::new(argon2_hasher, user_repo);
    container.register_user_command.call("\tqotofey    \r\n".to_string(), "\t Qwerty123!    \n".to_string()).await.unwrap();
}

