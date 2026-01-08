#![warn(clippy::all, clippy::pedantic)]

use std::sync::Arc;

use crate::transports::web::Server;

pub mod adapters;
pub mod app;
pub mod config;
pub mod di;
pub mod errors;
pub mod providers;
pub mod transports;

const ARGON2_MEMORY_COST: u32 = 8; //32768;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

#[tokio::main]
async fn main() {
    let conf = config::Config::init();
    println!("SERVER_URL={}:{}", conf.server.host, conf.server.port);

    let db_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(conf.database_max_connections as u32)
        .connect(&conf.database_url)
        .await
        .unwrap();

    let argon2_hasher = providers::argon2_hasher::Argon2HasherProvider::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
    );
    let argon2_verifier = providers::argon2_verifier::Argon2VerifierProvider::new(
        ARGON2_MEMORY_COST,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
    );

    let refresh_token_generator = providers::refresh_token_generator::RefreshTokenGeneratorProvider;
    let jwt_encoder = providers::jwt_encoder::JwtEncoderProvider::new(
        conf.jwt_secret.as_bytes(),
        conf.jwt_access_token_ttl_minutes,
    );

    let user_repo = adapters::postgres::UserRepository::new(db_pool.clone());
    let container = Arc::new(di::Container::new(
        argon2_hasher,
        argon2_verifier,
        refresh_token_generator,
        jwt_encoder,
        user_repo.clone(),
        user_repo.clone(),
        user_repo.clone(),
        user_repo.clone(),
        user_repo,
    ));

    let server = Server::new(container);
    server.run(conf.server.port).await;
}
