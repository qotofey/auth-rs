#![warn(clippy::all, clippy::pedantic)]

pub mod config;
// pub mod di;
pub mod providers;
pub mod app;

use crate::providers::HashFuncProvider;

fn main() {
    dotenvy::dotenv().ok();
    let conf = config::Config::init();
    println!("DATABASE_URL={}", conf.database_url);
    let argon2_provider = providers::Argon2Provider::new();
    println!("Password hash = {}", argon2_provider.provide("Qwerty123!".to_string()));
}

