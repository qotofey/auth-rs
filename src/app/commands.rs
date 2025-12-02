pub mod register_user;
pub mod authenticate_user;
pub mod refresh_session;

pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
}
