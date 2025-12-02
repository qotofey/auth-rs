use crate::{
    app::commands::{
        register_user::{RegisterUser, RegisterUserDao},
        authenticate_user::{AuthenticateUser, AuthenticateUserDao},
        refresh_session::{RefreshSession, RefreshSessionDao},
    },
    providers::{HashFuncProvider, HashVerifierProvider, IdProvider, TokenProvider},
};

pub struct Container<H, V, I, T, R, A, S>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    I: IdProvider + Clone,
    T: TokenProvider + Clone,
    R: RegisterUserDao,
    A: AuthenticateUserDao,
    S: RefreshSessionDao,
{
    pub register_user_command: RegisterUser<H, R>,
    pub authenticate_user_command: AuthenticateUser<V, I, T, A>,
    pub refresh_session_command: RefreshSession<I, T, S>
}

impl<H, V, I, T, R, A, S> Container<H, V, I, T, R, A, S>
where
    H: HashFuncProvider,
    V: HashVerifierProvider,
    I: IdProvider + Clone,
    T: TokenProvider + Clone,
    R: RegisterUserDao,
    A: AuthenticateUserDao,
    S: RefreshSessionDao,
{
    pub fn new(
        hash_func_provider: H,
        hash_verifier_provider: V,
        id_provider: I,
        token_provider: T,
        register_user_dto: R, 
        authenticate_user_dto: A,
        refresh_session_dto: S,
    ) -> Self {
        let register_user_command = RegisterUser::new(hash_func_provider, register_user_dto);
        let authenticate_user_command = AuthenticateUser::new(hash_verifier_provider, id_provider.clone(), token_provider.clone(), authenticate_user_dto);
        let refresh_session_command = RefreshSession::new(id_provider, token_provider, refresh_session_dto);
        
        Self { 
            register_user_command,
            authenticate_user_command,
            refresh_session_command,
        }
    }
}

