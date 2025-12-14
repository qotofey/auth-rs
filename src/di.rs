use crate::{
    app::commands::{
        RegisterUserDao,
        AuthenticateUserDao,
        RefreshSessionDao,
        ChangePasswordDao, 
        DeleteUserDao,
        register_user::RegisterUser,
        authenticate_user::AuthenticateUser,
        refresh_session::RefreshSession,
        change_password::ChangePassword,
        delete_user::DeleteUser,
    },
    providers::{HashFuncProvider, HashVerifierProvider, IdProvider, TokenProvider},
};

pub struct Container<H, V, I, T, R, A, S, D>
where
    H: HashFuncProvider + Clone,
    V: HashVerifierProvider + Clone,
    I: IdProvider + Clone,
    T: TokenProvider + Clone,
    R: RegisterUserDao,
    A: AuthenticateUserDao + ChangePasswordDao + Clone,
    S: RefreshSessionDao,
    D: DeleteUserDao,
{
    pub register_user_command: RegisterUser<H, R>,
    pub authenticate_user_command: AuthenticateUser<H, V, I, T, A>,
    pub refresh_session_command: RefreshSession<I, T, S>,
    pub change_password_command: ChangePassword<H, V, A>,
    pub delete_user_command: DeleteUser<V, D>,
}

impl<H, V, I, T, R, A, S, D> Container<H, V, I, T, R, A, S, D>
where
    H: HashFuncProvider + Clone,
    V: HashVerifierProvider + Clone,
    I: IdProvider + Clone,
    T: TokenProvider + Clone,
    R: RegisterUserDao,
    A: AuthenticateUserDao + ChangePasswordDao + Clone,
    S: RefreshSessionDao,
    D: DeleteUserDao,
{
    pub fn new(
        hash_func_provider: H,
        hash_verifier_provider: V,
        id_provider: I,
        token_provider: T,
        register_user_dto: R, 
        authenticate_user_dto: A,
        refresh_session_dto: S,
        delete_user_dto: D,
    ) -> Self {
        let register_user_command = RegisterUser::new(hash_func_provider.clone(), register_user_dto);
        let authenticate_user_command = AuthenticateUser::new(
            hash_func_provider.clone(), 
            hash_verifier_provider.clone(), 
            id_provider.clone(), 
            token_provider.clone(), 
            authenticate_user_dto.clone(),
        );
        let refresh_session_command = RefreshSession::new(id_provider, token_provider, refresh_session_dto);
        let change_password_command = ChangePassword::new(hash_func_provider, hash_verifier_provider.clone(), authenticate_user_dto);
        let delete_user_command = DeleteUser::new(hash_verifier_provider, delete_user_dto);

        Self {
            register_user_command,
            authenticate_user_command,
            refresh_session_command,
            change_password_command,
            delete_user_command,
        }
    }
}

