use crate::{
    app::{
        queries::{
            FindUserCredentialDao,
            FindUserSecretDao,
        },
        commands::{
            RegisterUserDao,
            AuthenticateUserDao,
            RefreshSessionDao,
            ChangePasswordDao,
            DeleteUserDao,
            RestoreUserDao,
            register_user::RegisterUserCommand,
            authenticate_user::AuthenticateUserCommand,
            refresh_session::RefreshSessionCommand,
            change_password::ChangePasswordCommand,
            delete_user::SoftDeleteUserCommand,
            restore_user::RestoreUserCommand,
        },
    },
    providers::{HashFuncProvider, HashVerifierProvider, IdProvider, TokenEncoderProvider},
};

pub struct Container<H, V, I, T, R, A, S, D, C>
where
    H: HashFuncProvider + Clone,
    V: HashVerifierProvider + Clone,
    I: IdProvider + Clone,
    T: TokenEncoderProvider + Clone,
    R: RegisterUserDao,
    A: FindUserCredentialDao + FindUserSecretDao+ AuthenticateUserDao + ChangePasswordDao + Clone,
    S: RefreshSessionDao,
    D: DeleteUserDao,
    C: RestoreUserDao,
{
    pub register_user_command: RegisterUserCommand<H, R>,
    pub authenticate_user_command: AuthenticateUserCommand<H, V, I, T, A>,
    pub refresh_session_command: RefreshSessionCommand<I, T, S>,
    pub change_password_command: ChangePasswordCommand<H, V, A>,
    pub delete_user_command: SoftDeleteUserCommand<V, D>,
    pub restore_user_command: RestoreUserCommand<V, C>,
}

impl<H, V, I, T, R, A, S, D, C> Container<H, V, I, T, R, A, S, D, C>
where
    H: HashFuncProvider + Clone,
    V: HashVerifierProvider + Clone,
    I: IdProvider + Clone,
    T: TokenEncoderProvider + Clone,
    R: RegisterUserDao,
    A: FindUserCredentialDao + FindUserSecretDao + AuthenticateUserDao + ChangePasswordDao + Clone,
    S: RefreshSessionDao,
    D: DeleteUserDao,
    C: RestoreUserDao,
{
    pub fn new(
        hash_func_provider: H,
        hash_verifier_provider: V,
        id_provider: I,
        token_provider: T,
        register_user_dao: R, 
        authenticate_user_dao: A,
        refresh_session_dao: S,
        delete_user_dao: D,
        restore_user_dao: C,
    ) -> Self {
        let register_user_command = RegisterUserCommand::new(hash_func_provider.clone(), register_user_dao);
        let authenticate_user_command = AuthenticateUserCommand::new(
            hash_func_provider.clone(), 
            hash_verifier_provider.clone(), 
            id_provider.clone(), 
            token_provider.clone(), 
            authenticate_user_dao.clone(),
        );
        let refresh_session_command = RefreshSessionCommand::new(id_provider, token_provider, refresh_session_dao);
        let change_password_command = ChangePasswordCommand::new(hash_func_provider, hash_verifier_provider.clone(), authenticate_user_dao);
        let delete_user_command = SoftDeleteUserCommand::new(hash_verifier_provider.clone(), delete_user_dao);
        let restore_user_command = RestoreUserCommand::new(hash_verifier_provider, restore_user_dao);

        Self {
            register_user_command,
            authenticate_user_command,
            refresh_session_command,
            change_password_command,
            delete_user_command,
            restore_user_command,
        }
    }
}

