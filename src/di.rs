use crate::{
    app::commands::{
        register_user::{RegisterUser, RegisterUserDao},
    },
    providers::HashFuncProvider,
};

pub struct Container<H, R>
where
    H: HashFuncProvider,
    R: RegisterUserDao,
{
    pub register_user_command: RegisterUser<H, R>, 
}

impl<H, R> Container<H, R>
where
    H: HashFuncProvider,
    R: RegisterUserDao,
{
    pub fn new(hash_func_provider: H, repo: R) -> Self {
        let register_user_command = RegisterUser::new(hash_func_provider, repo);
        
        Self { 
            register_user_command,
        }
    }
}

