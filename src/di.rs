use crate::{
    config::Config,
    providers::HasherProvider,
};

pub struct Container<H>
where
    H: HasherProvider,
{
    pub hasher_provider: H,
}

impl<H> Container<H> {
    pub fn new(hasher_provider: H) -> Self {
        Self { hasher_provider }
    }
}

