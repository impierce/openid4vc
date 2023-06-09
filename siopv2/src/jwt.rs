use getset::Getters;
use jsonwebtoken::{Algorithm, Header};
use serde::Serialize;

#[derive(Debug, Serialize, Getters)]
pub struct JsonWebToken<C>
where
    C: Serialize,
{
    #[getset(get = "pub")]
    pub header: Header,
    pub payload: C,
}

impl<C> JsonWebToken<C>
where
    C: Serialize,
{
    pub fn new(payload: C) -> Self {
        JsonWebToken {
            // TODO: Undo hardcoding and consider not using the jsonwebtoken crate.
            header: Header::new(Algorithm::EdDSA),
            payload,
        }
    }

    pub fn kid(mut self, kid: String) -> Self {
        self.header.kid = Some(kid);
        self
    }
}
