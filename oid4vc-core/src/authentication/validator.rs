use crate::{jwt, Subject, Verify};
use anyhow::Result;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use tracing::info;

pub enum Validator {
    Subject(Arc<dyn Subject>),
    Verifier(Arc<dyn Verify>),
}

impl Validator {
    pub async fn public_key(&self, kid: &str) -> Result<Vec<u8>> {
        match self {
            Validator::Subject(subject) => subject.public_key(kid).await,
            Validator::Verifier(verifier) => verifier.public_key(kid).await,
        }
    }

    pub async fn decode<T: DeserializeOwned>(&self, jwt: String) -> Result<T> {
        info!("Decoding JWT: {}", jwt);
        let (kid, algorithm) = jwt::extract_header(&jwt)?;

        info!("Extracted KID: {}, Algorithm: {:?}", kid, algorithm);

        let public_key = self.public_key(&kid).await?;

        info!("Public key retrieved for KID: {}", kid);

        jwt::decode(&jwt, public_key, algorithm)
    }
}
