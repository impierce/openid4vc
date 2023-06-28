use crate::{jwt, subject_syntax_type::DidMethod, Subjects, Validators};
use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;
use std::str::FromStr;

pub struct Decoder {
    pub validators: Validators,
}

impl Decoder {
    pub async fn decode<T: DeserializeOwned>(&self, jwt: String) -> Result<T> {
        let (kid, algorithm) = jwt::extract_header(&jwt)?;
        //  TODO: decode for JWK Thumbprint
        let did_method = DidMethod::from(did_url::DID::from_str(&kid)?);

        let validator = self
            .validators
            .get(&did_method.into())
            .ok_or_else(|| anyhow!("No validator found for this signed JWT."))?;
        let public_key = validator.public_key(&kid).await?;
        jwt::decode(&jwt, public_key, algorithm)
    }
}

impl From<&Subjects> for Decoder {
    fn from(subjects: &Subjects) -> Self {
        Self {
            validators: Validators::from(subjects),
        }
    }
}
