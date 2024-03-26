use crate::{jwt, Subjects, Validators};
use anyhow::{anyhow, Result};
use serde::de::DeserializeOwned;

pub struct Decoder {
    pub validators: Validators,
}

impl Decoder {
    pub async fn decode<T: DeserializeOwned>(&self, jwt: String) -> Result<T> {
        let (kid, algorithm) = jwt::extract_header(&jwt)?;
        //  TODO: decode for JWK Thumbprint
        for validator in &self.validators.0 {
            if let Ok(public_key) = validator.1.public_key(&kid).await {
                return jwt::decode(&jwt, public_key, algorithm);
            }
        }

        Err(anyhow!("No validator found for this signed JWT."))
    }
}

impl From<&Subjects> for Decoder {
    fn from(subjects: &Subjects) -> Self {
        Self {
            validators: Validators::from(subjects),
        }
    }
}
