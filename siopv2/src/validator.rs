use crate::subject_syntax_type::DidMethod;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::{slice::Iter, sync::Arc};

/// This [`Validator`] trait is used to verify JWTs.
#[async_trait]
pub trait Validator: Sync {
    async fn public_key(&self, kid: &str) -> Result<Vec<u8>>;
    fn did_method(&self) -> DidMethod;
}

#[derive(Default)]
pub struct Validators(pub Vec<Arc<dyn Validator>>);

impl Validators {
    pub fn find_validator(&self, did_method: DidMethod) -> Result<Arc<dyn Validator>> {
        self.iter()
            .find(|validator| validator.did_method() == did_method)
            .cloned()
            .ok_or_else(|| anyhow!("No validator found for DID method: {did_method}"))
    }

    pub fn add<V: Validator + 'static>(&mut self, validator: V) {
        self.0.push(Arc::new(validator));
    }

    pub fn iter(&self) -> Iter<'_, Arc<dyn Validator>> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockValidator;
    use std::str::FromStr;

    #[test]
    fn test_validators() {
        let mut validators = Validators::default();

        // Should not be able to find a validator for the 'mock' DID method.
        assert!(validators
            .find_validator(DidMethod::from_str("did:mock").unwrap())
            .is_err());

        // Add a validator for the 'mock' DID method.
        validators.add(MockValidator::new());

        // Should be able to find a validator for the 'mock' DID method.
        assert!(validators
            .find_validator(DidMethod::from_str("did:mock").unwrap())
            .is_ok());
    }
}
