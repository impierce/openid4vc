pub mod did_methods;

use anyhow::Result;
use did_methods::DidMethod;

pub trait Subject {
    fn did(&self) -> String;
    fn key_identifier(&self) -> Option<String>;
    fn sign(&self, message: &String) -> Result<Vec<u8>>;
}

#[derive(PartialEq)]
pub enum SubjectSyntaxType {
    JWKThumbprint,
    DID(DidMethod),
}

impl std::str::FromStr for SubjectSyntaxType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "urn:ietf:params:oauth:jwk-thumbprint" {
            Ok(SubjectSyntaxType::JWKThumbprint)
        } else if s.starts_with("did:iota") {
            Ok(SubjectSyntaxType::DID(DidMethod::Iota))
        } else {
            Err(())
        }
    }
}

// implement to_string for SubjectSyntaxType
impl ToString for SubjectSyntaxType {
    fn to_string(&self) -> String {
        match self {
            SubjectSyntaxType::JWKThumbprint => "urn:ietf:params:oauth:jwk-thumbprint".to_string(),
            SubjectSyntaxType::DID(DidMethod::Iota) => "did:iota".to_string(),
        }
    }
}
