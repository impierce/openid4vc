pub mod authorization_details;
pub mod authorization_request;
pub mod authorization_response;
pub mod credential;
pub mod credential_definition;
pub mod credential_format;
pub mod credential_format_profiles;
pub mod credential_issuer;
pub mod credential_offer;
pub mod credential_request;
pub mod credential_response;
pub mod credentials_supported;
pub mod proof;
pub mod token_request;
pub mod token_response;
pub mod wallet;

use crate::credential_format::{CredentialFormat, Format};
pub use credential::{VerifiableCredentialJwt, VerifiableCredentialJwtBuilder};
pub use proof::{Cwt, Jwt, Proof, ProofType};
pub use wallet::Wallet;

#[macro_export]
macro_rules! serialize_unit_struct {
    ($format:literal, $name:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str($format)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Visitor;

                impl<'de> serde::de::Visitor<'de> for Visitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                        formatter.write_str($format)
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        if value == $format {
                            Ok($name)
                        } else {
                            Err(serde::de::Error::custom(format!(
                                "expected {}, found {}",
                                $format, value
                            )))
                        }
                    }
                }

                deserializer.deserialize_str(Visitor)
            }
        }
    };
}
