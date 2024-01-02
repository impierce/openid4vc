pub mod iso_mdl;
pub mod w3c_verifiable_credentials;

use self::{
    iso_mdl::mso_mdoc::MsoMdoc,
    sealed::FormatExtension,
    w3c_verifiable_credentials::{jwt_vc_json::JwtVcJson, jwt_vc_json_ld::JwtVcJsonLd, ldp_vc::LdpVc},
};
use oid4vc_core::JsonValue;
use serde::{Deserialize, Serialize};

#[macro_export]
macro_rules! credential_format {
    ($format:literal, $name:ty, {$($field_name:ident: $field_type:ty),*}) => {
        use oid4vc_core::JsonValue;
        paste::paste! {
            #[derive(Debug, Clone, Eq, PartialEq, Default)]
            pub struct $name;
            impl $crate::credential_format_profiles::Format for $name {
                type Parameters = [< $name Parameters >];
                type Credential = JsonValue;
            }

            #[serde_with::skip_serializing_none]
            #[derive(Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq, Clone)]
            pub struct [< $name Parameters >] {
                $(pub $field_name: $field_type),*
            }

            #[serde_with::skip_serializing_none]
            #[derive(Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq, Clone)]
            pub struct [< $name Credential >] {
                $(pub $field_name: $field_type),*
            }

            #[allow(unused_parens)]
            impl From<($($field_type),*)> for [< $name Parameters >] {
                fn from(($($field_name),*): ($($field_type),*)) -> Self {
                    Self {
                        $($field_name),*
                    }
                }
            }
        }
    };
}

pub trait Format: std::fmt::Debug + Sync + Send + Clone {
    type Parameters: std::fmt::Debug + Serialize + Clone + Send + Sync;
    type Credential: std::fmt::Debug + Serialize + Clone + Send + Sync;
}

mod sealed {
    use super::Format;
    use serde::Serialize;

    pub trait FormatExtension: Clone + std::fmt::Debug {
        type Container<F: Format + Clone>: Serialize + std::fmt::Debug + Clone + Sync + Send;
    }
}

impl FormatExtension for () {
    type Container<F: Format> = ();
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct WithParameters;
impl FormatExtension for WithParameters {
    type Container<F: Format> = Parameters<F>;
}
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub struct Parameters<F>
where
    F: Format,
{
    #[serde(flatten)]
    pub parameters: F::Parameters,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct WithCredential;
impl FormatExtension for WithCredential {
    type Container<F: Format> = Credential<F>;
}
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Credential<F>
where
    F: Format,
{
    pub credential: F::Credential,
}

pub trait CredentialFormatCollection: Serialize + Send + Sync + Clone + std::fmt::Debug {}

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
#[serde(tag = "format")]
pub enum CredentialFormats<C = ()>
where
    C: FormatExtension,
{
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson(C::Container<JwtVcJson>),
    #[serde(rename = "jwt_vc_json-ld")]
    JwtVcJsonLd(C::Container<JwtVcJsonLd>),
    #[serde(rename = "ldp_vc")]
    LdpVc(C::Container<LdpVc>),
    #[serde(rename = "mso_mdoc")]
    MsoMdoc(C::Container<MsoMdoc>),
}

impl<C> CredentialFormatCollection for CredentialFormats<C> where C: FormatExtension {}

impl CredentialFormats<WithCredential> {
    pub fn credential(&self) -> anyhow::Result<&JsonValue> {
        match self {
            CredentialFormats::JwtVcJson(credential) => Ok(&credential.credential),
            CredentialFormats::JwtVcJsonLd(credential) => Ok(&credential.credential),
            CredentialFormats::LdpVc(credential) => Ok(&credential.credential),
            CredentialFormats::MsoMdoc(credential) => Ok(&credential.credential),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        w3c_verifiable_credentials::jwt_vc_json::{self, JwtVcJsonParameters},
        *,
    };
    use serde_json::json;

    #[test]
    fn test_credential_formats() {
        // Assert that the credential formats with known value 'jwt_vc_json' can be deserialized.
        assert_eq!(
            serde_json::from_value::<CredentialFormats>(json!({
                "format": "jwt_vc_json"
            }))
            .unwrap(),
            CredentialFormats::JwtVcJson(())
        );
    }

    #[test]
    fn test_credential_formats_with_parameters() {
        // Assert that the credential formats with known value 'jwt_vc_json' can be deserialized
        // with format specific parameters.
        assert_eq!(
            serde_json::from_value::<CredentialFormats<WithParameters>>(json!({
                "format": "jwt_vc_json",
                "credential_definition":{
                    "type": [
                        "VerifiableCredential",
                        "DriverLicenseCredential"
                    ]
                }
            }))
            .unwrap(),
            CredentialFormats::JwtVcJson(Parameters {
                parameters: JwtVcJsonParameters {
                    credential_definition: jwt_vc_json::CredentialDefinition {
                        type_: vec![
                            "VerifiableCredential".to_string(),
                            "DriverLicenseCredential".to_string(),
                        ],
                        credential_subject: None,
                    },
                    order: None,
                },
            })
        );
    }
}
