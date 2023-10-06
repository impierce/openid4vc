pub mod iso_mdl;
pub mod w3c_verifiable_credentials;

use self::{
    iso_mdl::mso_mdoc::MsoMdoc,
    sealed::FormatExtension,
    w3c_verifiable_credentials::{jwt_vc_json::JwtVcJson, jwt_vc_json_ld::JwtVcJsonLd, ldp_vc::LdpVc},
};
use oid4vc_core::JsonValue;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

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

            $crate::serialize_unit_struct!($format, $name);
        }
    };
}

pub trait Format: std::fmt::Debug + Serialize + Sync + Send + Clone {
    type Parameters: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Send + Sync;
    type Credential: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Send + Sync;
}

mod sealed {
    use super::Format;
    use serde::{de::DeserializeOwned, Serialize};

    pub trait FormatExtension: Serialize + Clone + DeserializeOwned + std::fmt::Debug {
        type Container<F: Format + Clone + DeserializeOwned>: Serialize
            + std::fmt::Debug
            + Clone
            + Sync
            + Send
            + DeserializeOwned;
    }
}

impl FormatExtension for () {
    type Container<F: Format + DeserializeOwned> = Profile<F>;
}
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub struct Profile<F>
where
    F: Format,
{
    pub format: F,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct WithParameters;
impl FormatExtension for WithParameters {
    type Container<F: Format + DeserializeOwned> = Parameters<F>;
}
#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
pub struct Parameters<F>
where
    F: Format,
{
    pub format: F,
    #[serde(flatten)]
    pub parameters: F::Parameters,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct WithCredential;
impl FormatExtension for WithCredential {
    type Container<F: Format + DeserializeOwned> = Credential<F>;
}
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Credential<F>
where
    F: Format,
{
    pub format: F,
    pub credential: F::Credential,
}

pub trait CredentialFormatCollection: Serialize + Send + Sync + Clone + std::fmt::Debug {}

#[derive(Debug, Serialize, Clone, Eq, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum CredentialFormats<C = ()>
where
    C: FormatExtension + DeserializeOwned,
{
    JwtVcJson(C::Container<JwtVcJson>),
    JwtVcJsonLd(C::Container<JwtVcJsonLd>),
    LdpVc(C::Container<LdpVc>),
    MsoMdoc(C::Container<MsoMdoc>),
    Other(JsonValue),
}

impl<C> CredentialFormatCollection for CredentialFormats<C> where C: FormatExtension {}

impl<C> CredentialFormats<C>
where
    C: FormatExtension + DeserializeOwned,
{
    pub fn format(&self) -> anyhow::Result<CredentialFormats> {
        match self {
            CredentialFormats::JwtVcJson(_) => Ok(CredentialFormats::JwtVcJson(Profile { format: JwtVcJson })),
            CredentialFormats::JwtVcJsonLd(_) => Ok(CredentialFormats::JwtVcJsonLd(Profile { format: JwtVcJsonLd })),
            CredentialFormats::LdpVc(_) => Ok(CredentialFormats::LdpVc(Profile { format: LdpVc })),
            CredentialFormats::MsoMdoc(_) => Ok(CredentialFormats::MsoMdoc(Profile { format: MsoMdoc })),
            CredentialFormats::Other(_) => Err(anyhow::anyhow!("unable to get the format")),
        }
    }
}

impl CredentialFormats<WithCredential> {
    pub fn credential(&self) -> anyhow::Result<&JsonValue> {
        match self {
            CredentialFormats::JwtVcJson(credential) => Ok(&credential.credential),
            CredentialFormats::JwtVcJsonLd(credential) => Ok(&credential.credential),
            CredentialFormats::LdpVc(credential) => Ok(&credential.credential),
            CredentialFormats::MsoMdoc(credential) => Ok(&credential.credential),
            CredentialFormats::Other(_) => Err(anyhow::anyhow!(
                "unable to get credential from CredentialFormats<WithCredential>"
            )),
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
            CredentialFormats::JwtVcJson(Profile { format: JwtVcJson })
        );

        // Assert that unknown credential formats can still be deserialized.
        assert_eq!(
            serde_json::from_value::<CredentialFormats>(json!({
                "format": "unknown_format"
            }))
            .unwrap(),
            CredentialFormats::Other(json!({
                "format": "unknown_format"
            }))
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
                format: JwtVcJson,
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

        // Assert that unknown credential formats iwth parameters can still be deserialized.
        assert_eq!(
            serde_json::from_value::<CredentialFormats<WithParameters>>(json!({
                "format": "unknown_format",
                "unknown_format_specific_parameter": "unknown_value"
            }))
            .unwrap(),
            CredentialFormats::Other(json!(
                {
                    "format": "unknown_format",
                    "unknown_format_specific_parameter": "unknown_value"
                }
            ))
        );
    }
}
