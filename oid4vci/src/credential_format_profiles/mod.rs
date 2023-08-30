pub mod iso_mdl;
pub mod w3c_verifiable_credentials;

use self::{
    iso_mdl::mso_mdoc::MsoMdoc,
    sealed::FormatExtension,
    w3c_verifiable_credentials::{jwt_vc_json::JwtVcJson, jwt_vc_json_ld::JwtVcJsonLd, ldp_vc::LdpVc},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[macro_export]
macro_rules! credential_format {
    ($format:literal, $name:ty, {$($field_name:ident: $field_type:ty),*}) => {
        paste::paste! {
            #[derive(Debug, Clone, Eq, PartialEq, Default)]
            pub struct $name;
            impl $crate::credential_format_profiles::Format for $name {
                type Parameters = [< $name Parameters >];
                type Credential = serde_json::Value;
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
pub enum CredentialFormats<C = WithParameters>
where
    C: FormatExtension + DeserializeOwned,
{
    JwtVcJson(C::Container<JwtVcJson>),
    JwtVcJsonLd(C::Container<JwtVcJsonLd>),
    LdpVc(C::Container<LdpVc>),
    MsoMdoc(C::Container<MsoMdoc>),
    Other(serde_json::Value),
}

impl<C> CredentialFormatCollection for CredentialFormats<C> where C: FormatExtension {}

impl TryInto<CredentialFormats<()>> for &CredentialFormats<WithCredential> {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<CredentialFormats<()>, Self::Error> {
        match self {
            CredentialFormats::JwtVcJson(credential) => Ok(CredentialFormats::<()>::JwtVcJson(Profile {
                format: credential.format.clone(),
            })),
            CredentialFormats::JwtVcJsonLd(credential) => Ok(CredentialFormats::<()>::JwtVcJsonLd(Profile {
                format: credential.format.clone(),
            })),
            CredentialFormats::LdpVc(credential) => Ok(CredentialFormats::<()>::LdpVc(Profile {
                format: credential.format.clone(),
            })),
            CredentialFormats::MsoMdoc(credential) => Ok(CredentialFormats::<()>::MsoMdoc(Profile {
                format: credential.format.clone(),
            })),
            CredentialFormats::Other(_) => Err(anyhow::anyhow!(
                "unable to convert CredentialFormats<WithCredential> to CredentialFormats<()>"
            )),
        }
    }
}

impl CredentialFormats<WithCredential> {
    pub fn credential(&self) -> anyhow::Result<&serde_json::Value> {
        match self {
            CredentialFormats::JwtVcJson(credential) => Ok(&credential.credential),
            CredentialFormats::JwtVcJsonLd(credential) => Ok(&credential.credential),
            CredentialFormats::LdpVc(credential) => Ok(&credential.credential),
            CredentialFormats::MsoMdoc(credential) => Ok(&credential.credential),
            CredentialFormats::Other(_) => Err(anyhow::anyhow!(
                "unable to convert CredentialFormats<WithCredential> to CredentialFormats<()>"
            )),
        }
    }
}
