pub mod iso_mdl;
pub mod w3c_verifiable_credentials;

use self::{
    iso_mdl::mso_mdoc::MsoMdoc,
    w3c_verifiable_credentials::{jwt_vc_json::JwtVcJson, jwt_vc_json_ld::JwtVcJsonLd, ldp_vc::LdpVc},
};
use serde::{Deserialize, Serialize};

#[macro_export]
macro_rules! credential_format {
    ($format:literal, $name:ty, {$($field_name:ident: $field_type:ty),*}) => {
        paste::paste! {
            #[derive(Debug, Clone, Eq, PartialEq, Default)]
            pub struct $name;
            impl $crate::credential_format_profiles::Format for $name {
                type Parameters = [< $name Parameters >];
            }

            #[serde_with::skip_serializing_none]
            #[derive(Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq, Clone)]
            pub struct [< $name Parameters >] {
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

pub trait Format: std::fmt::Debug + Serialize + Eq + PartialEq + Default {
    type Parameters: std::fmt::Debug + Serialize + for<'de> Deserialize<'de> + Eq + PartialEq + Clone;
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct CredentialFormat<F>
where
    F: Format,
{
    pub format: F,
    #[serde(flatten)]
    pub parameters: F::Parameters,
}

pub trait CredentialFormatCollection: Serialize + Send + Sync + Clone {}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum CredentialFormats {
    JwtVcJson(CredentialFormat<JwtVcJson>),
    LdpVc(CredentialFormat<LdpVc>),
    JwtVcJsonLd(CredentialFormat<JwtVcJsonLd>),
    MsoMdoc(CredentialFormat<MsoMdoc>),
    Other(serde_json::Value),
}
impl CredentialFormatCollection for CredentialFormats {}
