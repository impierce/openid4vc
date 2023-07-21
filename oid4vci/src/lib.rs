pub mod authorization_details;
pub mod authorization_server_metadata;
pub mod credential;
pub mod credential_definition;
pub mod credential_issuer;
pub mod credential_issuer_metadata;
pub mod credential_offer;
pub mod credential_request;
pub mod credential_response;
pub mod proof;
pub mod token_request;
pub mod token_response;
pub mod wallet;

pub use credential::{VerifiableCredentialJwt, VerifiableCredentialJwtBuilder};
use credential_definition::CredentialDefinition;
pub use proof::{Cwt, Jwt, Proof, ProofType};
use serde_with::skip_serializing_none;
pub use wallet::Wallet;

////////////////////

#[macro_export]
macro_rules! serialize_unit_struct {
    ($format:literal, $name:ident) => {
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str($format)
            }
        }

        impl<'de> Deserialize<'de> for $name {
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

////////////////////

use paste::paste;
use serde::{Deserialize, Serialize};

pub trait Format: std::fmt::Debug + Serialize {
    type Parameters: std::fmt::Debug + Serialize + for<'de> Deserialize<'de> + Clone;
}

macro_rules! impl_format {
    ($format:literal, $name:ty, {$($field_name:ident: $field_type:ty),*}) => {
        paste! {
            #[derive(Debug, Clone)]
            pub struct $name;
            impl Format for $name {
                type Parameters = [< $name Parameters >];
            }

            #[derive(Debug, Serialize, Deserialize, Clone)]
            pub struct [< $name Parameters >] {
                $(pub $field_name: $field_type),*
            }

            serialize_unit_struct!($format, $name);
        }
    };
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialFormat<F>
where
    F: Format,
{
    pub format: F,
    #[serde(flatten)]
    pub parameters: F::Parameters,
}

impl_format!("jwt_vc_json", JwtVcJson, {
    credential_definition: CredentialDefinition
});
impl_format!("mso_doc", MsoDoc, {
    doctype: String,
    claims: serde_json::Value
});

////////////////////

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CredentialFormatEnum {
    JwtVcJson(CredentialFormat<JwtVcJson>),
    MsoDoc(CredentialFormat<MsoDoc>),
}

////////////////////
/// https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-request-issuance-of-a-certa

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationDetails<F>
where
    F: Format,
{
    #[serde(rename = "type")]
    type_: String,
    #[serde(flatten)]
    credential_format: CredentialFormat<F>,
}

#[test]
fn test_authorization_details() {
    let jwt_vc_json = CredentialFormat {
        format: JwtVcJson,
        parameters: JwtVcJsonParameters {
            credential_definition: CredentialDefinition {
                type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                credential_subject: None,
            },
        },
    };

    let authorization_details = AuthorizationDetails {
        type_: "openid_credential".to_string(),
        credential_format: jwt_vc_json,
    };

    println!("{}", serde_json::to_string_pretty(&authorization_details).unwrap());
}

////////////////////
/// https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-objects-comprising-credenti

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialsSupportedObject<F>
where
    F: Format,
{
    id: Option<String>,
    #[serde(flatten)]
    credential_format: CredentialFormat<F>,
    scope: Option<String>,
    cryptographic_binding_methods_supported: Option<Vec<String>>,
    cryptographic_suites_supported: Option<Vec<String>>,
    proof_types_supported: Option<Vec<ProofType>>,
    // TODO: fix this
    display: Option<Vec<serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CredentialsSupportedJson(serde_json::Value);

impl<F: Format> From<CredentialsSupportedObject<F>> for CredentialsSupportedJson {
    fn from(value: CredentialsSupportedObject<F>) -> Self {
        CredentialsSupportedJson(serde_json::to_value(value).unwrap())
    }
}

#[test]
fn test() {
    let jwt_vc_json = CredentialFormat {
        format: JwtVcJson,
        parameters: JwtVcJsonParameters {
            credential_definition: CredentialDefinition {
                type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
                credential_subject: None,
            },
        },
    };

    let mso_doc = CredentialFormat {
        format: MsoDoc,
        parameters: MsoDocParameters {
            doctype: "org.iso.18013.5.1.mDL".to_string(),
            claims: serde_json::json!({
                "org.iso.18013.5.1": {
                    "given_name": {},
                    "last_name": {},
                    "birth_date": {}
                },
                "org.iso.18013.5.1.aamva": {
                    "organ_donor": {}
                }
            }),
        },
    };

    // let vec = vec![
    //     serde_json::to_value(&jwt_vc_json).unwrap(),
    //     serde_json::to_value(&mso_doc).unwrap(),
    // ];

    // let test = serde_json::to_string_pretty(&vec).unwrap();
    // println!("{}", &test);

    // let vec: Vec<CredentialFormatEnum> = serde_json::from_str(&test).unwrap();
    // println!("{:#?}", vec);

    // let test_a = serde_json::to_string_pretty(&jwt_vc_json).unwrap();
    // println!("{}", test_a);
    // let cusom_a = serde_json::from_str::<CredentialFormat<JwtVcJson>>(&test_a).unwrap();
    // println!("{:#?}", cusom_a);
    // println!("{}", serde_json::to_string_pretty(&mso_doc).unwrap());

    // let vec: Vec<Box<dyn MyTrait>> = vec![Box::new(jwt_vc_json), Box::new(mso_doc)];

    // println!("{}", serde_json::to_string_pretty(&vec).unwrap());
}
