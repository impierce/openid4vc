pub mod authorization_details;
pub mod authorization_server_metadata;
pub mod credential;
pub mod credential_definition;
pub mod credential_issuer;
pub mod credential_issuer_metadata;
pub mod credential_offer;
pub mod credential_request;
pub mod credential_response;
pub mod credentials_supported;
pub mod proof;
pub mod token_request;
pub mod token_response;
pub mod wallet;

pub use credential::{VerifiableCredentialJwt, VerifiableCredentialJwtBuilder};
use credential_definition::CredentialDefinition;
use paste::paste;
pub use proof::{Cwt, Jwt, Proof, ProofType};
use serde::{Deserialize, Serialize};
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

            #[allow(unused_parens)]
            impl From<($($field_type),*)> for [< $name Parameters >] {
                fn from(($($field_name),*): ($($field_type),*)) -> Self {
                    Self {
                        $($field_name),*
                    }
                }
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

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CredentialFormatEnum {
    JwtVcJson(CredentialFormat<JwtVcJson>),
    MsoDoc(CredentialFormat<MsoDoc>),
}

#[test]
fn test() {
    let jwt_vc_json = CredentialFormat {
        format: JwtVcJson,
        parameters: CredentialDefinition {
            type_: vec!["VerifiableCredential".into(), "UniversityDegreeCredential".into()],
            credential_subject: None,
        }
        .into(),
    };

    let mso_doc = CredentialFormat {
        format: MsoDoc,
        parameters: (
            "org.iso.18013.5.1.mDL".to_string(),
            serde_json::json!({
                "org.iso.18013.5.1": {
                    "given_name": {},
                    "last_name": {},
                    "birth_date": {}
                },
                "org.iso.18013.5.1.aamva": {
                    "organ_donor": {}
                }
            }),
        )
            .into(),
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
