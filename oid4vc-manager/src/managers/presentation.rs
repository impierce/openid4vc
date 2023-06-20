use anyhow::Result;
use oid4vp::{
    evaluate_input, ClaimFormatDesignation, InputDescriptor, InputDescriptorMappingObject, PathNested,
    PresentationDefinition, PresentationSubmission,
};
use siopv2;

// #[derive(Default)]
// pub struct InputDescriptorMappingObjectBuilder {
//     id: Option<String>,
//     format: Option<ClaimFormatDesignation>,
//     path: Option<String>,
//     path_nested: Option<PathNested>,
// }

// impl InputDescriptorMappingObjectBuilder {
//     pub fn new() -> Self {
//         InputDescriptorMappingObjectBuilder::default()
//     }

//     pub fn build(self) -> Result<InputDescriptorMappingObject> {
//         Ok(InputDescriptorMappingObject {
//             id: self.id.ok_or_else(|| anyhow::anyhow!("id parameter is required."))?,
//             format: self
//                 .format
//                 .ok_or_else(|| anyhow::anyhow!("format parameter is required."))?,
//             path: self
//                 .path
//                 .ok_or_else(|| anyhow::anyhow!("path parameter is required."))?,
//             path_nested: self.path_nested,
//         })
//     }

//     pub fn input_descriptor(mut self, input_descriptor: &InputDescriptor) -> Self {}

//     // pub fn id(mut self, id: String) -> Self {
//     //     self.id = Some(id);
//     //     self
//     // }

//     // pub fn format(mut self, format: ClaimFormatDesignation) -> Self {
//     //     self.format = Some(format);
//     //     self
//     // }

//     // pub fn path(mut self, path: String) -> Self {
//     //     self.path = Some(path);
//     //     self
//     // }

//     // pub fn path_nested(mut self, path_nested: PathNested) -> Self {
//     //     self.path_nested = Some(path_nested);
//     //     self
//     // }
// }

pub struct PresentationManager;

impl PresentationManager {
    pub fn create_presentation_submission(
        presentation_definition: &PresentationDefinition,
        credential: &serde_json::Value,
    ) -> Result<PresentationSubmission> {
        let id = "Submission ID".to_string();
        let definition_id = presentation_definition.id().clone();
        let descriptor_map = presentation_definition
            .input_descriptors()
            .iter()
            .map(|input_descriptor| {
                if evaluate_input(input_descriptor, &credential) {
                    Ok(InputDescriptorMappingObject {
                        id: input_descriptor.id().clone(),
                        format: ClaimFormatDesignation::LdpVc,
                        path: "$".to_string(),
                        path_nested: None,
                    })
                } else {
                    Err(anyhow::anyhow!("Input descriptor evaluation failed"))
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(PresentationSubmission {
            id,
            definition_id,
            descriptor_map,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use did_key::{generate, Ed25519KeyPair, PatchedKeyPair};
    use getset::Getters;
    use identity_core::common::{Object, Url};
    use identity_credential::{
        credential::{Credential, Jwt},
        presentation::JwtPresentation,
    };
    use oid4vp::VerifiablePresentation;
    use serde::{Deserialize, Serialize};
    use serde_with::skip_serializing_none;
    use siopv2::{
        jwt, request::ResponseType, token::id_token::RFC7519Claims, AuthorizationRequest, RequestUrl, Scope, Subject,
    };

    use crate::{methods::key_method::KeySubject, ProviderManager};

    use super::*;

    #[skip_serializing_none]
    #[derive(Serialize, Deserialize, Debug, Getters, Default, PartialEq)]
    pub struct TempVc {
        #[serde(flatten)]
        #[getset(get = "pub")]
        pub rfc7519_claims: RFC7519Claims,
        pub vc: serde_json::Value,
    }

    #[skip_serializing_none]
    #[derive(Serialize, Deserialize, Debug, Getters, Default, PartialEq)]
    pub struct TempVp {
        #[serde(flatten)]
        #[getset(get = "pub")]
        pub rfc7519_claims: RFC7519Claims,
        pub vp: serde_json::Value,
    }

    #[tokio::test]
    async fn test_presentation_manager() {
        let presentation_definition: PresentationDefinition = serde_json::from_str(
            r#"{
                    "id":"Verifiable Presentation request for sign-on",
                    "input_descriptors":[
                    {
                        "id":"Request for Ferris's Verifiable Credential",
                        "constraints":{
                            "fields":[
                                {
                                    "path":[
                                        "$.vc.type"
                                    ],
                                    "filter":{
                                        "type":"array",
                                        "contains":{
                                            "const":"PersonalInformation"
                                        }
                                    }
                                },
                                {
                                    "path":[
                                        "$.vc.credentialSubject.givenName"
                                    ]
                                },
                                {
                                    "path":[
                                        "$.vc.credentialSubject.familyName"
                                    ]
                                },
                                {
                                    "path":[
                                        "$.vc.credentialSubject.email"
                                    ]
                                },
                                {
                                    "path":[
                                        "$.vc.credentialSubject.birthdate"
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }"#,
        )
        .unwrap();

        let issuer = KeySubject::from_keypair(generate::<Ed25519KeyPair>(Some(&[0x0d; 32])));

        let credential: TempVc = serde_json::from_str(
            r#"{
                "sub": "did:key:z6Mkg1XXGUqfkhAKU1kVd1Pmw6UEj1vxiLj1xc91MBz5owNY",
                "iss": "did:key:z6MkpFkurpyZgyna5SAfLpvdzp7W6cvdc1fn9YECrwv3AMbF",
                "iat": 0,
                "exp": 9999999999,
                "nonce": "nonce",
                "vc": {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "PersonalInformation"
                    ],
                    "issuanceDate": "2022-01-01T00:00:00Z",
                    "issuer": "did:key:z6MkpFkurpyZgyna5SAfLpvdzp7W6cvdc1fn9YECrwv3AMbF",
                    "credentialSubject": {
                    "id": "did:key:z6Mkg1XXGUqfkhAKU1kVd1Pmw6UEj1vxiLj1xc91MBz5owNY",
                    "givenName": "Ferris",
                    "familyName": "Crabman",
                    "email": "ferris.crabman@crabmail.com",
                    "birthdate": "1985-05-21"
                    }
                }
            }"#,
        )
        .unwrap();

        dbg!(&credential);

        let credential = jwt::encode(Arc::new(issuer), &credential).await.unwrap();

        dbg!(&presentation_definition);

        let authorization_request: AuthorizationRequest = RequestUrl::builder()
            .response_type(ResponseType::IdTokenVpToken)
            .client_id("did:example:123".to_string())
            .redirect_uri("https://example.com".to_string())
            .scope(Scope::openid())
            .presentation_definition(presentation_definition)
            .nonce("nonce".to_string())
            .build()
            .and_then(TryInto::try_into)
            .unwrap();

        let presentation_definition = authorization_request
            .presentation_definition()
            .as_ref()
            .unwrap()
            .clone();

        // for input_descriptor in presentation_definition.input_descriptors() {
        //     let temp = evaluate_input(input_descriptor, &credential);
        //     assert!(temp);
        // }

        let presentation_manager = PresentationManager;

        let subject = KeySubject::from_keypair(generate::<Ed25519KeyPair>(Some(
            "this-is-a-very-UNSAFE-secret-key".as_bytes().try_into().unwrap(),
        )));

        let provider_manager = ProviderManager::new([Arc::new(subject)]).unwrap();
        let request_url = RequestUrl::Request(Box::new(authorization_request));

        let authorization_request = provider_manager.validate_request(request_url).await.unwrap();

        let verifiable_presentation = JwtPresentation::builder(
            Url::parse("did:key:z6Mkg1XXGUqfkhAKU1kVd1Pmw6UEj1vxiLj1xc91MBz5owNY").unwrap(),
            Object::new(),
        )
        .credential(Jwt::from(credential))
        .build()
        .unwrap();

        let verifiable_presentation = VerifiablePresentation::JwtVp(verifiable_presentation);

        dbg!(&serde_json::to_string(&verifiable_presentation));

        let presentation_submission = PresentationSubmission {
            id: "id".to_string(),
            definition_id: "Verifiable Presentation request for sign-on".to_string(),
            descriptor_map: vec![InputDescriptorMappingObject {
                id: "Request for Ferris's Verifiable Credential".to_string(),
                format: ClaimFormatDesignation::JwtVp,
                path: "$".to_string(),
                path_nested: Some(PathNested {
                    id: None,
                    path: "$.vp.verifiableCredential".to_string(),
                    format: ClaimFormatDesignation::JwtVcJson,
                    path_nested: None,
                }),
            }],
        };

        let authorization_response = provider_manager
            .generate_response(
                authorization_request,
                Default::default(),
                Some(verifiable_presentation),
                Some(presentation_submission),
            )
            .await
            .unwrap();

        dbg!(&authorization_response);
    }
}
